/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2008
 *
 * Authors:
 * Daniel Lezcano <daniel.lezcano at free.fr>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "bdev.h"
#include "log.h"
#include "lxcaufs.h"
#include "lxcrsync.h"
#include "utils.h"

lxc_log_define(lxcaufs, lxc);

/* the bulk of this needs to become a common helper */
extern char *dir_new_path(char *src, const char *oldname, const char *name,
		const char *oldpath, const char *lxcpath);

int aufs_clonepaths(struct bdev *orig, struct bdev *new, const char *oldname,
		const char *cname, const char *oldpath, const char *lxcpath,
		int snap, uint64_t newsize, struct lxc_conf *conf)
{
	if (!snap) {
		ERROR("aufs is only for snapshot clones");
		return -22;
	}

	if (!orig->src || !orig->dest)
		return -1;

	new->dest = dir_new_path(orig->dest, oldname, cname, oldpath, lxcpath);
	if (!new->dest)
		return -1;
	if (mkdir_p(new->dest, 0755) < 0)
		return -1;

	if (am_unpriv() && chown_mapped_root(new->dest, conf) < 0)
		WARN("Failed to update ownership of %s", new->dest);

	if (strcmp(orig->type, "dir") == 0) {
		char *delta, *lastslash;
		int ret, len, lastslashidx;

		// if we have /var/lib/lxc/c2/rootfs, then delta will be
		//            /var/lib/lxc/c2/delta0
		lastslash = strrchr(new->dest, '/');
		if (!lastslash)
			return -22;
		if (strlen(lastslash) < 7)
			return -22;
		lastslash++;
		lastslashidx = lastslash - new->dest;

		delta = malloc(lastslashidx + 7);
		if (!delta)
			return -1;
		strncpy(delta, new->dest, lastslashidx+1);
		strcpy(delta+lastslashidx, "delta0");
		if ((ret = mkdir(delta, 0755)) < 0) {
			SYSERROR("error: mkdir %s", delta);
			free(delta);
			return -1;
		}
		if (am_unpriv() && chown_mapped_root(delta, conf) < 0)
			WARN("Failed to update ownership of %s", delta);

		// the src will be 'aufs:lowerdir:upperdir'
		len = strlen(delta) + strlen(orig->src) + 12;
		new->src = malloc(len);
		if (!new->src) {
			free(delta);
			return -ENOMEM;
		}
		ret = snprintf(new->src, len, "aufs:%s:%s", orig->src, delta);
		free(delta);
		if (ret < 0 || ret >= len)
			return -ENOMEM;
	} else if (strcmp(orig->type, "aufs") == 0) {
		// What exactly do we want to do here?
		// I think we want to use the original lowerdir, with a
		// private delta which is originally rsynced from the
		// original delta
		char *osrc, *odelta, *nsrc, *ndelta;
		int len, ret;
		if (!(osrc = strdup(orig->src)))
			return -22;
		nsrc = strchr(osrc, ':') + 1;
		if (nsrc != osrc + 5 || (odelta = strchr(nsrc, ':')) == NULL) {
			free(osrc);
			return -22;
		}
		*odelta = '\0';
		odelta++;
		ndelta = dir_new_path(odelta, oldname, cname, oldpath, lxcpath);
		if (!ndelta) {
			free(osrc);
			return -ENOMEM;
		}
		if ((ret = mkdir(ndelta, 0755)) < 0 && errno != EEXIST) {
			SYSERROR("error: mkdir %s", ndelta);
			free(osrc);
			free(ndelta);
			return -1;
		}
		if (am_unpriv() && chown_mapped_root(ndelta, conf) < 0)
			WARN("Failed to update ownership of %s", ndelta);

		struct rsync_data_char rdata;
		rdata.src = odelta;
		rdata.dest = ndelta;
		if (am_unpriv())
			ret = userns_exec_1(conf, rsync_delta_wrapper, &rdata);
		else
			ret = rsync_delta(&rdata);
		if (ret) {
			free(osrc);
			free(ndelta);
			ERROR("copying aufs delta");
			return -1;
		}
		len = strlen(nsrc) + strlen(ndelta) + 12;
		new->src = malloc(len);
		if (!new->src) {
			free(osrc);
			free(ndelta);
			return -ENOMEM;
		}
		ret = snprintf(new->src, len, "aufs:%s:%s", nsrc, ndelta);
		free(osrc);
		free(ndelta);
		if (ret < 0 || ret >= len)
			return -ENOMEM;
	} else {
		ERROR("aufs clone of %s container is not yet supported",
			orig->type);
		// Note, supporting this will require aufs_mount supporting
		// mounting of the underlay.  No big deal, just needs to be done.
		return -1;
	}

	return 0;
}

/*
 * to say 'lxc-create -t ubuntu -n o1 -B aufs' means you want
 * $lxcpath/$lxcname/rootfs to have the created container, while all
 * changes after starting the container are written to
 * $lxcpath/$lxcname/delta0
 */
int aufs_create(struct bdev *bdev, const char *dest, const char *n,
		struct bdev_specs *specs)
{
	char *delta;
	int ret, len = strlen(dest), newlen;

	if (len < 8 || strcmp(dest+len-7, "/rootfs") != 0)
		return -1;

	if (!(bdev->dest = strdup(dest))) {
		ERROR("Out of memory");
		return -1;
	}

	delta = alloca(strlen(dest)+1);
	strcpy(delta, dest);
	strcpy(delta+len-6, "delta0");

	if (mkdir_p(delta, 0755) < 0) {
		ERROR("Error creating %s", delta);
		return -1;
	}

	/* aufs:lower:upper */
	newlen = (2 * len) + strlen("aufs:") + 2;
	bdev->src = malloc(newlen);
	if (!bdev->src) {
		ERROR("Out of memory");
		return -1;
	}
	ret = snprintf(bdev->src, newlen, "aufs:%s:%s", dest, delta);
	if (ret < 0 || ret >= newlen)
		return -1;

	if (mkdir_p(bdev->dest, 0755) < 0) {
		ERROR("Error creating %s", bdev->dest);
		return -1;
	}

	return 0;
}

int aufs_destroy(struct bdev *orig)
{
	char *upper;

	if (strncmp(orig->src, "aufs:", 5) != 0)
		return -22;
	upper = strchr(orig->src + 5, ':');
	if (!upper)
		return -22;
	upper++;
	return lxc_rmdir_onedev(upper, NULL);
}

int aufs_detect(const char *path)
{
	if (strncmp(path, "aufs:", 5) == 0)
		return 1; // take their word for it
	return 0;
}

int aufs_mount(struct bdev *bdev)
{
	char *tmp, *options, *dup, *lower, *upper;
	int len;
	unsigned long mntflags;
	char *mntdata;
	int ret;
	const char *xinopath = "/dev/shm/aufs.xino";

	if (strcmp(bdev->type, "aufs"))
		return -22;
	if (!bdev->src || !bdev->dest)
		return -22;

	//  separately mount it first
	//  mount -t aufs -obr=${upper}=rw:${lower}=ro lower dest
	dup = alloca(strlen(bdev->src)+1);
	strcpy(dup, bdev->src);
	/* support multiple lower layers */
	if (!(lower = strstr(dup, ":/")))
			return -22;
	lower++;
	upper = lower;
	while ((tmp = strstr(++upper, ":/"))) {
		upper = tmp;
	}
	if (--upper == lower)
		return -22;
	*upper = '\0';
	upper++;

	if (parse_mntopts(bdev->mntopts, &mntflags, &mntdata) < 0) {
		free(mntdata);
		return -22;
	}

	// TODO We should check whether bdev->src is a blockdev, and if so
	// but for now, only support aufs of a basic directory

	// AUFS does not work on top of certain filesystems like (XFS or Btrfs)
	// so add xino=/dev/shm/aufs.xino parameter to mount options.
	// The same xino option can be specified to multiple aufs mounts, and
	// a xino file is not shared among multiple aufs mounts.
	//
	// see http://www.mail-archive.com/aufs-users@lists.sourceforge.net/msg02587.html
	//     http://www.mail-archive.com/aufs-users@lists.sourceforge.net/msg05126.html
	if (mntdata) {
		len = strlen(lower) + strlen(upper) + strlen(xinopath) + strlen("br==rw:=ro,,xino=") + strlen(mntdata) + 1;
		options = alloca(len);
		ret = snprintf(options, len, "br=%s=rw:%s=ro,%s,xino=%s", upper, lower, mntdata, xinopath);
	}
	else {
		len = strlen(lower) + strlen(upper) + strlen(xinopath) + strlen("br==rw:=ro,xino=") + 1;
		options = alloca(len);
		ret = snprintf(options, len, "br=%s=rw:%s=ro,xino=%s", upper, lower, xinopath);
	}

	if (ret < 0 || ret >= len) {
		free(mntdata);
		return -1;
	}

	ret = mount(lower, bdev->dest, "aufs", MS_MGC_VAL | mntflags, options);
	if (ret < 0)
		SYSERROR("aufs: error mounting %s onto %s options %s",
			lower, bdev->dest, options);
	else
		INFO("aufs: mounted %s onto %s options %s",
			lower, bdev->dest, options);
	return ret;
}

int aufs_umount(struct bdev *bdev)
{
	if (strcmp(bdev->type, "aufs"))
		return -22;
	if (!bdev->src || !bdev->dest)
		return -22;
	return umount(bdev->dest);
}

char *aufs_get_rootfs(const char *rootfs_path, size_t *rootfslen)
{
	char *rootfsdir = NULL;
	char *s1 = NULL;
	char *s2 = NULL;
	char *s3 = NULL;

	if (!rootfs_path || !rootfslen)
		return NULL;

	s1 = strdup(rootfs_path);
	if (!s1)
		return NULL;

	if ((s2 = strstr(s1, ":/"))) {
		s2 = s2 + 1;
		if ((s3 = strstr(s2, ":/")))
			*s3 = '\0';
		rootfsdir = strdup(s2);
		if (!rootfsdir) {
			free(s1);
			return NULL;
		}
	}

	if (!rootfsdir)
		rootfsdir = s1;
	else
		free(s1);

	*rootfslen = strlen(rootfsdir);

	return rootfsdir;
}

int aufs_mkdir(const struct mntent *mntent, const struct lxc_rootfs *rootfs,
		const char *lxc_name, const char *lxc_path)
{
	char lxcpath[MAXPATHLEN];
	char *rootfs_path = NULL;
	char *rootfsdir = NULL;
	char *scratch = NULL;
	char *tmp = NULL;
	char *upperdir = NULL;
	char **opts = NULL;
	int fret = -1;
	int ret = 0;
	size_t arrlen = 0;
	size_t i;
	size_t len = 0;
	size_t rootfslen = 0;

	/* When rootfs == NULL we have a container without a rootfs. */
	if (rootfs && rootfs->path)
		rootfs_path = rootfs->path;

	opts = lxc_string_split(mntent->mnt_opts, ',');
	if (opts)
		arrlen = lxc_array_len((void **)opts);
	else
		goto err;

	for (i = 0; i < arrlen; i++) {
		if (strstr(opts[i], "br=") && (strlen(opts[i]) > (len = strlen("br="))))
			tmp = opts[i] + len;
	}
	if (!tmp)
		goto err;

	upperdir = strtok_r(tmp, ":=", &scratch);
	if (!upperdir)
		goto err;

	if (rootfs_path) {
		ret = snprintf(lxcpath, MAXPATHLEN, "%s/%s", lxc_path, lxc_name);
		if (ret < 0 || ret >= MAXPATHLEN)
			goto err;

		rootfsdir = aufs_get_rootfs(rootfs->path, &rootfslen);
		if (!rootfsdir)
			goto err;
	}

	/*
	 * We neither allow users to create upperdirs and workdirs outside the
	 * containerdir nor inside the rootfs. The latter might be debatable.
	 * When we have a container without a rootfs we skip the checks.
	 */
	ret = 0;
	if (!rootfs_path)
		ret = mkdir_p(upperdir, 0755);
	else if ((strncmp(upperdir, lxcpath, strlen(lxcpath)) == 0) && (strncmp(upperdir, rootfsdir, rootfslen) != 0))
		ret = mkdir_p(upperdir, 0755);
	if (ret < 0)
		WARN("Failed to create upperdir");

	fret = 0;

err:
	free(rootfsdir);
	lxc_free_array((void **)opts, free);
	return fret;
}


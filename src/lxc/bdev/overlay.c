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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bdev.h"
#include "conf.h"
#include "confile.h"
#include "log.h"
#include "lxccontainer.h"
#include "overlay.h"
#include "utils.h"

lxc_log_define(overlay, lxc);

struct ovl_rsync_data {
	struct bdev *orig;
	struct bdev *new;
};

/* defined in lxccontainer.c: needs to become common helper */
extern int do_rsync(const char *src, const char *dest);

/* defined in lxccontainer.c: needs to become common helper */
extern char *dir_new_path(char *src, const char *oldname, const char *name,
			  const char *oldpath, const char *lxcpath);

char *overlay_getlower(char *p)
{
	char *p1 = strchr(p, ':');
	if (p1)
		*p1 = '\0';
	return p;
}

int overlayfs_detect(const char *path)
{
	if (strncmp(path, "overlayfs:", 10) == 0)
		return 1; // take their word for it
	return 0;
}

static char *overlayfs_name;
static char *detect_overlayfs_name(void)
{
	char *v = "overlayfs";
	char *line = NULL;
	size_t len = 0;
	FILE *f = fopen("/proc/filesystems", "r");
	if (!f)
		return v;

	while (getline(&line, &len, f) != -1) {
		if (strcmp(line, "nodev\toverlay\n") == 0) {
			v = "overlay";
			break;
		}
	}

	fclose(f);
	free(line);
	return v;
}

/* XXXXXXX plain directory bind mount ops */
int overlayfs_mount(struct bdev *bdev)
{
	char *options, *dup, *lower, *upper;
	char *options_work, *work, *lastslash;
	int lastslashidx;
	int len, len2;
	unsigned long mntflags;
	char *mntdata;
	int ret, ret2;

	if (strcmp(bdev->type, "overlayfs"))
		return -22;
	if (!bdev->src || !bdev->dest)
		return -22;

	// defined in bdev.c
	if (!overlayfs_name)
		overlayfs_name = detect_overlayfs_name();

	//  separately mount it first
	//  mount -t overlayfs -oupperdir=${upper},lowerdir=${lower} lower dest
	dup = alloca(strlen(bdev->src)+1);
	strcpy(dup, bdev->src);
	if (!(lower = strchr(dup, ':')))
		return -22;
	if (!(upper = strchr(++lower, ':')))
		return -22;
	*upper = '\0';
	upper++;

	// if delta doesn't yet exist, create it
	if (mkdir_p(upper, 0755) < 0 && errno != EEXIST)
		return -22;

	// overlayfs.v22 or higher needs workdir option
	// if upper is /var/lib/lxc/c2/delta0,
	// then workdir is /var/lib/lxc/c2/olwork
	lastslash = strrchr(upper, '/');
	if (!lastslash)
		return -22;
	lastslash++;
	lastslashidx = lastslash - upper;

	work = alloca(lastslashidx + 7);
	strncpy(work, upper, lastslashidx+7);
	strcpy(work+lastslashidx, "olwork");

	if (parse_mntopts(bdev->mntopts, &mntflags, &mntdata) < 0) {
		free(mntdata);
		return -22;
	}

	if (mkdir_p(work, 0755) < 0 && errno != EEXIST) {
		free(mntdata);
		return -22;
	}

	// TODO We should check whether bdev->src is a blockdev, and if so
	// but for now, only support overlays of a basic directory

	if (mntdata) {
		len = strlen(lower) + strlen(upper) + strlen("upperdir=,lowerdir=,") + strlen(mntdata) + 1;
		options = alloca(len);
		ret = snprintf(options, len, "upperdir=%s,lowerdir=%s,%s", upper, lower, mntdata);

		len2 = strlen(lower) + strlen(upper) + strlen(work)
			+ strlen("upperdir=,lowerdir=,workdir=") + strlen(mntdata) + 1;
		options_work = alloca(len2);
		ret2 = snprintf(options, len2, "upperdir=%s,lowerdir=%s,workdir=%s,%s",
				upper, lower, work, mntdata);
	}
	else {
		len = strlen(lower) + strlen(upper) + strlen("upperdir=,lowerdir=") + 1;
		options = alloca(len);
		ret = snprintf(options, len, "upperdir=%s,lowerdir=%s", upper, lower);

		len2 = strlen(lower) + strlen(upper) + strlen(work)
			+ strlen("upperdir=,lowerdir=,workdir=") + 1;
		options_work = alloca(len2);
		ret2 = snprintf(options_work, len2, "upperdir=%s,lowerdir=%s,workdir=%s",
			upper, lower, work);
	}
	if (ret < 0 || ret >= len || ret2 < 0 || ret2 >= len2) {
		free(mntdata);
		return -1;
	}

	// mount without workdir option for overlayfs before v21
	ret = mount(lower, bdev->dest, overlayfs_name, MS_MGC_VAL | mntflags, options);
	if (ret < 0) {
		INFO("overlayfs: error mounting %s onto %s options %s. retry with workdir",
			lower, bdev->dest, options);

		// retry with workdir option for overlayfs v22 and higher
		ret = mount(lower, bdev->dest, overlayfs_name, MS_MGC_VAL | mntflags, options_work);
		if (ret < 0)
			SYSERROR("overlayfs: error mounting %s onto %s options %s",
				lower, bdev->dest, options_work);
		else
			INFO("overlayfs: mounted %s onto %s options %s",
				lower, bdev->dest, options_work);
	}
	else
		INFO("overlayfs: mounted %s onto %s options %s",
			lower, bdev->dest, options);
	return ret;
}

int overlayfs_umount(struct bdev *bdev)
{
	if (strcmp(bdev->type, "overlayfs"))
		return -22;
	if (!bdev->src || !bdev->dest)
		return -22;
	return umount(bdev->dest);
}

static int ovl_rsync(struct ovl_rsync_data *data)
{
	int ret;

	if (setgid(0) < 0) {
		ERROR("Failed to setgid to 0");
		return -1;
	}
	if (setgroups(0, NULL) < 0)
		WARN("Failed to clear groups");
	if (setuid(0) < 0) {
		ERROR("Failed to setuid to 0");
		return -1;
	}

	if (unshare(CLONE_NEWNS) < 0) {
		SYSERROR("Unable to unshare mounts ns");
		return -1;
	}
	if (detect_shared_rootfs()) {
		if (mount(NULL, "/", NULL, MS_SLAVE|MS_REC, NULL)) {
			SYSERROR("Failed to make / rslave");
			ERROR("Continuing...");
		}
	}
	if (overlayfs_mount(data->orig) < 0) {
		ERROR("Failed mounting original container fs");
		return -1;
	}
	if (overlayfs_mount(data->new) < 0) {
		ERROR("Failed mounting new container fs");
		return -1;
	}
	ret = do_rsync(data->orig->dest, data->new->dest);

	overlayfs_umount(data->new);
	overlayfs_umount(data->orig);

	if (ret < 0) {
		ERROR("rsyncing %s to %s", data->orig->dest, data->new->dest);
		return -1;
	}

	return 0;
}

static int ovl_rsync_wrapper(void *data)
{
	struct ovl_rsync_data *arg = data;
	return ovl_rsync(arg);
}

static int ovl_do_rsync(struct bdev *orig, struct bdev *new, struct lxc_conf *conf)
{
	int ret = -1;
	struct ovl_rsync_data rdata;

	rdata.orig = orig;
	rdata.new = new;
	if (am_unpriv())
		ret = userns_exec_1(conf, ovl_rsync_wrapper, &rdata);
	else
		ret = ovl_rsync(&rdata);
	if (ret)
		ERROR("copying overlayfs delta");

	return ret;
}

int overlayfs_clonepaths(struct bdev *orig, struct bdev *new, const char *oldname,
		const char *cname, const char *oldpath, const char *lxcpath, int snap,
		uint64_t newsize, struct lxc_conf *conf)
{
	if (!snap) {
		ERROR("overlayfs is only for snapshot clones");
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
		char *work;
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

		// make workdir for overlayfs.v22 or higher
		// workdir is /var/lib/lxc/c2/olwork
		// it is used to prepare files before atomically swithing with destination,
		// and needs to be on the same filesystem as upperdir,
		// so it's OK for it to be empty.
		work = malloc(lastslashidx + 7);
		if (!work) {
			free(delta);
			return -1;
		}
		strncpy(work, new->dest, lastslashidx+1);
		strcpy(work+lastslashidx, "olwork");
		if (mkdir(work, 0755) < 0) {
			SYSERROR("error: mkdir %s", work);
			free(delta);
			free(work);
			return -1;
		}
		if (am_unpriv() && chown_mapped_root(work, conf) < 0)
			WARN("Failed to update ownership of %s", work);
		free(work);

		// the src will be 'overlayfs:lowerdir:upperdir'
		len = strlen(delta) + strlen(orig->src) + 12;
		new->src = malloc(len);
		if (!new->src) {
			free(delta);
			return -ENOMEM;
		}
		ret = snprintf(new->src, len, "overlayfs:%s:%s", orig->src, delta);
		free(delta);
		if (ret < 0 || ret >= len)
			return -ENOMEM;
	} else if (strcmp(orig->type, "overlayfs") == 0) {
		// What exactly do we want to do here?
		// I think we want to use the original lowerdir, with a
		// private delta which is originally rsynced from the
		// original delta
		char *osrc, *odelta, *nsrc, *ndelta, *work;
		char *lastslash;
		int len, ret, lastslashidx;
		if (!(osrc = strdup(orig->src)))
			return -22;
		nsrc = strchr(osrc, ':') + 1;
		if (nsrc != osrc + 10 || (odelta = strchr(nsrc, ':')) == NULL) {
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

		// make workdir for overlayfs.v22 or higher
		// for details, see above.
		lastslash = strrchr(ndelta, '/');
		if (!lastslash)
			return -1;
		lastslash++;
		lastslashidx = lastslash - ndelta;

		work = malloc(lastslashidx + 7);
		if (!work)
			return -1;
		strncpy(work, ndelta, lastslashidx+1);
		strcpy(work+lastslashidx, "olwork");
		if ((mkdir(work, 0755) < 0) && errno != EEXIST) {
			SYSERROR("error: mkdir %s", work);
			free(work);
			return -1;
		}
		if (am_unpriv() && chown_mapped_root(work, conf) < 0)
			WARN("Failed to update ownership of %s", work);
		free(work);

		len = strlen(nsrc) + strlen(ndelta) + 12;
		new->src = malloc(len);
		if (!new->src) {
			free(osrc);
			free(ndelta);
			return -ENOMEM;
		}
		ret = snprintf(new->src, len, "overlayfs:%s:%s", nsrc, ndelta);
		free(osrc);
		free(ndelta);
		if (ret < 0 || ret >= len)
			return -ENOMEM;

		return ovl_do_rsync(orig, new, conf);
	} else {
		ERROR("overlayfs clone of %s container is not yet supported",
			orig->type);
		// Note, supporting this will require overlayfs_mount supporting
		// mounting of the underlay.  No big deal, just needs to be done.
		return -1;
	}

	return 0;
}

int overlayfs_destroy(struct bdev *orig)
{
	char *upper;

	if (strncmp(orig->src, "overlayfs:", 10) != 0)
		return -22;
	upper = strchr(orig->src + 10, ':');
	if (!upper)
		return -22;
	upper++;
	return lxc_rmdir_onedev(upper, NULL);
}

/*
 * to say 'lxc-create -t ubuntu -n o1 -B overlayfs' means you want
 * $lxcpath/$lxcname/rootfs to have the created container, while all
 * changes after starting the container are written to
 * $lxcpath/$lxcname/delta0
 */
int overlayfs_create(struct bdev *bdev, const char *dest, const char *n,
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

	/* overlayfs:lower:upper */
	newlen = (2 * len) + strlen("overlayfs:") + 2;
	bdev->src = malloc(newlen);
	if (!bdev->src) {
		ERROR("Out of memory");
		return -1;
	}
	ret = snprintf(bdev->src, newlen, "overlayfs:%s:%s", dest, delta);
	if (ret < 0 || ret >= newlen)
		return -1;

	if (mkdir_p(bdev->dest, 0755) < 0) {
		ERROR("Error creating %s", bdev->dest);
		return -1;
	}

	return 0;
}

/*
 * To be called from lxcapi_clone() in lxccontainer.c: When we clone a container
 * with overlay lxc.mount.entry entries we need to update absolute paths for
 * upper- and workdir. This update is done in two locations:
 * lxc_conf->unexpanded_config and lxc_conf->mount_list. Both updates are done
 * independent of each other since lxc_conf->mountlist may container more mount
 * entries (e.g. from other included files) than lxc_conf->unexpanded_config .
 */
int update_ovl_paths(struct lxc_conf *lxc_conf, const char *lxc_path,
		     const char *lxc_name, const char *newpath,
		     const char *newname)
{
	char new_upper[MAXPATHLEN];
	char new_work[MAXPATHLEN];
	char old_upper[MAXPATHLEN];
	char old_work[MAXPATHLEN];
	char *cleanpath = NULL;
	int i;
	int fret = -1;
	int ret = 0;
	struct lxc_list *iterator;
	const char *ovl_dirs[] = {"br", "upperdir", "workdir"};

	cleanpath = strdup(newpath);
	if (!cleanpath)
		goto err;

	remove_trailing_slashes(cleanpath);

	/* We have to update lxc_conf->unexpanded_config separately from
	*  lxc_conf->mount_list. */
	for (i = 0; i < sizeof(ovl_dirs) / sizeof(ovl_dirs[0]); i++) {
		if (!clone_update_unexp_ovl_paths(lxc_conf, lxc_path, newpath,
						  lxc_name, newname,
						  ovl_dirs[i]))
			goto err;
	}

	ret = snprintf(old_work, MAXPATHLEN, "workdir=%s/%s", lxc_path, lxc_name);
	if (ret < 0 || ret >= MAXPATHLEN)
		goto err;

	ret = snprintf(new_work, MAXPATHLEN, "workdir=%s/%s", cleanpath, newname);
	if (ret < 0 || ret >= MAXPATHLEN)
		goto err;

	lxc_list_for_each(iterator, &lxc_conf->mount_list) {
		char *mnt_entry = NULL;
		char *new_mnt_entry = NULL;
		char *tmp = NULL;
		char *tmp_mnt_entry = NULL;
		mnt_entry = iterator->elem;

		if (strstr(mnt_entry, "overlay"))
			tmp = "upperdir";
		else if (strstr(mnt_entry, "aufs"))
			tmp = "br";

		if (!tmp)
			continue;

		ret = snprintf(old_upper, MAXPATHLEN, "%s=%s/%s", tmp, lxc_path, lxc_name);
		if (ret < 0 || ret >= MAXPATHLEN)
			goto err;

		ret = snprintf(new_upper, MAXPATHLEN, "%s=%s/%s", tmp, cleanpath, newname);
		if (ret < 0 || ret >= MAXPATHLEN)
			goto err;

		if (strstr(mnt_entry, old_upper)) {
			tmp_mnt_entry = lxc_string_replace(old_upper, new_upper, mnt_entry);
		}

		if (strstr(mnt_entry, old_work)) {
			if (tmp_mnt_entry)
				new_mnt_entry = lxc_string_replace(old_work, new_work, tmp_mnt_entry);
			else
				new_mnt_entry = lxc_string_replace(old_work, new_work, mnt_entry);
		}

		if (new_mnt_entry) {
			free(iterator->elem);
			iterator->elem = strdup(new_mnt_entry);
		} else if (tmp_mnt_entry) {
			free(iterator->elem);
			iterator->elem = strdup(tmp_mnt_entry);
		}

		free(new_mnt_entry);
		free(tmp_mnt_entry);
	}

	fret = 0;
err:
	free(cleanpath);
	return fret;
}


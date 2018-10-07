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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "conf.h"
#include "config.h"
#include "confile.h"
#include "log.h"
#include "lxccontainer.h"
#include "macro.h"
#include "overlay.h"
#include "rsync.h"
#include "storage.h"
#include "storage_utils.h"
#include "utils.h"

lxc_log_define(overlay, lxc);

static char *ovl_name;
static char *ovl_version[] = {"overlay", "overlayfs"};

static char *ovl_detect_name(void);
static int ovl_do_rsync(const char *src, const char *dest,
			struct lxc_conf *conf);
static int ovl_remount_on_enodev(const char *lower, const char *target,
				 const char *name, unsigned long mountflags,
				 const void *options);

int ovl_clonepaths(struct lxc_storage *orig, struct lxc_storage *new, const char *oldname,
		   const char *cname, const char *oldpath, const char *lxcpath,
		   int snap, uint64_t newsize, struct lxc_conf *conf)
{
	int ret;
	const char *src;

	if (!snap) {
		ERROR("The overlay storage driver can only be used for "
		      "snapshots");
		return -22;
	}

	if (!orig->src || !orig->dest)
		return -1;

	new->dest = must_make_path(lxcpath, cname, "rootfs", NULL);

	ret = mkdir_p(new->dest, 0755);
	if (ret < 0 && errno != EEXIST) {
		SYSERROR("Failed to create directory \"%s\"", new->dest);
		return -1;
	}

	if (am_guest_unpriv()) {
		ret = chown_mapped_root(new->dest, conf);
		if (ret < 0)
			WARN("Failed to update ownership of %s", new->dest);
	}

	if (strcmp(orig->type, "dir") == 0) {
		char *delta, *lastslash;
		char *work;
		int ret, len, lastslashidx;

		/* If we have "/var/lib/lxc/c2/rootfs" then delta will be
		 * "/var/lib/lxc/c2/delta0".
		 */
		lastslash = strrchr(new->dest, '/');
		if (!lastslash) {
			ERROR("Failed to detect \"/\" in string \"%s\"",
			      new->dest);
			return -22;
		}

		if (strlen(lastslash) < STRLITERALLEN("/rootfs")) {
			ERROR("Failed to detect \"/rootfs\" in string \"%s\"",
			      new->dest);
			return -22;
		}

		lastslash++;
		lastslashidx = lastslash - new->dest;

		delta = malloc(lastslashidx + 7);
		if (!delta) {
			ERROR("Failed to allocate memory");
			return -1;
		}

		memcpy(delta, new->dest, lastslashidx + 1);
		memcpy(delta + lastslashidx, "delta0", STRLITERALLEN("delta0"));
		delta[lastslashidx + STRLITERALLEN("delta0")] = '\0';

		ret = mkdir(delta, 0755);
		if (ret < 0 && errno != EEXIST) {
			SYSERROR("Failed to create directory \"%s\"", delta);
			free(delta);
			return -1;
		}

		if (am_guest_unpriv()) {
			ret = chown_mapped_root(delta, conf);
			if (ret < 0)
				WARN("Failed to update ownership of %s", delta);
		}

		/* Make workdir for overlayfs.v22 or higher:
		 * The workdir will be
		 *	/var/lib/lxc/c2/olwork
		 * and is used to prepare files before they are atomically
		 * switched to the overlay destination. Workdirs need to be on
		 * the same filesystem as the upperdir so it's OK for it to be
		 * empty.
		 */
		work = malloc(lastslashidx + 7);
		if (!work) {
			ERROR("Failed to allocate memory");
			free(delta);
			return -1;
		}

		memcpy(work, new->dest, lastslashidx + 1);
		memcpy(work + lastslashidx, "olwork", STRLITERALLEN("olwork"));
		work[lastslashidx + STRLITERALLEN("olwork")] = '\0';

		ret = mkdir(work, 0755);
		if (ret < 0) {
			SYSERROR("Failed to create directory \"%s\"", work);
			free(delta);
			free(work);
			return -1;
		}

		if (am_guest_unpriv()) {
			ret = chown_mapped_root(work, conf);
			if (ret < 0)
				WARN("Failed to update ownership of %s", work);
		}
		free(work);

		/* strlen("overlay:") = 8
		 * +
		 * strlen(delta)
		 * +
		 * :
		 * +
		 * strlen(src)
		 * +
		 * \0
		 */
		src = lxc_storage_get_path(orig->src, orig->type);
		len = 8 + strlen(delta) + 1 + strlen(src) + 1;
		new->src = malloc(len);
		if (!new->src) {
			ERROR("Failed to allocate memory");
			free(delta);
			return -ENOMEM;
		}

		ret = snprintf(new->src, len, "overlay:%s:%s", src, delta);
		free(delta);
		if (ret < 0 || (size_t)ret >= len) {
			ERROR("Failed to create string");
			return -1;
		}
	} else if (!strcmp(orig->type, "overlayfs") ||
		   !strcmp(orig->type, "overlay")) {
		char *clean_old_path, *clean_new_path;
		char *lastslash, *ndelta, *nsrc, *odelta, *osrc, *s1, *s2, *s3,
		    *work;
		int ret, lastslashidx;
		size_t len, name_len;

		osrc = strdup(orig->src);
		if (!osrc) {
			ERROR("Failed to duplicate string \"%s\"", orig->src);
			return -22;
		}

		nsrc = osrc;
		if (strncmp(osrc, "overlay:", 8) == 0)
			nsrc += 8;
		else if (strncmp(osrc, "overlayfs:", 10) == 0)
			nsrc += 10;

		odelta = strchr(nsrc, ':');
		if (!odelta) {
			ERROR("Failed to find \":\" in \"%s\"", nsrc);
			free(osrc);
			return -22;
		}

		*odelta = '\0';
		odelta++;
		ndelta = must_make_path(lxcpath, cname, "delta0", NULL);

		ret = mkdir(ndelta, 0755);
		if (ret < 0 && errno != EEXIST) {
			SYSERROR("Failed to create directory \"%s\"", ndelta);
			free(osrc);
			free(ndelta);
			return -1;
		}

		if (am_guest_unpriv()) {
			ret = chown_mapped_root(ndelta, conf);
			if (ret < 0)
				WARN("Failed to update ownership of %s",
				     ndelta);
		}

		/* Make workdir for overlayfs.v22 or higher (See the comment
		 * further up.).
		 */
		lastslash = strrchr(ndelta, '/');
		if (!lastslash) {
			ERROR("Failed to detect \"/\" in \"%s\"", ndelta);
			free(osrc);
			free(ndelta);
			return -1;
		}
		lastslash++;
		lastslashidx = lastslash - ndelta;

		work = malloc(lastslashidx + 7);
		if (!work) {
			free(osrc);
			free(ndelta);
			ERROR("Failed to allocate memory");
			return -1;
		}

		memcpy(work, ndelta, lastslashidx + 1);
		memcpy(work + lastslashidx, "olwork", STRLITERALLEN("olwork"));
		work[lastslashidx + STRLITERALLEN("olwork")] = '\0';

		ret = mkdir(work, 0755);
		if (ret < 0 && errno != EEXIST) {
			SYSERROR("Failed to create directory \"%s\"", ndelta);
			free(osrc);
			free(ndelta);
			free(work);
			return -1;
		}

		if (am_guest_unpriv()) {
			ret = chown_mapped_root(work, conf);
			if (ret < 0)
				WARN("Failed to update ownership of %s", work);
		}
		free(work);

		/* strlen("overlay:") = 8
		 * +
		 * strlen(delta)
		 * +
		 * :
		 * +
		 * strlen(src)
		 * +
		 * \0
		 */
		len = 8 + strlen(ndelta) + 1 + strlen(nsrc) + 1;
		new->src = malloc(len);
		if (!new->src) {
			free(osrc);
			free(ndelta);
			ERROR("Failed to allocate memory");
			return -ENOMEM;
		}
		ret = snprintf(new->src, len, "overlay:%s:%s", nsrc, ndelta);
		if (ret < 0 || (size_t)ret >= len) {
			ERROR("Failed to create string");
			free(osrc);
			free(ndelta);
			return -1;
		}

		ret = ovl_do_rsync(odelta, ndelta, conf);
		free(osrc);
		free(ndelta);
		if (ret < 0)
			return -1;

		/* When we create an overlay snapshot of an overlay container in
		 * the snapshot directory under "<lxcpath>/<name>/snaps/" we
		 * don't need to record a dependency. If we would restore would
		 * also fail.
		 */
		clean_old_path = lxc_deslashify(oldpath);
		if (!clean_old_path)
			return -1;

		clean_new_path = lxc_deslashify(lxcpath);
		if (!clean_new_path) {
			free(clean_old_path);
			return -1;
		}

		s1 = strrchr(clean_old_path, '/');
		if (!s1) {
			ERROR("Failed to detect \"/\" in string \"%s\"", clean_old_path);
			free(clean_old_path);
			free(clean_new_path);
			return -1;
		}

		s2 = strrchr(clean_new_path, '/');
		if (!s2) {
			ERROR("Failed to detect \"/\" in string \"%s\"", clean_new_path);
			free(clean_old_path);
			free(clean_new_path);
			return -1;
		}

		if (!strncmp(s1, "/snaps", STRLITERALLEN("/snaps"))) {
			s1 = clean_new_path;
			s2 = clean_old_path;
			s3 = (char *)cname;
		} else if (!strncmp(s2, "/snaps", STRLITERALLEN("/snaps"))) {
			s1 = clean_old_path;
			s2 = clean_new_path;
			s3 = (char *)oldname;
		} else {
			free(clean_old_path);
			free(clean_new_path);
			return 0;
		}

		len = strlen(s1);
		if (!strncmp(s1, s2, len)) {
			char *tmp;

			tmp = (char *)(s2 + len + 1);
			if (*tmp == '\0') {
				free(clean_old_path);
				free(clean_new_path);
				return 0;
			}

			name_len = strlen(s3);
			if (strncmp(s3, tmp, name_len)) {
				free(clean_old_path);
				free(clean_new_path);
				return 0;
			}

			free(clean_old_path);
			free(clean_new_path);
			return LXC_CLONE_SNAPSHOT;
		}

		free(clean_old_path);
		free(clean_new_path);
		return 0;
	} else {
		ERROR("overlay clone of %s container is not yet supported",
		      orig->type);
		/* Note, supporting this will require ovl_mount supporting
		 * mounting of the underlay. No big deal, just needs to be done.
		 */
		return -1;
	}

	return 0;
}

/* To say "lxc-create -t ubuntu -n o1 -B overlay" means you want
 * "<lxcpath>/<lxcname>/rootfs" to have the created container, while all changes
 * after starting the container are written to "<lxcpath>/<lxcname>/delta0".
 */
int ovl_create(struct lxc_storage *bdev, const char *dest, const char *n,
	       struct bdev_specs *specs)
{
	char *delta;
	int ret;
	size_t len, newlen;

	len = strlen(dest);
	if (len < 8 || strcmp(dest + len - 7, "/rootfs")) {
		ERROR("Failed to detect \"/rootfs\" in \"%s\"", dest);
		return -1;
	}

	bdev->dest = strdup(dest);
	if (!bdev->dest) {
		ERROR("Failed to duplicate string \"%s\"", dest);
		return -1;
	}

	delta = strdup(dest);
	if (!delta) {
		ERROR("Failed to allocate memory");
		return -1;
	}
	memcpy(delta + len - 6, "delta0", STRLITERALLEN("delta0"));

	ret = mkdir_p(delta, 0755);
	if (ret < 0) {
		SYSERROR("Failed to create directory \"%s\"", delta);
		free(delta);
		return -1;
	}

	/* overlay:lower:upper */
	newlen = (2 * len) + strlen("overlay:") + 2;
	bdev->src = malloc(newlen);
	if (!bdev->src) {
		ERROR("Failed to allocate memory");
		free(delta);
		return -1;
	}

	ret = snprintf(bdev->src, newlen, "overlay:%s:%s", dest, delta);
	if (ret < 0 || (size_t)ret >= newlen) {
		ERROR("Failed to create string");
		free(delta);
		return -1;
	}

	ret = mkdir_p(bdev->dest, 0755);
	if (ret < 0) {
		SYSERROR("Failed to create directory \"%s\"", bdev->dest);
		free(delta);
		return -1;
	}

	free(delta);
	return 0;
}

int ovl_destroy(struct lxc_storage *orig)
{
	char *upper = orig->src;

	/* For an overlay container the rootfs is considered immutable
	 * and cannot be removed when restoring from a snapshot.
	 */
	if (orig->flags & LXC_STORAGE_INTERNAL_OVERLAY_RESTORE)
		return 0;

	if (strncmp(upper, "overlay:", 8) == 0)
		upper += 8;
	else if (strncmp(upper, "overlayfs:", 10) == 0)
		upper += 10;

	upper = strchr(upper, ':');
	if (!upper)
		return -22;
	upper++;

	return lxc_rmdir_onedev(upper, NULL);
}

bool ovl_detect(const char *path)
{
	if (!strncmp(path, "overlay:", 8))
		return true;

	if (!strncmp(path, "overlayfs:", 10))
		return true;

	return false;
}

int ovl_mount(struct lxc_storage *bdev)
{
	char *tmp, *options, *dup, *lower, *upper;
	char *options_work, *work, *lastslash;
	int lastslashidx;
	size_t len, len2;
	unsigned long mntflags;
	char *mntdata;
	int ret, ret2;

	if (strcmp(bdev->type, "overlay") && strcmp(bdev->type, "overlayfs"))
		return -22;

	if (!bdev->src || !bdev->dest)
		return -22;

	if (!ovl_name)
		ovl_name = ovl_detect_name();

	/* Separately mount it first:
	 * mount -t overlay * -o upperdir=${upper},lowerdir=${lower} lower dest
	 */
	dup = strdup(bdev->src);
	if (!dup) {
		ERROR("Failed to allocate memory");
		return -1;
	}
	upper = dup;
	lower = dup;

	if (strncmp(dup, "overlay:", 8) == 0)
		lower += 8;
	else if (strncmp(dup, "overlayfs:", 10) == 0)
		lower += 10;
	if (upper != lower)
		upper = lower;

	/* support multiple lower layers */
	while ((tmp = strstr(upper, ":/"))) {
		tmp++;
		upper = tmp;
	}

	upper--;
	if (upper == lower) {
		free(dup);
		return -22;
	}
	*upper = '\0';
	upper++;

	/* if delta doesn't yet exist, create it */
	ret = mkdir_p(upper, 0755);
	if (ret < 0 && errno != EEXIST) {
		SYSERROR("Failed to create directory \"%s\"", upper);
		free(dup);
		return -22;
	}

	/* overlayfs.v22 or higher needs workdir option:
	 * if upper is
	 *	/var/lib/lxc/c2/delta0
	 * then workdir is
	 *	/var/lib/lxc/c2/olwork
	 */
	lastslash = strrchr(upper, '/');
	if (!lastslash) {
		ERROR("Failed to detect \"/\" in string \"%s\"", upper);
		free(dup);
		return -22;
	}

	lastslash++;
	lastslashidx = lastslash - upper;

	work = malloc(lastslashidx + 7);
	if (!work) {
		ERROR("Failed to allocate memory");
		free(dup);
		return -22;
	}

	memcpy(work, upper, lastslashidx + 1);
	memcpy(work + lastslashidx, "olwork", STRLITERALLEN("olwork"));
	work[lastslashidx + STRLITERALLEN("olwork")] = '\0';

	ret = parse_mntopts(bdev->mntopts, &mntflags, &mntdata);
	if (ret < 0) {
		ERROR("Failed to parse mount options");
		free(mntdata);
		free(dup);
		free(work);
		return -22;
	}

	ret = mkdir_p(work, 0755);
	if (ret < 0 && errno != EEXIST) {
		SYSERROR("Failed to create directory \"%s\"", work);
		free(mntdata);
		free(dup);
		free(work);
		return -22;
	}

	/*
	 * TODO:
	 * We should check whether bdev->src is a blockdev but for now only
	 * support overlays of a basic directory
	 */

	if (mntdata) {
		len = strlen(lower) + strlen(upper) +
		      strlen("upperdir=,lowerdir=,") + strlen(mntdata) + 1;
		options = alloca(len);
		ret = snprintf(options, len, "upperdir=%s,lowerdir=%s,%s",
			       upper, lower, mntdata);

		len2 = strlen(lower) + strlen(upper) + strlen(work) +
		       strlen("upperdir=,lowerdir=,workdir=") +
		       strlen(mntdata) + 1;
		options_work = alloca(len2);
		ret2 = snprintf(options, len2,
				"upperdir=%s,lowerdir=%s,workdir=%s,%s", upper,
				lower, work, mntdata);
	} else {
		len = strlen(lower) + strlen(upper) +
		      strlen("upperdir=,lowerdir=") + 1;
		options = alloca(len);
		ret = snprintf(options, len, "upperdir=%s,lowerdir=%s", upper,
			       lower);

		len2 = strlen(lower) + strlen(upper) + strlen(work) +
		       strlen("upperdir=,lowerdir=,workdir=") + 1;
		options_work = alloca(len2);
		ret2 = snprintf(options_work, len2,
				"upperdir=%s,lowerdir=%s,workdir=%s", upper,
				lower, work);
	}

	if (ret < 0 || ret >= len || ret2 < 0 || ret2 >= len2) {
		ERROR("Failed to create string");
		free(mntdata);
		free(dup);
		free(work);
		return -1;
	}

	/* Assume we need a workdir as we are on a overlay version >= v22. */
	ret = ovl_remount_on_enodev(lower, bdev->dest, ovl_name,
				    MS_MGC_VAL | mntflags, options_work);
	if (ret < 0) {
		SYSINFO("Failed to mount \"%s\" on \"%s\" with options \"%s\". "
		        "Retrying without workdir",
		        lower, bdev->dest, options_work);

		/* Assume we cannot use a workdir as we are on a version <= v21.
		 */
		ret = ovl_remount_on_enodev(lower, bdev->dest, ovl_name,
					    MS_MGC_VAL | mntflags, options);
		if (ret < 0)
			SYSERROR("Failed to mount \"%s\" on \"%s\" with options \"%s\"",
			         lower, bdev->dest, options);
		else
			INFO("Mounted \"%s\" on \"%s\" with options \"%s\"",
			     lower, bdev->dest, options);
	} else {
		INFO("Mounted \"%s\" on \"%s\" with options \"%s\"", lower,
		     bdev->dest, options_work);
	}

	free(dup);
	free(work);
	return ret;
}

int ovl_umount(struct lxc_storage *bdev)
{
	int ret;

	if (strcmp(bdev->type, "overlay") && strcmp(bdev->type, "overlayfs"))
		return -22;

	if (!bdev->src || !bdev->dest)
		return -22;

	ret = umount(bdev->dest);
	if (ret < 0)
		SYSERROR("Failed to unmount \"%s\"", bdev->dest);
	else
		TRACE("Unmounted \"%s\"", bdev->dest);

	return ret;
}

const char *ovl_get_lower(const char *rootfs_path)
{
	const char *s1 = rootfs_path;

	if (strncmp(rootfs_path, "overlay:", 8) == 0)
		s1 += 8;
	else if (strncmp(rootfs_path, "overlayfs:", 10) == 0)
		s1 += 10;

	s1 = strstr(s1, ":/");
	if (!s1)
		return NULL;
	s1++;

	return s1;
}

char *ovl_get_rootfs(const char *rootfs_path, size_t *rootfslen)
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

	s2 = s1;
	if (strncmp(rootfs_path, "overlay:", 8) == 0)
		s2 += 8;
	else if (strncmp(rootfs_path, "overlayfs:", 10) == 0)
		s2 += 10;

	s3 = strstr(s2, ":/");
	if (s3)
		*s3 = '\0';

	rootfsdir = strdup(s2);
	free(s1);
	if (!rootfsdir)
		return NULL;

	*rootfslen = strlen(rootfsdir);

	return rootfsdir;
}

int ovl_mkdir(const struct mntent *mntent, const struct lxc_rootfs *rootfs,
	      const char *lxc_name, const char *lxc_path)
{
	char lxcpath[PATH_MAX];
	char **opts;
	int ret;
	size_t arrlen, i, len, rootfslen;
	int fret = -1;
	size_t dirlen = 0;
	char *rootfs_dir = NULL, *rootfs_path = NULL, *upperdir = NULL,
	     *workdir = NULL;

	/* When rootfs == NULL we have a container without a rootfs. */
	if (rootfs && rootfs->path)
		rootfs_path = rootfs->path;

	opts = lxc_string_split(mntent->mnt_opts, ',');
	if (opts)
		arrlen = lxc_array_len((void **)opts);
	else
		goto err;

	for (i = 0; i < arrlen; i++) {
		if (strstr(opts[i], "upperdir=") &&
		    (strlen(opts[i]) > (len = strlen("upperdir="))))
			upperdir = opts[i] + len;
		else if (strstr(opts[i], "workdir=") &&
			 (strlen(opts[i]) > (len = strlen("workdir="))))
			workdir = opts[i] + len;
	}

	if (rootfs_path) {
		ret = snprintf(lxcpath, PATH_MAX, "%s/%s", lxc_path, lxc_name);
		if (ret < 0 || ret >= PATH_MAX)
			goto err;

		rootfs_dir = ovl_get_rootfs(rootfs_path, &rootfslen);
		if (!rootfs_dir)
			goto err;

		dirlen = strlen(lxcpath);
	}

	/*
	 * We neither allow users to create upperdirs and workdirs outside the
	 * containerdir nor inside the rootfs. The latter might be debatable.
	 * When we have a container without a rootfs we skip the checks.
	 */
	ret = 0;
	if (upperdir) {
		if (!rootfs_path)
			ret = mkdir_p(upperdir, 0755);
		else if (!strncmp(upperdir, lxcpath, dirlen) &&
			 strncmp(upperdir, rootfs_dir, rootfslen))
			ret = mkdir_p(upperdir, 0755);

		if (ret < 0)
			SYSWARN("Failed to create directory \"%s\"", upperdir);
	}

	ret = 0;
	if (workdir) {
		if (!rootfs_path)
			ret = mkdir_p(workdir, 0755);
		else if (!strncmp(workdir, lxcpath, dirlen) &&
			 strncmp(workdir, rootfs_dir, rootfslen))
			ret = mkdir_p(workdir, 0755);

		if (ret < 0)
			SYSWARN("Failed to create directory \"%s\"", workdir);
	}

	fret = 0;

err:
	free(rootfs_dir);
	lxc_free_array((void **)opts, free);
	return fret;
}

/* To be called from lxcapi_clone() in lxccontainer.c: When we clone a container
 * with overlay lxc.mount.entry entries we need to update absolute paths for
 * upper- and workdir. This update is done in two locations:
 * lxc_conf->unexpanded_config and lxc_conf->mount_list. Both updates are done
 * independent of each other since lxc_conf->mountlist may contain more mount
 * entries (e.g. from other included files) than lxc_conf->unexpanded_config.
 */
int ovl_update_abs_paths(struct lxc_conf *lxc_conf, const char *lxc_path,
			 const char *lxc_name, const char *newpath,
			 const char *newname)
{
	char new_upper[PATH_MAX], new_work[PATH_MAX], old_upper[PATH_MAX],
	    old_work[PATH_MAX];
	size_t i;
	struct lxc_list *iterator;
	char *cleanpath = NULL;
	int fret = -1;
	int ret = 0;
	const char *ovl_dirs[] = {"br", "upperdir", "workdir"};

	cleanpath = strdup(newpath);
	if (!cleanpath)
		goto err;

	remove_trailing_slashes(cleanpath);

	/*
	 * We have to update lxc_conf->unexpanded_config separately from
	 * lxc_conf->mount_list.
	 */
	for (i = 0; i < sizeof(ovl_dirs) / sizeof(ovl_dirs[0]); i++) {
		if (!clone_update_unexp_ovl_paths(lxc_conf, lxc_path, newpath,
						  lxc_name, newname,
						  ovl_dirs[i]))
			goto err;
	}

	ret =
	    snprintf(old_work, PATH_MAX, "workdir=%s/%s", lxc_path, lxc_name);
	if (ret < 0 || ret >= PATH_MAX)
		goto err;

	ret =
	    snprintf(new_work, PATH_MAX, "workdir=%s/%s", cleanpath, newname);
	if (ret < 0 || ret >= PATH_MAX)
		goto err;

	lxc_list_for_each(iterator, &lxc_conf->mount_list) {
		char *mnt_entry = NULL, *new_mnt_entry = NULL, *tmp = NULL,
		     *tmp_mnt_entry = NULL;

		mnt_entry = iterator->elem;

		if (strstr(mnt_entry, "overlay"))
			tmp = "upperdir";
		if (!tmp)
			continue;

		ret = snprintf(old_upper, PATH_MAX, "%s=%s/%s", tmp, lxc_path,
			       lxc_name);
		if (ret < 0 || ret >= PATH_MAX)
			goto err;

		ret = snprintf(new_upper, PATH_MAX, "%s=%s/%s", tmp,
			       cleanpath, newname);
		if (ret < 0 || ret >= PATH_MAX)
			goto err;

		if (strstr(mnt_entry, old_upper)) {
			tmp_mnt_entry =
			    lxc_string_replace(old_upper, new_upper, mnt_entry);
		}

		if (strstr(mnt_entry, old_work)) {
			if (tmp_mnt_entry)
				new_mnt_entry = lxc_string_replace(
				    old_work, new_work, tmp_mnt_entry);
			else
				new_mnt_entry = lxc_string_replace(
				    old_work, new_work, mnt_entry);
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

static int ovl_remount_on_enodev(const char *lower, const char *target,
				 const char *name, unsigned long mountflags,
				 const void *options)
{
	int ret;
	ret = mount(lower, target, ovl_name, MS_MGC_VAL | mountflags, options);
	if (ret < 0 && errno == ENODEV) /* Try other module name. */
		ret = mount(lower, target,
			    ovl_name == ovl_version[0] ? ovl_version[1]
						       : ovl_version[0],
			    MS_MGC_VAL | mountflags, options);
	return ret;
}

static char *ovl_detect_name(void)
{
	FILE *f;
	char *v = ovl_version[0];
	char *line = NULL;
	size_t len = 0;

	f = fopen("/proc/filesystems", "r");
	if (!f)
		return v;

	while (getline(&line, &len, f) != -1) {
		if (strcmp(line, "nodev\toverlayfs\n") == 0) {
			v = ovl_version[1];
			break;
		}
	}

	fclose(f);
	free(line);
	return v;
}

static int ovl_do_rsync(const char *src, const char *dest,
			struct lxc_conf *conf)
{
	int ret = -1;
	struct rsync_data_char rdata = {0};
	char cmd_output[PATH_MAX] = {0};

	rdata.src = (char *)src;
	rdata.dest = (char *)dest;
	if (am_guest_unpriv())
		ret = userns_exec_full(conf, lxc_rsync_exec_wrapper, &rdata,
				       "lxc_rsync_exec_wrapper");
	else
		ret = run_command(cmd_output, sizeof(cmd_output),
				  lxc_rsync_exec_wrapper, (void *)&rdata);
	if (ret < 0)
		ERROR("Failed to rsync from \"%s\" into \"%s\"%s%s", src, dest,
		      cmd_output[0] != '\0' ? ": " : "",
		      cmd_output[0] != '\0' ? cmd_output : "");

	return ret;
}

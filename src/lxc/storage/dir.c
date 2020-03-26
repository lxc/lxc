/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "config.h"
#include "log.h"
#include "macro.h"
#include "memory_utils.h"
#include "storage.h"
#include "utils.h"

lxc_log_define(dir, lxc);

/*
 * For a simple directory bind mount, we substitute the old container name and
 * paths for the new.
 */
int dir_clonepaths(struct lxc_storage *orig, struct lxc_storage *new,
		   const char *oldname, const char *cname, const char *oldpath,
		   const char *lxcpath, int snap, uint64_t newsize,
		   struct lxc_conf *conf)
{
	const char *src_no_prefix;
	int ret;
	size_t len;

	if (snap)
		return log_error_errno(-EINVAL, EINVAL, "Directories cannot be snapshotted");

	if (!orig->dest || !orig->src)
		return ret_errno(EINVAL);

	len = STRLITERALLEN("dir:") + strlen(lxcpath) + STRLITERALLEN("/") +
	      strlen(cname) + STRLITERALLEN("/rootfs") + 1;
	new->src = malloc(len);
	if (!new->src)
		return ret_errno(ENOMEM);

	ret = snprintf(new->src, len, "dir:%s/%s/rootfs", lxcpath, cname);
	if (ret < 0 || (size_t)ret >= len)
		return ret_errno(EIO);

	src_no_prefix = lxc_storage_get_path(new->src, new->type);
	new->dest = strdup(src_no_prefix);
	if (!new->dest)
		return log_error_errno(-ENOMEM, ENOMEM, "Failed to duplicate string \"%s\"", new->src);

	TRACE("Created new path \"%s\" for dir storage driver", new->dest);
	return 0;
}

int dir_create(struct lxc_storage *bdev, const char *dest, const char *n,
	       struct bdev_specs *specs, const struct lxc_conf *conf)
{
	__do_free char *bdev_src = NULL, *bdev_dest = NULL;
	int ret;
	const char *src;
	size_t len;

	len = STRLITERALLEN("dir:");
	if (specs && specs->dir)
		src = specs->dir;
	else
		src = dest;

	len += strlen(src) + 1;
	bdev_src = malloc(len);
	if (!bdev_src)
		return ret_errno(ENOMEM);

	ret = snprintf(bdev_src, len, "dir:%s", src);
	if (ret < 0 || (size_t)ret >= len)
		return ret_errno(EIO);

	bdev_dest = strdup(dest);
	if (!bdev_dest)
		return ret_errno(ENOMEM);

	ret = mkdir_p(dest, 0755);
	if (ret < 0)
		return log_error_errno(-errno, errno, "Failed to create directory \"%s\"", dest);

	TRACE("Created directory \"%s\"", dest);
	bdev->src = move_ptr(bdev_src);
	bdev->dest = move_ptr(bdev_dest);

	return 0;
}

int dir_destroy(struct lxc_storage *orig)
{
	int ret;
	const char *src;

	src = lxc_storage_get_path(orig->src, orig->src);

	ret = lxc_rmdir_onedev(src, NULL);
	if (ret < 0)
		return log_error_errno(ret, errno, "Failed to delete \"%s\"", src);

	return 0;
}

bool dir_detect(const char *path)
{
	struct stat statbuf;
	int ret;

	if (!strncmp(path, "dir:", 4))
		return true;

	ret = stat(path, &statbuf);
	if (ret == -1 && errno == EPERM)
		return log_error_errno(false, errno, "dir_detect: failed to look at \"%s\"", path);

	if (ret == 0 && S_ISDIR(statbuf.st_mode))
		return true;

	return false;
}

int dir_mount(struct lxc_storage *bdev)
{
	__do_free char *mntdata = NULL;
	unsigned long mflags = 0, mntflags = 0, pflags = 0;
	int ret;
	const char *src;

	if (strcmp(bdev->type, "dir"))
		return -22;

	if (!bdev->src || !bdev->dest)
		return -22;

	ret = parse_mntopts(bdev->mntopts, &mntflags, &mntdata);
	if (ret < 0)
		return log_error_errno(ret, errno, "Failed to parse mount options \"%s\"", bdev->mntopts);

	ret = parse_propagationopts(bdev->mntopts, &pflags);
	if (ret < 0)
		return log_error_errno(-EINVAL, EINVAL, "Failed to parse mount propagation options \"%s\"", bdev->mntopts);

	src = lxc_storage_get_path(bdev->src, bdev->type);

	ret = mount(src, bdev->dest, "bind", MS_BIND | MS_REC | mntflags | pflags, mntdata);
	if (ret < 0)
		return log_error_errno(-errno, errno, "Failed to mount \"%s\" on \"%s\"", src, bdev->dest);

	if (ret == 0 && (mntflags & MS_RDONLY)) {
		mflags = add_required_remount_flags(src, bdev->dest, MS_BIND | MS_REC | mntflags | pflags | MS_REMOUNT);
		ret = mount(src, bdev->dest, "bind", mflags, mntdata);
		if (ret < 0)
			return log_error_errno(-errno, errno, "Failed to remount \"%s\" on \"%s\" read-only with options \"%s\", mount flags \"%lu\", and propagation flags \"%lu\"",
					       src ? src : "(none)", bdev->dest ? bdev->dest : "(none)", mntdata, mflags, pflags);
		else
			DEBUG("Remounted \"%s\" on \"%s\" read-only with options \"%s\", mount flags \"%lu\", and propagation flags \"%lu\"",
			      src ? src : "(none)", bdev->dest ? bdev->dest : "(none)", mntdata, mflags, pflags);
	}

	TRACE("Mounted \"%s\" on \"%s\" with options \"%s\", mount flags \"%lu\", and propagation flags \"%lu\"",
	      src ? src : "(none)", bdev->dest ? bdev->dest : "(none)", mntdata, mflags, pflags);
	return 0;
}

int dir_umount(struct lxc_storage *bdev)
{
	if (strcmp(bdev->type, "dir"))
		return ret_errno(EINVAL);

	if (!bdev->src || !bdev->dest)
		return ret_errno(EINVAL);

	return umount2(bdev->dest, MNT_DETACH);
}

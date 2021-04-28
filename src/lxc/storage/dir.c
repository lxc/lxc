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
#include "mount_utils.h"
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
	struct lxc_rootfs *rootfs = bdev->rootfs;
	struct lxc_mount_options *mnt_opts = &rootfs->mnt_opts;
	int ret;
	const char *source, *target;

	if (!strequal(bdev->type, "dir"))
		return syserror_set(-EINVAL, "Invalid storage driver");

	if (is_empty_string(bdev->src))
		return syserror_set(-EINVAL, "Missing rootfs path");

	if (is_empty_string(bdev->dest))
		return syserror_set(-EINVAL, "Missing target mountpoint");

	if (rootfs->dfd_idmapped >= 0 && !can_use_bind_mounts())
		return syserror_set(-EOPNOTSUPP, "Idmapped mount requested but kernel doesn't support new mount API");

	source = lxc_storage_get_path(bdev->src, bdev->type);
	target = bdev->dest;

	if (can_use_bind_mounts()) {
		__do_close int fd_source = -EBADF, fd_target = -EBADF;

		fd_target = open_at(-EBADF, target, PROTECT_OPATH_DIRECTORY, 0, 0);
		if (fd_target < 0)
			return syserror("Failed to open \"%s\"", target);

		if (rootfs->dfd_idmapped >= 0) {
			ret = move_detached_mount(rootfs->dfd_idmapped, fd_target, "",
						  PROTECT_OPATH_DIRECTORY,
						  PROTECT_LOOKUP_BENEATH);
		} else {
			fd_source = open_at(-EBADF, source, PROTECT_OPATH_DIRECTORY, 0, 0);
			if (fd_source < 0)
				return syserror("Failed to open \"%s\"", source);

			ret = fd_bind_mount(fd_source, "",
					    PROTECT_OPATH_DIRECTORY,
					    PROTECT_LOOKUP_BENEATH, fd_target,
					    "", PROTECT_OPATH_DIRECTORY,
					    PROTECT_LOOKUP_BENEATH, 0, true);
		}
	} else {
		ret = mount(source, target, "bind", MS_BIND | MS_REC | mnt_opts->mnt_flags | mnt_opts->prop_flags, mnt_opts->data);
		if (!ret && (mnt_opts->mnt_flags & MS_RDONLY)) {
			unsigned long mflags;

			mflags = add_required_remount_flags(source, target,
							    MS_BIND |
							    MS_REC |
							    mnt_opts->mnt_flags |
							    MS_REMOUNT);

			ret = mount(source, target, "bind", mflags, mnt_opts->data);
			if (ret)
				SYSERROR("Failed to remount \"%s\" on \"%s\" read-only", source, target);
			else
				TRACE("Remounted \"%s\" on \"%s\" read-only", source, target);
		}
	}
	if (ret < 0)
		return syserror_set(ret, "Failed to mount \"%s\" onto \"%s\"", source, target);

	TRACE("Mounted \"%s\" onto \"%s\"", source, target);
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

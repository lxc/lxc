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
#include <stdint.h>
#include <string.h>

#include "log.h"
#include "storage.h"
#include "utils.h"

lxc_log_define(dir, lxc);

/* For a simple directory bind mount, we substitute the old container name and
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

	if (snap) {
		ERROR("Directories cannot be snapshotted");
		return -1;
	}

	if (!orig->dest || !orig->src)
		return -1;

	len = strlen(lxcpath) + strlen(cname) + strlen("rootfs") + 4 + 3;
	new->src = malloc(len);
	if (!new->src) {
		ERROR("Failed to allocate memory");
		return -1;
	}

	ret = snprintf(new->src, len, "dir:%s/%s/rootfs", lxcpath, cname);
	if (ret < 0 || (size_t)ret >= len) {
		ERROR("Failed to create string");
		return -1;
	}

	src_no_prefix = lxc_storage_get_path(new->src, new->type);
	new->dest = strdup(src_no_prefix);
	if (!new->dest) {
		ERROR("Failed to duplicate string \"%s\"", new->src);
		return -1;
	}

	TRACE("Created new path \"%s\" for dir storage driver", new->dest);
	return 0;
}

int dir_create(struct lxc_storage *bdev, const char *dest, const char *n,
	       struct bdev_specs *specs)
{
	int ret;
	const char *src;
	size_t len;

	/* strlen("dir:") */
	len = 4;
	if (specs && specs->dir)
		src = specs->dir;
	else
		src = dest;

	len += strlen(src) + 1;
	bdev->src = malloc(len);
	if (!bdev->src) {
		ERROR("Failed to allocate memory");
		return -1;
	}

	ret = snprintf(bdev->src, len, "dir:%s", src);
	if (ret < 0 || (size_t)ret >= len) {
		ERROR("Failed to create string");
		return -1;
	}

	bdev->dest = strdup(dest);
	if (!bdev->dest) {
		ERROR("Failed to duplicate string \"%s\"", dest);
		return -1;
	}

	ret = mkdir_p(dest, 0755);
	if (ret < 0) {
		ERROR("Failed to create directory \"%s\"", dest);
		return -1;
	}
	TRACE("Created directory \"%s\"", dest);

	return 0;
}

int dir_destroy(struct lxc_storage *orig)
{
	int ret;
	const char *src;

	src = lxc_storage_get_path(orig->src, orig->src);

	ret = lxc_rmdir_onedev(src, NULL);
	if (ret < 0) {
		ERROR("Failed to delete \"%s\"", src);
		return -1;
	}

	return 0;
}

bool dir_detect(const char *path)
{
	struct stat statbuf;
	int ret;

	if (!strncmp(path, "dir:", 4))
		return true;

	ret = stat(path, &statbuf);
	if (ret == -1 && errno == EPERM) {
		SYSERROR("dir_detect: failed to look at \"%s\"", path);
		return false;
	}

	if (ret == 0 && S_ISDIR(statbuf.st_mode))
		return true;

	return false;
}

int dir_mount(struct lxc_storage *bdev)
{
	int ret;
	unsigned long mflags = 0, mntflags = 0, pflags = 0;
	char *mntdata;
	const char *src;

	if (strcmp(bdev->type, "dir"))
		return -22;

	if (!bdev->src || !bdev->dest)
		return -22;

	ret = parse_mntopts(bdev->mntopts, &mntflags, &mntdata);
	if (ret < 0) {
		ERROR("Failed to parse mount options \"%s\"", bdev->mntopts);
		free(mntdata);
		return -EINVAL;
	}

	ret = parse_propagationopts(bdev->mntopts, &pflags);
	if (ret < 0) {
		ERROR("Failed to parse propagation options \"%s\"", bdev->mntopts);
		free(mntdata);
		return -EINVAL;
	}

	src = lxc_storage_get_path(bdev->src, bdev->type);

	ret = mount(src, bdev->dest, "bind", MS_BIND | MS_REC | mntflags | pflags, mntdata);
	if ((0 == ret) && (mntflags & MS_RDONLY)) {
		DEBUG("Remounting \"%s\" on \"%s\" readonly",
		      src ? src : "(none)", bdev->dest ? bdev->dest : "(none)");
		mflags = add_required_remount_flags(src, bdev->dest, MS_BIND | MS_REC | mntflags | pflags | MS_REMOUNT);
		ret = mount(src, bdev->dest, "bind", mflags, mntdata);
	}

	if (ret < 0) {
		SYSERROR("Failed to mount \"%s\" on \"%s\"", src, bdev->dest);
		free(mntdata);
		return -1;
	}

	TRACE("Mounted \"%s\" on \"%s\"", src, bdev->dest);
	free(mntdata);
	return ret;
}

int dir_umount(struct lxc_storage *bdev)
{
	if (strcmp(bdev->type, "dir"))
		return -22;

	if (!bdev->src || !bdev->dest)
		return -22;

	return umount(bdev->dest);
}

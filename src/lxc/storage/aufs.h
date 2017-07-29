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

#ifndef __LXC_AUFS_H
#define __LXC_AUFS_H

#define _GNU_SOURCE
#include <stdint.h>

#if IS_BIONIC
#include <../include/lxcmntent.h>
#else
#include <mntent.h>
#endif

/* defined in bdev.h */
struct bdev;

/* defined in lxccontainer.h */
struct bdev_specs;

/* defined conf.h */
struct lxc_conf;

/* defined in conf.h */
struct lxc_rootfs;

/*
 * Functions associated with an aufs bdev struct.
 */
int aufs_clonepaths(struct bdev *orig, struct bdev *new, const char *oldname,
		const char *cname, const char *oldpath, const char *lxcpath,
		int snap, uint64_t newsize, struct lxc_conf *conf);
int aufs_create(struct bdev *bdev, const char *dest, const char *n,
		struct bdev_specs *specs);
int aufs_destroy(struct bdev *orig);
int aufs_detect(const char *path);
int aufs_mount(struct bdev *bdev);
int aufs_umount(struct bdev *bdev);

/*
 * Get rootfs path for aufs backed containers. Allocated memory must be freed
 * by caller.
 */
char *aufs_get_rootfs(const char *rootfs_path, size_t *rootfslen);

/*
 * Create directories for aufs mounts.
 */
int aufs_mkdir(const struct mntent *mntent, const struct lxc_rootfs *rootfs,
		const char *lxc_name, const char *lxc_path);

#endif /* __LXC_AUFS_H */

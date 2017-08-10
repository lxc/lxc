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
#include <stdio.h>

#include "storage.h"

struct lxc_storage;

struct bdev_specs;

struct lxc_conf;

struct lxc_rootfs;

int aufs_clonepaths(struct lxc_storage *orig, struct lxc_storage *new,
		    const char *oldname, const char *cname, const char *oldpath,
		    const char *lxcpath, int snap, uint64_t newsize,
		    struct lxc_conf *conf);
int aufs_create(struct lxc_storage *bdev, const char *dest, const char *n,
		struct bdev_specs *specs);
int aufs_destroy(struct lxc_storage *orig);
int aufs_detect(const char *path);
int aufs_mount(struct lxc_storage *bdev);
int aufs_umount(struct lxc_storage *bdev);

/* Get rootfs path for aufs backed containers. Allocated memory must be freed by
 * caller.
 */
char *aufs_get_rootfs(const char *rootfs_path, size_t *rootfslen);

/*
 * Create directories for aufs mounts.
 */
int aufs_mkdir(const struct mntent *mntent, const struct lxc_rootfs *rootfs,
		const char *lxc_name, const char *lxc_path);

#endif /* __LXC_AUFS_H */

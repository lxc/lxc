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

#ifndef __LXC_ZFS_H
#define __LXC_ZFS_H

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>

/* defined in bdev.h */
struct bdev;

/* defined in lxccontainer.h */
struct bdev_specs;

/* defined conf.h */
struct lxc_conf;

/*
 * Functions associated with an zfs bdev struct.
 */
int zfs_clone(const char *opath, const char *npath, const char *oname,
		const char *nname, const char *lxcpath, int snapshot);
int zfs_clonepaths(struct bdev *orig, struct bdev *new, const char *oldname,
		const char *cname, const char *oldpath, const char *lxcpath,
		int snap, uint64_t newsize, struct lxc_conf *conf);
int zfs_create(struct bdev *bdev, const char *dest, const char *n,
		struct bdev_specs *specs);
/*
 * TODO: detect whether this was a clone, and if so then also delete the
 * snapshot it was based on, so that we don't hold the original
 * container busy.
 */
int zfs_destroy(struct bdev *orig);
int zfs_detect(const char *path);
int zfs_list_entry(const char *path, char *output, size_t inlen);
int zfs_mount(struct bdev *bdev);
int zfs_umount(struct bdev *bdev);

#endif /* __LXC_ZFS_H */

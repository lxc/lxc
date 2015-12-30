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

#ifndef __LXC_LOOP_H
#define __LXC_LOOP_H

#define _GNU_SOURCE
#include <stdint.h>

/* defined in bdev.h */
struct bdev;

/* defined in lxccontainer.h */
struct bdev_specs;

/* defined conf.h */
struct lxc_conf;

/*
 * functions associated with a loop bdev struct
 */
int loop_clonepaths(struct bdev *orig, struct bdev *new, const char *oldname,
		const char *cname, const char *oldpath, const char *lxcpath,
		int snap, uint64_t newsize, struct lxc_conf *conf);
int loop_create(struct bdev *bdev, const char *dest, const char *n,
		struct bdev_specs *specs);
int loop_destroy(struct bdev *orig);
int loop_detect(const char *path);
int loop_mount(struct bdev *bdev);
int loop_umount(struct bdev *bdev);

#endif /* __LXC_LOOP_H */

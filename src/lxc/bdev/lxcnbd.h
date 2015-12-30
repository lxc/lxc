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

#ifndef __LXC_NBD_H
#define __LXC_NBD_H

#define _GNU_SOURCE
#include <stdbool.h>
#include <stdint.h>

/* defined in bdev.h */
struct bdev;

/* defined in lxccontainer.h */
struct bdev_specs;

/* defined conf.h */
struct lxc_conf;

/*
 * Functions associated with an nbd bdev struct.
 */
int nbd_clonepaths(struct bdev *orig, struct bdev *new, const char *oldname,
		const char *cname, const char *oldpath, const char *lxcpath,
		int snap, uint64_t newsize, struct lxc_conf *conf);
int nbd_create(struct bdev *bdev, const char *dest, const char *n,
		struct bdev_specs *specs);
int nbd_destroy(struct bdev *orig);
int nbd_detect(const char *path);
int nbd_mount(struct bdev *bdev);
int nbd_umount(struct bdev *bdev);

/* helpers */
bool attach_nbd(char *src, struct lxc_conf *conf);
void detach_nbd_idx(int idx);
bool requires_nbd(const char *path);

#endif /* __LXC_NBD_H */

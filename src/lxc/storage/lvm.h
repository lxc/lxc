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

#ifndef __LXC_LVM_H
#define __LXC_LVM_H

#include <stdbool.h>
#include <stdint.h>

struct lxc_storage;

struct bdev_specs;

struct lxc_conf;

extern bool lvm_detect(const char *path);
extern int lvm_mount(struct lxc_storage *bdev);
extern int lvm_umount(struct lxc_storage *bdev);
extern int lvm_compare_lv_attr(const char *path, int pos, const char expected);
extern int lvm_is_thin_volume(const char *path);
extern int lvm_is_thin_pool(const char *path);
extern int lvm_clonepaths(struct lxc_storage *orig, struct lxc_storage *new,
			  const char *oldname, const char *cname,
			  const char *oldpath, const char *lxcpath, int snap,
			  uint64_t newsize, struct lxc_conf *conf);
extern int lvm_destroy(struct lxc_storage *orig);
extern int lvm_create(struct lxc_storage *bdev, const char *dest, const char *n,
		      struct bdev_specs *specs);
extern bool lvm_create_clone(struct lxc_conf *conf, struct lxc_storage *orig,
			     struct lxc_storage *new, uint64_t newsize);
extern bool lvm_create_snapshot(struct lxc_conf *conf, struct lxc_storage *orig,
				struct lxc_storage *new, uint64_t newsize);

#endif /* __LXC_LVM_H */

/* SPDX-License-Identifier: LGPL-2.1+ */

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
		      struct bdev_specs *specs, const struct lxc_conf *conf);
extern bool lvm_create_clone(struct lxc_conf *conf, struct lxc_storage *orig,
			     struct lxc_storage *new, uint64_t newsize);
extern bool lvm_create_snapshot(struct lxc_conf *conf, struct lxc_storage *orig,
				struct lxc_storage *new, uint64_t newsize);

#endif /* __LXC_LVM_H */

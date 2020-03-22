/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_ZFS_H
#define __LXC_ZFS_H

#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>

struct lxc_storage;

struct bdev_specs;

struct lxc_conf;

extern int zfs_clonepaths(struct lxc_storage *orig, struct lxc_storage *new,
			  const char *oldname, const char *cname,
			  const char *oldpath, const char *lxcpath, int snap,
			  uint64_t newsize, struct lxc_conf *conf);
extern int zfs_create(struct lxc_storage *bdev, const char *dest, const char *n,
		      struct bdev_specs *specs, const struct lxc_conf *conf);
extern int zfs_destroy(struct lxc_storage *orig);
extern bool zfs_detect(const char *path);
extern int zfs_mount(struct lxc_storage *bdev);
extern int zfs_umount(struct lxc_storage *bdev);

extern bool zfs_copy(struct lxc_conf *conf, struct lxc_storage *orig,
		     struct lxc_storage *new, uint64_t newsize);
extern bool zfs_snapshot(struct lxc_conf *conf, struct lxc_storage *orig,
			 struct lxc_storage *new, uint64_t newsize);

#endif /* __LXC_ZFS_H */

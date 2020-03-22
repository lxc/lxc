/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_RDB_H
#define __LXC_RDB_H

#include <stdbool.h>
#include <stdint.h>

struct lxc_storage;

struct bdev_specs;

struct lxc_conf;

extern int rbd_clonepaths(struct lxc_storage *orig, struct lxc_storage *new,
			  const char *oldname, const char *cname,
			  const char *oldpath, const char *lxcpath, int snap,
			  uint64_t newsize, struct lxc_conf *conf);
extern int rbd_create(struct lxc_storage *bdev, const char *dest, const char *n,
		      struct bdev_specs *specs, const struct lxc_conf *conf);
extern int rbd_destroy(struct lxc_storage *orig);
extern bool rbd_detect(const char *path);
extern int rbd_mount(struct lxc_storage *bdev);
extern int rbd_umount(struct lxc_storage *bdev);

#endif /* __LXC_RDB_H */

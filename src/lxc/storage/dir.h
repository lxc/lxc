/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_DIR_H
#define __LXC_DIR_H

#include <stdbool.h>
#include <stdint.h>

struct lxc_storage;

struct bdev_specs;

struct lxc_conf;

extern int dir_clonepaths(struct lxc_storage *orig, struct lxc_storage *new,
			  const char *oldname, const char *cname,
			  const char *oldpath, const char *lxcpath, int snap,
			  uint64_t newsize, struct lxc_conf *conf);
extern int dir_create(struct lxc_storage *bdev, const char *dest, const char *n,
		      struct bdev_specs *specs, const struct lxc_conf *conf);
extern int dir_destroy(struct lxc_storage *orig);
extern bool dir_detect(const char *path);
extern int dir_mount(struct lxc_storage *bdev);
extern int dir_umount(struct lxc_storage *bdev);

#endif /* __LXC_DIR_H */

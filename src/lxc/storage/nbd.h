/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_NBD_H
#define __LXC_NBD_H

#include <stdbool.h>
#include <stdint.h>

struct lxc_storage;

struct bdev_specs;

struct lxc_conf;

extern int nbd_clonepaths(struct lxc_storage *orig, struct lxc_storage *new,
			  const char *oldname, const char *cname,
			  const char *oldpath, const char *lxcpath, int snap,
			  uint64_t newsize, struct lxc_conf *conf);
extern int nbd_create(struct lxc_storage *bdev, const char *dest, const char *n,
		      struct bdev_specs *specs, const struct lxc_conf *conf);
extern int nbd_destroy(struct lxc_storage *orig);
extern bool nbd_detect(const char *path);
extern int nbd_mount(struct lxc_storage *bdev);
extern int nbd_umount(struct lxc_storage *bdev);

extern bool attach_nbd(char *src, struct lxc_conf *conf);
extern void detach_nbd_idx(int idx);
extern bool requires_nbd(const char *path);

#endif /* __LXC_NBD_H */

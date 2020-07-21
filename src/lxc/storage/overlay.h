/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_OVERLAY_H
#define __LXC_OVERLAY_H

#include <grp.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>

#include "compiler.h"
#include "storage.h"

struct lxc_storage;

struct bdev_specs;

struct lxc_conf;

struct lxc_rootfs;

__hidden extern int ovl_clonepaths(struct lxc_storage *orig, struct lxc_storage *new,
				   const char *oldname, const char *cname, const char *oldpath,
				   const char *lxcpath, int snap, uint64_t newsize,
				   struct lxc_conf *conf);
__hidden extern int ovl_create(struct lxc_storage *bdev, const char *dest, const char *n,
			       struct bdev_specs *specs, const struct lxc_conf *conf);
__hidden extern int ovl_destroy(struct lxc_storage *orig);
__hidden extern bool ovl_detect(const char *path);
__hidden extern int ovl_mount(struct lxc_storage *bdev);
__hidden extern int ovl_umount(struct lxc_storage *bdev);

/* To be called from lxcapi_clone() in lxccontainer.c: When we clone a container
 * with overlay lxc.mount.entry entries we need to update absolute paths for
 * upper- and workdir. This update is done in two locations:
 * lxc_conf->unexpanded_config and lxc_conf->mount_list. Both updates are done
 * independent of each other since lxc_conf->mountlist may container more mount
 * entries (e.g. from other included files) than lxc_conf->unexpanded_config .
 */
__hidden extern int ovl_update_abs_paths(struct lxc_conf *lxc_conf, const char *lxc_path,
					 const char *lxc_name, const char *newpath,
					 const char *newname);

/* To be called from functions in lxccontainer.c: Get lower directory for
 * overlay rootfs.
 */
__hidden extern const char *ovl_get_lower(const char *rootfs_path);

/* Get rootfs path for overlay backed containers. Allocated memory must be freed
 * by caller.
 */
__hidden extern char *ovl_get_rootfs(const char *rootfs_path, size_t *rootfslen);

/* Create upper- and workdirs for overlay mounts.
 */
__hidden extern int ovl_mkdir(const struct mntent *mntent, const struct lxc_rootfs *rootfs,
			      const char *lxc_name, const char *lxc_path);

#endif /* __LXC_OVERLAY_H */

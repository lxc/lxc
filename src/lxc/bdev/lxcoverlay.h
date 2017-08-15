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

#ifndef __LXC_OVERLAY_H
#define __LXC_OVERLAY_H

#include <grp.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>

#if IS_BIONIC
#include <../include/lxcmntent.h>
#else
#include <mntent.h>
#endif

/* defined in bdev.h */
struct bdev;

/* defined in lxccontainer.h */
struct bdev_specs;

/* defined conf.h */
struct lxc_conf;

/* defined in conf.h */
struct lxc_rootfs;

/*
 * Functions associated with an overlay bdev struct.
 */
int ovl_clonepaths(struct bdev *orig, struct bdev *new, const char *oldname,
		   const char *cname, const char *oldpath, const char *lxcpath,
		   int snap, uint64_t newsize, struct lxc_conf *conf);
int ovl_create(struct bdev *bdev, const char *dest, const char *n,
	       struct bdev_specs *specs);
int ovl_destroy(struct bdev *orig);
int ovl_detect(const char *path);
int ovl_mount(struct bdev *bdev);
int ovl_umount(struct bdev *bdev);

/*
 * To be called from lxcapi_clone() in lxccontainer.c: When we clone a container
 * with overlay lxc.mount.entry entries we need to update absolute paths for
 * upper- and workdir. This update is done in two locations:
 * lxc_conf->unexpanded_config and lxc_conf->mount_list. Both updates are done
 * independent of each other since lxc_conf->mountlist may container more mount
 * entries (e.g. from other included files) than lxc_conf->unexpanded_config .
 */
int ovl_update_abs_paths(struct lxc_conf *lxc_conf, const char *lxc_path,
			 const char *lxc_name, const char *newpath,
			 const char *newname);

/*
 * To be called from functions in lxccontainer.c: Get lower directory for
 * overlay rootfs.
 */
char *ovl_getlower(char *p);

/*
 * Get rootfs path for overlay backed containers. Allocated memory must be freed
 * by caller.
 */
char *ovl_get_rootfs(const char *rootfs_path, size_t *rootfslen);

/*
 * Create upper- and workdirs for overlay mounts.
 */
int ovl_mkdir(const struct mntent *mntent, const struct lxc_rootfs *rootfs,
	      const char *lxc_name, const char *lxc_path);

#endif /* __LXC_OVERLAY_H */

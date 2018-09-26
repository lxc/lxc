/*
 * lxc: linux Container library
 *
 * Copyright © 2017 Canonical Ltd.
 *
 * Authors:
 * Christian Brauner <christian.brauner@ubuntu.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef __LXC_STORAGE_UTILS_H
#define __LXC_STORAGE_UTILS_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "conf.h"

struct lxc_storage;
struct lxc_conf;

extern char *dir_new_path(char *src, const char *oldname, const char *name,
			  const char *oldpath, const char *lxcpath);
extern bool attach_block_device(struct lxc_conf *conf);
extern void detach_block_device(struct lxc_conf *conf);
extern int blk_getsize(struct lxc_storage *bdev, uint64_t *size);
extern int detect_fs(struct lxc_storage *bdev, char *type, int len);
extern int do_mkfs_exec_wrapper(void *args);
extern int is_blktype(struct lxc_storage *b);
extern int mount_unknown_fs(const char *rootfs, const char *target,
			    const char *options);
extern int find_fstype_cb(char *buffer, void *data);
extern const char *linkderef(const char *path, char *dest);
extern bool unpriv_snap_allowed(struct lxc_storage *b, const char *t, bool snap,
				bool maybesnap);
extern uint64_t get_fssize(char *s);
extern bool is_valid_storage_type(const char *type);
extern int storage_destroy_wrapper(void *data);

#endif /* __LXC_STORAGE_UTILS_H */

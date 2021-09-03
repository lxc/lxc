/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_STORAGE_UTILS_H
#define __LXC_STORAGE_UTILS_H

#include "config.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "compiler.h"
#include "conf.h"
#include "macro.h"

#define LXC_OVERLAY_PRIVATE_DIR "overlay"
#define LXC_OVERLAY_DELTA_DIR "delta"
#define LXC_OVERLAY_WORK_DIR "work"
#define LXC_OVERLAY_DELTA_PATH LXC_OVERLAY_PRIVATE_DIR "/" LXC_OVERLAY_DELTA_DIR
#define LXC_OVERLAY_WORK_PATH LXC_OVERLAY_PRIVATE_DIR "/" LXC_OVERLAY_WORK_DIR
#define LXC_OVERLAY_PATH_LEN \
	(STRLITERALLEN(LXC_OVERLAY_PRIVATE_DIR) + STRLITERALLEN("/") + 256 + 1)

struct lxc_storage;
struct lxc_conf;

__hidden extern bool attach_block_device(struct lxc_conf *conf);
__hidden extern void detach_block_device(struct lxc_conf *conf);
__hidden extern int blk_getsize(struct lxc_storage *bdev, uint64_t *size);
__hidden extern int detect_fs(struct lxc_storage *bdev, char *type, int len);
__hidden extern int do_mkfs_exec_wrapper(void *args);
__hidden extern int is_blktype(struct lxc_storage *b);
__hidden extern int mount_unknown_fs(const char *rootfs, const char *target, const char *options);
__hidden extern int find_fstype_cb(char *buffer, void *data);
__hidden extern const char *linkderef(const char *path, char *dest);
__hidden extern bool unpriv_snap_allowed(struct lxc_storage *b, const char *t, bool snap,
					 bool maybesnap);
__hidden extern uint64_t get_fssize(char *s);
__hidden extern bool is_valid_storage_type(const char *type);
__hidden extern int storage_destroy_wrapper(void *data);

#endif /* __LXC_STORAGE_UTILS_H */

/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_STORAGE_UTILS_H
#define __LXC_STORAGE_UTILS_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

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

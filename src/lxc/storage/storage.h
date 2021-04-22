/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_STORAGE_H
#define __LXC_STORAGE_H

#include <stdint.h>
#include <sys/mount.h>

#include <lxc/lxccontainer.h>

#if IS_BIONIC
#include <../include/lxcmntent.h>
#else
#include <mntent.h>
#endif

#include "compiler.h"
#include "conf.h"

#ifndef MS_DIRSYNC
#define MS_DIRSYNC 128
#endif

#ifndef MS_REC
#define MS_REC 16384
#endif

#ifndef MNT_DETACH
#define MNT_DETACH 2
#endif

#ifndef MS_SLAVE
#define MS_SLAVE (1 << 19)
#endif

#ifndef MS_RELATIME
#define MS_RELATIME (1 << 21)
#endif

#ifndef MS_STRICTATIME
#define MS_STRICTATIME (1 << 24)
#endif

#define DEFAULT_FS_SIZE 1073741824
#define DEFAULT_FSTYPE "ext4"

#define LXC_STORAGE_INTERNAL_OVERLAY_RESTORE  (1 << 6)

struct lxc_storage;

struct lxc_storage_ops {
	/* detect whether path is of this bdev type */
	bool (*detect)(const char *path);

	/* mount requires src and dest to be set. */
	int (*mount)(struct lxc_storage *bdev);
	int (*umount)(struct lxc_storage *bdev);
	int (*destroy)(struct lxc_storage *bdev);
	int (*create)(struct lxc_storage *bdev, const char *dest, const char *n,
		      struct bdev_specs *specs, const struct lxc_conf *conf);
	/* given original mount, rename the paths for cloned container */
	int (*clone_paths)(struct lxc_storage *orig, struct lxc_storage *new,
			   const char *oldname, const char *cname,
			   const char *oldpath, const char *lxcpath, int snap,
			   uint64_t newsize, struct lxc_conf *conf);
	bool (*copy)(struct lxc_conf *conf, struct lxc_storage *orig,
		     struct lxc_storage *new, uint64_t newsize);
	bool (*snapshot)(struct lxc_conf *conf, struct lxc_storage *orig,
			 struct lxc_storage *new, uint64_t newsize);
	bool can_snapshot;
	bool can_backup;
};

/* When lxc is mounting a rootfs, then src will be the "lxc.rootfs.path" value,
 * dest will be the mount dir (i.e. "<libdir>/lxc")  When clone or create is
 * doing so, then dest will be "<lxcpath>/<lxcname>/rootfs", since we may need
 * to rsync from one to the other.
 */
struct lxc_storage {
	const struct lxc_storage_ops *ops;
	const char *type;
	char *src;
	char *dest;
	char *mntopts;
	/* Turn the following into a union if need be. */
	/* lofd is the open fd for the mounted loopback file. */
	int lofd;
	/* index for the connected nbd device. */
	int nbd_idx;
	int flags;
	struct lxc_rootfs *rootfs;
};

/**
 * storage_is_dir : Check whether the roots is a directory. This function will
 *                  trust the config file. If the config file key
 *                  lxc.rootfs.path is set to <storage type>:<container path>
 *                  the confile parser will have split this into <storage type>
 *                  and <container path> and set the <bdev_type> member in the
 *                  lxc_rootfs struct to <storage type> and the <path> member
 *                  will be set to a clean <container path> without the <storage
 *                  type> prefix. This is the new, clean way of handling storage
 *                  type specifications.  If the <storage type> prefix is not
 *                  detected liblxc will try to detect the storage type.
 */
__hidden extern bool storage_is_dir(struct lxc_conf *conf);
__hidden extern bool storage_can_backup(struct lxc_conf *conf);
__hidden extern struct lxc_storage *storage_init(struct lxc_conf *conf);
__hidden extern struct lxc_storage *storage_copy(struct lxc_container *c, const char *cname,
						 const char *lxcpath, const char *bdevtype,
						 int flags, const char *bdevdata, uint64_t newsize,
						 bool *needs_rdep);
__hidden extern struct lxc_storage *storage_create(const char *dest, const char *type,
						   const char *cname, struct bdev_specs *specs,
						   const struct lxc_conf *conf);
__hidden extern void storage_put(struct lxc_storage *bdev);
__hidden extern bool storage_destroy(struct lxc_conf *conf);
__hidden extern bool rootfs_is_blockdev(struct lxc_conf *conf);
__hidden extern const char *lxc_storage_get_path(char *src, const char *prefix);

#endif /* #define __LXC_STORAGE_H */

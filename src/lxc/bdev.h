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

#ifndef __LXC_BDEV_H
#define __LXC_BDEV_H
/* blockdev operations for:
 * dir, raw, btrfs, overlayfs, aufs, lvm, loop, zfs
 * someday: qemu-nbd, qcow2, qed
 */

#include "config.h"
#include <stdint.h>
#include <lxc/lxccontainer.h>

struct bdev;

/*
 * specifications for how to create a new backing store
 */
struct bdev_specs {
	char *fstype;
	uint64_t fssize;  // fs size in bytes
	struct {
		char *zfsroot;
	} zfs;
	struct {
		char *vg;
		char *lv;
		char *thinpool; // lvm thin pool to use, if any
	} lvm;
};

struct bdev_ops {
	/* detect whether path is of this bdev type */
	int (*detect)(const char *path);
	// mount requires src and dest to be set.
	int (*mount)(struct bdev *bdev);
	int (*umount)(struct bdev *bdev);
	int (*destroy)(struct bdev *bdev);
	int (*create)(struct bdev *bdev, const char *dest, const char *n,
			struct bdev_specs *specs);
	/* given original mount, rename the paths for cloned container */
	int (*clone_paths)(struct bdev *orig, struct bdev *new, const char *oldname,
			const char *cname, const char *oldpath, const char *lxcpath,
			int snap, uint64_t newsize);
	bool can_snapshot;
};

/*
 * When lxc-start (conf.c) is mounting a rootfs, then src will be the
 * 'lxc.rootfs' value, dest will be mount dir (i.e. $libdir/lxc)  When clone
 * or create is doing so, then dest will be $lxcpath/$lxcname/rootfs, since
 * we may need to rsync from one to the other.
 * data is so far unused.
 */
struct bdev {
	const struct bdev_ops *ops;
	const char *type;
	char *src;
	char *dest;
	char *data;
	// turn the following into a union if need be
	// lofd is the open fd for the mounted loopback file
	int lofd;
};

char *overlayfs_getlower(char *p);

/*
 * Instantiate a bdev object.  The src is used to determine which blockdev
 * type this should be.  The dst and data are optional, and will be used
 * in case of mount/umount.
 *
 * Optionally, src can be 'dir:/var/lib/lxc/c1' or 'lvm:/dev/lxc/c1'.  For
 * other backing stores, this will allow additional options.  In particular,
 * "overlayfs:/var/lib/lxc/canonical/rootfs:/var/lib/lxc/c1/delta" will mean
 * use /var/lib/lxc/canonical/rootfs as lower dir, and /var/lib/lxc/c1/delta
 * as the upper, writeable layer.
 */
struct bdev *bdev_init(const char *src, const char *dst, const char *data);

struct bdev *bdev_copy(const char *src, const char *oldname, const char *cname,
			const char *oldpath, const char *lxcpath, const char *bdevtype,
			int flags, const char *bdevdata, uint64_t newsize,
			int *needs_rdep);
struct bdev *bdev_create(const char *dest, const char *type,
			const char *cname, struct bdev_specs *specs);
void bdev_put(struct bdev *bdev);

/* define constants if the kernel/glibc headers don't define them */
#ifndef MS_DIRSYNC
#define MS_DIRSYNC  128
#endif

#ifndef MS_REC
#define MS_REC 16384
#endif

#ifndef MNT_DETACH
#define MNT_DETACH 2
#endif

#ifndef MS_SLAVE
#define MS_SLAVE (1<<19)
#endif

#ifndef MS_RELATIME
#define MS_RELATIME (1 << 21)
#endif

#ifndef MS_STRICTATIME
#define MS_STRICTATIME (1 << 24)
#endif

#endif

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

#define _GNU_SOURCE
#define __STDC_FORMAT_MACROS /* Required for PRIu64 to work. */
#include <inttypes.h> /* Required for PRIu64 to work. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bdev.h"
#include "log.h"
#include "utils.h"

lxc_log_define(lxcrbd, lxc);

int rbd_clonepaths(struct bdev *orig, struct bdev *new, const char *oldname,
		const char *cname, const char *oldpath, const char *lxcpath,
		int snap, uint64_t newsize, struct lxc_conf *conf)
{
	ERROR("rbd clonepaths not implemented");
	return -1;
}

int rbd_create(struct bdev *bdev, const char *dest, const char *n,
		struct bdev_specs *specs)
{
	const char *rbdpool, *rbdname = n, *fstype;
	uint64_t size;
	int ret, len;
	char sz[24];
	pid_t pid;

	if (!specs)
		return -1;

	rbdpool = specs->rbd.rbdpool;
	if (!rbdpool)
		rbdpool = lxc_global_config_value("lxc.bdev.rbd.rbdpool");

	if (specs->rbd.rbdname)
		rbdname = specs->rbd.rbdname;

	/* source device /dev/rbd/lxc/ctn */
	len = strlen(rbdpool) + strlen(rbdname) + 11;
	bdev->src = malloc(len);
	if (!bdev->src)
		return -1;

	ret = snprintf(bdev->src, len, "/dev/rbd/%s/%s", rbdpool, rbdname);
	if (ret < 0 || ret >= len)
		return -1;

	// fssize is in bytes.
	size = specs->fssize;
	if (!size)
		size = DEFAULT_FS_SIZE;

	// in megabytes for rbd tool
	ret = snprintf(sz, 24, "%"PRIu64, size / 1024 / 1024 );
	if (ret < 0 || ret >= 24)
		exit(1);

	if ((pid = fork()) < 0)
		return -1;
	if (!pid) {
		execlp("rbd", "rbd", "create" , "--pool", rbdpool, rbdname, "--size", sz, (char *)NULL);
		exit(1);
	}
	if (wait_for_pid(pid) < 0)
		return -1;

	if ((pid = fork()) < 0)
		return -1;
	if (!pid) {
		execlp("rbd", "rbd", "map", "--pool", rbdpool, rbdname, (char *)NULL);
		exit(1);
	}
	if (wait_for_pid(pid) < 0)
		return -1;

	fstype = specs->fstype;
	if (!fstype)
		fstype = DEFAULT_FSTYPE;

	if (do_mkfs(bdev->src, fstype) < 0) {
		ERROR("Error creating filesystem type %s on %s", fstype,
			bdev->src);
		return -1;
	}
	if (!(bdev->dest = strdup(dest)))
		return -1;

	if (mkdir_p(bdev->dest, 0755) < 0 && errno != EEXIST) {
		ERROR("Error creating %s", bdev->dest);
		return -1;
	}

	return 0;
}

int rbd_destroy(struct bdev *orig)
{
	pid_t pid;
	char *rbdfullname;

	if ( file_exists(orig->src) ) {
		if ((pid = fork()) < 0)
			return -1;
		if (!pid) {
			execlp("rbd", "rbd", "unmap" , orig->src, (char *)NULL);
			exit(1);
		}
		if (wait_for_pid(pid) < 0)
			return -1;
	}

	if ((pid = fork()) < 0)
		return -1;
	if (!pid) {
		rbdfullname = alloca(strlen(orig->src) - 8);
		strcpy( rbdfullname, &orig->src[9] );
		execlp("rbd", "rbd", "rm" , rbdfullname, (char *)NULL);
		exit(1);
	}
	return wait_for_pid(pid);

}

int rbd_detect(const char *path)
{
	if ( memcmp(path, "/dev/rbd/", 9) == 0)
		return 1;
	return 0;
}

int rbd_mount(struct bdev *bdev)
{
	if (strcmp(bdev->type, "rbd"))
		return -22;
	if (!bdev->src || !bdev->dest)
		return -22;

	if ( !file_exists(bdev->src) ) {
		// if blkdev does not exist it should be mapped, because it is not persistent on reboot
		ERROR("Block device %s is not mapped.", bdev->src);
		return -1;
	}

	return mount_unknown_fs(bdev->src, bdev->dest, bdev->mntopts);
}

int rbd_umount(struct bdev *bdev)
{
	if (strcmp(bdev->type, "rbd"))
		return -22;
	if (!bdev->src || !bdev->dest)
		return -22;
	return umount(bdev->dest);
}

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
#include <dirent.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/loop.h>
#include <sys/types.h>

#include "bdev.h"
#include "log.h"
#include "lxcloop.h"
#include "utils.h"

lxc_log_define(lxcloop, lxc);

static int do_loop_create(const char *path, uint64_t size, const char *fstype);

/*
 * No idea what the original blockdev will be called, but the copy will be
 * called $lxcpath/$lxcname/rootdev
 */
int loop_clonepaths(struct bdev *orig, struct bdev *new, const char *oldname,
		const char *cname, const char *oldpath, const char *lxcpath,
		int snap, uint64_t newsize, struct lxc_conf *conf)
{
	char fstype[100];
	uint64_t size = newsize;
	int len, ret;
	char *srcdev;

	if (snap) {
		ERROR("loop devices cannot be snapshotted.");
		return -1;
	}

	if (!orig->dest || !orig->src)
		return -1;

	len = strlen(lxcpath) + strlen(cname) + strlen("rootdev") + 3;
	srcdev = alloca(len);
	ret = snprintf(srcdev, len, "%s/%s/rootdev", lxcpath, cname);
	if (ret < 0 || ret >= len)
		return -1;

	new->src = malloc(len + 5);
	if (!new->src)
		return -1;
	ret = snprintf(new->src, len + 5, "loop:%s", srcdev);
	if (ret < 0 || ret >= len + 5)
		return -1;

	new->dest = malloc(len);
	if (!new->dest)
		return -1;
	ret = snprintf(new->dest, len, "%s/%s/rootfs", lxcpath, cname);
	if (ret < 0 || ret >= len)
		return -1;

	// it's tempting to say: if orig->src == loopback and !newsize, then
	// copy the loopback file.  However, we'd have to make sure to
	// correctly keep holes!  So punt for now.

	if (is_blktype(orig)) {
		if (!newsize && blk_getsize(orig, &size) < 0) {
			ERROR("Error getting size of %s", orig->src);
			return -1;
		}
		if (detect_fs(orig, fstype, 100) < 0) {
			INFO("could not find fstype for %s, using %s", orig->src,
				DEFAULT_FSTYPE);
			return -1;
		}
	} else {
		sprintf(fstype, "%s", DEFAULT_FSTYPE);
		if (!newsize)
			size = DEFAULT_FS_SIZE;
	}
	return do_loop_create(srcdev, size, fstype);
}

int loop_create(struct bdev *bdev, const char *dest, const char *n,
		struct bdev_specs *specs)
{
	const char *fstype;
	uint64_t sz;
	int ret, len;
	char *srcdev;

	if (!specs)
		return -1;

	// dest is passed in as $lxcpath / $lxcname / rootfs
	// srcdev will be:      $lxcpath / $lxcname / rootdev
	// src will be 'loop:$srcdev'
	len = strlen(dest) + 2;
	srcdev = alloca(len);

	ret = snprintf(srcdev, len, "%s", dest);
	if (ret < 0 || ret >= len)
		return -1;
	sprintf(srcdev + len - 4, "dev");

	bdev->src = malloc(len + 5);
	if (!bdev->src)
		return -1;
	ret = snprintf(bdev->src, len + 5, "loop:%s", srcdev);
	if (ret < 0 || ret >= len + 5)
		return -1;

	sz = specs->fssize;
	if (!sz)
		sz = DEFAULT_FS_SIZE;

	fstype = specs->fstype;
	if (!fstype)
		fstype = DEFAULT_FSTYPE;

	if (!(bdev->dest = strdup(dest)))
		return -1;

	if (mkdir_p(bdev->dest, 0755) < 0) {
		ERROR("Error creating %s", bdev->dest);
		return -1;
	}

	return do_loop_create(srcdev, sz, fstype);
}

int loop_destroy(struct bdev *orig)
{
	return unlink(orig->src + 5);
}

int loop_detect(const char *path)
{
	if (strncmp(path, "loop:", 5) == 0)
		return 1;
	return 0;
}

int loop_mount(struct bdev *bdev)
{
	int ret, loopfd;
	char loname[MAXPATHLEN];

	if (strcmp(bdev->type, "loop"))
		return -22;
	if (!bdev->src || !bdev->dest)
		return -22;

	loopfd = lxc_prepare_loop_dev(bdev->src + 5, loname, LO_FLAGS_AUTOCLEAR);
	if (loopfd < 0)
		return -1;
	DEBUG("prepared loop device \"%s\"", loname);

	ret = mount_unknown_fs(loname, bdev->dest, bdev->mntopts);
	if (ret < 0)
		ERROR("failed to mount rootfs \"%s\" onto \"%s\" via loop device \"%s\"", bdev->src, bdev->dest, loname);
	else
		bdev->lofd = loopfd;
	DEBUG("mounted rootfs \"%s\" onto \"%s\" via loop device \"%s\"", bdev->src, bdev->dest, loname);

	return ret;
}

int loop_umount(struct bdev *bdev)
{
	int ret;

	if (strcmp(bdev->type, "loop"))
		return -22;
	if (!bdev->src || !bdev->dest)
		return -22;
	ret = umount(bdev->dest);
	if (bdev->lofd >= 0) {
		close(bdev->lofd);
		bdev->lofd = -1;
	}
	return ret;
}

static int do_loop_create(const char *path, uint64_t size, const char *fstype)
{
	int fd, ret;
	// create the new loopback file.
	fd = creat(path, S_IRUSR|S_IWUSR);
	if (fd < 0)
		return -1;
	if (lseek(fd, size, SEEK_SET) < 0) {
		SYSERROR("Error seeking to set new loop file size");
		close(fd);
		return -1;
	}
	if (write(fd, "1", 1) != 1) {
		SYSERROR("Error creating new loop file");
		close(fd);
		return -1;
	}
	ret = close(fd);
	if (ret < 0) {
		SYSERROR("Error closing new loop file");
		return -1;
	}

	// create an fs in the loopback file
	if (do_mkfs(path, fstype) < 0) {
		ERROR("Error creating filesystem type %s on %s", fstype,
			path);
		return -1;
	}

	return 0;
}

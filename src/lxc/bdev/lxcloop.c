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

#ifndef LO_FLAGS_AUTOCLEAR
#define LO_FLAGS_AUTOCLEAR 4
#endif

#ifndef LOOP_CTL_GET_FREE
#define LOOP_CTL_GET_FREE 0x4C82
#endif

lxc_log_define(lxcloop, lxc);

static int do_loop_create(const char *path, uint64_t size, const char *fstype);
static int find_free_loopdev_no_control(int *retfd, char *namep);
static int find_free_loopdev(int *retfd, char *namep);

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
	int lfd, ffd = -1, ret = -1;
	struct loop_info64 lo;
	char loname[100];

	if (strcmp(bdev->type, "loop"))
		return -22;
	if (!bdev->src || !bdev->dest)
		return -22;
	if (find_free_loopdev(&lfd, loname) < 0)
		return -22;

	ffd = open(bdev->src + 5, O_RDWR);
	if (ffd < 0) {
		SYSERROR("Error opening backing file %s", bdev->src);
		goto out;
	}

	if (ioctl(lfd, LOOP_SET_FD, ffd) < 0) {
		SYSERROR("Error attaching backing file to loop dev");
		goto out;
	}
	memset(&lo, 0, sizeof(lo));
	lo.lo_flags = LO_FLAGS_AUTOCLEAR;
	if (ioctl(lfd, LOOP_SET_STATUS64, &lo) < 0) {
		SYSERROR("Error setting autoclear on loop dev");
		goto out;
	}

	ret = mount_unknown_fs(loname, bdev->dest, bdev->mntopts);
	if (ret < 0)
		ERROR("Error mounting %s", bdev->src);
	else
		bdev->lofd = lfd;

out:
	if (ffd > -1)
		close(ffd);
	if (ret < 0) {
		close(lfd);
		bdev->lofd = -1;
	}
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

static int find_free_loopdev_no_control(int *retfd, char *namep)
{
	struct dirent dirent, *direntp;
	struct loop_info64 lo;
	DIR *dir;
	int fd = -1;

	dir = opendir("/dev");
	if (!dir) {
		SYSERROR("Error opening /dev");
		return -1;
	}
	while (!readdir_r(dir, &dirent, &direntp)) {

		if (!direntp)
			break;
		if (strncmp(direntp->d_name, "loop", 4) != 0)
			continue;
		fd = openat(dirfd(dir), direntp->d_name, O_RDWR);
		if (fd < 0)
			continue;
		if (ioctl(fd, LOOP_GET_STATUS64, &lo) == 0 || errno != ENXIO) {
			close(fd);
			fd = -1;
			continue;
		}
		// We can use this fd
		snprintf(namep, 100, "/dev/%s", direntp->d_name);
		break;
	}
	closedir(dir);
	if (fd == -1) {
		ERROR("No loop device found");
		return -1;
	}

	*retfd = fd;
	return 0;
}

static int find_free_loopdev(int *retfd, char *namep)
{
	int rc, fd = -1;
	int ctl = open("/dev/loop-control", O_RDWR);
	if (ctl < 0)
		return find_free_loopdev_no_control(retfd, namep);
	rc = ioctl(ctl, LOOP_CTL_GET_FREE);
	if (rc >= 0) {
		snprintf(namep, 100, "/dev/loop%d", rc);
		fd = open(namep, O_RDWR);
	}
	close(ctl);
	if (fd == -1) {
		ERROR("No loop device found");
		return -1;
	}
	*retfd = fd;
	return 0;
}

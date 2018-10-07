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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#define __STDC_FORMAT_MACROS
#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <linux/loop.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"
#include "log.h"
#include "loop.h"
#include "storage.h"
#include "storage_utils.h"
#include "utils.h"

lxc_log_define(loop, lxc);

static int do_loop_create(const char *path, uint64_t size, const char *fstype);

/*
 * No idea what the original blockdev will be called, but the copy will be
 * called $lxcpath/$lxcname/rootdev
 */
int loop_clonepaths(struct lxc_storage *orig, struct lxc_storage *new,
		    const char *oldname, const char *cname, const char *oldpath,
		    const char *lxcpath, int snap, uint64_t newsize,
		    struct lxc_conf *conf)
{
	uint64_t size = newsize;
	int len, ret;
	char *srcdev;
	char fstype[100] = "ext4";

	if (snap) {
		ERROR("The loop storage driver does not support snapshots");
		return -1;
	}

	if (!orig->dest || !orig->src)
		return -1;

	len = strlen(lxcpath) + strlen(cname) + strlen("rootdev") + 3;
	srcdev = alloca(len);
	ret = snprintf(srcdev, len, "%s/%s/rootdev", lxcpath, cname);
	if (ret < 0 || ret >= len) {
		ERROR("Failed to create string");
		return -1;
	}

	new->src = malloc(len + 5);
	if (!new->src) {
		ERROR("Failed to allocate memory");
		return -1;
	}

	ret = snprintf(new->src, (len + 5), "loop:%s", srcdev);
	if (ret < 0 || ret >= (len + 5)) {
		ERROR("Failed to create string");
		return -1;
	}

	new->dest = malloc(len);
	if (!new->dest) {
		ERROR("Failed to allocate memory");
		return -1;
	}

	ret = snprintf(new->dest, len, "%s/%s/rootfs", lxcpath, cname);
	if (ret < 0 || ret >= len) {
		ERROR("Failed to create string");
		return -1;
	}

	/* It's tempting to say: if orig->src == loopback and !newsize, then
	 * copy the loopback file. However, we'd have to make sure to correctly
	 * keep holes! So punt for now.
	 */
	if (is_blktype(orig)) {
		/* detect size */
		if (!newsize && blk_getsize(orig, &size) < 0) {
			ERROR("Failed to detect size of loop file \"%s\"",
			      orig->src);
			return -1;
		}

		/* detect filesystem */
		if (detect_fs(orig, fstype, 100) < 0) {
			INFO("Failed to detect filesystem type for \"%s\"", orig->src);
			return -1;
		}
	} else if (!newsize) {
			size = DEFAULT_FS_SIZE;
	}

	ret = do_loop_create(srcdev, size, fstype);
	if (ret < 0) {
		ERROR("Failed to create loop storage volume \"%s\" with "
		      "filesystem \"%s\" and size \"%" PRIu64 "\"",
		      srcdev, fstype, size);
		return -1;
	}

	return 0;
}

int loop_create(struct lxc_storage *bdev, const char *dest, const char *n,
		struct bdev_specs *specs)
{
	const char *fstype;
	uint64_t sz;
	int ret, len;
	char *srcdev;

	if (!specs)
		return -1;

	/* <dest> is passed in as <lxcpath>/<lxcname>/rootfs, <srcdev> will
	 * be <lxcpath>/<lxcname>/rootdev, and <src> will be "loop:<srcdev>".
	 */
	len = strlen(dest) + 2;
	srcdev = alloca(len);

	ret = snprintf(srcdev, len, "%s", dest);
	if (ret < 0 || ret >= len) {
		ERROR("Failed to create string");
		return -1;
	}

	ret = sprintf(srcdev + len - 4, "dev");
	if (ret < 0) {
		ERROR("Failed to create string");
		return -1;
	}

	bdev->src = malloc(len + 5);
	if (!bdev->src) {
		ERROR("Failed to allocate memory");
		return -1;
	}

	ret = snprintf(bdev->src, len + 5, "loop:%s", srcdev);
	if (ret < 0 || ret >= len + 5) {
		ERROR("Failed to create string");
		return -1;
	}

	sz = specs->fssize;
	if (!sz)
		sz = DEFAULT_FS_SIZE;

	fstype = specs->fstype;
	if (!fstype)
		fstype = DEFAULT_FSTYPE;

	bdev->dest = strdup(dest);
	if (!bdev->dest) {
		ERROR("Failed to duplicate string \"%s\"", dest);
		return -1;
	}

	ret = mkdir_p(bdev->dest, 0755);
	if (ret < 0) {
		ERROR("Failed creating directory \"%s\"", bdev->dest);
		return -1;
	}


	ret = do_loop_create(srcdev, sz, fstype);
	if (ret < 0) {
		ERROR("Failed to create loop storage volume \"%s\" with "
		      "filesystem \"%s\" and size \"%" PRIu64 "\"",
		      srcdev, fstype, sz);
		return -1;
	}

	return 0;
}

int loop_destroy(struct lxc_storage *orig) {
	char *dir;

	dir = orig->src;
	if (strncmp(orig->src, "loop:", 5) == 0)
		dir += 5;

	return unlink(dir);
}

bool loop_detect(const char *path)
{
	int ret;
	struct stat s;

	if (!strncmp(path, "loop:", 5))
		return true;

	ret = stat(path, &s);
	if (ret < 0)
		return false;

	if (__S_ISTYPE(s.st_mode, S_IFREG))
		return true;

	return false;
}

int loop_mount(struct lxc_storage *bdev)
{
	int ret, loopfd;
	char loname[PATH_MAX];
	const char *src;

	if (strcmp(bdev->type, "loop"))
		return -22;

	if (!bdev->src || !bdev->dest)
		return -22;

	/* skip prefix */
	src = lxc_storage_get_path(bdev->src, bdev->type);

	loopfd = lxc_prepare_loop_dev(src, loname, LO_FLAGS_AUTOCLEAR);
	if (loopfd < 0) {
		ERROR("Failed to prepare loop device for loop file \"%s\"", src);
		return -1;
	}
	DEBUG("Prepared loop device \"%s\"", loname);

	ret = mount_unknown_fs(loname, bdev->dest, bdev->mntopts);
	if (ret < 0) {
		ERROR("Failed to mount rootfs \"%s\" on \"%s\" via loop device \"%s\"",
		      bdev->src, bdev->dest, loname);
		close(loopfd);
		return -1;
	}

	bdev->lofd = loopfd;
	DEBUG("Mounted rootfs \"%s\" on \"%s\" via loop device \"%s\"",
	      bdev->src, bdev->dest, loname);

	return 0;
}

int loop_umount(struct lxc_storage *bdev)
{
	int ret, saved_errno;

	if (strcmp(bdev->type, "loop"))
		return -22;

	if (!bdev->src || !bdev->dest)
		return -22;

	ret = umount(bdev->dest);
	saved_errno = errno;
	if (bdev->lofd >= 0) {
		close(bdev->lofd);
		bdev->lofd = -1;
	}
	errno = saved_errno;

	if (ret < 0) {
		SYSERROR("Failed to umount \"%s\"", bdev->dest);
		return -1;
	}

	return 0;
}

static int do_loop_create(const char *path, uint64_t size, const char *fstype)
{
	int fd, ret;
	off_t ret_size;
	char cmd_output[PATH_MAX];
	const char *cmd_args[2] = {fstype, path};

	/* create the new loopback file */
	fd = creat(path, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		SYSERROR("Failed to create new loop file \"%s\"", path);
		return -1;
	}

	ret_size = lseek(fd, size, SEEK_SET);
	if (ret_size < 0) {
		SYSERROR("Failed to seek to set new loop file size for loop "
			 "file \"%s\"", path);
		close(fd);
		return -1;
	}

	ret = write(fd, "1", 1);
	if (ret != 1) {
		SYSERROR("Failed creating new loop file \"%s\"", path);
		close(fd);
		return -1;
	}

	ret = close(fd);
	if (ret < 0) {
		SYSERROR("Failed to create new loop file \"%s\"", path);
		return -1;
	}

	/* Create an fs in the loopback file. */
	ret = run_command(cmd_output, sizeof(cmd_output), do_mkfs_exec_wrapper,
			  (void *)cmd_args);
	if (ret < 0) {
		ERROR("Failed to create new filesystem \"%s\" for loop file "
		      "\"%s\": %s", fstype, path, cmd_output);
		return -1;
	}

	return 0;
}

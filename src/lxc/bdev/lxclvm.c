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
#include <unistd.h>
#include <sys/wait.h>

#include "bdev.h"
#include "log.h"
#include "lxclvm.h"
#include "utils.h"

lxc_log_define(lxclvm, lxc);

extern char *dir_new_path(char *src, const char *oldname, const char *name,
		const char *oldpath, const char *lxcpath);

    /*
     * LVM ops
     */

    /*
     * path must be '/dev/$vg/$lv', $vg must be an existing VG, and $lv must not
     * yet exist.  This function will attempt to create /dev/$vg/$lv of size
     * $size. If thinpool is specified, we'll check for it's existence and if
     * it's
     * a valid thin pool, and if so, we'll create the requested lv from that
     * thin
     * pool.
     */
    static int do_lvm_create(const char *path, uint64_t size,
			     const char *thinpool)
{
	int ret, pid, len;
	char sz[24], *pathdup, *vg, *lv, *tp = NULL;

	if ((pid = fork()) < 0) {
		SYSERROR("failed fork");
		return -1;
	}
	if (pid > 0)
		return wait_for_pid(pid);

	// specify bytes to lvcreate
	ret = snprintf(sz, 24, "%"PRIu64"b", size);
	if (ret < 0 || ret >= 24)
		exit(EXIT_FAILURE);

	pathdup = strdup(path);
	if (!pathdup)
		exit(EXIT_FAILURE);

	lv = strrchr(pathdup, '/');
	if (!lv)
		exit(EXIT_FAILURE);

	*lv = '\0';
	lv++;

	vg = strrchr(pathdup, '/');
	if (!vg)
		exit(EXIT_FAILURE);
	vg++;

	if (thinpool) {
		len = strlen(pathdup) + strlen(thinpool) + 2;
		tp = alloca(len);

		ret = snprintf(tp, len, "%s/%s", pathdup, thinpool);
		if (ret < 0 || ret >= len)
			exit(EXIT_FAILURE);

		ret = lvm_is_thin_pool(tp);
		INFO("got %d for thin pool at path: %s", ret, tp);
		if (ret < 0)
			exit(EXIT_FAILURE);

		if (!ret)
			tp = NULL;
	}

	if (!tp)
	    execlp("lvcreate", "lvcreate", "-L", sz, vg, "-n", lv, (char *)NULL);
	else
	    execlp("lvcreate", "lvcreate", "--thinpool", tp, "-V", sz, vg, "-n", lv, (char *)NULL);

	SYSERROR("execlp");
	exit(EXIT_FAILURE);
}


/*
 * Look at /sys/dev/block/maj:min/dm/uuid.  If it contains the hardcoded LVM
 * prefix "LVM-", then this is an lvm2 LV
 */
int lvm_detect(const char *path)
{
	char devp[MAXPATHLEN], buf[4];
	FILE *fout;
	int ret;
	struct stat statbuf;

	if (strncmp(path, "lvm:", 4) == 0)
		return 1; // take their word for it

	ret = stat(path, &statbuf);
	if (ret != 0)
		return 0;
	if (!S_ISBLK(statbuf.st_mode))
		return 0;

	ret = snprintf(devp, MAXPATHLEN, "/sys/dev/block/%d:%d/dm/uuid",
			major(statbuf.st_rdev), minor(statbuf.st_rdev));
	if (ret < 0 || ret >= MAXPATHLEN) {
		ERROR("lvm uuid pathname too long");
		return 0;
	}
	fout = fopen(devp, "r");
	if (!fout)
		return 0;
	ret = fread(buf, 1, 4, fout);
	fclose(fout);
	if (ret != 4 || strncmp(buf, "LVM-", 4) != 0)
		return 0;
	return 1;
}

int lvm_mount(struct bdev *bdev)
{
	if (strcmp(bdev->type, "lvm"))
		return -22;
	if (!bdev->src || !bdev->dest)
		return -22;
	/* if we might pass in data sometime, then we'll have to enrich
	 * mount_unknown_fs */
	return mount_unknown_fs(bdev->src, bdev->dest, bdev->mntopts);
}

int lvm_umount(struct bdev *bdev)
{
	if (strcmp(bdev->type, "lvm"))
		return -22;
	if (!bdev->src || !bdev->dest)
		return -22;
	return umount(bdev->dest);
}

int lvm_compare_lv_attr(const char *path, int pos, const char expected)
{
	struct lxc_popen_FILE *f;
	int ret, len, status, start=0;
	char *cmd, output[12];
	const char *lvscmd = "lvs --unbuffered --noheadings -o lv_attr %s 2>/dev/null";

	len = strlen(lvscmd) + strlen(path) - 1;
	cmd = alloca(len);

	ret = snprintf(cmd, len, lvscmd, path);
	if (ret < 0 || ret >= len)
		return -1;

	f = lxc_popen(cmd);

	if (f == NULL) {
		SYSERROR("popen failed");
		return -1;
	}

	ret = fgets(output, 12, f->f) == NULL;

	status = lxc_pclose(f);

	if (ret || WEXITSTATUS(status))
		// Assume either vg or lvs do not exist, default
		// comparison to false.
		return 0;

	len = strlen(output);
	while(start < len && output[start] == ' ') start++;

	if (start + pos < len && output[start + pos] == expected)
		return 1;

	return 0;
}

int lvm_is_thin_volume(const char *path)
{
	return lvm_compare_lv_attr(path, 6, 't');
}

int lvm_is_thin_pool(const char *path)
{
	return lvm_compare_lv_attr(path, 0, 't');
}

int lvm_snapshot(const char *orig, const char *path, uint64_t size)
{
	int ret, pid;
	char sz[24], *pathdup, *lv;

	if ((pid = fork()) < 0) {
		SYSERROR("failed fork");
		return -1;
	}
	if (pid > 0)
		return wait_for_pid(pid);

	// specify bytes to lvcreate
	ret = snprintf(sz, 24, "%"PRIu64"b", size);
	if (ret < 0 || ret >= 24)
		exit(EXIT_FAILURE);

	pathdup = strdup(path);
	if (!pathdup)
		exit(EXIT_FAILURE);
	lv = strrchr(pathdup, '/');
	if (!lv) {
		free(pathdup);
		exit(EXIT_FAILURE);
	}
	*lv = '\0';
	lv++;

	// check if the original lv is backed by a thin pool, in which case we
	// cannot specify a size that's different from the original size.
	ret = lvm_is_thin_volume(orig);
	if (ret == -1) {
		free(pathdup);
		return -1;
	}

	if (!ret) {
		ret = execlp("lvcreate", "lvcreate", "-s", "-L", sz, "-n", lv, orig, (char *)NULL);
	} else {
		ret = execlp("lvcreate", "lvcreate", "-s", "-n", lv, orig, (char *)NULL);
	}

	free(pathdup);
	exit(EXIT_FAILURE);
}

int lvm_clonepaths(struct bdev *orig, struct bdev *new, const char *oldname,
		const char *cname, const char *oldpath, const char *lxcpath, int snap,
		uint64_t newsize, struct lxc_conf *conf)
{
	char fstype[100];
	uint64_t size = newsize;
	int len, ret;

	if (!orig->src || !orig->dest)
		return -1;

	if (strcmp(orig->type, "lvm")) {
		const char *vg;

		if (snap) {
			ERROR("LVM snapshot from %s backing store is not supported",
				orig->type);
			return -1;
		}
		vg = lxc_global_config_value("lxc.bdev.lvm.vg");
		len = strlen("/dev/") + strlen(vg) + strlen(cname) + 2;
		if ((new->src = malloc(len)) == NULL)
			return -1;
		ret = snprintf(new->src, len, "/dev/%s/%s", vg, cname);
		if (ret < 0 || ret >= len)
			return -1;
	} else {
		new->src = dir_new_path(orig->src, oldname, cname, oldpath, lxcpath);
		if (!new->src)
			return -1;
	}

	if (orig->mntopts) {
		new->mntopts = strdup(orig->mntopts);
		if (!new->mntopts)
			return -1;
	}

	len = strlen(lxcpath) + strlen(cname) + strlen("rootfs") + 3;
	new->dest = malloc(len);
	if (!new->dest)
		return -1;
	ret = snprintf(new->dest, len, "%s/%s/rootfs", lxcpath, cname);
	if (ret < 0 || ret >= len)
		return -1;
	if (mkdir_p(new->dest, 0755) < 0)
		return -1;

	if (is_blktype(orig)) {
		if (!newsize && blk_getsize(orig, &size) < 0) {
			ERROR("Error getting size of %s", orig->src);
			return -1;
		}
		if (detect_fs(orig, fstype, 100) < 0) {
			INFO("could not find fstype for %s, using ext3", orig->src);
			return -1;
		}
	} else {
		sprintf(fstype, "ext3");
		if (!newsize)
			size = DEFAULT_FS_SIZE;
	}

	if (snap) {
		if (lvm_snapshot(orig->src, new->src, size) < 0) {
			ERROR("could not create %s snapshot of %s", new->src, orig->src);
			return -1;
		}
	} else {
		if (do_lvm_create(new->src, size, lxc_global_config_value("lxc.bdev.lvm.thin_pool")) < 0) {
			ERROR("Error creating new lvm blockdev");
			return -1;
		}
		if (do_mkfs(new->src, fstype) < 0) {
			ERROR("Error creating filesystem type %s on %s", fstype,
				new->src);
			return -1;
		}
	}

	return 0;
}

int lvm_destroy(struct bdev *orig)
{
	pid_t pid;

	if ((pid = fork()) < 0)
		return -1;
	if (!pid) {
		execlp("lvremove", "lvremove", "-f", orig->src, (char *)NULL);
		exit(EXIT_FAILURE);
	}
	return wait_for_pid(pid);
}

int lvm_create(struct bdev *bdev, const char *dest, const char *n,
		struct bdev_specs *specs)
{
	const char *vg, *thinpool, *fstype, *lv = n;
	uint64_t sz;
	int ret, len;

	if (!specs)
		return -1;

	vg = specs->lvm.vg;
	if (!vg)
		vg = lxc_global_config_value("lxc.bdev.lvm.vg");

	thinpool = specs->lvm.thinpool;
	if (!thinpool)
		thinpool = lxc_global_config_value("lxc.bdev.lvm.thin_pool");

	/* /dev/$vg/$lv */
	if (specs->lvm.lv)
		lv = specs->lvm.lv;

	len = strlen(vg) + strlen(lv) + 7;
	bdev->src = malloc(len);
	if (!bdev->src)
		return -1;

	ret = snprintf(bdev->src, len, "/dev/%s/%s", vg, lv);
	if (ret < 0 || ret >= len)
		return -1;

	// fssize is in bytes.
	sz = specs->fssize;
	if (!sz)
		sz = DEFAULT_FS_SIZE;

	if (do_lvm_create(bdev->src, sz, thinpool) < 0) {
		ERROR("Error creating new lvm blockdev %s size %"PRIu64" bytes", bdev->src, sz);
		return -1;
	}

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

	if (mkdir_p(bdev->dest, 0755) < 0) {
		ERROR("Error creating %s", bdev->dest);
		return -1;
	}

	return 0;
}

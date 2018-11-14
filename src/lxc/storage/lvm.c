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
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <unistd.h>

#include "config.h"
#include "log.h"
#include "lvm.h"
#include "rsync.h"
#include "storage.h"
#include "storage_utils.h"
#include "utils.h"

#ifdef MAJOR_IN_MKDEV
#include <sys/mkdev.h>
#endif

lxc_log_define(lvm, lxc);

struct lvcreate_args {
	const char *size;
	const char *vg;
	const char *lv;
	const char *thinpool;
	const char *fstype;

	/* snapshot specific arguments */
	const char *source_lv;
};

static int lvm_destroy_exec_wrapper(void *data)
{
	struct lvcreate_args *args = data;

	(void)setenv("LVM_SUPPRESS_FD_WARNINGS", "1", 1);
	execlp("lvremove", "lvremove", "-f", args->lv, (char *)NULL);

	return -1;
}

static int lvm_create_exec_wrapper(void *data)
{
	struct lvcreate_args *args = data;

	(void)setenv("LVM_SUPPRESS_FD_WARNINGS", "1", 1);
	if (args->thinpool)
		execlp("lvcreate", "lvcreate", "-qq", "--thinpool", args->thinpool,
		       "-V", args->size, args->vg, "-n", args->lv,
		       (char *)NULL);
	else
		execlp("lvcreate", "lvcreate", "-qq", "-L", args->size, args->vg, "-n",
		       args->lv, (char *)NULL);

	return -1;
}

static int lvm_snapshot_exec_wrapper(void *data)
{
	struct lvcreate_args *args = data;

	(void)setenv("LVM_SUPPRESS_FD_WARNINGS", "1", 1);
	if (args->thinpool)
		execlp("lvcreate", "lvcreate", "-s", "-n", args->lv,
		       args->source_lv, (char *)NULL);
	else
		execlp("lvcreate", "lvcreate", "-s", "-L", args->size, "-n",
		       args->lv, args->source_lv, (char *)NULL);

	return -1;
}

/* The path must be "/dev/<vg>/<lv>". The volume group <vg> must be an existing
 * volume group, and the logical volume <lv> must not yet exist.
 * This function will attempt to create "/dev/<vg>/<lv> of size <size>. If
 * thinpool is specified, we'll check for it's existence and if it's a valid
 * thin pool, and if so, we'll create the requested logical volume from that
 * thin pool.
 */
static int do_lvm_create(const char *path, uint64_t size, const char *thinpool)
{
	int len, ret;
	char *pathdup, *vg, *lv;
	char cmd_output[PATH_MAX];
	char sz[24];
	char *tp = NULL;
	struct lvcreate_args cmd_args = {0};

	ret = snprintf(sz, 24, "%" PRIu64 "b", size);
	if (ret < 0 || ret >= 24) {
		ERROR("Failed to create string: %d", ret);
		return -1;
	}

	pathdup = strdup(path);
	if (!pathdup) {
		ERROR("Failed to duplicate string \"%s\"", path);
		return -1;
	}

	lv = strrchr(pathdup, '/');
	if (!lv) {
		ERROR("Failed to detect \"/\" in string \"%s\"", pathdup);
		free(pathdup);
		return -1;
	}
	*lv = '\0';
	lv++;
	TRACE("Parsed logical volume \"%s\"", lv);

	vg = strrchr(pathdup, '/');
	if (!vg) {
		ERROR("Failed to detect \"/\" in string \"%s\"", pathdup);
		free(pathdup);
		return -1;
	}
	vg++;
	TRACE("Parsed volume group \"%s\"", vg);

	if (thinpool) {
		len = strlen(pathdup) + strlen(thinpool) + 2;
		tp = alloca(len);

		ret = snprintf(tp, len, "%s/%s", pathdup, thinpool);
		if (ret < 0 || ret >= len) {
			ERROR("Failed to create string: %d", ret);
			free(pathdup);
			return -1;
		}

		ret = lvm_is_thin_pool(tp);
		TRACE("got %d for thin pool at path: %s", ret, tp);
		if (ret < 0) {
			ERROR("Failed to detect whether \"%s\" is a thinpool", tp);
			free(pathdup);
			return -1;
		} else if (!ret) {
			TRACE("Detected that \"%s\" is not a thinpool", tp);
			tp = NULL;
		} else {
			TRACE("Detected \"%s\" is a thinpool", tp);
		}
	}

	cmd_args.thinpool = tp;
	cmd_args.vg = vg;
	cmd_args.lv = lv;
	cmd_args.size = sz;
	TRACE("Creating new lvm storage volume \"%s\" on volume group \"%s\" "
	      "of size \"%s\"", lv, vg, sz);
	ret = run_command(cmd_output, sizeof(cmd_output),
			  lvm_create_exec_wrapper, (void *)&cmd_args);
	if (ret < 0) {
		ERROR("Failed to create logical volume \"%s\": %s", lv,
		      cmd_output);
		free(pathdup);
		return -1;
	}
	TRACE("Created new lvm storage volume \"%s\" on volume group \"%s\" "
	      "of size \"%s\"", lv, vg, sz);

	free(pathdup);
	return ret;
}

/* Look at "/sys/dev/block/maj:min/dm/uuid". If it contains the hardcoded LVM
 * prefix "LVM-" then this is an lvm2 LV.
 */
bool lvm_detect(const char *path)
{
	int fd;
	ssize_t ret;
	struct stat statbuf;
	char devp[PATH_MAX], buf[4];

	if (!strncmp(path, "lvm:", 4))
		return true;

	ret = stat(path, &statbuf);
	if (ret < 0)
		return false;

	if (!S_ISBLK(statbuf.st_mode))
		return false;

	ret = snprintf(devp, PATH_MAX, "/sys/dev/block/%d:%d/dm/uuid",
		       major(statbuf.st_rdev), minor(statbuf.st_rdev));
	if (ret < 0 || ret >= PATH_MAX) {
		ERROR("Failed to create string");
		return false;
	}

	fd = open(devp, O_RDONLY);
	if (fd < 0)
		return false;

	ret = read(fd, buf, sizeof(buf));
	close(fd);
	if (ret != sizeof(buf))
		return false;

	if (strncmp(buf, "LVM-", 4))
		return false;

	return true;
}

int lvm_mount(struct lxc_storage *bdev)
{
	const char *src;

	if (strcmp(bdev->type, "lvm"))
		return -22;

	if (!bdev->src || !bdev->dest)
		return -22;

	src = lxc_storage_get_path(bdev->src, bdev->type);

	/* If we might pass in data sometime, then we'll have to enrich
	 * mount_unknown_fs().
	 */
	return mount_unknown_fs(src, bdev->dest, bdev->mntopts);
}

int lvm_umount(struct lxc_storage *bdev)
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
	int ret, status;
	size_t len;
	char *cmd;
	char output[12];
	int start = 0;
	const char *lvscmd = "lvs --unbuffered --noheadings -o lv_attr %s 2>/dev/null";

	len = strlen(lvscmd) + strlen(path) + 1;
	cmd = alloca(len);

	ret = snprintf(cmd, len, lvscmd, path);
	if (ret < 0 || (size_t)ret >= len)
		return -1;

	f = lxc_popen(cmd);
	if (!f) {
		SYSERROR("popen failed");
		return -1;
	}

	ret = 0;
	if (!fgets(output, 12, f->f))
		ret = 1;

	status = lxc_pclose(f);
	/* Assume either vg or lvs do not exist, default comparison to false. */
	if (ret || WEXITSTATUS(status))
		return 0;

	len = strlen(output);
	while (start < len && output[start] == ' ')
		start++;

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

static int lvm_snapshot_create_new_uuid_wrapper(void *data)
{
	struct lvcreate_args *args = data;

	if (strcmp(args->fstype, "xfs") == 0)
		execlp("xfs_admin", "xfs_admin", "-U", "generate", args->lv, (char *)NULL);

	if (strcmp(args->fstype, "btrfs") == 0)
		execlp("btrfstune", "btrfstune", "-f", "-u", args->lv, (char *)NULL);

	return 0;
}

static int lvm_snapshot(struct lxc_storage *orig, const char *path, uint64_t size)
{
	int ret;
	char *lv, *pathdup;
	char sz[24];
	char fstype[100];
	char cmd_output[PATH_MAX];
	char repairchar;
	const char *origsrc;
	struct lvcreate_args cmd_args = {0};

	ret = snprintf(sz, 24, "%" PRIu64 "b", size);
	if (ret < 0 || ret >= 24) {
		ERROR("Failed to create string");
		return -1;
	}

	pathdup = strdup(path);
	if (!pathdup) {
		ERROR("Failed to duplicate string \"%s\"", path);
		return -1;
	}

	lv = strrchr(pathdup, '/');
	if (!lv) {
		ERROR("Failed to detect \"/\" in string \"%s\"", pathdup);
		free(pathdup);
		return -1;
	}
	repairchar = *lv;
	*lv = '\0';
	lv++;
	TRACE("Parsed logical volume \"%s\"", lv);

	/* Check if the original logical volume is backed by a thinpool, in
	 * which case we cannot specify a size that's different from the
	 * original size.
	 */
	origsrc = lxc_storage_get_path(orig->src, "lvm");
	ret = lvm_is_thin_volume(origsrc);
	if (ret < 0) {
		free(pathdup);
		return -1;
	} else if (ret) {
		cmd_args.thinpool = origsrc;
	}

	cmd_args.lv = lv;
	cmd_args.source_lv = origsrc;
	cmd_args.size = sz;
	TRACE("Creating new lvm snapshot \"%s\" of \"%s\" with size \"%s\"", lv,
	      origsrc, sz);
	ret = run_command(cmd_output, sizeof(cmd_output),
			  lvm_snapshot_exec_wrapper, (void *)&cmd_args);
	if (ret < 0) {
		ERROR("Failed to create logical volume \"%s\": %s", lv, cmd_output);
		free(pathdup);
		return -1;
	}

	if (detect_fs(orig, fstype, 100) < 0) {
		INFO("Failed to detect filesystem type for \"%s\"", origsrc);
		free(pathdup);
		return -1;
	}

	/* repair path */
	lv--;
	*lv = repairchar;
	cmd_args.lv = pathdup;
	cmd_args.fstype = fstype;
	ret = run_command(cmd_output, sizeof(cmd_output),
			  lvm_snapshot_create_new_uuid_wrapper, (void *)&cmd_args);
	if (ret < 0) {
		ERROR("Failed to create new uuid for volume \"%s\": %s", pathdup, cmd_output);
		free(pathdup);
		return -1;
	}

	free(pathdup);
	return 0;
}

int lvm_clonepaths(struct lxc_storage *orig, struct lxc_storage *new,
		   const char *oldname, const char *cname, const char *oldpath,
		   const char *lxcpath, int snap, uint64_t newsize,
		   struct lxc_conf *conf)
{
	int len, ret;
	const char *vg;

	if (!orig->src || !orig->dest)
		return -1;

	if (strcmp(orig->type, "lvm") && snap) {
		ERROR("LVM snapshot from \"%s\" storage driver is not supported",
		      orig->type);
		return -1;
	}

	if (strcmp(orig->type, "lvm")) {
		vg = lxc_global_config_value("lxc.bdev.lvm.vg");
		new->src = lxc_string_join(
		    "/",
		    (const char *[]){"lvm:", "dev", vg, cname, NULL},
		    false);
	} else {
		const char *src;
		char *dup, *slider;

		src = lxc_storage_get_path(orig->src, orig->type);

		dup = strdup(src);
		if (!dup) {
			ERROR("Failed to duplicate string \"%s\"", src);
			return -1;
		}

		slider = strrchr(dup, '/');
		if (!slider) {
			ERROR("Failed to detect \"/\" in string \"%s\"", dup);
			free(dup);
			return -1;
		}
		*slider = '\0';
		slider = dup;

		new->src = lxc_string_join(
		    "/",
		    (const char *[]){"lvm:", *slider == '/' ? ++slider : slider,
				     cname, NULL},
		    false);
		free(dup);
	}
	if (!new->src) {
		ERROR("Failed to create string");
		return -1;
	}

	if (orig->mntopts) {
		new->mntopts = strdup(orig->mntopts);
		if (!new->mntopts) {
			ERROR("Failed to duplicate string \"%s\"", orig->mntopts);
			return -1;
		}
	}

	len = strlen(lxcpath) + strlen(cname) + strlen("rootfs") + 3;
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

	ret = mkdir_p(new->dest, 0755);
	if (ret < 0) {
		SYSERROR("Failed to create directory \"%s\"", new->dest);
		return -1;
	}

	return 0;
}

bool lvm_create_clone(struct lxc_conf *conf, struct lxc_storage *orig,
		      struct lxc_storage *new, uint64_t newsize)
{
	int ret;
	const char *src;
	const char *thinpool;
	struct rsync_data data;
	const char *cmd_args[2];
	char cmd_output[PATH_MAX] = {0};
	char fstype[100] = "ext4";
	uint64_t size = newsize;

	if (is_blktype(orig)) {
		/* detect size */
		if (!newsize && blk_getsize(orig, &size) < 0) {
			ERROR("Failed to detect size of logical volume \"%s\"",
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

	src = lxc_storage_get_path(new->src, "lvm");
	thinpool = lxc_global_config_value("lxc.bdev.lvm.thin_pool");

	ret = do_lvm_create(src, size, thinpool);
	if (ret < 0) {
		ERROR("Failed to create lvm storage volume \"%s\"", src);
		return -1;
	}

	cmd_args[0] = fstype;
	cmd_args[1] = src;
	ret = run_command(cmd_output, sizeof(cmd_output),
			do_mkfs_exec_wrapper, (void *)cmd_args);
	if (ret < 0) {
		ERROR("Failed to create new filesystem \"%s\" for lvm storage "
		      "volume \"%s\": %s", fstype, src, cmd_output);
		return -1;
	}

	data.orig = orig;
	data.new = new;
	ret = run_command(cmd_output, sizeof(cmd_output),
			  lxc_storage_rsync_exec_wrapper, (void *)&data);
	if (ret < 0) {
		ERROR("Failed to rsync from \"%s\" to \"%s\"", orig->dest,
		      new->dest);
		return false;
	}

	TRACE("Created lvm storage volume \"%s\"", new->dest);
	return true;
}

bool lvm_create_snapshot(struct lxc_conf *conf, struct lxc_storage *orig,
			 struct lxc_storage *new, uint64_t newsize)
{
	int ret;
	const char *newsrc;
	uint64_t size = newsize;

	if (is_blktype(orig)) {
		if (!newsize && blk_getsize(orig, &size) < 0) {
			ERROR("Failed to detect size of logical volume \"%s\"",
			      orig->src);
			return -1;
		}
	} else if (!newsize) {
			size = DEFAULT_FS_SIZE;
	}

	newsrc = lxc_storage_get_path(new->src, "lvm");

	ret = lvm_snapshot(orig, newsrc, size);
	if (ret < 0) {
		ERROR("Failed to create lvm \"%s\" snapshot of \"%s\"",
		      new->src, orig->src);
		return false;
	}

	TRACE("Created lvm snapshot \"%s\" from \"%s\"", new->dest, orig->dest);
	return true;
}

int lvm_destroy(struct lxc_storage *orig)
{
	int ret;
	char cmd_output[PATH_MAX];
	struct lvcreate_args cmd_args = {0};

	cmd_args.lv = lxc_storage_get_path(orig->src, "lvm");
	ret = run_command(cmd_output, sizeof(cmd_output),
			  lvm_destroy_exec_wrapper, (void *)&cmd_args);
	if (ret < 0) {
		ERROR("Failed to destroy logical volume \"%s\": %s", orig->src,
		      cmd_output);
		return -1;
	}

	TRACE("Destroyed logical volume \"%s\"", orig->src);
	return 0;
}

int lvm_create(struct lxc_storage *bdev, const char *dest, const char *n,
	       struct bdev_specs *specs)
{
	const char *vg, *thinpool, *fstype, *lv = n;
	uint64_t sz;
	int ret, len;
	const char *cmd_args[2];
	char cmd_output[PATH_MAX];

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

	len = strlen(vg) + strlen(lv) + 4 + 7;
	bdev->src = malloc(len);
	if (!bdev->src) {
		ERROR("Failed to allocate memory");
		return -1;
	}

	ret = snprintf(bdev->src, len, "lvm:/dev/%s/%s", vg, lv);
	if (ret < 0 || ret >= len) {
		ERROR("Failed to create string");
		return -1;
	}

	/* size is in bytes */
	sz = specs->fssize;
	if (!sz)
		sz = DEFAULT_FS_SIZE;

	ret = do_lvm_create(bdev->src + 4, sz, thinpool);
	if (ret < 0) {
		ERROR("Error creating new logical volume \"%s\" of size "
		      "\"%" PRIu64 " bytes\"", bdev->src, sz);
		return -1;
	}

	fstype = specs->fstype;
	if (!fstype)
		fstype = DEFAULT_FSTYPE;

	cmd_args[0] = fstype;
	cmd_args[1] = lxc_storage_get_path(bdev->src, bdev->type);
	ret = run_command(cmd_output, sizeof(cmd_output), do_mkfs_exec_wrapper,
			  (void *)cmd_args);
	if (ret < 0) {
		ERROR("Failed to create new logical volume \"%s\": %s",
		      bdev->src, cmd_output);
		return -1;
	}

	bdev->dest = strdup(dest);
	if (!bdev->dest) {
		ERROR("Failed to duplicate string \"%s\"", dest);
		return -1;
	}

	ret = mkdir_p(bdev->dest, 0755);
	if (ret < 0) {
		SYSERROR("Failed to create directory \"%s\"", bdev->dest);
		return -1;
	}

	TRACE("Created new logical volume \"%s\"", bdev->dest);
	return 0;
}

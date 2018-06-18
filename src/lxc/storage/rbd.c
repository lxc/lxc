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
#include <inttypes.h>	/* Required for PRIu64 to work. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "storage.h"
#include "storage_utils.h"
#include "utils.h"

#ifndef HAVE_STRLCPY
#include "include/strlcpy.h"
#endif

lxc_log_define(rbd, lxc);

struct rbd_args {
	const char *osd_pool_name;
	const char *rbd_name;
	const char *size;
};

int rbd_create_wrapper(void *data)
{
	struct rbd_args *args = data;

	execlp("rbd", "rbd", "create", "--pool", args->osd_pool_name,
	       args->rbd_name, "--size", args->size, (char *)NULL);

	return -1;
}

int rbd_map_wrapper(void *data)
{
	struct rbd_args *args = data;

	execlp("rbd", "rbd", "map", "--pool", args->osd_pool_name,
	       args->rbd_name, (char *)NULL);

	return -1;
}

int rbd_unmap_wrapper(void *data)
{
	struct rbd_args *args = data;

	execlp("rbd", "rbd", "unmap", args->rbd_name, (char *)NULL);

	return -1;
}

int rbd_delete_wrapper(void *data)
{
	struct rbd_args *args = data;

	execlp("rbd", "rbd", "rm", args->rbd_name, (char *)NULL);

	return -1;
}

int rbd_clonepaths(struct lxc_storage *orig, struct lxc_storage *new,
		   const char *oldname, const char *cname, const char *oldpath,
		   const char *lxcpath, int snap, uint64_t newsize,
		   struct lxc_conf *conf)
{
	ERROR("rbd clonepaths not implemented");
	return -1;
}

int rbd_create(struct lxc_storage *bdev, const char *dest, const char *n,
	       struct bdev_specs *specs)
{
	const char *rbdpool, *fstype;
	uint64_t size;
	int ret, len;
	char sz[24];
	const char *cmd_args[2];
	char cmd_output[MAXPATHLEN];
	const char *rbdname = n;
	struct rbd_args args = {0};

	if (!specs)
		return -1;

	rbdpool = specs->rbd.rbdpool;
	if (!rbdpool)
		rbdpool = lxc_global_config_value("lxc.bdev.rbd.rbdpool");

	if (specs->rbd.rbdname)
		rbdname = specs->rbd.rbdname;

	/* source device /dev/rbd/lxc/ctn */
	len = strlen(rbdpool) + strlen(rbdname) + 4 + 11;
	bdev->src = malloc(len);
	if (!bdev->src) {
		ERROR("Failed to allocate memory");
		return -1;
	}

	ret = snprintf(bdev->src, len, "rbd:/dev/rbd/%s/%s", rbdpool, rbdname);
	if (ret < 0 || ret >= len) {
		ERROR("Failed to create string");
		return -1;
	}

	/* fssize is in bytes */
	size = specs->fssize;
	if (!size)
		size = DEFAULT_FS_SIZE;

	/* in megabytes for rbd tool */
	ret = snprintf(sz, 24, "%" PRIu64, size / 1024 / 1024);
	if (ret < 0 || ret >= 24) {
		ERROR("Failed to create string");
		return -1;
	}

	args.osd_pool_name = rbdpool;
	args.rbd_name = rbdname;
	args.size = sz;
	ret = run_command(cmd_output, sizeof(cmd_output), rbd_create_wrapper,
			  (void *)&args);
	if (ret < 0) {
		ERROR("Failed to create rbd storage volume \"%s\": %s", rbdname,
		      cmd_output);
		return -1;
	}

	ret = run_command(cmd_output, sizeof(cmd_output), rbd_map_wrapper,
			  (void *)&args);
	if (ret < 0) {
		ERROR("Failed to map rbd storage volume \"%s\": %s", rbdname,
		      cmd_output);
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
		ERROR("Failed to map rbd storage volume \"%s\": %s", rbdname,
		      cmd_output);
		return -1;
	}

	bdev->dest = strdup(dest);
	if (!bdev->dest) {
		ERROR("Failed to duplicate string \"%s\"", dest);
		return -1;
	}

	ret = mkdir_p(bdev->dest, 0755);
	if (ret < 0 && errno != EEXIST) {
		ERROR("Failed to create directory \"%s\"", bdev->dest);
		return -1;
	}

	TRACE("Created rbd storage volume \"%s\"", bdev->dest);
	return 0;
}

int rbd_destroy(struct lxc_storage *orig)
{
	int ret;
	const char *src;
	char *rbdfullname;
	char cmd_output[MAXPATHLEN];
	struct rbd_args args = {0};
	size_t len;

	src = lxc_storage_get_path(orig->src, orig->type);
	if (file_exists(src)) {
		args.rbd_name = src;
		ret = run_command(cmd_output, sizeof(cmd_output),
				  rbd_unmap_wrapper, (void *)&args);
		if (ret < 0) {
			ERROR("Failed to map rbd storage volume \"%s\": %s",
			      src, cmd_output);
			return -1;
		}
	}

	len = strlen(src);
	rbdfullname = alloca(len - 8);
	(void)strlcpy(rbdfullname, &src[9], len - 8);
	args.rbd_name = rbdfullname;

	ret = run_command(cmd_output, sizeof(cmd_output),
			rbd_delete_wrapper, (void *)&args);
	if (ret < 0) {
		ERROR("Failed to delete rbd storage volume \"%s\": %s",
		      rbdfullname, cmd_output);
		return -1;
	}

	return 0;
}

bool rbd_detect(const char *path)
{
	if (!strncmp(path, "rbd:", 4))
		return true;

	if (!strncmp(path, "/dev/rbd/", 9))
		return true;

	return false;
}

int rbd_mount(struct lxc_storage *bdev)
{
	const char *src;

	if (strcmp(bdev->type, "rbd"))
		return -22;

	if (!bdev->src || !bdev->dest)
		return -22;

	src = lxc_storage_get_path(bdev->src, bdev->type);
	if (!file_exists(src)) {
		/* If blkdev does not exist it should be mapped, because it is
		 * not persistent on reboot.
		 */
		ERROR("Block device %s is not mapped.", bdev->src);
		return -1;
	}

	return mount_unknown_fs(src, bdev->dest, bdev->mntopts);
}

int rbd_umount(struct lxc_storage *bdev)
{
	if (strcmp(bdev->type, "rbd"))
		return -22;

	if (!bdev->src || !bdev->dest)
		return -22;

	return umount(bdev->dest);
}

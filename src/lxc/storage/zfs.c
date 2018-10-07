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
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <unistd.h>

#include "config.h"
#include "log.h"
#include "parse.h"
#include "rsync.h"
#include "storage.h"
#include "utils.h"
#include "zfs.h"

lxc_log_define(zfs, lxc);

struct zfs_args {
	const char *dataset;
	const char *snapshot;
	const char *options;
	void *argv;
};

int zfs_detect_exec_wrapper(void *data)
{
	struct zfs_args *args = data;

	execlp("zfs", "zfs", "get", "type", "-H", "-o", "name", args->dataset,
	       (char *)NULL);

	return -1;
}

int zfs_create_exec_wrapper(void *args)
{
	struct zfs_args *zfs_args = args;

	execvp("zfs", zfs_args->argv);

	return -1;
}

int zfs_delete_exec_wrapper(void *args)
{
	struct zfs_args *zfs_args = args;

	execlp("zfs", "zfs", "destroy", "-r", zfs_args->dataset, (char *)NULL);

	return -1;
}

int zfs_snapshot_exec_wrapper(void *args)
{
	struct zfs_args *zfs_args = args;

	execlp("zfs", "zfs", "snapshot", "-r", zfs_args->snapshot, (char *)NULL);

	return -1;
}

int zfs_clone_exec_wrapper(void *args)
{
	struct zfs_args *zfs_args = args;

	execlp("zfs", "zfs", "clone", "-p", "-o", "canmount=noauto", "-o",
	       zfs_args->options, zfs_args->snapshot, zfs_args->dataset,
	       (char *)NULL);

	return -1;
}

int zfs_get_parent_snapshot_exec_wrapper(void *args)
{
	struct zfs_args *zfs_args = args;

	execlp("zfs", "zfs", "get", "origin", "-o", "value", "-H",
	       zfs_args->dataset, (char *)NULL);

	return -1;
}

static bool zfs_list_entry(const char *path, char *output, size_t inlen)
{
	struct lxc_popen_FILE *f;
	bool found = false;

	f = lxc_popen("zfs list 2> /dev/null");
	if (f == NULL) {
		SYSERROR("popen failed");
		return false;
	}

	while (fgets(output, inlen, f->f)) {
		if (strstr(output, path)) {
			found = true;
			break;
		}
	}
	(void)lxc_pclose(f);

	return found;
}

bool zfs_detect(const char *path)
{
	int ret;
	char *dataset;
	struct zfs_args cmd_args = {0};
	char cmd_output[PATH_MAX] = {0};

	if (!strncmp(path, "zfs:", 4))
		return true;

	/* This is a legacy zfs setup where the rootfs path
	 * "<lxcpath>/<lxcname>/rootfs" is given.
	 */
	if (*path == '/') {
		bool found;
		char *output = malloc(LXC_LOG_BUFFER_SIZE);

		if (!output) {
			ERROR("out of memory");
			return false;
		}

		found = zfs_list_entry(path, output, LXC_LOG_BUFFER_SIZE);
		free(output);
		return found;
	}

	cmd_args.dataset = path;
	ret = run_command(cmd_output, sizeof(cmd_output),
			  zfs_detect_exec_wrapper, (void *)&cmd_args);
	if (ret < 0) {
		ERROR("Failed to detect zfs dataset \"%s\": %s", path, cmd_output);
		return false;
	}

	if (cmd_output[0] == '\0')
		return false;

	/* remove any possible leading and trailing whitespace */
	dataset = cmd_output;
	dataset += lxc_char_left_gc(dataset, strlen(dataset));
	dataset[lxc_char_right_gc(dataset, strlen(dataset))] = '\0';

	if (strcmp(dataset, path))
		return false;

	return true;
}

int zfs_mount(struct lxc_storage *bdev)
{
	int ret;
	size_t oldlen, newlen, totallen;
	char *mntdata, *tmp;
	const char *src;
	unsigned long mntflags;
	char cmd_output[PATH_MAX] = {0};

	if (strcmp(bdev->type, "zfs"))
		return -22;

	if (!bdev->src || !bdev->dest)
		return -22;

	ret = parse_mntopts(bdev->mntopts, &mntflags, &mntdata);
	if (ret < 0) {
		ERROR("Failed to parse mount options");
		free(mntdata);
		return -22;
	}

	/* This is a legacy zfs setup where the rootfs path
	 * "<lxcpath>/<lxcname>/rootfs" is given and we do a bind-mount.
	 */
	src = lxc_storage_get_path(bdev->src, bdev->type);
	if (*src == '/') {
		bool found;

		found = zfs_list_entry(src, cmd_output, sizeof(cmd_output));
		if (!found) {
			ERROR("Failed to find zfs entry \"%s\"", src);
			return -1;
		}

		tmp = strchr(cmd_output, ' ');
		if (!tmp) {
			ERROR("Failed to detect zfs dataset associated with "
			      "\"%s\"", src);
			return -1;
		}
		*tmp = '\0';
		src = cmd_output;
	}

	/* ','
	 * +
	 * strlen("zfsutil")
	 * +
	 * ','
	 * +
	 * strlen(mntpoint=)
	 * +
	 * strlen(src)
	 * +
	 * '\0'
	 */
	newlen = 1 + 7 + 1 + 9 + strlen(src) + 1;
	oldlen = mntdata ? strlen(mntdata) : 0;
	totallen = (newlen + oldlen);
	tmp = realloc(mntdata, totallen);
	if (!tmp) {
		ERROR("Failed to reallocate memory");
		free(mntdata);
		return -1;
	}
	mntdata = tmp;

	ret = snprintf((mntdata + oldlen), newlen, ",zfsutil,mntpoint=%s", src);
	if (ret < 0 || (size_t)ret >= newlen) {
		ERROR("Failed to create string");
		free(mntdata);
		return -1;
	}

	ret = mount(src, bdev->dest, "zfs", mntflags, mntdata);
	free(mntdata);
	if (ret < 0 && errno != EBUSY) {
		SYSERROR("Failed to mount \"%s\" on \"%s\"", src, bdev->dest);
		return -1;
	}

	TRACE("Mounted \"%s\" on \"%s\"", src, bdev->dest);
	return 0;
}

int zfs_umount(struct lxc_storage *bdev)
{
	int ret;

	if (strcmp(bdev->type, "zfs"))
		return -22;

	if (!bdev->src || !bdev->dest)
		return -22;

	ret = umount(bdev->dest);
	if (ret < 0)
		SYSERROR("Failed to unmount \"%s\"", bdev->dest);
	else
		TRACE("Unmounted \"%s\"", bdev->dest);

	return ret;
}

bool zfs_copy(struct lxc_conf *conf, struct lxc_storage *orig,
	      struct lxc_storage *new, uint64_t newsize)
{
	int ret;
	char cmd_output[PATH_MAX], option[PATH_MAX];
	struct rsync_data data = {0, 0};
	struct zfs_args cmd_args = {0};
	const char *argv[] = {"zfs",			   /* 0    */
			      "create",			   /* 1    */
			      "-o",     "",		   /* 2, 3 */
			      "-o",     "canmount=noauto", /* 4, 5 */
			      "-p",			   /* 6    */
			      "",			   /* 7    */
			      NULL};

	/* mountpoint */
	ret = snprintf(option, PATH_MAX, "mountpoint=%s", new->dest);
	if (ret < 0 || ret >= PATH_MAX) {
		ERROR("Failed to create string");
		return false;
	}
	argv[3] = option;
	argv[7] = lxc_storage_get_path(new->src, new->type);

	cmd_args.argv = argv;
	ret = run_command(cmd_output, sizeof(cmd_output),
			  zfs_create_exec_wrapper, (void *)&cmd_args);
	if (ret < 0) {
		ERROR("Failed to create zfs dataset \"%s\": %s", new->src, cmd_output);
		return false;
	} else if (cmd_output[0] != '\0') {
		INFO("Created zfs dataset \"%s\": %s", new->src, cmd_output);
	} else {
		TRACE("Created zfs dataset \"%s\"", new->src);
	}

	ret = mkdir_p(new->dest, 0755);
	if (ret < 0 && errno != EEXIST) {
		SYSERROR("Failed to create directory \"%s\"", new->dest);
		return false;
	}

	data.orig = orig;
	data.new = new;
	ret = run_command(cmd_output, sizeof(cmd_output),
			  lxc_storage_rsync_exec_wrapper, (void *)&data);
	if (ret < 0) {
		ERROR("Failed to rsync from \"%s\" into \"%s\": %s", orig->dest,
		      new->dest, cmd_output);
		return false;
	}
	TRACE("Rsynced from \"%s\" to \"%s\"", orig->dest, new->dest);

	return true;
}

/* create read-only snapshot and create a clone from it */
bool zfs_snapshot(struct lxc_conf *conf, struct lxc_storage *orig,
		  struct lxc_storage *new, uint64_t newsize)
{
	int ret;
	size_t snapshot_len, len;
	char *tmp, *snap_name, *snapshot;
	const char *orig_src;
	struct zfs_args cmd_args = {0};
	char cmd_output[PATH_MAX] = {0}, option[PATH_MAX];

	orig_src = lxc_storage_get_path(orig->src, orig->type);
	if (*orig_src == '/') {
		bool found;

		found = zfs_list_entry(orig_src, cmd_output, sizeof(cmd_output));
		if (!found) {
			ERROR("Failed to find zfs entry \"%s\"", orig_src);
			return false;
		}

		tmp = strchr(cmd_output, ' ');
		if (!tmp) {
			ERROR("Failed to detect zfs dataset associated with "
			      "\"%s\"", orig_src);
			return false;
		}
		*tmp = '\0';
		orig_src = cmd_output;
	}

	snapshot = strdup(orig_src);
	if (!snapshot) {
		ERROR("Failed to duplicate string \"%s\"", orig_src);
		return false;
	}

	snap_name = strrchr(new->src, '/');
	if (!snap_name) {
		ERROR("Failed to detect \"/\" in \"%s\"", new->src);
		free(snapshot);
		return false;
	}
	snap_name++;

	/* strlen(snapshot)
	 * +
	 * @
	 * +
	 * strlen(cname)
	 * +
	 * \0
	 */
	snapshot_len = strlen(snapshot);
	len = snapshot_len + 1 + strlen(snap_name) + 1;
	tmp = realloc(snapshot, len);
	if (!tmp) {
		ERROR("Failed to reallocate memory");
		free(snapshot);
		return false;
	}
	snapshot = tmp;

	len -= snapshot_len;
	ret = snprintf(snapshot + snapshot_len, len, "@%s", snap_name);
	if (ret < 0 || ret >= len) {
		ERROR("Failed to create string");
		free(snapshot);
		return false;
	}

	cmd_args.snapshot = snapshot;
	ret = run_command(cmd_output, sizeof(cmd_output),
			  zfs_snapshot_exec_wrapper, (void *)&cmd_args);
	if (ret < 0) {
		ERROR("Failed to create zfs snapshot \"%s\": %s", snapshot, cmd_output);
		free(snapshot);
		return false;
	} else if (cmd_output[0] != '\0') {
		INFO("Created zfs snapshot \"%s\": %s", snapshot, cmd_output);
	} else {
		TRACE("Created zfs snapshot \"%s\"", snapshot);
	}

	ret = snprintf(option, PATH_MAX, "mountpoint=%s", new->dest);
	if (ret < 0 || ret >= PATH_MAX) {
		ERROR("Failed to create string");
		free(snapshot);
		return -1;
	}

	cmd_args.dataset = lxc_storage_get_path(new->src, new->type);
	cmd_args.snapshot = snapshot;
	cmd_args.options = option;
	ret = run_command(cmd_output, sizeof(cmd_output),
			  zfs_clone_exec_wrapper, (void *)&cmd_args);
	if (ret < 0)
		ERROR("Failed to create zfs dataset \"%s\": %s", new->src, cmd_output);
	else if (cmd_output[0] != '\0')
		INFO("Created zfs dataset \"%s\": %s", new->src, cmd_output);
	else
		TRACE("Created zfs dataset \"%s\"", new->src);

	free(snapshot);
	return true;
}

int zfs_clonepaths(struct lxc_storage *orig, struct lxc_storage *new,
		   const char *oldname, const char *cname, const char *oldpath,
		   const char *lxcpath, int snap, uint64_t newsize,
		   struct lxc_conf *conf)
{
	int ret;
	char *dataset, *tmp;
	const char *orig_src;
	size_t dataset_len, len;
	char cmd_output[PATH_MAX] = {0};

	if (!orig->src || !orig->dest)
		return -1;

	if (snap && strcmp(orig->type, "zfs")) {
		ERROR("zfs snapshot from %s backing store is not supported",
		      orig->type);
		return -1;
	}

	orig_src = lxc_storage_get_path(orig->src, orig->type);
	if (!strcmp(orig->type, "zfs")) {
		size_t len;
		if (*orig_src == '/') {
			bool found;

			found = zfs_list_entry(orig_src, cmd_output,
					       sizeof(cmd_output));
			if (!found) {
				ERROR("Failed to find zfs entry \"%s\"", orig_src);
				return -1;
			}

			tmp = strchr(cmd_output, ' ');
			if (!tmp) {
				ERROR("Failed to detect zfs dataset associated "
				      "with \"%s\"", orig_src);
				return -1;
			}
			*tmp = '\0';
			orig_src = cmd_output;
		}

		tmp = strrchr(orig_src, '/');
		if (!tmp) {
			ERROR("Failed to detect \"/\" in \"%s\"", orig_src);
			return -1;
		}

		len = tmp - orig_src;
		dataset = strndup(orig_src, len);
		if (!dataset) {
			ERROR("Failed to duplicate string \"%zu\" "
					"bytes of string \"%s\"", len, orig_src);
			return -1;
		}
	} else {
		tmp = (char *)lxc_global_config_value("lxc.bdev.zfs.root");
		if (!tmp) {
			ERROR("The \"lxc.bdev.zfs.root\" property is not set");
			return -1;
		}

		dataset = strdup(tmp);
		if (!dataset) {
			ERROR("Failed to duplicate string \"%s\"", tmp);
			return -1;
		}
	}

	/* strlen("zfs:") = 4
	 * +
	 * strlen(dataset)
	 * +
	 * / = 1
	 * +
	 * strlen(cname)
	 * +
	 * \0
	 */
	dataset_len = strlen(dataset);
	len = 4 + dataset_len + 1 + strlen(cname) + 1;
	new->src = realloc(dataset, len);
	if (!new->src) {
		ERROR("Failed to reallocate memory");
		free(dataset);
		return -1;
	}
	memmove(new->src + 4, new->src, dataset_len);
	memmove(new->src, "zfs:", 4);

	len -= dataset_len - 4;
	ret = snprintf(new->src + dataset_len + 4, len, "/%s", cname);
	if (ret < 0 || ret >= len) {
		ERROR("Failed to create string");
		return -1;
	}

	/* strlen(lxcpath)
	 * +
	 * /
	 * +
	 * strlen(cname)
	 * +
	 * /
	 * +
	 * strlen("rootfs")
	 * +
	 * \0
	 */
	len = strlen(lxcpath) + 1 + strlen(cname) + 1 + strlen("rootfs") + 1;
	new->dest = malloc(len);
	if (!new->dest) {
		ERROR("Failed to allocate memory");
		return -1;
	}

	ret = snprintf(new->dest, len, "%s/%s/rootfs", lxcpath, cname);
	if (ret < 0 || ret >= len) {
		ERROR("Failed to create string \"%s/%s/rootfs\"", lxcpath, cname);
		return -1;
	}

	ret = mkdir_p(new->dest, 0755);
	if (ret < 0 && errno != EEXIST) {
		SYSERROR("Failed to create directory \"%s\"", new->dest);
		return -1;
	}

	return 0;
}

int zfs_destroy(struct lxc_storage *orig)
{
	int ret;
	char *dataset, *tmp;
	const char *src;
	bool found;
	char *parent_snapshot = NULL;
	struct zfs_args cmd_args = {0};
	char cmd_output[PATH_MAX] = {0};

	src = lxc_storage_get_path(orig->src, orig->type);

	/* This is a legacy zfs setup where the rootfs path
	 * "<lxcpath>/<lxcname>/rootfs" is given.
	 */
	if (*src == '/') {
		char *tmp;

		found = zfs_list_entry(src, cmd_output, sizeof(cmd_output));
		if (!found) {
			ERROR("Failed to find zfs entry \"%s\"", orig->src);
			return -1;
		}

		tmp = strchr(cmd_output, ' ');
		if (!tmp) {
			ERROR("Failed to detect zfs dataset associated with "
			      "\"%s\"", cmd_output);
			return -1;
		}
		*tmp = '\0';
		dataset = cmd_output;
	} else {
		cmd_args.dataset = src;
		ret = run_command(cmd_output, sizeof(cmd_output),
				  zfs_detect_exec_wrapper, (void *)&cmd_args);
		if (ret < 0) {
			ERROR("Failed to detect zfs dataset \"%s\": %s", src,
			      cmd_output);
			return -1;
		}

		if (cmd_output[0] == '\0') {
			ERROR("Failed to detect zfs dataset \"%s\"", src);
			return -1;
		}

		/* remove any possible leading and trailing whitespace */
		dataset = cmd_output;
		dataset += lxc_char_left_gc(dataset, strlen(dataset));
		dataset[lxc_char_right_gc(dataset, strlen(dataset))] = '\0';

		if (strcmp(dataset, src)) {
			ERROR("Detected dataset \"%s\" does not match expected "
			      "dataset \"%s\"", dataset, src);
			return -1;
		}
	}

	cmd_args.dataset = strdup(dataset);
	if (!cmd_args.dataset) {
		ERROR("Failed to duplicate string \"%s\"", dataset);
		return -1;
	}

	ret = run_command(cmd_output, sizeof(cmd_output),
			  zfs_get_parent_snapshot_exec_wrapper,
			  (void *)&cmd_args);
	if (ret < 0) {
		ERROR("Failed to retrieve parent snapshot of zfs dataset "
		      "\"%s\": %s", dataset, cmd_output);
		free((void *)cmd_args.dataset);
		return -1;
	} else {
		INFO("Retrieved parent snapshot of zfs dataset \"%s\": %s", src,
		     cmd_output);
	}

	/* remove any possible leading and trailing whitespace */
	tmp = cmd_output;
	tmp += lxc_char_left_gc(tmp, strlen(tmp));
	tmp[lxc_char_right_gc(tmp, strlen(tmp))] = '\0';

	/* check whether the dataset has a parent snapshot */
	if (*tmp != '-' && *(tmp + 1) != '\0') {
		parent_snapshot = strdup(tmp);
		if (!parent_snapshot) {
			ERROR("Failed to duplicate string \"%s\"", tmp);
			free((void *)cmd_args.dataset);
			return -1;
		}
	}

	/* delete dataset */
	ret = run_command(cmd_output, sizeof(cmd_output),
			  zfs_delete_exec_wrapper, (void *)&cmd_args);
	if (ret < 0) {
		ERROR("Failed to delete zfs dataset \"%s\": %s", dataset,
		      cmd_output);
		free((void *)cmd_args.dataset);
		free(parent_snapshot);
		return -1;
	} else if (cmd_output[0] != '\0') {
		INFO("Deleted zfs dataset \"%s\": %s", src, cmd_output);
	} else {
		INFO("Deleted zfs dataset \"%s\"", src);
	}

	free((void *)cmd_args.dataset);

	/* Not a clone so nothing more to do. */
	if (!parent_snapshot)
		return 0;

	/* delete parent snapshot */
	cmd_args.dataset = parent_snapshot;
	ret = run_command(cmd_output, sizeof(cmd_output),
			  zfs_delete_exec_wrapper, (void *)&cmd_args);
	if (ret < 0)
		ERROR("Failed to delete zfs snapshot \"%s\": %s", dataset, cmd_output);
	else if (cmd_output[0] != '\0')
		INFO("Deleted zfs snapshot \"%s\": %s", src, cmd_output);
	else
		INFO("Deleted zfs snapshot \"%s\"", src);

	free((void *)cmd_args.dataset);
	return ret;
}

int zfs_create(struct lxc_storage *bdev, const char *dest, const char *n,
	       struct bdev_specs *specs)
{
	const char *zfsroot;
	int ret;
	size_t len;
	struct zfs_args cmd_args = {0};
	char cmd_output[PATH_MAX], option[PATH_MAX];
	const char *argv[] = {"zfs",			   /* 0    */
			      "create",			   /* 1    */
			      "-o",     "",		   /* 2, 3 */
			      "-o",     "canmount=noauto", /* 4, 5 */
			      "-p",			   /* 6    */
			      "",			   /* 7    */
			      NULL};

	if (!specs || !specs->zfs.zfsroot)
		zfsroot = lxc_global_config_value("lxc.bdev.zfs.root");
	else
		zfsroot = specs->zfs.zfsroot;

	bdev->dest = strdup(dest);
	if (!bdev->dest) {
		ERROR("Failed to duplicate string \"%s\"", dest);
		return -1;
	}

	len = strlen(zfsroot) + 1 + strlen(n) + 1;
	/* strlen("zfs:") */
	len += 4;
	bdev->src = malloc(len);
	if (!bdev->src) {
		ERROR("Failed to allocate memory");
		return -1;
	}

	ret = snprintf(bdev->src, len, "zfs:%s/%s", zfsroot, n);
	if (ret < 0 || ret >= len) {
		ERROR("Failed to create string");
		return -1;
	}
	argv[7] = lxc_storage_get_path(bdev->src, bdev->type);

	ret = snprintf(option, PATH_MAX, "mountpoint=%s", bdev->dest);
	if (ret < 0 || ret >= PATH_MAX) {
		ERROR("Failed to create string");
		return -1;
	}
	argv[3] = option;

	cmd_args.argv = argv;
	ret = run_command(cmd_output, sizeof(cmd_output),
			  zfs_create_exec_wrapper, (void *)&cmd_args);
	if (ret < 0) {
		ERROR("Failed to create zfs dataset \"%s\": %s", bdev->src, cmd_output);
		return -1;
	} else if (cmd_output[0] != '\0') {
		INFO("Created zfs dataset \"%s\": %s", bdev->src, cmd_output);
	} else {
		TRACE("Created zfs dataset \"%s\"", bdev->src);
	}

	ret = mkdir_p(bdev->dest, 0755);
	if (ret < 0 && errno != EEXIST) {
		SYSERROR("Failed to create directory \"%s\"", bdev->dest);
		return -1;
	}

	return ret;
}

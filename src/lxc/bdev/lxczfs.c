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
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>

#include "bdev.h"
#include "config.h"
#include "log.h"
#include "lxczfs.h"
#include "utils.h"

lxc_log_define(lxczfs, lxc);

/*
 * zfs ops:
 * There are two ways we could do this. We could always specify the 'zfs device'
 * (i.e. tank/lxc lxc/container) as rootfs. But instead (at least right now) we
 * have lxc-create specify $lxcpath/$lxcname/rootfs as the mountpoint, so that
 * it is always mounted. That means 'mount' is really never needed and could be
 * noop, but for the sake of flexibility let's always bind-mount.
 */

int zfs_list_entry(const char *path, char *output, size_t inlen)
{
	struct lxc_popen_FILE *f;
	int found=0;

	f = lxc_popen("zfs list 2> /dev/null");
	if (f == NULL) {
		SYSERROR("popen failed");
		return 0;
	}

	while (fgets(output, inlen, f->f)) {
		if (strstr(output, path)) {
			found = 1;
			break;
		}
	}
	(void) lxc_pclose(f);

	return found;
}

int zfs_detect(const char *path)
{
	char *output = malloc(LXC_LOG_BUFFER_SIZE);

	if (!output) {
		ERROR("out of memory");
		return 0;
	}

	int found = zfs_list_entry(path, output, LXC_LOG_BUFFER_SIZE);
	free(output);

	return found;
}

int zfs_mount(struct bdev *bdev)
{
	if (strcmp(bdev->type, "zfs"))
		return -22;

	if (!bdev->src || !bdev->dest)
		return -22;

	char *mntdata;
	unsigned long mntflags;
	if (parse_mntopts(bdev->mntopts, &mntflags, &mntdata) < 0) {
		free(mntdata);
		return -22;
	}

	int ret = mount(bdev->src, bdev->dest, "bind", MS_BIND | MS_REC | mntflags, mntdata);
	free(mntdata);

	return ret;
}

int zfs_umount(struct bdev *bdev)
{
	if (strcmp(bdev->type, "zfs"))
		return -22;

	if (!bdev->src || !bdev->dest)
		return -22;

	return umount(bdev->dest);
}

int zfs_clone(const char *opath, const char *npath, const char *oname,
		const char *nname, const char *lxcpath, int snapshot)
{
	// use the 'zfs list | grep opath' entry to get the zfsroot
	char output[MAXPATHLEN], option[MAXPATHLEN];
	char *p;
	const char *zfsroot = output;
	int ret;
	pid_t pid;

	if (zfs_list_entry(opath, output, MAXPATHLEN)) {
		// zfsroot is output up to ' '
		if ((p = strchr(output, ' ')) == NULL)
			return -1;
		*p = '\0';

		if ((p = strrchr(output, '/')) == NULL)
			return -1;
		*p = '\0';
	} else {
		zfsroot = lxc_global_config_value("lxc.bdev.zfs.root");
	}

	ret = snprintf(option, MAXPATHLEN, "-omountpoint=%s/%s/rootfs", lxcpath, nname);
	if (ret < 0  || ret >= MAXPATHLEN)
		return -1;

	// zfs create -omountpoint=$lxcpath/$lxcname $zfsroot/$nname
	if (!snapshot) {
		if ((pid = fork()) < 0)
			return -1;
		if (!pid) {
			char dev[MAXPATHLEN];
			ret = snprintf(dev, MAXPATHLEN, "%s/%s", zfsroot, nname);
			if (ret < 0  || ret >= MAXPATHLEN)
				exit(EXIT_FAILURE);
			execlp("zfs", "zfs", "create", option, dev, (char *)NULL);
			exit(EXIT_FAILURE);
		}
		return wait_for_pid(pid);
	} else {
		// if snapshot, do
		// 'zfs snapshot zfsroot/oname@nname
		// zfs clone zfsroot/oname@nname zfsroot/nname
		char path1[MAXPATHLEN], path2[MAXPATHLEN];

		ret = snprintf(path1, MAXPATHLEN, "%s/%s@%s", zfsroot,
				oname, nname);
		if (ret < 0 || ret >= MAXPATHLEN)
			return -1;
		(void) snprintf(path2, MAXPATHLEN, "%s/%s", zfsroot, nname);

		// if the snapshot exists, delete it
		if ((pid = fork()) < 0)
			return -1;
		if (!pid) {
			execlp("zfs", "zfs", "destroy", path1, (char *)NULL);
			exit(EXIT_FAILURE);
		}
		// it probably doesn't exist so destroy probably will fail.
		(void) wait_for_pid(pid);

		// run first (snapshot) command
		if ((pid = fork()) < 0)
			return -1;
		if (!pid) {
			execlp("zfs", "zfs", "snapshot", path1, (char *)NULL);
			exit(EXIT_FAILURE);
		}
		if (wait_for_pid(pid) < 0)
			return -1;

		// run second (clone) command
		if ((pid = fork()) < 0)
			return -1;
		if (!pid) {
			execlp("zfs", "zfs", "clone", option, path1, path2, (char *)NULL);
			exit(EXIT_FAILURE);
		}
		return wait_for_pid(pid);
	}
}

int zfs_clonepaths(struct bdev *orig, struct bdev *new, const char *oldname,
		const char *cname, const char *oldpath, const char *lxcpath, int snap,
		uint64_t newsize, struct lxc_conf *conf)
{
	int len, ret;

	if (!orig->src || !orig->dest)
		return -1;

	if (snap && strcmp(orig->type, "zfs")) {
		ERROR("zfs snapshot from %s backing store is not supported", orig->type);
		return -1;
	}

	len = strlen(lxcpath) + strlen(cname) + strlen("rootfs") + 3;
	new->src = malloc(len);
	if (!new->src)
		return -1;

	ret = snprintf(new->src, len, "%s/%s/rootfs", lxcpath, cname);
	if (ret < 0 || ret >= len)
		return -1;

	if ((new->dest = strdup(new->src)) == NULL)
		return -1;

	return zfs_clone(orig->src, new->src, oldname, cname, lxcpath, snap);
}

/*
 * TODO: detect whether this was a clone, and if so then also delete the
 * snapshot it was based on, so that we don't hold the original
 * container busy.
 */
int zfs_destroy(struct bdev *orig)
{
	pid_t pid;
	char output[MAXPATHLEN];
	char *p;

	if ((pid = fork()) < 0)
		return -1;
	if (pid)
		return wait_for_pid(pid);

	if (!zfs_list_entry(orig->src, output, MAXPATHLEN)) {
		ERROR("Error: zfs entry for %s not found", orig->src);
		return -1;
	}

	// zfs mount is output up to ' '
	if ((p = strchr(output, ' ')) == NULL)
		return -1;
	*p = '\0';

	execlp("zfs", "zfs", "destroy", output, (char *)NULL);
	exit(EXIT_FAILURE);
}

int zfs_create(struct bdev *bdev, const char *dest, const char *n,
		struct bdev_specs *specs)
{
	const char *zfsroot;
	char option[MAXPATHLEN];
	int ret;
	pid_t pid;

	if (!specs || !specs->zfs.zfsroot)
		zfsroot = lxc_global_config_value("lxc.bdev.zfs.root");
	else
		zfsroot = specs->zfs.zfsroot;

	if (!(bdev->dest = strdup(dest))) {
		ERROR("No mount target specified or out of memory");
		return -1;
	}
	if (!(bdev->src = strdup(bdev->dest))) {
		ERROR("out of memory");
		return -1;
	}

	ret = snprintf(option, MAXPATHLEN, "-omountpoint=%s", bdev->dest);
	if (ret < 0  || ret >= MAXPATHLEN)
		return -1;
	if ((pid = fork()) < 0)
		return -1;
	if (pid)
		return wait_for_pid(pid);

	char dev[MAXPATHLEN];
	ret = snprintf(dev, MAXPATHLEN, "%s/%s", zfsroot, n);
	if (ret < 0  || ret >= MAXPATHLEN)
		exit(EXIT_FAILURE);

	execlp("zfs", "zfs", "create", option, dev, (char *)NULL);
	exit(EXIT_FAILURE);
}

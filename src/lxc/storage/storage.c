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
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <libgen.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "aufs.h"
#include "btrfs.h"
#include "conf.h"
#include "config.h"
#include "dir.h"
#include "error.h"
#include "log.h"
#include "loop.h"
#include "lvm.h"
#include "lxc.h"
#include "lxclock.h"
#include "nbd.h"
#include "namespace.h"
#include "overlay.h"
#include "parse.h"
#include "rbd.h"
#include "rsync.h"
#include "storage.h"
#include "storage_utils.h"
#include "utils.h"
#include "zfs.h"

#ifndef HAVE_STRLCPY
#include "include/strlcpy.h"
#endif

#ifndef BLKGETSIZE64
#define BLKGETSIZE64 _IOR(0x12, 114, size_t)
#endif

lxc_log_define(storage, lxc);

/* aufs */
static const struct lxc_storage_ops aufs_ops = {
    .detect = &aufs_detect,
    .mount = &aufs_mount,
    .umount = &aufs_umount,
    .clone_paths = &aufs_clonepaths,
    .destroy = &aufs_destroy,
    .create = &aufs_create,
    .can_snapshot = true,
    .can_backup = true,
};

/* btrfs */
static const struct lxc_storage_ops btrfs_ops = {
    .detect = &btrfs_detect,
    .mount = &btrfs_mount,
    .umount = &btrfs_umount,
    .clone_paths = &btrfs_clonepaths,
    .destroy = &btrfs_destroy,
    .create = &btrfs_create,
    .can_snapshot = true,
    .can_backup = true,
};

/* dir */
static const struct lxc_storage_ops dir_ops = {
    .detect = &dir_detect,
    .mount = &dir_mount,
    .umount = &dir_umount,
    .clone_paths = &dir_clonepaths,
    .destroy = &dir_destroy,
    .create = &dir_create,
    .can_snapshot = false,
    .can_backup = true,
};

/* loop */
static const struct lxc_storage_ops loop_ops = {
    .detect = &loop_detect,
    .mount = &loop_mount,
    .umount = &loop_umount,
    .clone_paths = &loop_clonepaths,
    .destroy = &loop_destroy,
    .create = &loop_create,
    .can_snapshot = false,
    .can_backup = true,
};

/* lvm */
static const struct lxc_storage_ops lvm_ops = {
    .detect = &lvm_detect,
    .mount = &lvm_mount,
    .umount = &lvm_umount,
    .clone_paths = &lvm_clonepaths,
    .destroy = &lvm_destroy,
    .create = &lvm_create,
    .can_snapshot = true,
    .can_backup = false,
};

/* nbd */
const struct lxc_storage_ops nbd_ops = {
    .detect = &nbd_detect,
    .mount = &nbd_mount,
    .umount = &nbd_umount,
    .clone_paths = &nbd_clonepaths,
    .destroy = &nbd_destroy,
    .create = &nbd_create,
    .can_snapshot = true,
    .can_backup = false,
};

/* overlay */
static const struct lxc_storage_ops ovl_ops = {
    .detect = &ovl_detect,
    .mount = &ovl_mount,
    .umount = &ovl_umount,
    .clone_paths = &ovl_clonepaths,
    .destroy = &ovl_destroy,
    .create = &ovl_create,
    .can_snapshot = true,
    .can_backup = true,
};

/* rbd */
static const struct lxc_storage_ops rbd_ops = {
    .detect = &rbd_detect,
    .mount = &rbd_mount,
    .umount = &rbd_umount,
    .clone_paths = &rbd_clonepaths,
    .destroy = &rbd_destroy,
    .create = &rbd_create,
    .can_snapshot = false,
    .can_backup = false,
};

/* zfs */
static const struct lxc_storage_ops zfs_ops = {
    .detect = &zfs_detect,
    .mount = &zfs_mount,
    .umount = &zfs_umount,
    .clone_paths = &zfs_clonepaths,
    .destroy = &zfs_destroy,
    .create = &zfs_create,
    .can_snapshot = true,
    .can_backup = true,
};

struct lxc_storage_type {
	const char *name;
	const struct lxc_storage_ops *ops;
};

static const struct lxc_storage_type bdevs[] = {
	{ .name = "zfs",       .ops = &zfs_ops,   },
	{ .name = "lvm",       .ops = &lvm_ops,   },
	{ .name = "rbd",       .ops = &rbd_ops,   },
	{ .name = "btrfs",     .ops = &btrfs_ops, },
	{ .name = "dir",       .ops = &dir_ops,   },
	{ .name = "aufs",      .ops = &aufs_ops,  },
	{ .name = "overlayfs", .ops = &ovl_ops,   },
	{ .name = "loop",      .ops = &loop_ops,  },
	{ .name = "nbd",       .ops = &nbd_ops,   },
};

static const size_t numbdevs = sizeof(bdevs) / sizeof(struct lxc_storage_type);

static const struct lxc_storage_type *get_storage_by_name(const char *name)
{
	size_t i, cmplen;

	cmplen = strcspn(name, ":");
	if (cmplen == 0)
		return NULL;

	for (i = 0; i < numbdevs; i++)
		if (strncmp(bdevs[i].name, name, cmplen) == 0)
			break;

	if (i == numbdevs)
		return NULL;

	DEBUG("Detected rootfs type \"%s\"", bdevs[i].name);
	return &bdevs[i];
}

const struct lxc_storage_type *storage_query(struct lxc_conf *conf,
					     const char *src)
{
	size_t i;
	const struct lxc_storage_type *bdev;

	bdev = get_storage_by_name(src);
	if (bdev)
		return bdev;

	for (i = 0; i < numbdevs; i++)
		if (bdevs[i].ops->detect(src))
			break;

	if (i == numbdevs)
		return NULL;

	DEBUG("Detected rootfs type \"%s\"", bdevs[i].name);
	return &bdevs[i];
}

struct lxc_storage *storage_get(const char *type)
{
	size_t i;
	struct lxc_storage *bdev;

	for (i = 0; i < numbdevs; i++) {
		if (strcmp(bdevs[i].name, type) == 0)
			break;
	}

	if (i == numbdevs)
		return NULL;

	bdev = malloc(sizeof(struct lxc_storage));
	if (!bdev)
		return NULL;

	memset(bdev, 0, sizeof(struct lxc_storage));
	bdev->ops = bdevs[i].ops;
	bdev->type = bdevs[i].name;

	return bdev;
}

static struct lxc_storage *do_storage_create(const char *dest, const char *type,
					     const char *cname,
					     struct bdev_specs *specs)
{

	struct lxc_storage *bdev;

	if (!type)
		type = "dir";

	bdev = storage_get(type);
	if (!bdev)
		return NULL;

	if (bdev->ops->create(bdev, dest, cname, specs) < 0) {
		storage_put(bdev);
		return NULL;
	}

	return bdev;
}

bool storage_can_backup(struct lxc_conf *conf)
{
	struct lxc_storage *bdev = storage_init(conf, NULL, NULL, NULL);
	bool ret;

	if (!bdev)
		return false;

	ret = bdev->ops->can_backup;
	storage_put(bdev);
	return ret;
}

/* If we're not snaphotting, then storage_copy becomes a simple case of mount
 * the original, mount the new, and rsync the contents.
 */
struct lxc_storage *storage_copy(struct lxc_container *c0, const char *cname,
				 const char *lxcpath, const char *bdevtype,
				 int flags, const char *bdevdata,
				 uint64_t newsize, int *needs_rdep)
{
	struct lxc_storage *orig, *new;
	pid_t pid;
	int ret;
	bool snap = flags & LXC_CLONE_SNAPSHOT;
	bool maybe_snap = flags & LXC_CLONE_MAYBE_SNAPSHOT;
	bool keepbdevtype = flags & LXC_CLONE_KEEPBDEVTYPE;
	const char *src = c0->lxc_conf->rootfs.path;
	const char *oldname = c0->name;
	const char *oldpath = c0->config_path;
	struct rsync_data data;

	/* If the container name doesn't show up in the rootfs path, then we
	 * don't know how to come up with a new name.
	 */
	if (!src) {
		ERROR("No rootfs specified");
		return NULL;
	}

	if (strstr(src, oldname) == NULL) {
		ERROR(
		    "original rootfs path %s doesn't include container name %s",
		    src, oldname);
		return NULL;
	}

	orig = storage_init(c0->lxc_conf, src, NULL, NULL);
	if (!orig) {
		ERROR("failed to detect blockdev type for %s", src);
		return NULL;
	}

	if (!orig->dest) {
		int ret;
		size_t len;
		struct stat sb;

		len = strlen(oldpath) + strlen(oldname) + strlen("/rootfs") + 2;
		orig->dest = malloc(len);
		if (!orig->dest) {
			ERROR("Failed to allocate memory");
			storage_put(orig);
			return NULL;
		}

		ret = snprintf(orig->dest, len, "%s/%s/rootfs", oldpath, oldname);
		if (ret < 0 || (size_t)ret >= len) {
			ERROR("Failed to create string");
			storage_put(orig);
			return NULL;
		}
		ret = stat(orig->dest, &sb);

		if (ret < 0 && errno == ENOENT)
			if (mkdir_p(orig->dest, 0755) < 0)
				WARN("Error creating '%s', continuing.",
				     orig->dest);
	}

	/*
	 * special case for snapshot - if caller requested maybe_snapshot and
	 * keepbdevtype and backing store is directory, then proceed with a copy
	 * clone rather than returning error
	 */
	if (maybe_snap && keepbdevtype && !bdevtype && !orig->ops->can_snapshot)
		snap = false;

	/* If newtype is NULL and snapshot is set, then use overlayfs. */
	if (!bdevtype && !keepbdevtype && snap && (!strcmp(orig->type, "dir") || !strcmp(orig->type, "overlayfs")))
		bdevtype = "overlayfs";

	if (am_guest_unpriv() && !unpriv_snap_allowed(orig, bdevtype, snap, maybe_snap)) {
		ERROR("Unsupported snapshot type \"%s\" for unprivileged users",
		      bdevtype ? bdevtype : "(null)");
		storage_put(orig);
		return NULL;
	}

	*needs_rdep = 0;
	if (bdevtype && strcmp(orig->type, "dir") == 0 &&
	    (strcmp(bdevtype, "aufs") == 0 ||
	     strcmp(bdevtype, "overlayfs") == 0)) {
		*needs_rdep = 1;
	} else if (snap && strcmp(orig->type, "lvm") == 0 &&
		   !lvm_is_thin_volume(orig->src)) {
		*needs_rdep = 1;
	}

	if (strcmp(oldpath, lxcpath) && !bdevtype && strcmp(orig->type, "overlayfs"))
		bdevtype = "dir";
	else if (!bdevtype)
		bdevtype = orig->type;

	/* get new bdev type */
	new = storage_get(bdevtype);
	if (!new) {
		ERROR("no such block device type: %s",
		      bdevtype ? bdevtype : orig->type);
		storage_put(orig);
		return NULL;
	}

	if (new->ops->clone_paths(orig, new, oldname, cname, oldpath, lxcpath,
				  snap, newsize, c0->lxc_conf) < 0) {
		ERROR("failed getting pathnames for cloned storage: %s", src);
		goto err;
	}

	if (am_guest_unpriv() && chown_mapped_root(new->src, c0->lxc_conf) < 0)
		WARN("Failed to update ownership of %s", new->dest);

	if (snap)
		return new;

	/*
	 * https://github.com/lxc/lxc/issues/131
	 * Use btrfs snapshot feature instead of rsync to restore if both orig
	 * and new are btrfs
	 */
	if (bdevtype && strcmp(orig->type, "btrfs") == 0 &&
	    strcmp(new->type, "btrfs") == 0 &&
	    btrfs_same_fs(orig->dest, new->dest) == 0) {
		if (btrfs_destroy(new) < 0) {
			ERROR("Error destroying %s subvolume", new->dest);
			goto err;
		}
		if (mkdir_p(new->dest, 0755) < 0) {
			ERROR("Error creating %s directory", new->dest);
			goto err;
		}
		if (btrfs_snapshot(orig->dest, new->dest) < 0) {
			ERROR("Error restoring %s to %s", orig->dest,
			      new->dest);
			goto err;
		}
		storage_put(orig);
		return new;
	}

	pid = fork();
	if (pid < 0) {
		SYSERROR("fork");
		goto err;
	}

	if (pid > 0) {
		int ret = wait_for_pid(pid);
		storage_put(orig);
		if (ret < 0) {
			storage_put(new);
			return NULL;
		}
		return new;
	}

	data.orig = orig;
	data.new = new;
	if (am_guest_unpriv())
		ret = userns_exec_full(c0->lxc_conf, rsync_rootfs_wrapper,
				       &data, "rsync_rootfs_wrapper");
	else
		ret = rsync_rootfs(&data);

	exit(ret == 0 ? 0 : 1);

err:
	storage_put(orig);
	storage_put(new);
	return NULL;
}

/* Create a backing store for a container.
 * If successful, return a struct bdev *, with the bdev mounted and ready
 * for use.  Before completing, the caller will need to call the
 * umount operation and storage_put().
 * @dest: the mountpoint (i.e. /var/lib/lxc/$name/rootfs)
 * @type: the bdevtype (dir, btrfs, zfs, rbd, etc)
 * @cname: the container name
 * @specs: details about the backing store to create, like fstype
 */
struct lxc_storage *storage_create(const char *dest, const char *type,
				   const char *cname, struct bdev_specs *specs)
{
	int ret;
	struct lxc_storage *bdev;
	char *best_options[] = {"btrfs", "zfs", "lvm", "dir", "rbd", NULL};

	if (!type)
		return do_storage_create(dest, "dir", cname, specs);

	ret = strcmp(type, "best");
	if (ret == 0) {
		int i;
		/* Try for the best backing store type, according to our
		 * opinionated preferences.
		 */
		for (i = 0; best_options[i]; i++) {
			bdev = do_storage_create(dest, best_options[i], cname, specs);
			if (bdev)
				return bdev;
		}

		return NULL;
	}

	/* -B lvm,dir */
	if (strchr(type, ',')) {
		char *dup, *token;
		char *saveptr = NULL;
		size_t len;

		len = strlen(type);
		dup = alloca(len + 1);
		(void)strlcpy(dup, type, len + 1);

		for (token = strtok_r(dup, ",", &saveptr); token;
		     token = strtok_r(NULL, ",", &saveptr)) {
			bdev = do_storage_create(dest, token, cname, specs);
			if (bdev)
				return bdev;
		}
	}

	return do_storage_create(dest, type, cname, specs);
}

bool storage_destroy(struct lxc_conf *conf)
{
	struct lxc_storage *r;
	bool ret = false;

	r = storage_init(conf, conf->rootfs.path, conf->rootfs.mount, NULL);
	if (!r)
		return ret;

	if (r->ops->destroy(r) == 0)
		ret = true;

	storage_put(r);
	return ret;
}

struct lxc_storage *storage_init(struct lxc_conf *conf, const char *src,
				 const char *dst, const char *mntopts)
{
	struct lxc_storage *bdev;
	const struct lxc_storage_type *q;

	if (!src)
		src = conf->rootfs.path;

	if (!src)
		return NULL;

	q = storage_query(conf, src);
	if (!q)
		return NULL;

	bdev = malloc(sizeof(struct lxc_storage));
	if (!bdev)
		return NULL;

	memset(bdev, 0, sizeof(struct lxc_storage));
	bdev->ops = q->ops;
	bdev->type = q->name;
	if (mntopts)
		bdev->mntopts = strdup(mntopts);
	if (src)
		bdev->src = strdup(src);
	if (dst)
		bdev->dest = strdup(dst);
	if (strcmp(bdev->type, "nbd") == 0)
		bdev->nbd_idx = conf->nbd_idx;

	return bdev;
}

bool storage_is_dir(struct lxc_conf *conf, const char *path)
{
	struct lxc_storage *orig;
	bool bret = false;

	orig = storage_init(conf, path, NULL, NULL);
	if (!orig)
		return bret;

	if (strcmp(orig->type, "dir") == 0)
		bret = true;

	storage_put(orig);
	return bret;
}

void storage_put(struct lxc_storage *bdev)
{
	free(bdev->mntopts);
	free(bdev->src);
	free(bdev->dest);
	free(bdev);
}

bool rootfs_is_blockdev(struct lxc_conf *conf)
{
	const struct lxc_storage_type *q;
	struct stat st;
	int ret;

	if (!conf->rootfs.path || strcmp(conf->rootfs.path, "/") == 0 ||
	    strlen(conf->rootfs.path) == 0)
		return false;

	ret = stat(conf->rootfs.path, &st);
	if (ret == 0 && S_ISBLK(st.st_mode))
		return true;

	q = storage_query(conf, conf->rootfs.path);
	if (!q)
		return false;

	if (strcmp(q->name, "lvm") == 0 ||
	    strcmp(q->name, "loop") == 0 ||
	    strcmp(q->name, "nbd") == 0)
		return true;

	return false;
}

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

/*
 * this is all just a first shot for experiment.  If we go this route, much
 * should change.  bdev should be a directory with per-bdev file.  Things which
 * I'm doing by calling out to userspace should sometimes be done through
 * libraries like liblvm2
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

#include "bdev.h"
#include "conf.h"
#include "config.h"
#include "error.h"
#include "log.h"
#include "lxc.h"
#include "lxcaufs.h"
#include "lxcbtrfs.h"
#include "lxcdir.h"
#include "lxclock.h"
#include "lxclvm.h"
#include "lxcloop.h"
#include "lxcnbd.h"
#include "lxcoverlay.h"
#include "lxcrbd.h"
#include "lxcrsync.h"
#include "lxczfs.h"
#include "namespace.h"
#include "parse.h"
#include "storage_utils.h"
#include "utils.h"

#ifndef BLKGETSIZE64
#define BLKGETSIZE64 _IOR(0x12, 114, size_t)
#endif

lxc_log_define(bdev, lxc);

/* aufs */
static const struct bdev_ops aufs_ops = {
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
static const struct bdev_ops btrfs_ops = {
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
static const struct bdev_ops dir_ops = {
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
static const struct bdev_ops loop_ops = {
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
static const struct bdev_ops lvm_ops = {
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
const struct bdev_ops nbd_ops = {
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
static const struct bdev_ops ovl_ops = {
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
static const struct bdev_ops rbd_ops = {
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
static const struct bdev_ops zfs_ops = {
    .detect = &zfs_detect,
    .mount = &zfs_mount,
    .umount = &zfs_umount,
    .clone_paths = &zfs_clonepaths,
    .destroy = &zfs_destroy,
    .create = &zfs_create,
    .can_snapshot = true,
    .can_backup = true,
};

struct bdev_type {
	const char *name;
	const struct bdev_ops *ops;
};

static const struct bdev_type bdevs[] = {
	{ .name = "dir",       .ops = &dir_ops,   },
	{ .name = "zfs",       .ops = &zfs_ops,   },
	{ .name = "lvm",       .ops = &lvm_ops,   },
	{ .name = "rbd",       .ops = &rbd_ops,   },
	{ .name = "btrfs",     .ops = &btrfs_ops, },
	{ .name = "aufs",      .ops = &aufs_ops,  },
	{ .name = "overlayfs", .ops = &ovl_ops,   },
	{ .name = "loop",      .ops = &loop_ops,  },
	{ .name = "nbd",       .ops = &nbd_ops,   },
};

static const size_t numbdevs = sizeof(bdevs) / sizeof(struct bdev_type);

static const struct bdev_type *get_bdev_by_name(const char *name)
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

const struct bdev_type *bdev_query(struct lxc_conf *conf, const char *src)
{
	size_t i;
	const struct bdev_type *bdev;

	bdev = get_bdev_by_name(src);
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

struct bdev *bdev_get(const char *type)
{
	size_t i;
	struct bdev *bdev;

	for (i = 0; i < numbdevs; i++) {
		if (strcmp(bdevs[i].name, type) == 0)
			break;
	}

	if (i == numbdevs)
		return NULL;

	bdev = malloc(sizeof(struct bdev));
	if (!bdev)
		return NULL;

	memset(bdev, 0, sizeof(struct bdev));
	bdev->ops = bdevs[i].ops;
	bdev->type = bdevs[i].name;

	return bdev;
}

static struct bdev *do_bdev_create(const char *dest, const char *type,
				   const char *cname, struct bdev_specs *specs)
{

	struct bdev *bdev;

	if (!type)
		type = "dir";

	bdev = bdev_get(type);
	if (!bdev)
		return NULL;

	if (bdev->ops->create(bdev, dest, cname, specs) < 0) {
		bdev_put(bdev);
		return NULL;
	}

	return bdev;
}

bool bdev_can_backup(struct lxc_conf *conf)
{
	struct bdev *bdev = bdev_init(conf, NULL, NULL, NULL);
	bool ret;

	if (!bdev)
		return false;

	ret = bdev->ops->can_backup;
	bdev_put(bdev);
	return ret;
}

/*
 * If we're not snaphotting, then bdev_copy becomes a simple case of mount
 * the original, mount the new, and rsync the contents.
 */
struct bdev *bdev_copy(struct lxc_container *c0, const char *cname,
		       const char *lxcpath, const char *bdevtype, int flags,
		       const char *bdevdata, uint64_t newsize, int *needs_rdep)
{
	struct bdev *orig, *new;
	pid_t pid;
	int ret;
	char *src_no_prefix;
	bool snap = flags & LXC_CLONE_SNAPSHOT;
	bool maybe_snap = flags & LXC_CLONE_MAYBE_SNAPSHOT;
	bool keepbdevtype = flags & LXC_CLONE_KEEPBDEVTYPE;
	const char *src = c0->lxc_conf->rootfs.path;
	const char *oldname = c0->name;
	const char *oldpath = c0->config_path;
	struct rsync_data data;

	/* if the container name doesn't show up in the rootfs path, then
	 * we don't know how to come up with a new name
	 */
	if (strstr(src, oldname) == NULL) {
		ERROR(
		    "original rootfs path %s doesn't include container name %s",
		    src, oldname);
		return NULL;
	}

	orig = bdev_init(c0->lxc_conf, src, NULL, NULL);
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
			ERROR("out of memory");
			bdev_put(orig);
			return NULL;
		}

		ret = snprintf(orig->dest, len, "%s/%s/rootfs", oldpath, oldname);
		if (ret < 0 || (size_t)ret >= len) {
			ERROR("rootfs path too long");
			bdev_put(orig);
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

	/*
	 * If newtype is NULL and snapshot is set, then use overlayfs
	 */
	if (!bdevtype && !keepbdevtype && snap &&
	    strcmp(orig->type, "dir") == 0)
		bdevtype = "overlayfs";

	if (am_unpriv() && !unpriv_snap_allowed(orig, bdevtype, snap, maybe_snap)) {
		ERROR("Unsupported snapshot type for unprivileged users");
		bdev_put(orig);
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

	if (strcmp(oldpath, lxcpath) && !bdevtype && !snap)
		bdevtype = "dir";
	else if (!bdevtype)
		bdevtype = orig->type;
	new = bdev_get(bdevtype);
	if (!new) {
		ERROR("no such block device type: %s",
		      bdevtype ? bdevtype : orig->type);
		bdev_put(orig);
		return NULL;
	}
	TRACE("Detected \"%s\" storage driver", new->type);

	if (new->ops->clone_paths(orig, new, oldname, cname, oldpath, lxcpath,
				  snap, newsize, c0->lxc_conf) < 0) {
		ERROR("failed getting pathnames for cloned storage: %s", src);
		goto err;
	}

	src_no_prefix = lxc_storage_get_path(new->src, new->type);

	if (am_unpriv() && chown_mapped_root(src_no_prefix, c0->lxc_conf) < 0)
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
		bdev_put(orig);
		return new;
	}

	pid = fork();
	if (pid < 0) {
		SYSERROR("fork");
		goto err;
	}

	if (pid > 0) {
		int ret = wait_for_pid(pid);
		bdev_put(orig);
		if (ret < 0) {
			bdev_put(new);
			return NULL;
		}
		return new;
	}

	data.orig = orig;
	data.new = new;
	if (am_unpriv())
		ret = userns_exec_1(c0->lxc_conf, rsync_rootfs_wrapper, &data,
				    "rsync_rootfs_wrapper");
	else
		ret = rsync_rootfs(&data);
	if (ret < 0)
		ERROR("Failed to rsync");

	exit(ret == 0 ? 0 : 1);

err:
	bdev_put(orig);
	bdev_put(new);
	return NULL;
}

/*
 * bdev_create:
 * Create a backing store for a container.
 * If successful, return a struct bdev *, with the bdev mounted and ready
 * for use.  Before completing, the caller will need to call the
 * umount operation and bdev_put().
 * @dest: the mountpoint (i.e. /var/lib/lxc/$name/rootfs)
 * @type: the bdevtype (dir, btrfs, zfs, rbd, etc)
 * @cname: the container name
 * @specs: details about the backing store to create, like fstype
 */
struct bdev *bdev_create(const char *dest, const char *type, const char *cname,
			 struct bdev_specs *specs)
{
	struct bdev *bdev;
	char *best_options[] = {"btrfs", "zfs", "lvm", "dir", "rbd", NULL};

	if (!type)
		return do_bdev_create(dest, "dir", cname, specs);

	if (strcmp(type, "best") == 0) {
		int i;
		// try for the best backing store type, according to our
		// opinionated preferences
		for (i = 0; best_options[i]; i++) {
			if ((bdev = do_bdev_create(dest, best_options[i], cname,
						   specs)))
				return bdev;
		}

		return NULL; // 'dir' should never fail, so this shouldn't
			     // happen
	}

	// -B lvm,dir
	if (strchr(type, ',') != NULL) {
		char *dup = alloca(strlen(type) + 1), *saveptr = NULL, *token;
		strcpy(dup, type);
		for (token = strtok_r(dup, ",", &saveptr); token;
		     token = strtok_r(NULL, ",", &saveptr)) {
			if ((bdev = do_bdev_create(dest, token, cname, specs)))
				return bdev;
		}
	}

	return do_bdev_create(dest, type, cname, specs);
}

bool bdev_destroy(struct lxc_conf *conf)
{
	struct bdev *r;
	bool ret = false;

	r = bdev_init(conf, conf->rootfs.path, conf->rootfs.mount, NULL);
	if (!r)
		return ret;

	if (r->ops->destroy(r) == 0)
		ret = true;
	bdev_put(r);

	return ret;
}

struct bdev *bdev_init(struct lxc_conf *conf, const char *src, const char *dst,
		       const char *mntopts)
{
	struct bdev *bdev;
	const struct bdev_type *q;

	if (!src)
		src = conf->rootfs.path;

	if (!src)
		return NULL;

	q = bdev_query(conf, src);
	if (!q)
		return NULL;

	bdev = malloc(sizeof(struct bdev));
	if (!bdev)
		return NULL;

	memset(bdev, 0, sizeof(struct bdev));
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

bool bdev_is_dir(struct lxc_conf *conf, const char *path)
{
	struct bdev *orig = bdev_init(conf, path, NULL, NULL);
	bool ret = false;
	if (!orig)
		return ret;
	if (strcmp(orig->type, "dir") == 0)
		ret = true;
	bdev_put(orig);
	return ret;
}

void bdev_put(struct bdev *bdev)
{
	free(bdev->mntopts);
	free(bdev->src);
	free(bdev->dest);
	free(bdev);
}

bool rootfs_is_blockdev(struct lxc_conf *conf)
{
	const struct bdev_type *q;
	struct stat st;
	int ret;

	if (!conf->rootfs.path || strcmp(conf->rootfs.path, "/") == 0 ||
	    strlen(conf->rootfs.path) == 0)
		return false;

	ret = stat(conf->rootfs.path, &st);
	if (ret == 0 && S_ISBLK(st.st_mode))
		return true;

	q = bdev_query(conf, conf->rootfs.path);
	if (!q)
		return false;

	if (strcmp(q->name, "lvm") == 0 ||
	    strcmp(q->name, "loop") == 0 ||
	    strcmp(q->name, "nbd") == 0)
		return true;

	return false;
}

char *lxc_storage_get_path(char *src, const char *prefix)
{
	size_t prefix_len;

	prefix_len = strlen(prefix);
	if (!strncmp(src, prefix, prefix_len) && (*(src + prefix_len) == ':'))
		return (src + prefix_len + 1);

	return src;
}

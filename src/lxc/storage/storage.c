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
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

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
#include "namespace.h"
#include "nbd.h"
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

/* btrfs */
static const struct lxc_storage_ops btrfs_ops = {
    .detect = &btrfs_detect,
    .mount = &btrfs_mount,
    .umount = &btrfs_umount,
    .clone_paths = &btrfs_clonepaths,
    .destroy = &btrfs_destroy,
    .create = &btrfs_create,
    .copy = &btrfs_create_clone,
    .snapshot = &btrfs_create_snapshot,
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
    .copy = NULL,
    .snapshot = NULL,
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
    .copy = NULL,
    .snapshot = NULL,
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
    .copy = &lvm_create_clone,
    .snapshot = &lvm_create_snapshot,
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
    .copy = NULL,
    .snapshot = NULL,
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
    .copy = NULL,
    .snapshot = NULL,
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
    .copy = NULL,
    .snapshot = NULL,
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
    .copy = &zfs_copy,
    .snapshot = &zfs_snapshot,
    .can_snapshot = true,
    .can_backup = true,
};

struct lxc_storage_type {
	const char *name;
	const struct lxc_storage_ops *ops;
};

static const struct lxc_storage_type bdevs[] = {
	{ .name = "dir",       .ops = &dir_ops,   },
	{ .name = "zfs",       .ops = &zfs_ops,   },
	{ .name = "lvm",       .ops = &lvm_ops,   },
	{ .name = "rbd",       .ops = &rbd_ops,   },
	{ .name = "btrfs",     .ops = &btrfs_ops, },
	{ .name = "overlay",   .ops = &ovl_ops,   },
	{ .name = "overlayfs", .ops = &ovl_ops,   },
	{ .name = "loop",      .ops = &loop_ops,  },
	{ .name = "nbd",       .ops = &nbd_ops,   },
};

static const size_t numbdevs = sizeof(bdevs) / sizeof(struct lxc_storage_type);

static const struct lxc_storage_type *get_storage_by_name(const char *path,
							  const char *type)
{
	int ret;
	size_t i, cmplen;

	if (type)
		cmplen = strlen(type);
	else
		cmplen = strcspn(path, ":");
	if (cmplen == 0)
		return NULL;

	for (i = 0; i < numbdevs; i++) {
		if (type)
			ret = strncmp(bdevs[i].name, type, cmplen);
		else
			ret = strncmp(bdevs[i].name, path, cmplen);
		if (ret == 0)
			break;
	}

	if (i == numbdevs)
		return NULL;

	DEBUG("Detected rootfs type \"%s\"", bdevs[i].name);
	return &bdevs[i];
}

static const struct lxc_storage_type *storage_query(struct lxc_conf *conf)
{
	size_t i;
	const struct lxc_storage_type *bdev;
	const char *path = conf->rootfs.path;
	const char *type = conf->rootfs.bdev_type;

	bdev = get_storage_by_name(path, type);
	if (bdev)
		return bdev;

	for (i = 0; i < numbdevs; i++)
		if (bdevs[i].ops->detect(path))
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

	for (i = 0; i < numbdevs; i++)
		if (strcmp(bdevs[i].name, type) == 0)
			break;

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
	int ret;
	struct lxc_storage *bdev;

	if (!type)
		type = "dir";

	bdev = storage_get(type);
	if (!bdev)
		return NULL;

	ret = bdev->ops->create(bdev, dest, cname, specs);
	if (ret < 0) {
		storage_put(bdev);
		return NULL;
	}

	return bdev;
}

bool storage_can_backup(struct lxc_conf *conf)
{
	bool ret;
	struct lxc_storage *bdev;

	bdev = storage_init(conf);
	if (!bdev)
		return false;

	ret = bdev->ops->can_backup;
	storage_put(bdev);
	return ret;
}

/* If we're not snapshotting, then storage_copy becomes a simple case of mount
 * the original, mount the new, and rsync the contents.
 */
struct lxc_storage *storage_copy(struct lxc_container *c, const char *cname,
				 const char *lxcpath, const char *bdevtype,
				 int flags, const char *bdevdata,
				 uint64_t newsize, bool *needs_rdep)
{
	int ret;
	const char *src_no_prefix;
	struct lxc_storage *new, *orig;
	bool snap = (flags & LXC_CLONE_SNAPSHOT);
	bool maybe_snap = (flags & LXC_CLONE_MAYBE_SNAPSHOT);
	bool keepbdevtype = (flags & LXC_CLONE_KEEPBDEVTYPE);
	const char *src = c->lxc_conf->rootfs.path;
	const char *oldname = c->name;
	const char *oldpath = c->config_path;
	char cmd_output[PATH_MAX] = {0};
	struct rsync_data data = {0};

	if (!src) {
		ERROR("No rootfs specified");
		return NULL;
	}

	/* If the container name doesn't show up in the rootfs path, then we
	 * don't know how to come up with a new name.
	 */
	if (!strstr(src, oldname)) {
		ERROR("Original rootfs path \"%s\" does not include container "
		      "name \"%s\"", src, oldname);
		return NULL;
	}

	orig = storage_init(c->lxc_conf);
	if (!orig) {
		ERROR("Failed to detect storage driver for \"%s\"", oldname);
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
			goto on_error_put_orig;
		}

		ret = snprintf(orig->dest, len, "%s/%s/rootfs", oldpath, oldname);
		if (ret < 0 || (size_t)ret >= len) {
			ERROR("Failed to create string");
			goto on_error_put_orig;
		}

		ret = stat(orig->dest, &sb);
		if (ret < 0 && errno == ENOENT) {
			ret = mkdir_p(orig->dest, 0755);
			if (ret < 0)
				WARN("Failed to create directory \"%s\"", orig->dest);
		}
	}

	/* Special case for snapshot. If the caller requested maybe_snapshot and
	 * keepbdevtype and the backing store is directory, then proceed with a
	 * a copy clone rather than returning error.
	 */
	if (maybe_snap && keepbdevtype && !bdevtype && !orig->ops->can_snapshot)
		snap = false;

	/* If newtype is NULL and snapshot is set, then use overlay. */
	if (!bdevtype && !keepbdevtype && snap && !strcmp(orig->type, "dir"))
		bdevtype = "overlay";

	if (am_guest_unpriv() && !unpriv_snap_allowed(orig, bdevtype, snap, maybe_snap)) {
		ERROR("Unsupported snapshot type \"%s\" for unprivileged users",
		      bdevtype ? bdevtype : "(null)");
		goto on_error_put_orig;
	}

	*needs_rdep = false;
	if (bdevtype) {
		if (snap && !strcmp(orig->type, "lvm") &&
		    !lvm_is_thin_volume(orig->src))
			*needs_rdep = true;
		else if (!strcmp(bdevtype, "overlay") ||
			 !strcmp(bdevtype, "overlayfs"))
			*needs_rdep = true;
	} else {
		if (!snap && strcmp(oldpath, lxcpath))
			bdevtype = "dir";
		else
			bdevtype = orig->type;

		if (!strcmp(bdevtype, "overlay") ||
		    !strcmp(bdevtype, "overlayfs"))
			*needs_rdep = true;
	}

	/* get new bdev type */
	new = storage_get(bdevtype);
	if (!new) {
		ERROR("Failed to initialize %s storage driver",
		      bdevtype ? bdevtype : orig->type);
		goto on_error_put_orig;
	}
	TRACE("Initialized %s storage driver", new->type);

	/* create new paths */
	ret = new->ops->clone_paths(orig, new, oldname, cname, oldpath, lxcpath,
				    snap, newsize, c->lxc_conf);
	if (ret < 0) {
		ERROR("Failed creating new paths for clone of \"%s\"", src);
		goto on_error_put_new;
	}

	/* When we create an overlay snapshot of an overlay container in the
	 * snapshot directory under "<lxcpath>/<name>/snaps/" we don't need to
	 * record a dependency. If we would restore would also fail.
	 */
	if ((strcmp(new->type, "overlay") == 0 ||
	     strcmp(new->type, "overlayfs") == 0) &&
	    ret == LXC_CLONE_SNAPSHOT)
		*needs_rdep = false;

	/* btrfs */
	if (!strcmp(orig->type, "btrfs") && !strcmp(new->type, "btrfs")) {
		bool bret;

		if (snap || btrfs_same_fs(orig->dest, new->dest) == 0)
			bret = new->ops->snapshot(c->lxc_conf, orig, new, 0);
		else
			bret = new->ops->copy(c->lxc_conf, orig, new, 0);
		if (!bret)
			goto on_error_put_new;

		goto on_success;
	}

	/* lvm */
	if (!strcmp(orig->type, "lvm") && !strcmp(new->type, "lvm")) {
		bool bret;

		if (snap)
			bret = new->ops->snapshot(c->lxc_conf, orig, new, newsize);
		else
			bret = new->ops->copy(c->lxc_conf, orig, new, newsize);
		if (!bret)
			goto on_error_put_new;

		goto on_success;
	}

	/* zfs */
	if (!strcmp(orig->type, "zfs") && !strcmp(new->type, "zfs")) {
		bool bret;

		if (snap)
			bret = new->ops->snapshot(c->lxc_conf, orig, new, newsize);
		else
			bret = new->ops->copy(c->lxc_conf, orig, new, newsize);
		if (!bret)
			goto on_error_put_new;

		goto on_success;
	}

	if (strcmp(bdevtype, "btrfs")) {
		if (!strcmp(new->type, "overlay") || !strcmp(new->type, "overlayfs"))
			src_no_prefix = ovl_get_lower(new->src);
		else
			src_no_prefix = lxc_storage_get_path(new->src, new->type);

		if (am_guest_unpriv()) {
			ret = chown_mapped_root(src_no_prefix, c->lxc_conf);
			if (ret < 0)
				WARN("Failed to chown \"%s\"", new->src);
		}
	}

	if (snap)
		goto on_success;

	/* rsync the contents from source to target */
	data.orig = orig;
	data.new = new;
	if (am_guest_unpriv())
		ret = userns_exec_full(c->lxc_conf,
				       lxc_storage_rsync_exec_wrapper, &data,
				       "lxc_storage_rsync_exec_wrapper");
	else
		ret = run_command(cmd_output, sizeof(cmd_output),
				  lxc_storage_rsync_exec_wrapper, (void *)&data);
	if (ret < 0) {
		ERROR("Failed to rsync from \"%s\" into \"%s\"%s%s", orig->dest,
		      new->dest,
		      cmd_output[0] != '\0' ? ": " : "",
		      cmd_output[0] != '\0' ? cmd_output : "");
		goto on_error_put_new;
	}

on_success:
	storage_put(orig);

	return new;

on_error_put_new:
	storage_put(new);

on_error_put_orig:
	storage_put(orig);

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
		size_t len;

		len = strlen(type);
		dup = alloca(len + 1);
		(void)strlcpy(dup, type, len + 1);

		lxc_iterate_parts(token, dup, ",") {
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
	int destroy_rv = 0;

	r = storage_init(conf);
	if (!r)
		return ret;

	destroy_rv = r->ops->destroy(r);
	if (destroy_rv == 0)
		ret = true;

	storage_put(r);
	return ret;
}

struct lxc_storage *storage_init(struct lxc_conf *conf)
{
	struct lxc_storage *bdev;
	const struct lxc_storage_type *q;
	const char *src = conf->rootfs.path;
	const char *dst = conf->rootfs.mount;
	const char *mntopts = conf->rootfs.options;

	BUILD_BUG_ON(LXC_STORAGE_INTERNAL_OVERLAY_RESTORE <= LXC_CLONE_MAXFLAGS);

	if (!src)
		return NULL;

	q = storage_query(conf);
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

bool storage_is_dir(struct lxc_conf *conf)
{
	struct lxc_storage *orig;
	char *type = conf->rootfs.bdev_type;
	bool bret = false;

	if (type)
		return (strcmp(type, "dir") == 0);

	orig = storage_init(conf);
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

	q = storage_query(conf);
	if (!q)
		return false;

	if (strcmp(q->name, "lvm") == 0 ||
	    strcmp(q->name, "loop") == 0 ||
	    strcmp(q->name, "nbd") == 0 ||
	    strcmp(q->name, "rbd") == 0 ||
	    strcmp(q->name, "zfs") == 0)
		return true;

	return false;
}

const char *lxc_storage_get_path(char *src, const char *prefix)
{
	size_t prefix_len;

	prefix_len = strlen(prefix);
	if (!strncmp(src, prefix, prefix_len) && (*(src + prefix_len) == ':'))
		return (src + prefix_len + 1);

	return src;
}

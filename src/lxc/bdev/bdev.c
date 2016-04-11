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
#include "utils.h"

#ifndef BLKGETSIZE64
#define BLKGETSIZE64 _IOR(0x12,114,size_t)
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
	{.name = "zfs", .ops = &zfs_ops,},
	{.name = "lvm", .ops = &lvm_ops,},
	{.name = "rbd", .ops = &rbd_ops,},
	{.name = "btrfs", .ops = &btrfs_ops,},
	{.name = "dir", .ops = &dir_ops,},
	{.name = "aufs", .ops = &aufs_ops,},
	{.name = "overlayfs", .ops = &ovl_ops,},
	{.name = "loop", .ops = &loop_ops,},
	{.name = "nbd", .ops = &nbd_ops,},
};

static const size_t numbdevs = sizeof(bdevs) / sizeof(struct bdev_type);

/* helpers */
static const struct bdev_type *bdev_query(struct lxc_conf *conf, const char *src);
static struct bdev *bdev_get(const char *type);
static struct bdev *do_bdev_create(const char *dest, const char *type,
		const char *cname, struct bdev_specs *specs);
static int find_fstype_cb(char *buffer, void *data);
static char *linkderef(char *path, char *dest);
static bool unpriv_snap_allowed(struct bdev *b, const char *t, bool snap,
		bool maybesnap);

/* the bulk of this needs to become a common helper */
char *dir_new_path(char *src, const char *oldname, const char *name,
		const char *oldpath, const char *lxcpath)
{
	char *ret, *p, *p2;
	int l1, l2, nlen;

	nlen = strlen(src) + 1;
	l1 = strlen(oldpath);
	p = src;
	/* if src starts with oldpath, look for oldname only after
	 * that path */
	if (strncmp(src, oldpath, l1) == 0) {
		p += l1;
		nlen += (strlen(lxcpath) - l1);
	}
	l2 = strlen(oldname);
	while ((p = strstr(p, oldname)) != NULL) {
		p += l2;
		nlen += strlen(name) - l2;
	}

	ret = malloc(nlen);
	if (!ret)
		return NULL;

	p = ret;
	if (strncmp(src, oldpath, l1) == 0) {
		p += sprintf(p, "%s", lxcpath);
		src += l1;
	}

	while ((p2 = strstr(src, oldname)) != NULL) {
		strncpy(p, src, p2 - src); // copy text up to oldname
		p += p2 - src; // move target pointer (p)
		p += sprintf(p, "%s", name); // print new name in place of oldname
		src = p2 + l2;  // move src to end of oldname
	}
	sprintf(p, "%s", src);  // copy the rest of src
	return ret;
}

/*
 * attach_block_device returns true if all went well,
 * meaning either a block device was attached or was not
 * needed.  It returns false if something went wrong and
 * container startup should be stopped.
 */
bool attach_block_device(struct lxc_conf *conf)
{
	char *path;

	if (!conf->rootfs.path)
		return true;
	path = conf->rootfs.path;
	if (!requires_nbd(path))
		return true;
	path = strchr(path, ':');
	if (!path)
		return false;
	path++;
	if (!attach_nbd(path, conf))
		return false;
	return true;
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
		ERROR("original rootfs path %s doesn't include container name %s",
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
				WARN("Error creating '%s', continuing.", orig->dest);
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
	if (!bdevtype && !keepbdevtype && snap && strcmp(orig->type , "dir") == 0)
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

	new = bdev_get(bdevtype ? bdevtype : orig->type);
	if (!new) {
		ERROR("no such block device type: %s", bdevtype ? bdevtype : orig->type);
		bdev_put(orig);
		return NULL;
	}

	if (new->ops->clone_paths(orig, new, oldname, cname, oldpath, lxcpath,
				snap, newsize, c0->lxc_conf) < 0) {
		ERROR("failed getting pathnames for cloned storage: %s", src);
		goto err;
	}

	if (am_unpriv() && chown_mapped_root(new->src, c0->lxc_conf) < 0)
		WARN("Failed to update ownership of %s", new->dest);

	if (snap)
		return new;

	/*
	 * https://github.com/lxc/lxc/issues/131
	 * Use btrfs snapshot feature instead of rsync to restore if both orig and new are btrfs
	 */
	if (bdevtype &&
			strcmp(orig->type, "btrfs") == 0 && strcmp(new->type, "btrfs") == 0 &&
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
			ERROR("Error restoring %s to %s", orig->dest, new->dest);
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
		ret = userns_exec_1(c0->lxc_conf, rsync_rootfs_wrapper, &data);
	else
		ret = rsync_rootfs(&data);

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
			if ((bdev = do_bdev_create(dest, best_options[i], cname, specs)))
				return bdev;
		}
		return NULL;  // 'dir' should never fail, so this shouldn't happen
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

int bdev_destroy_wrapper(void *data)
{
	struct lxc_conf *conf = data;

	if (setgid(0) < 0) {
		ERROR("Failed to setgid to 0");
		return -1;
	}
	if (setgroups(0, NULL) < 0)
		WARN("Failed to clear groups");
	if (setuid(0) < 0) {
		ERROR("Failed to setuid to 0");
		return -1;
	}
	if (!bdev_destroy(conf))
		return -1;
	else
		return 0;
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

/*
 * return block size of dev->src in units of bytes
 */
int blk_getsize(struct bdev *bdev, uint64_t *size)
{
	int fd, ret;
	char *path = bdev->src;

	if (strcmp(bdev->type, "loop") == 0)
		path = bdev->src + 5;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;

	ret = ioctl(fd, BLKGETSIZE64, size); // size of device in bytes
	close(fd);
	return ret;
}

void detach_block_device(struct lxc_conf *conf)
{
	if (conf->nbd_idx != -1)
		detach_nbd_idx(conf->nbd_idx);
}

/*
 * Given a bdev (presumably blockdev-based), detect the fstype
 * by trying mounting (in a private mntns) it.
 * @bdev: bdev to investigate
 * @type: preallocated char* in which to write the fstype
 * @len: length of passed in char*
 * Returns length of fstype, of -1 on error
 */
int detect_fs(struct bdev *bdev, char *type, int len)
{
	int  p[2], ret;
	size_t linelen;
	pid_t pid;
	FILE *f;
	char *sp1, *sp2, *sp3, *line = NULL;
	char *srcdev;

	if (!bdev || !bdev->src || !bdev->dest)
		return -1;

	srcdev = bdev->src;
	if (strcmp(bdev->type, "loop") == 0)
		srcdev = bdev->src + 5;

	ret = pipe(p);
	if (ret < 0)
		return -1;
	if ((pid = fork()) < 0)
		return -1;
	if (pid > 0) {
		int status;
		close(p[1]);
		memset(type, 0, len);
		ret = read(p[0], type, len - 1);
		close(p[0]);
		if (ret < 0) {
			SYSERROR("error reading from pipe");
			wait(&status);
			return -1;
		} else if (ret == 0) {
			ERROR("child exited early - fstype not found");
			wait(&status);
			return -1;
		}
		wait(&status);
		type[len - 1] = '\0';
		INFO("detected fstype %s for %s", type, srcdev);
		return ret;
	}

	if (unshare(CLONE_NEWNS) < 0)
		exit(1);

	if (detect_shared_rootfs()) {
		if (mount(NULL, "/", NULL, MS_SLAVE|MS_REC, NULL)) {
			SYSERROR("Failed to make / rslave");
			ERROR("Continuing...");
		}
	}

	ret = mount_unknown_fs(srcdev, bdev->dest, bdev->mntopts);
	if (ret < 0) {
		ERROR("failed mounting %s onto %s to detect fstype", srcdev, bdev->dest);
		exit(1);
	}
	// if symlink, get the real dev name
	char devpath[MAXPATHLEN];
	char *l = linkderef(srcdev, devpath);
	if (!l)
		exit(1);
	f = fopen("/proc/self/mounts", "r");
	if (!f)
		exit(1);
	while (getline(&line, &linelen, f) != -1) {
		sp1 = strchr(line, ' ');
		if (!sp1)
			exit(1);
		*sp1 = '\0';
		if (strcmp(line, l))
			continue;
		sp2 = strchr(sp1 + 1, ' ');
		if (!sp2)
			exit(1);
		*sp2 = '\0';
		sp3 = strchr(sp2 + 1, ' ');
		if (!sp3)
			exit(1);
		*sp3 = '\0';
		sp2++;
		if (write(p[1], sp2, strlen(sp2)) != strlen(sp2))
			exit(1);
		exit(0);
	}
	exit(1);
}

int do_mkfs(const char *path, const char *fstype)
{
	pid_t pid;

	if ((pid = fork()) < 0) {
		ERROR("error forking");
		return -1;
	}
	if (pid > 0)
		return wait_for_pid(pid);

	// If the file is not a block device, we don't want mkfs to ask
	// us about whether to proceed.
	if (null_stdfds() < 0)
		exit(1);
	execlp("mkfs", "mkfs", "-t", fstype, path, (char *)NULL);
	exit(1);
}

/*
 * This will return 1 for physical disks, qemu-nbd, loop, etc right now only lvm
 * is a block device.
 */
int is_blktype(struct bdev *b)
{
	if (strcmp(b->type, "lvm") == 0)
		return 1;
	return 0;
}

int mount_unknown_fs(const char *rootfs, const char *target,
		const char *options)
{
	struct cbarg {
		const char *rootfs;
		const char *target;
		const char *options;
	} cbarg = {
		.rootfs = rootfs,
		.target = target,
		.options = options,
	};

	/*
	 * find the filesystem type with brute force:
	 * first we check with /etc/filesystems, in case the modules
	 * are auto-loaded and fall back to the supported kernel fs
	 */
	char *fsfile[] = {
		"/etc/filesystems",
		"/proc/filesystems",
	};

	size_t i;
	for (i = 0; i < sizeof(fsfile) / sizeof(fsfile[0]); i++) {

		int ret;

		if (access(fsfile[i], F_OK))
			continue;

		ret = lxc_file_for_each_line(fsfile[i], find_fstype_cb, &cbarg);
		if (ret < 0) {
			ERROR("failed to parse '%s'", fsfile[i]);
			return -1;
		}

		if (ret)
			return 0;
	}

	ERROR("failed to determine fs type for '%s'", rootfs);
	return -1;
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

static struct bdev *do_bdev_create(const char *dest, const char *type,
		const char *cname, struct bdev_specs *specs)
{

	struct bdev *bdev = bdev_get(type);
	if (!bdev) {
		return NULL;
	}

	if (bdev->ops->create(bdev, dest, cname, specs) < 0) {
		 bdev_put(bdev);
		 return NULL;
	}

	return bdev;
}

static struct bdev *bdev_get(const char *type)
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

static const struct bdev_type *get_bdev_by_name(const char *name)
{
	size_t i;

	for (i = 0; i < numbdevs; i++) {
		if (strcmp(bdevs[i].name, name) == 0)
			return &bdevs[i];
	}

	ERROR("Backing store %s unknown but not caught earlier\n", name);
	return NULL;
}

static const struct bdev_type *bdev_query(struct lxc_conf *conf, const char *src)
{
	size_t i;

	if (conf->rootfs.bdev_type)
		return get_bdev_by_name(conf->rootfs.bdev_type);

	for (i = 0; i < numbdevs; i++) {
		int r;
		r = bdevs[i].ops->detect(src);
		if (r)
			break;
	}

	if (i == numbdevs)
		return NULL;
	return &bdevs[i];
}

/*
 * These are copied from conf.c.  However as conf.c will be moved to using
 * the callback system, they can be pulled from there eventually, so we
 * don't need to pollute utils.c with these low level functions
 */
static int find_fstype_cb(char* buffer, void *data)
{
	struct cbarg {
		const char *rootfs;
		const char *target;
		const char *options;
	} *cbarg = data;

	unsigned long mntflags;
	char *mntdata;
	char *fstype;

	/* we don't try 'nodev' entries */
	if (strstr(buffer, "nodev"))
		return 0;

	fstype = buffer;
	fstype += lxc_char_left_gc(fstype, strlen(fstype));
	fstype[lxc_char_right_gc(fstype, strlen(fstype))] = '\0';

	DEBUG("trying to mount '%s'->'%s' with fstype '%s'",
	      cbarg->rootfs, cbarg->target, fstype);

	if (parse_mntopts(cbarg->options, &mntflags, &mntdata) < 0) {
		free(mntdata);
		return 0;
	}

	if (mount(cbarg->rootfs, cbarg->target, fstype, mntflags, mntdata)) {
		DEBUG("mount failed with error: %s", strerror(errno));
		free(mntdata);
		return 0;
	}

	free(mntdata);

	INFO("mounted '%s' on '%s', with fstype '%s'",
	     cbarg->rootfs, cbarg->target, fstype);

	return 1;
}

static char *linkderef(char *path, char *dest)
{
	struct stat sbuf;
	ssize_t ret;

	ret = stat(path, &sbuf);
	if (ret < 0)
		return NULL;
	if (!S_ISLNK(sbuf.st_mode))
		return path;
	ret = readlink(path, dest, MAXPATHLEN);
	if (ret < 0) {
		SYSERROR("error reading link %s", path);
		return NULL;
	} else if (ret >= MAXPATHLEN) {
		ERROR("link in %s too long", path);
		return NULL;
	}
	dest[ret] = '\0';
	return dest;
}

/*
 * is an unprivileged user allowed to make this kind of snapshot
 */
static bool unpriv_snap_allowed(struct bdev *b, const char *t, bool snap,
		bool maybesnap)
{
	if (!t) {
		// new type will be same as original
		// (unless snap && b->type == dir, in which case it will be
		// overlayfs -- which is also allowed)
		if (strcmp(b->type, "dir") == 0 ||
				strcmp(b->type, "aufs") == 0 ||
				strcmp(b->type, "overlayfs") == 0 ||
				strcmp(b->type, "btrfs") == 0 ||
				strcmp(b->type, "loop") == 0)
			return true;
		return false;
	}

	// unprivileged users can copy and snapshot dir, overlayfs,
	// and loop.  In particular, not zfs, btrfs, or lvm.
	if (strcmp(t, "dir") == 0 ||
		strcmp(t, "aufs") == 0 ||
		strcmp(t, "overlayfs") == 0 ||
		strcmp(t, "btrfs") == 0 ||
		strcmp(t, "loop") == 0)
		return true;
	return false;
}

bool is_valid_bdev_type(const char *type)
{
	if (strcmp(type, "dir") == 0 ||
			strcmp(type, "btrfs") == 0 ||
			strcmp(type, "aufs") == 0 ||
			strcmp(type, "loop") == 0 ||
			strcmp(type, "lvm") == 0 ||
			strcmp(type, "nbd") == 0 ||
			strcmp(type, "overlayfs") == 0 ||
			strcmp(type, "rbd") == 0 ||
			strcmp(type, "zfs") == 0)
		return true;
	return false;
}

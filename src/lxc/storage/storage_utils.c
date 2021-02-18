/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <ctype.h>
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

#include "config.h"
#include "log.h"
#include "nbd.h"
#include "parse.h"
#include "storage.h"
#include "storage_utils.h"
#include "syscall_wrappers.h"
#include "utils.h"

#ifndef HAVE_STRLCPY
#include "include/strlcpy.h"
#endif

#ifndef BLKGETSIZE64
#define BLKGETSIZE64 _IOR(0x12, 114, size_t)
#endif

lxc_log_define(storage_utils, lxc);

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

/*
 * return block size of dev->src in units of bytes
 */
int blk_getsize(struct lxc_storage *bdev, uint64_t *size)
{
	int fd, ret;
	const char *src;

	src = lxc_storage_get_path(bdev->src, bdev->type);

	fd = open(src, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		SYSERROR("Failed to open \"%s\"", src);
		return -1;
	}

	/* size of device in bytes */
	ret = ioctl(fd, BLKGETSIZE64, size);
	if (ret < 0)
		SYSERROR("Failed to get block size of dev-src");

	close(fd);
	return ret;
}

void detach_block_device(struct lxc_conf *conf)
{
	if (conf->nbd_idx != -1)
		detach_nbd_idx(conf->nbd_idx);
}

/*
 * Given a lxc_storage (presumably blockdev-based), detect the fstype
 * by trying mounting (in a private mntns) it.
 * @lxc_storage: bdev to investigate
 * @type: preallocated char* in which to write the fstype
 * @len: length of passed in char*
 * Returns length of fstype, of -1 on error
 */
int detect_fs(struct lxc_storage *bdev, char *type, int len)
{
	int ret;
	int p[2];
	size_t linelen;
	pid_t pid;
	FILE *f;
	char *sp1, *sp2, *sp3;
	const char *l, *srcdev;
	char devpath[PATH_MAX];
	char *line = NULL;

	if (!bdev || !bdev->src || !bdev->dest)
		return -1;

	srcdev = lxc_storage_get_path(bdev->src, bdev->type);

	ret = pipe(p);
	if (ret < 0) {
		SYSERROR("Failed to create pipe");
		return -1;
	}

	pid = fork();
	if (pid < 0) {
		SYSERROR("Failed to fork process");
		return -1;
	}

	if (pid > 0) {
		int status;

		close(p[1]);
		memset(type, 0, len);

		ret = read(p[0], type, len - 1);
		if (ret < 0) {
			SYSERROR("Failed to read FSType from pipe");
		} else if (ret == 0) {
			ERROR("FSType not found - child exited early");
			ret = -1;
		}

		close(p[0]);
		wait(&status);

		if (ret < 0)
			return ret;

		type[len - 1] = '\0';
		INFO("Detected FSType \"%s\" for \"%s\"", type, srcdev);

		return ret;
	}

	if (unshare(CLONE_NEWNS) < 0)
		_exit(EXIT_FAILURE);

	if (detect_shared_rootfs() && mount(NULL, "/", NULL, MS_SLAVE | MS_REC, NULL))
		SYSERROR("Failed to recursively turn root mount tree into dependent mount. Continuing...");

	ret = mount_unknown_fs(srcdev, bdev->dest, bdev->mntopts);
	if (ret < 0) {
		ERROR("Failed to mount \"%s\" onto \"%s\" to detect FSType", srcdev,
		      bdev->dest);
		_exit(EXIT_FAILURE);
	}

	l = linkderef(srcdev, devpath);
	if (!l)
		_exit(EXIT_FAILURE);

	f = fopen("/proc/self/mounts", "r");
	if (!f)
		_exit(EXIT_FAILURE);

	while (getline(&line, &linelen, f) != -1) {
		sp1 = strchr(line, ' ');
		if (!sp1)
			_exit(EXIT_FAILURE);

		*sp1 = '\0';
		if (strcmp(line, l))
			continue;

		sp2 = strchr(sp1 + 1, ' ');
		if (!sp2)
			_exit(EXIT_FAILURE);
		*sp2 = '\0';

		sp3 = strchr(sp2 + 1, ' ');
		if (!sp3)
			_exit(EXIT_FAILURE);
		*sp3 = '\0';

		sp2++;
		if (write(p[1], sp2, strlen(sp2)) != strlen(sp2))
			_exit(EXIT_FAILURE);

		_exit(EXIT_SUCCESS);
	}

	_exit(EXIT_FAILURE);
}

int do_mkfs_exec_wrapper(void *args)
{
	int ret;
	char *mkfs;
	char **data = args;
	/* strlen("mkfs.")
	 * +
	 * strlen(data[0])
	 * +
	 * \0
	 */
	size_t len = 5 + strlen(data[0]) + 1;

	mkfs = malloc(len);
	if (!mkfs)
		return -1;

	ret = snprintf(mkfs, len, "mkfs.%s", data[0]);
	if (ret < 0 || (size_t)ret >= len) {
		free(mkfs);
		return -1;
	}

	TRACE("Executing \"%s %s\"", mkfs, data[1]);
	execlp(mkfs, mkfs, data[1], (char *)NULL);

	SYSERROR("Failed to run \"%s %s\"", mkfs, data[1]);
	free(mkfs);

	return -1;
}

/*
 * This will return 1 for physical disks, qemu-nbd, loop, etc right now only lvm
 * is a block device.
 */
int is_blktype(struct lxc_storage *b)
{
	if (strcmp(b->type, "lvm") == 0)
		return 1;

	return 0;
}

int mount_unknown_fs(const char *rootfs, const char *target,
		     const char *options)
{
	size_t i;
	int ret;
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

	for (i = 0; i < sizeof(fsfile) / sizeof(fsfile[0]); i++) {
		if (access(fsfile[i], F_OK))
			continue;

		ret = lxc_file_for_each_line(fsfile[i], find_fstype_cb, &cbarg);
		if (ret < 0) {
			ERROR("Failed to parse \"%s\"", fsfile[i]);
			return -1;
		}

		if (ret)
			return 0;
	}

	ERROR("Failed to determine FSType for \"%s\"", rootfs);

	return -1;
}

/*
 * These are copied from conf.c.  However as conf.c will be moved to using
 * the callback system, they can be pulled from there eventually, so we
 * don't need to pollute utils.c with these low level functions
 */
int find_fstype_cb(char *buffer, void *data)
{
	struct cbarg {
		const char *rootfs;
		const char *target;
		const char *options;
	} *cbarg = data;
	unsigned long mntflags = 0;
	char *mntdata = NULL;
	char *fstype;

	/* we don't try 'nodev' entries */
	if (strstr(buffer, "nodev"))
		return 0;

	fstype = buffer;
	fstype += lxc_char_left_gc(fstype, strlen(fstype));
	fstype[lxc_char_right_gc(fstype, strlen(fstype))] = '\0';

	DEBUG("Trying to mount \"%s\"->\"%s\" with FSType \"%s\"", cbarg->rootfs,
	      cbarg->target, fstype);

	if (parse_mntopts(cbarg->options, &mntflags, &mntdata) < 0) {
		free(mntdata);
		return 0;
	}

	if (mount(cbarg->rootfs, cbarg->target, fstype, mntflags, mntdata)) {
		SYSDEBUG("Failed to mount");
		free(mntdata);
		return 0;
	}

	free(mntdata);

	INFO("Mounted \"%s\" on \"%s\", with FSType \"%s\"", cbarg->rootfs,
	     cbarg->target, fstype);

	return 1;
}

const char *linkderef(const char *path, char *dest)
{
	struct stat sbuf;
	ssize_t ret;

	ret = stat(path, &sbuf);
	if (ret < 0) {
		SYSERROR("Failed to get status of file - \"%s\"", path);
		return NULL;
	}

	if (!S_ISLNK(sbuf.st_mode))
		return path;

	ret = readlink(path, dest, PATH_MAX);
	if (ret < 0) {
		SYSERROR("Failed to read link of \"%s\"", path);
		return NULL;
	} else if (ret >= PATH_MAX) {
		ERROR("The name of link of \"%s\" is too long", path);
		return NULL;
	}
	dest[ret] = '\0';

	return dest;
}

/*
 * is an unprivileged user allowed to make this kind of snapshot
 */
bool unpriv_snap_allowed(struct lxc_storage *b, const char *t, bool snap,
			 bool maybesnap)
{
	if (!t) {
		/* New type will be same as original (unless snap && b->type ==
		 * dir, in which case it will be overlayfs -- which is also
		 * allowed).
		 */
		if (strcmp(b->type, "dir") == 0 ||
		    strcmp(b->type, "overlay") == 0 ||
		    strcmp(b->type, "overlayfs") == 0 ||
		    strcmp(b->type, "btrfs") == 0 ||
		    strcmp(b->type, "loop") == 0)
			return true;

		return false;
	}

	/* Unprivileged users can copy and snapshot dir, overlayfs, and loop.
	 * In particular, not zfs, btrfs, or lvm.
	 */
	if (strcmp(t, "dir") == 0 ||
	    strcmp(t, "overlay") == 0 ||
	    strcmp(t, "overlayfs") == 0 ||
	    strcmp(t, "btrfs") == 0 ||
	    strcmp(t, "loop") == 0)
		return true;

	return false;
}

uint64_t get_fssize(char *s)
{
	uint64_t ret;
	char *end;

	ret = strtoull(s, &end, 0);
	if (end == s) {
		ERROR("Invalid blockdev size '%s', using default size", s);
		return 0;
	}

	while (isblank(*end))
		end++;

	if (*end == '\0') {
		ret *= 1024ULL * 1024ULL; /* MB by default */
	} else if (*end == 'b' || *end == 'B') {
		ret *= 1ULL;
	} else if (*end == 'k' || *end == 'K') {
		ret *= 1024ULL;
	} else if (*end == 'm' || *end == 'M') {
		ret *= 1024ULL * 1024ULL;
	} else if (*end == 'g' || *end == 'G') {
		ret *= 1024ULL * 1024ULL * 1024ULL;
	} else if (*end == 't' || *end == 'T') {
		ret *= 1024ULL * 1024ULL * 1024ULL * 1024ULL;
	} else {
		ERROR("Invalid blockdev unit size '%c' in '%s', using default size", *end, s);
		return 0;
	}

	return ret;
}

bool is_valid_storage_type(const char *type)
{
	if (strcmp(type, "dir") == 0 ||
	    strcmp(type, "btrfs") == 0 ||
	    strcmp(type, "loop") == 0 ||
	    strcmp(type, "lvm") == 0 ||
	    strcmp(type, "nbd") == 0 ||
	    strcmp(type, "overlay") == 0 ||
	    strcmp(type, "overlayfs") == 0 ||
	    strcmp(type, "rbd") == 0 ||
	    strcmp(type, "zfs") == 0)
		return true;

	return false;
}

int storage_destroy_wrapper(void *data)
{
	struct lxc_conf *conf = data;

	(void)lxc_drop_groups();

	if (setgid(0) < 0) {
		SYSERROR("Failed to setgid to 0");
		return -1;
	}

	if (setuid(0) < 0) {
		SYSERROR("Failed to setuid to 0");
		return -1;
	}

	if (!storage_destroy(conf)) {
		ERROR("Failed to destroy storage");
		return -1;
	}

	return 0;
}

/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "log.h"
#include "macro.h"
#include "memory_utils.h"
#include "mount_utils.h"
#include "syscall_numbers.h"
#include "syscall_wrappers.h"

lxc_log_define(mount_utils, lxc);

int mnt_attributes_new(unsigned int old_flags, unsigned int *new_flags)
{
	unsigned int flags = 0;

	if (old_flags & MS_RDONLY) {
		flags |= MOUNT_ATTR_RDONLY;
		old_flags &= ~MS_RDONLY;
	}

	if (old_flags & MS_NOSUID) {
		flags |= MOUNT_ATTR_NOSUID;
		old_flags &= ~MS_NOSUID;
	}

	if (old_flags & MS_NODEV) {
		flags |= MOUNT_ATTR_NODEV;
		old_flags &= ~MS_NODEV;
	}

	if (old_flags & MS_NOEXEC) {
		flags |= MOUNT_ATTR_NOEXEC;
		old_flags &= ~MS_NOEXEC;
	}

	if (old_flags & MS_RELATIME) {
		flags |= MOUNT_ATTR_RELATIME;
		old_flags &= ~MS_RELATIME;
	}

	if (old_flags & MS_NOATIME) {
		flags |= MOUNT_ATTR_NOATIME;
		old_flags &= ~MS_NOATIME;
	}

	if (old_flags & MS_STRICTATIME) {
		flags |= MOUNT_ATTR_STRICTATIME;
		old_flags &= ~MS_STRICTATIME;
	}

	if (old_flags & MS_NODIRATIME) {
		flags |= MOUNT_ATTR_NODIRATIME;
		old_flags &= ~MS_NODIRATIME;
	}

	*new_flags |= flags;
	return old_flags;
}

int mnt_attributes_old(unsigned int new_flags, unsigned int *old_flags)
{
	unsigned int flags = 0;

	if (new_flags & MOUNT_ATTR_RDONLY) {
		flags |= MS_RDONLY;
		new_flags &= ~MOUNT_ATTR_RDONLY;
	}

	if (new_flags & MOUNT_ATTR_NOSUID) {
		flags |= MS_NOSUID;
		new_flags &= ~MOUNT_ATTR_NOSUID;
	}

	if (new_flags & MS_NODEV) {
		flags |= MOUNT_ATTR_NODEV;
		new_flags &= ~MS_NODEV;
	}

	if (new_flags & MOUNT_ATTR_NOEXEC) {
		flags |= MS_NOEXEC;
		new_flags &= ~MOUNT_ATTR_NOEXEC;
	}

	if (new_flags & MS_RELATIME) {
		flags |= MS_RELATIME;
		new_flags &= ~MOUNT_ATTR_RELATIME;
	}

	if (new_flags & MS_NOATIME) {
		flags |= MS_NOATIME;
		new_flags &= ~MOUNT_ATTR_NOATIME;
	}

	if (new_flags & MS_STRICTATIME) {
		flags |= MS_STRICTATIME;
		new_flags &= ~MOUNT_ATTR_STRICTATIME;
	}

	if (new_flags & MS_NODIRATIME) {
		flags |= MS_NODIRATIME;
		new_flags &= ~MOUNT_ATTR_NODIRATIME;
	}

	*old_flags |= flags;
	return new_flags;
}

int mount_filesystem(const char *fs_name, const char *path, unsigned int attr_flags)
{
	__do_close int fsfd = -EBADF;
	unsigned int old_flags = 0;

	fsfd = fsopen(fs_name, FSOPEN_CLOEXEC);
	if (fsfd >= 0) {
		__do_close int mfd = -EBADF;

		if (fsconfig(fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0))
			return -1;

		mfd = fsmount(fsfd, FSMOUNT_CLOEXEC, attr_flags);
		if (mfd < 0)
			return -1;

		return move_mount(mfd, "", AT_FDCWD, path, MOVE_MOUNT_F_EMPTY_PATH);
	}

	TRACE("Falling back to old mount api");
	mnt_attributes_old(attr_flags, &old_flags);
	return mount("none", path, fs_name, old_flags, NULL);
}

static int __fs_prepare(const char *fs_name, int fd_from)
{
	__do_close int fd_fs = -EBADF;
	char source[LXC_PROC_PID_FD_LEN];
	int ret;

	/* This helper is only concerned with filesystems. */
	if (is_empty_string(fs_name))
		return ret_errno(EINVAL);

	/*
	 * So here is where I'm a bit disappointed. The new mount api doesn't
	 * let you specify the block device source through an fd. You need to
	 * pass a path which is obviously crap and runs afoul of the mission to
	 * only use fds for mount.
	 */
	if (fd_from >= 0) {
		ret = snprintf(source, sizeof(source), "/proc/self/fd/%d", fd_from);
		if (ret < 0 || ret >= sizeof(source))
			return log_error_errno(-EIO, EIO, "Failed to create /proc/self/fd/%d", fd_from);
	}

	fd_fs = fsopen(fs_name, FSOPEN_CLOEXEC);
	if (fd_fs < 0)
		return log_error_errno(-errno, errno, "Failed to create new open new %s filesystem context", fs_name);

	if (fd_from >= 0) {
		ret = fsconfig(fd_fs, FSCONFIG_SET_STRING, "source", source, 0);
		if (ret)
			return log_error_errno(-errno, errno, "Failed to set %s filesystem source to %s", fs_name, source);

		TRACE("Set %s filesystem source property to %s", fs_name, source);
	}

	TRACE("Finished initializing new %s filesystem context %d", fs_name, fd_fs);
	return move_fd(fd_fs);
}

int fs_prepare(const char *fs_name,
	       int dfd_from, const char *path_from,
	       __u64 o_flags_from, __u64 resolve_flags_from)
{
	__do_close int __fd_from = -EBADF;
	int fd_from;

	if (!is_empty_string(path_from)) {
		struct lxc_open_how how = {
			.flags		= o_flags_from,
			.resolve	= resolve_flags_from,
		};

		__fd_from = openat2(dfd_from, path_from, &how, sizeof(how));
		if (__fd_from < 0)
			return -errno;
		fd_from = __fd_from;
	} else {
		fd_from = dfd_from;
	}

	return __fs_prepare(fs_name, fd_from);
}

int fs_set_property(int fd_fs, const char *key, const char *val)
{
	int ret;

	ret = fsconfig(fd_fs, FSCONFIG_SET_STRING, key, val, 0);
	if (ret < 0)
		return log_error_errno(-errno, errno,
				       "Failed to set \"%s\" to \"%s\" on filesystem context %d",
				       key, val, fd_fs);

	TRACE("Set \"%s\" to \"%s\" on filesystem context %d", key, val, fd_fs);
	return 0;
}

int fs_attach(int fd_fs,
	      int dfd_to, const char *path_to,
	      __u64 o_flags_to, __u64 resolve_flags_to,
	      unsigned int attr_flags)
{
	__do_close int __fd_to = -EBADF, fd_fsmnt = -EBADF;
	int fd_to, ret;

	if (!is_empty_string(path_to)) {
		struct lxc_open_how how = {
			.flags		= o_flags_to,
			.resolve	= resolve_flags_to,
		};

		__fd_to = openat2(dfd_to, path_to, &how, sizeof(how));
		if (__fd_to < 0)
			return -errno;
		fd_to = __fd_to;
	} else {
		fd_to = dfd_to;
	}

	ret = fsconfig(fd_fs, FSCONFIG_CMD_CREATE, NULL, NULL, 0);
	if (ret < 0)
		return log_error_errno(-errno, errno, "Failed to finalize filesystem context %d", fd_fs);

	fd_fsmnt = fsmount(fd_fs, FSMOUNT_CLOEXEC, attr_flags);
	if (fd_fsmnt < 0)
		return log_error_errno(-errno, errno,
				       "Failed to create new mount for filesystem context %d", fd_fs);

	ret = move_mount(fd_fsmnt, "", fd_to, "", MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH);
	if (ret)
		return log_error_errno(-errno, errno, "Failed to mount %d onto %d", fd_fsmnt, fd_to);

	TRACE("Mounted %d onto %d", fd_fsmnt, fd_to);
	return 0;
}

int mount_from_at(int dfd_from, const char *path_from,
		  __u64 o_flags_from,
		  __u64 resolve_flags_from,
		  int dfd_to, const char *path_to,
		  __u64 o_flags_to,
		  __u64 resolve_flags_to,
		  const char *fstype, unsigned int mnt_flags, const void *data)
{
	__do_close int fd_from = -EBADF, fd_to = -EBADF;
	struct lxc_open_how how = {};
	int ret;
	char src_buf[LXC_PROC_PID_FD_LEN], dst_buf[LXC_PROC_PID_FD_LEN];

	if (is_empty_string(path_from)) {
		ret = snprintf(src_buf, sizeof(src_buf), "/proc/self/fd/%d", dfd_from);
	} else {
		how.flags	= o_flags_from;
		how.resolve	= resolve_flags_from;
		fd_from = openat2(dfd_from, path_from, &how, sizeof(how));
		if (fd_from < 0)
			return -errno;

		ret = snprintf(src_buf, sizeof(src_buf), "/proc/self/fd/%d", fd_from);
	}
	if (ret < 0 || ret >= sizeof(src_buf))
		return -EIO;

	if (is_empty_string(path_to)) {
		ret = snprintf(dst_buf, sizeof(dst_buf), "/proc/self/fd/%d", dfd_to);
	} else {
		how.flags	= o_flags_to;
		how.resolve	= resolve_flags_to;
		fd_to = openat2(dfd_to, path_to, &how, sizeof(how));
		if (fd_to < 0)
			return -errno;

		ret = snprintf(dst_buf, sizeof(dst_buf), "/proc/self/fd/%d", fd_to);
	}
	if (ret < 0 || ret >= sizeof(src_buf))
		return -EIO;

	if (is_empty_string(src_buf))
		ret = mount(NULL, dst_buf, fstype, mnt_flags, data);
	else
		ret = mount(src_buf, dst_buf, fstype, mnt_flags, data);

	return ret;
}

int fd_bind_mount(int dfd_from, const char *path_from,
		  __u64 o_flags_from, __u64 resolve_flags_from,
		  int dfd_to, const char *path_to,
		  __u64 o_flags_to, __u64 resolve_flags_to,
		  unsigned int attr_flags, bool recursive)
{
	__do_close int __fd_from = -EBADF, __fd_to = -EBADF;
	__do_close int fd_tree_from = -EBADF;
	unsigned int open_tree_flags = AT_EMPTY_PATH | OPEN_TREE_CLONE | OPEN_TREE_CLONE;
	int fd_from, fd_to, ret;

	if (!is_empty_string(path_from)) {
		struct lxc_open_how how = {
			.flags		= o_flags_from,
			.resolve	= resolve_flags_from,
		};

		__fd_from = openat2(dfd_from, path_from, &how, sizeof(how));
		if (__fd_from < 0)
			return -errno;
		fd_from = __fd_from;
	} else {
		fd_from = dfd_from;
	}

	if (recursive)
		open_tree_flags |= AT_RECURSIVE;

	fd_tree_from = open_tree(fd_from, "", open_tree_flags);
	if (fd_tree_from < 0)
		return log_error_errno(-errno, errno, "Failed to create detached mount");

	if (!is_empty_string(path_to)) {
		struct lxc_open_how how = {
			.flags		= o_flags_to,
			.resolve	= resolve_flags_to,
		};

		__fd_to = openat2(dfd_to, path_to, &how, sizeof(how));
		if (__fd_to < 0)
			return -errno;
		fd_to = __fd_to;
	} else {
		fd_to = dfd_to;
	}

	ret = move_mount(fd_tree_from, "", fd_to, "", MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH);
	if (ret)
		return log_error_errno(-errno, errno, "Failed to attach detached mount %d to filesystem at %d", fd_tree_from, fd_to);

	TRACE("Attach detached mount %d to filesystem at %d", fd_tree_from, fd_to);
	return 0;
}

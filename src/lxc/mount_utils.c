/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <fcntl.h>
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

int mount_at(int dfd,
	     const char *src_under_dfd,
	     const char *dst_under_dfd,
	     __u64 o_flags,
	     __u64 resolve_flags,
	     const char *fstype,
	     unsigned int mnt_flags,
	     const void *data)
{
	__do_close int source_fd = -EBADF, target_fd = -EBADF;
	struct lxc_open_how how = {
		.flags		= o_flags,
		.resolve	= resolve_flags,
	};
	int ret;
	char src_buf[LXC_PROC_PID_FD_LEN], dst_buf[LXC_PROC_PID_FD_LEN];

	if (dfd < 0)
		return ret_errno(EINVAL);

	if (!is_empty_string(src_buf) && *src_buf == '/')
		return log_error_errno(-EINVAL, EINVAL, "Absolute path specified");

	if (!is_empty_string(src_under_dfd)) {
		source_fd = openat2(dfd, src_under_dfd, &how, sizeof(how));
		if (source_fd < 0)
			return -errno;

		ret = snprintf(src_buf, sizeof(src_buf), "/proc/self/fd/%d", source_fd);
		if (ret < 0 || ret >= sizeof(src_buf))
			return -EIO;
	}

	if (!is_empty_string(dst_under_dfd)) {
		target_fd = openat2(dfd, dst_under_dfd, &how, sizeof(how));
		if (target_fd < 0)
			return log_error_errno(-errno, errno, "Failed to open %d(%s)", dfd, dst_under_dfd);

		TRACE("Mounting %d(%s) through /proc/self/fd/%d", target_fd, dst_under_dfd, target_fd);
		ret = snprintf(dst_buf, sizeof(dst_buf), "/proc/self/fd/%d", target_fd);
	} else {
		TRACE("Mounting %d through /proc/self/fd/%d", dfd, dfd);
		ret = snprintf(dst_buf, sizeof(dst_buf), "/proc/self/fd/%d", dfd);
	}
	if (ret < 0 || ret >= sizeof(dst_buf))
		return -EIO;

	if (!is_empty_string(src_buf))
		ret = mount(src_buf, dst_buf, fstype, mnt_flags, data);
	else
		ret = mount(NULL, dst_buf, fstype, mnt_flags, data);

	return ret;
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

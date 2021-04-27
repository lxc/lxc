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

#include "file_utils.h"
#include "log.h"
#include "macro.h"
#include "memory_utils.h"
#include "mount_utils.h"
#include "syscall_numbers.h"
#include "syscall_wrappers.h"

#ifdef HAVE_STATVFS
#include <sys/statvfs.h>
#endif

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
		ret = strnprintf(source, sizeof(source), "/proc/self/fd/%d", fd_from);
		if (ret < 0)
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

int create_detached_idmapped_mount(const char *path, int userns_fd, bool recursive)
{
	__do_close int fd_tree_from = -EBADF;
	unsigned int open_tree_flags = OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC;
	struct lxc_mount_attr attr = {
		.attr_set	= MOUNT_ATTR_IDMAP,
		.userns_fd	= userns_fd,
		.propagation	= MS_SLAVE,

	};
	int ret;

	TRACE("Idmapped mount \"%s\" requested with user namespace fd %d", path, userns_fd);

	if (recursive)
		open_tree_flags |= AT_RECURSIVE;

	fd_tree_from = open_tree(-EBADF, path, open_tree_flags);
	if (fd_tree_from < 0)
		return syserror("Failed to create detached mount");

	ret = mount_setattr(fd_tree_from, "",
			    AT_EMPTY_PATH | (recursive ? AT_RECURSIVE : 0),
			    &attr, sizeof(attr));
	if (ret < 0)
		return syserror("Failed to change mount attributes");

	return move_fd(fd_tree_from);
}

int move_detached_mount(int dfd_from, int dfd_to, const char *path_to,
			__u64 o_flags_to, __u64 resolve_flags_to)
{
	__do_close int __fd_to = -EBADF;
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

	ret = move_mount(dfd_from, "", fd_to, "", MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH);
	if (ret)
		return syserror("Failed to attach detached mount %d to filesystem at %d", dfd_from, fd_to);

	TRACE("Attach detached mount %d to filesystem at %d", dfd_from, fd_to);
	return 0;
}

static int __fd_bind_mount(int dfd_from, const char *path_from,
			   __u64 o_flags_from, __u64 resolve_flags_from,
			   int dfd_to, const char *path_to, __u64 o_flags_to,
			   __u64 resolve_flags_to, unsigned int attr_flags,
			   int userns_fd, bool recursive)
{
	struct lxc_mount_attr attr = {
		.attr_set = attr_flags,
	};
	__do_close int __fd_from = -EBADF;
	__do_close int fd_tree_from = -EBADF;
	unsigned int open_tree_flags = AT_EMPTY_PATH | OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC;
	int fd_from, ret;

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
		return syserror("Failed to create detached mount");

	if (userns_fd >= 0) {
		attr.attr_set	|= MOUNT_ATTR_IDMAP;
		attr.userns_fd	= userns_fd;
		TRACE("Idmapped mount requested with user namespace fd %d", userns_fd);
	}

	if (attr.attr_set) {
		ret = mount_setattr(fd_tree_from, "",
				    AT_EMPTY_PATH | (recursive ? AT_RECURSIVE : 0),
				    &attr, sizeof(attr));
		if (ret < 0)
			return syserror("Failed to change mount attributes");
	}

	return move_detached_mount(fd_tree_from, dfd_to, path_to, o_flags_to,
				   resolve_flags_to);
}

int fd_mount_idmapped(int dfd_from, const char *path_from,
		      __u64 o_flags_from, __u64 resolve_flags_from,
		      int dfd_to, const char *path_to,
		      __u64 o_flags_to, __u64 resolve_flags_to,
		      unsigned int attr_flags, int userns_fd, bool recursive)
{
	return __fd_bind_mount(dfd_from, path_from, o_flags_from, resolve_flags_from,
			       dfd_to, path_to, o_flags_to, resolve_flags_to,
			       attr_flags, userns_fd, recursive);
}

int fd_bind_mount(int dfd_from, const char *path_from,
		  __u64 o_flags_from, __u64 resolve_flags_from,
		  int dfd_to, const char *path_to,
		  __u64 o_flags_to, __u64 resolve_flags_to,
		  unsigned int attr_flags, bool recursive)
{
	return __fd_bind_mount(dfd_from, path_from, o_flags_from, resolve_flags_from,
			       dfd_to, path_to, o_flags_to, resolve_flags_to,
			       attr_flags, -EBADF, recursive);
}

int calc_remount_flags_new(int dfd_from, const char *path_from,
			   __u64 o_flags_from, __u64 resolve_flags_from,
			   bool remount, unsigned long cur_flags,
			   unsigned int *new_flags)
{
#ifdef HAVE_STATVFS
	__do_close int fd_from = -EBADF;
	unsigned int new_required_flags = 0;
	int ret;
	struct statvfs sb;

	fd_from = open_at(dfd_from, path_from, o_flags_from, resolve_flags_from, 0);
	if (fd_from < 0)
		return log_error_errno(-errno, errno, "Failed to open %d(%s)", dfd_from, maybe_empty(path_from));

	ret = fstatvfs(dfd_from, &sb);
	if (ret < 0)
		return log_error_errno(-errno, errno, "Failed to retrieve mount information from %d(%s)", fd_from, maybe_empty(path_from));

	if (remount) {
		if (sb.f_flag & MS_NOSUID)
			new_required_flags |= MOUNT_ATTR_NOSUID;

		if (sb.f_flag & MS_NODEV)
			new_required_flags |= MOUNT_ATTR_NODEV;

		if (sb.f_flag & MS_RDONLY)
			new_required_flags |= MOUNT_ATTR_RDONLY;

		if (sb.f_flag & MS_NOEXEC)
			new_required_flags |= MOUNT_ATTR_NOEXEC;
	}

	if (sb.f_flag & MS_NOATIME)
		new_required_flags |= MOUNT_ATTR_NOATIME;

	if (sb.f_flag & MS_NODIRATIME)
		new_required_flags |= MOUNT_ATTR_NODIRATIME;

	if (sb.f_flag & MS_RELATIME)
		new_required_flags |= MOUNT_ATTR_RELATIME;

	if (sb.f_flag & MS_STRICTATIME)
		new_required_flags |= MOUNT_ATTR_STRICTATIME;

	*new_flags = (cur_flags | new_required_flags);
#endif
	return 0;
}

int calc_remount_flags_old(int dfd_from, const char *path_from,
			   __u64 o_flags_from, __u64 resolve_flags_from,
			   bool remount, unsigned long cur_flags,
			   unsigned int *old_flags)
{
#ifdef HAVE_STATVFS
	__do_close int fd_from = -EBADF;
	unsigned int old_required_flags = 0;
	int ret;
	struct statvfs sb;

	fd_from = open_at(dfd_from, path_from, o_flags_from, resolve_flags_from, 0);
	if (fd_from < 0)
		return log_error_errno(-errno, errno, "Failed to open %d(%s)", dfd_from, maybe_empty(path_from));

	ret = fstatvfs(dfd_from, &sb);
	if (ret < 0)
		return log_error_errno(-errno, errno, "Failed to retrieve mount information from %d(%s)", fd_from, maybe_empty(path_from));

	if (remount) {
		if (sb.f_flag & MS_NOSUID)
			old_required_flags |= MS_NOSUID;

		if (sb.f_flag & MS_NODEV)
			old_required_flags |= MS_NODEV;

		if (sb.f_flag & MS_RDONLY)
			old_required_flags |= MS_RDONLY;

		if (sb.f_flag & MS_NOEXEC)
			old_required_flags |= MS_NOEXEC;
	}

	if (sb.f_flag & MS_NOATIME)
		old_required_flags |= MS_NOATIME;

	if (sb.f_flag & MS_NODIRATIME)
		old_required_flags |= MS_NODIRATIME;

	if (sb.f_flag & MS_RELATIME)
		old_required_flags |= MS_RELATIME;

	if (sb.f_flag & MS_STRICTATIME)
		old_required_flags |= MS_STRICTATIME;

	*old_flags = (cur_flags | old_required_flags);
#endif
	return 0;
}

/* If we are asking to remount something, make sure that any NOEXEC etc are
 * honored.
 */
unsigned long add_required_remount_flags(const char *s, const char *d,
                                        unsigned long flags)
{
#ifdef HAVE_STATVFS
       int ret;
       struct statvfs sb;
       unsigned long required_flags = 0;

       if (!s)
               s = d;

       if (!s)
               return flags;

       ret = statvfs(s, &sb);
       if (ret < 0)
               return flags;

       if (flags & MS_REMOUNT) {
               if (sb.f_flag & MS_NOSUID)
                       required_flags |= MS_NOSUID;
               if (sb.f_flag & MS_NODEV)
                       required_flags |= MS_NODEV;
               if (sb.f_flag & MS_RDONLY)
                       required_flags |= MS_RDONLY;
               if (sb.f_flag & MS_NOEXEC)
                       required_flags |= MS_NOEXEC;
       }

       if (sb.f_flag & MS_NOATIME)
               required_flags |= MS_NOATIME;
       if (sb.f_flag & MS_NODIRATIME)
               required_flags |= MS_NODIRATIME;
       if (sb.f_flag & MS_LAZYTIME)
               required_flags |= MS_LAZYTIME;
       if (sb.f_flag & MS_RELATIME)
               required_flags |= MS_RELATIME;
       if (sb.f_flag & MS_STRICTATIME)
               required_flags |= MS_STRICTATIME;

       return flags | required_flags;
#else
       return flags;
#endif
}

bool can_use_mount_api(void)
{
	static int supported = -1;

	if (supported == -1) {
		__do_close int fd = -EBADF;

		fd = openat2(-EBADF, "", NULL, 0);
		if (fd > 0 || errno == ENOSYS) {
			supported = 0;
			return false;
		}

		fd = fsmount(-EBADF, 0, 0);
		if (fd > 0 || errno == ENOSYS) {
			supported = 0;
			return false;
		}

		fd = fsconfig(-EBADF, -EINVAL, NULL, NULL, 0);
		if (fd > 0 || errno == ENOSYS) {
			supported = 0;
			return false;
		}

		fd = fsopen(NULL, 0);
		if (fd > 0 || errno == ENOSYS) {
			supported = 0;
			return false;
		}

		fd = move_mount(-EBADF, NULL, -EBADF, NULL, 0);
		if (fd > 0 || errno == ENOSYS) {
			supported = 0;
			return false;
		}

		fd = open_tree(-EBADF, NULL, 0);
		if (fd > 0 || errno == ENOSYS) {
			supported = 0;
			return false;
		}

		supported = 1;
		TRACE("Kernel supports mount api");
	}

	return supported == 1;
}

bool can_use_bind_mounts(void)
{
	static int supported = -1;

	if (supported == -1) {
		int ret;

		if (!can_use_mount_api()) {
			supported = 0;
			return false;
		}

		ret = mount_setattr(-EBADF, NULL, 0, NULL, 0);
		if (!ret || errno == ENOSYS) {
			supported = 0;
			return false;
		}

		supported = 1;
		TRACE("Kernel supports bind mounts in the new mount api");
	}

	return supported == 1;
}

/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_MOUNT_UTILS_H
#define __LXC_MOUNT_UTILS_H

#include "config.h"

#include <linux/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>

#include "compiler.h"
#include "memory_utils.h"
#include "syscall_wrappers.h"

struct lxc_rootfs;

/* open_tree() flags */

#ifndef AT_RECURSIVE
#define AT_RECURSIVE 0x8000 /* Apply to the entire subtree */
#endif

#ifndef OPEN_TREE_CLONE
#define OPEN_TREE_CLONE 1
#endif

#ifndef OPEN_TREE_CLOEXEC
#define OPEN_TREE_CLOEXEC O_CLOEXEC
#endif

/* move_mount() flags */
#ifndef MOVE_MOUNT_F_SYMLINKS
#define MOVE_MOUNT_F_SYMLINKS 0x00000001 /* Follow symlinks on from path */
#endif

#ifndef MOVE_MOUNT_F_AUTOMOUNTS
#define MOVE_MOUNT_F_AUTOMOUNTS 0x00000002 /* Follow automounts on from path */
#endif

#ifndef MOVE_MOUNT_F_EMPTY_PATH
#define MOVE_MOUNT_F_EMPTY_PATH 0x00000004 /* Empty from path permitted */
#endif

#ifndef MOVE_MOUNT_T_SYMLINKS
#define MOVE_MOUNT_T_SYMLINKS 0x00000010 /* Follow symlinks on to path */
#endif

#ifndef MOVE_MOUNT_T_AUTOMOUNTS
#define MOVE_MOUNT_T_AUTOMOUNTS 0x00000020 /* Follow automounts on to path */
#endif

#ifndef MOVE_MOUNT_T_EMPTY_PATH
#define MOVE_MOUNT_T_EMPTY_PATH 0x00000040 /* Empty to path permitted */
#endif

#ifndef MOVE_MOUNT__MASK
#define MOVE_MOUNT__MASK 0x00000077
#endif

/* fsopen() flags */
#ifndef FSOPEN_CLOEXEC
#define FSOPEN_CLOEXEC 0x00000001
#endif

/* fspick() flags */
#ifndef FSPICK_CLOEXEC
#define FSPICK_CLOEXEC 0x00000001
#endif

#ifndef FSPICK_SYMLINK_NOFOLLOW
#define FSPICK_SYMLINK_NOFOLLOW 0x00000002
#endif

#ifndef FSPICK_NO_AUTOMOUNT
#define FSPICK_NO_AUTOMOUNT 0x00000004
#endif

#ifndef FSPICK_EMPTY_PATH
#define FSPICK_EMPTY_PATH 0x00000008
#endif

/* fsconfig() commands */
#if !HAVE_FSCONFIG_SET_FLAG
#ifndef FSCONFIG_SET_FLAG
#define FSCONFIG_SET_FLAG 0 /* Set parameter, supplying no value */
#endif
#endif

#if !HAVE_FSCONFIG_SET_STRING
#ifndef FSCONFIG_SET_STRING
#define FSCONFIG_SET_STRING 1 /* Set parameter, supplying a string value */
#endif
#endif

#if !HAVE_FSCONFIG_SET_BINARY
#ifndef FSCONFIG_SET_BINARY
#define FSCONFIG_SET_BINARY 2 /* Set parameter, supplying a binary blob value */
#endif
#endif

#if !HAVE_FSCONFIG_SET_PATH
#ifndef FSCONFIG_SET_PATH
#define FSCONFIG_SET_PATH 3 /* Set parameter, supplying an object by path */
#endif
#endif

#if !HAVE_FSCONFIG_SET_PATH_EMPTY
#ifndef FSCONFIG_SET_PATH_EMPTY
#define FSCONFIG_SET_PATH_EMPTY 4 /* Set parameter, supplying an object by (empty) path */
#endif
#endif

#if !HAVE_FSCONFIG_SET_FD
#ifndef FSCONFIG_SET_FD
#define FSCONFIG_SET_FD 5 /* Set parameter, supplying an object by fd */
#endif
#endif

#if !HAVE_FSCONFIG_CMD_CREATE
#ifndef FSCONFIG_CMD_CREATE
#define FSCONFIG_CMD_CREATE 6 /* Invoke superblock creation */
#endif
#endif

#if !HAVE_FSCONFIG_CMD_RECONFIGURE
#ifndef FSCONFIG_CMD_RECONFIGURE
#define	FSCONFIG_CMD_RECONFIGURE 7	/* Invoke superblock reconfiguration */
#endif
#endif

/* fsmount() flags */
#ifndef FSMOUNT_CLOEXEC
#define FSMOUNT_CLOEXEC 0x00000001
#endif

/* mount attributes */
#ifndef MOUNT_ATTR_RDONLY
#define MOUNT_ATTR_RDONLY 0x00000001 /* Mount read-only */
#endif

#ifndef MOUNT_ATTR_NOSUID
#define MOUNT_ATTR_NOSUID 0x00000002 /* Ignore suid and sgid bits */
#endif

#ifndef MOUNT_ATTR_NODEV
#define MOUNT_ATTR_NODEV 0x00000004 /* Disallow access to device special files */
#endif

#ifndef MOUNT_ATTR_NOEXEC
#define MOUNT_ATTR_NOEXEC 0x00000008 /* Disallow program execution */
#endif

#ifndef MOUNT_ATTR__ATIME
#define MOUNT_ATTR__ATIME 0x00000070 /* Setting on how atime should be updated */
#endif

#ifndef MOUNT_ATTR_RELATIME
#define MOUNT_ATTR_RELATIME 0x00000000 /* - Update atime relative to mtime/ctime. */
#endif

#ifndef MOUNT_ATTR_NOATIME
#define MOUNT_ATTR_NOATIME 0x00000010 /* - Do not update access times. */
#endif

#ifndef MOUNT_ATTR_STRICTATIME
#define MOUNT_ATTR_STRICTATIME 0x00000020 /* - Always perform atime updates */
#endif

#ifndef MOUNT_ATTR_NODIRATIME
#define MOUNT_ATTR_NODIRATIME 0x00000080 /* Do not update directory access times */
#endif

#ifndef MOUNT_ATTR_IDMAP
#define MOUNT_ATTR_IDMAP 0x00100000
#endif

#ifndef MOUNT_ATTR_NOSYMFOLLOW
#define MOUNT_ATTR_NOSYMFOLLOW 0x00200000 /* Do not follow symlinks */
#endif

#if !HAVE_MOVE_MOUNT
static inline int move_mount_lxc(int from_dfd, const char *from_pathname,
				 int to_dfd, const char *to_pathname,
				 unsigned int flags)
{
	return syscall(__NR_move_mount, from_dfd, from_pathname, to_dfd,
		       to_pathname, flags);
}
#define move_mount move_mount_lxc
#else
extern int move_mount(int from_dfd, const char *from_pathname, int to_dfd,
		      const char *to_pathname, unsigned int flags);
#endif

#if !HAVE_OPEN_TREE
static inline int open_tree_lxc(int dfd, const char *filename, unsigned int flags)
{
	return syscall(__NR_open_tree, dfd, filename, flags);
}
#define open_tree open_tree_lxc
#else
extern int open_tree(int dfd, const char *filename, unsigned int flags);
#endif

#if !HAVE_FSOPEN
static inline int fsopen_lxc(const char *fs_name, unsigned int flags)
{
	return syscall(__NR_fsopen, fs_name, flags);
}
#define fsopen fsopen_lxc
#else
extern int fsopen(const char *fs_name, unsigned int flags);
#endif

#if !HAVE_FSPICK
static inline int fspick_lxc(int dfd, const char *path, unsigned int flags)
{
	return syscall(__NR_fspick, dfd, path, flags);
}
#define fspick fspick_lxc
#else
extern int fspick(int dfd, const char *path, unsigned int flags);
#endif

#if !HAVE_FSCONFIG
static inline int fsconfig_lxc(int fd, unsigned int cmd, const char *key, const void *value, int aux)
{
	return syscall(__NR_fsconfig, fd, cmd, key, value, aux);
}
#define fsconfig fsconfig_lxc
#else
extern int fsconfig(int fd, unsigned int cmd, const char *key, const void *value, int aux);
#endif

#if !HAVE_FSMOUNT
static inline int fsmount_lxc(int fs_fd, unsigned int flags, unsigned int attr_flags)
{
	return syscall(__NR_fsmount, fs_fd, flags, attr_flags);
}
#define fsmount fsmount_lxc
#else
extern int fsmount(int fs_fd, unsigned int flags, unsigned int attr_flags);
#endif

/*
 * mount_setattr()
 */
#if !HAVE_STRUCT_MOUNT_ATTR
struct mount_attr {
	__u64 attr_set;
	__u64 attr_clr;
	__u64 propagation;
	__u64 userns_fd;
};
#endif

#if !HAVE_MOUNT_SETATTR
static inline int mount_setattr(int dfd, const char *path, unsigned int flags,
				struct mount_attr *attr, size_t size)
{
	return syscall(__NR_mount_setattr, dfd, path, flags, attr, size);
}
#endif

__hidden extern int mnt_attributes_new(unsigned int old_flags, unsigned int *new_flags);

__hidden extern int mnt_attributes_old(unsigned int new_flags, unsigned int *old_flags);

__hidden extern int fs_prepare(const char *fs_name, int dfd_from,
			       const char *path_from, __u64 o_flags_from,
			       __u64 resolve_flags_from);
__hidden extern int fs_set_property(int fd_fs, const char *key, const char *val);
__hidden extern int fs_set_flag(int fd_fs, const char *key);
__hidden extern int fs_attach(int fd_fs, int dfd_to, const char *path_to,
			      __u64 o_flags_to, __u64 resolve_flags_to,
			      unsigned int attr_flags);

static inline int fs_mount(const char *fs_name, int dfd_from,
			   const char *path_from, __u64 o_flags_from,
			   __u64 resolve_flags_from, int dfd_to,
			   const char *path_to, __u64 o_flags_to,
			   __u64 resolve_flags_to,
			   unsigned int attr_flags)
{
	__do_close int fd_fs = -EBADF;

	fd_fs = fs_prepare(fs_name, dfd_from, path_from, o_flags_from, resolve_flags_from);
	if (fd_fs < 0)
		return -errno;
	return fs_attach(fd_fs, dfd_to, path_to, o_flags_to, resolve_flags_to, attr_flags);
}

__hidden extern int __fd_bind_mount(int dfd_from, const char *path_from,
				    __u64 o_flags_from,
				    __u64 resolve_flags_from, int dfd_to,
				    const char *path_to, __u64 o_flags_to,
				    __u64 resolve_flags_to, __u64 attr_set,
				    __u64 attr_clr, __u64 propagation,
				    int userns_fd, bool recursive);
static inline int fd_mount_idmapped(int dfd_from, const char *path_from,
				    __u64 o_flags_from,
				    __u64 resolve_flags_from, int dfd_to,
				    const char *path_to, __u64 o_flags_to,
				    __u64 resolve_flags_to, __u64 attr_set,
				    __u64 attr_clr, __u64 propagation,
				    int userns_fd, bool recursive)
{
	return __fd_bind_mount(dfd_from, path_from, o_flags_from,
			       resolve_flags_from, dfd_to, path_to, o_flags_to,
			       resolve_flags_to, attr_set, attr_clr,
			       propagation, userns_fd, recursive);
}

static inline int fd_bind_mount(int dfd_from, const char *path_from,
				__u64 o_flags_from, __u64 resolve_flags_from,
				int dfd_to, const char *path_to,
				__u64 o_flags_to, __u64 resolve_flags_to,
				__u64 attr_set, __u64 attr_clr,
				__u64 propagation, bool recursive)
{
	return __fd_bind_mount(dfd_from, path_from, o_flags_from, resolve_flags_from,
			       dfd_to, path_to, o_flags_to, resolve_flags_to,
			       attr_set, attr_clr, propagation, -EBADF, recursive);
}
__hidden extern int create_detached_idmapped_mount(const char *path,
						   int userns_fd, bool recursive,
						   __u64 attr_set, __u64 attr_clr);
__hidden extern int move_detached_mount(int dfd_from, int dfd_to,
					const char *path_to, __u64 o_flags_to,
					__u64 resolve_flags_to);

__hidden extern int calc_remount_flags_new(int dfd_from, const char *path_from,
					   __u64 o_flags_from,
					   __u64 resolve_flags_from,
					   bool remount, unsigned long cur_flags,
					   unsigned int *new_flags);

__hidden extern int calc_remount_flags_old(int dfd_from, const char *path_from,
					   __u64 o_flags_from,
					   __u64 resolve_flags_from,
					   bool remount, unsigned long cur_flags,
					   unsigned int *old_flags);

__hidden extern unsigned long add_required_remount_flags(const char *s,
							 const char *d,
							 unsigned long flags);

__hidden extern bool can_use_mount_api(void);
__hidden extern bool can_use_bind_mounts(void);
__hidden extern int mount_at(int dfd_from, const char *path_from,
			     __u64 resolve_flags_from, int dfd_to,
			     const char *path_to, __u64 resolve_flags_to,
			     const char *fs_name, unsigned int flags,
			     const void *data);
static inline int mount_fd(int fd_from, int fd_to, const char *fs_name,
			   unsigned int flags, const void *data)
{
	return mount_at(fd_from, "", 0, fd_to, "", 0, fs_name, flags, data);
}

#endif /* __LXC_MOUNT_UTILS_H */

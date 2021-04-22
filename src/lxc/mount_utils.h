/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_MOUNT_UTILS_H
#define __LXC_MOUNT_UTILS_H

#include <linux/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>

#include "compiler.h"
#include "memory_utils.h"
#include "syscall_wrappers.h"

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
#ifndef FSCONFIG_SET_FLAG
#define FSCONFIG_SET_FLAG 0 /* Set parameter, supplying no value */
#endif

#ifndef FSCONFIG_SET_STRING
#define FSCONFIG_SET_STRING 1 /* Set parameter, supplying a string value */
#endif

#ifndef FSCONFIG_SET_BINARY
#define FSCONFIG_SET_BINARY 2 /* Set parameter, supplying a binary blob value */
#endif

#ifndef FSCONFIG_SET_PATH
#define FSCONFIG_SET_PATH 3 /* Set parameter, supplying an object by path */
#endif

#ifndef FSCONFIG_SET_PATH_EMPTY
#define FSCONFIG_SET_PATH_EMPTY 4 /* Set parameter, supplying an object by (empty) path */
#endif

#ifndef FSCONFIG_SET_FD
#define FSCONFIG_SET_FD 5 /* Set parameter, supplying an object by fd */
#endif

#ifndef FSCONFIG_CMD_CREATE
#define FSCONFIG_CMD_CREATE 6 /* Invoke superblock creation */
#endif

#ifndef FSCONFIG_CMD_RECONFIGURE
#define	FSCONFIG_CMD_RECONFIGURE 7	/* Invoke superblock reconfiguration */
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

__hidden extern int mnt_attributes_new(unsigned int old_flags, unsigned int *new_flags);

__hidden extern int mnt_attributes_old(unsigned int new_flags, unsigned int *old_flags);

__hidden extern int fs_prepare(const char *fs_name, int dfd_from,
			       const char *path_from, __u64 o_flags_from,
			       __u64 resolve_flags_from);
__hidden extern int fs_set_property(int fd_fs, const char *key, const char *val);
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

__hidden extern int fd_bind_mount(int dfd_from, const char *path_from,
				  __u64 o_flags_from, __u64 resolve_flags_from,
				  int dfd_to, const char *path_to,
				  __u64 o_flags_to, __u64 resolve_flags_to,
				  unsigned int attr_flags, bool recursive);

__hidden extern int fd_mount_idmapped(int dfd_from, const char *path_from,
				      __u64 o_flags_from, __u64 resolve_flags_from,
				      int dfd_to, const char *path_to,
				      __u64 o_flags_to, __u64 resolve_flags_to,
				      unsigned int attr_flags, int userns_fd,
				      bool recursive);
__hidden extern int create_detached_idmapped_mount(const char *path,
						   int userns_fd, bool recursive);
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

#endif /* __LXC_MOUNT_UTILS_H */

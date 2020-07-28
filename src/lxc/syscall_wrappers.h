/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_SYSCALL_WRAPPER_H
#define __LXC_SYSCALL_WRAPPER_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <asm/unistd.h>
#include <errno.h>
#include <linux/keyctl.h>
#include <sched.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"
#include "syscall_numbers.h"

#ifdef HAVE_LINUX_MEMFD_H
#include <linux/memfd.h>
#endif

#ifdef HAVE_SYS_SIGNALFD_H
#include <sys/signalfd.h>
#endif

typedef int32_t key_serial_t;

#if !HAVE_KEYCTL
static inline long __keyctl(int cmd, unsigned long arg2, unsigned long arg3,
			    unsigned long arg4, unsigned long arg5)
{
	return syscall(__NR_keyctl, cmd, arg2, arg3, arg4, arg5);
}
#define keyctl __keyctl
#endif

#ifndef F_LINUX_SPECIFIC_BASE
#define F_LINUX_SPECIFIC_BASE 1024
#endif
#ifndef F_ADD_SEALS
#define F_ADD_SEALS (F_LINUX_SPECIFIC_BASE + 9)
#define F_GET_SEALS (F_LINUX_SPECIFIC_BASE + 10)
#endif
#ifndef F_SEAL_SEAL
#define F_SEAL_SEAL 0x0001
#define F_SEAL_SHRINK 0x0002
#define F_SEAL_GROW 0x0004
#define F_SEAL_WRITE 0x0008
#endif

#ifndef HAVE_MEMFD_CREATE
static inline int memfd_create_lxc(const char *name, unsigned int flags)
{
	return syscall(__NR_memfd_create, name, flags);
}
#define memfd_create memfd_create_lxc
#else
extern int memfd_create(const char *name, unsigned int flags);
#endif

#ifndef HAVE_PIVOT_ROOT
static int pivot_root(const char *new_root, const char *put_old)
{
	return syscall(__NR_pivot_root, new_root, put_old);
}
#else
extern int pivot_root(const char *new_root, const char *put_old);
#endif

/* Define sethostname() if missing from the C library */
#ifndef HAVE_SETHOSTNAME
static inline int sethostname(const char *name, size_t len)
{
	return syscall(__NR_sethostname, name, len);
}
#endif

/* Define setns() if missing from the C library */
#ifndef HAVE_SETNS
static inline int setns(int fd, int nstype)
{
	return syscall(__NR_setns, fd, nstype);
}
#endif

#ifndef HAVE_SYS_SIGNALFD_H
struct signalfd_siginfo {
	uint32_t ssi_signo;
	int32_t ssi_errno;
	int32_t ssi_code;
	uint32_t ssi_pid;
	uint32_t ssi_uid;
	int32_t ssi_fd;
	uint32_t ssi_tid;
	uint32_t ssi_band;
	uint32_t ssi_overrun;
	uint32_t ssi_trapno;
	int32_t ssi_status;
	int32_t ssi_int;
	uint64_t ssi_ptr;
	uint64_t ssi_utime;
	uint64_t ssi_stime;
	uint64_t ssi_addr;
	uint8_t __pad[48];
};

static inline int signalfd(int fd, const sigset_t *mask, int flags)
{
	int retval;

	retval = syscall(__NR_signalfd4, fd, mask, _NSIG / 8, flags);
#ifdef __NR_signalfd
	if (errno == ENOSYS && flags == 0)
		retval = syscall(__NR_signalfd, fd, mask, _NSIG / 8);
#endif

	return retval;
}
#endif

/* Define unshare() if missing from the C library */
#ifndef HAVE_UNSHARE
static inline int unshare(int flags)
{
	return syscall(__NR_unshare, flags);
}
#else
extern int unshare(int);
#endif

/* Define faccessat() if missing from the C library */
#ifndef HAVE_FACCESSAT
static int faccessat(int __fd, const char *__file, int __type, int __flag)
{
	return syscall(__NR_faccessat, __fd, __file, __type, __flag);
}
#endif

#ifndef HAVE_MOVE_MOUNT
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

#ifndef HAVE_OPEN_TREE
static inline int open_tree_lxc(int dfd, const char *filename, unsigned int flags)
{
	return syscall(__NR_open_tree, dfd, filename, flags);
}
#define open_tree open_tree_lxc
#else
extern int open_tree(int dfd, const char *filename, unsigned int flags);
#endif

#ifndef HAVE_FSOPEN
static inline int fsopen_lxc(const char *fs_name, unsigned int flags)
{
	return syscall(__NR_fsopen, fs_name, flags);
}
#define fsopen fsopen_lxc
#else
extern int fsopen(const char *fs_name, unsigned int flags);
#endif

#ifndef HAVE_FSPICK
static inline int fspick_lxc(int dfd, const char *path, unsigned int flags)
{
	return syscall(__NR_fspick, dfd, path, flags);
}
#define fspick fspick_lxc
#else
extern int fspick(int dfd, const char *path, unsigned int flags);
#endif

#ifndef HAVE_FSCONFIG
static inline int fsconfig_lxc(int fd, unsigned int cmd, const char *key, const void *value, int aux)
{
	return syscall(__NR_fsconfig, fd, cmd, key, value, aux);
}
#define fsconfig fsconfig_lxc
#else
extern int fsconfig(int fd, unsigned int cmd, const char *key, const void *value, int aux);
#endif

#ifndef HAVE_FSMOUNT
static inline int fsmount_lxc(int fs_fd, unsigned int flags, unsigned int attr_flags)
{
	return syscall(__NR_fsmount, fs_fd, flags, attr_flags);
}
#define fsmount fsmount_lxc
#else
extern int fsmount(int fs_fd, unsigned int flags, unsigned int attr_flags);
#endif

#endif /* __LXC_SYSCALL_WRAPPER_H */

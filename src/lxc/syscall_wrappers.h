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
#include "macro.h"
#include "syscall_numbers.h"

#ifdef HAVE_LINUX_MEMFD_H
#include <linux/memfd.h>
#endif

#ifdef HAVE_SYS_SIGNALFD_H
#include <sys/signalfd.h>
#endif

#ifdef HAVE_STRUCT_OPEN_HOW
#include <linux/openat2.h>
#endif

#if HAVE_SYS_PERSONALITY_H
#include <sys/personality.h>
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

/*
 * mount_setattr()
 */
struct lxc_mount_attr {
	__u64 attr_set;
	__u64 attr_clr;
	__u64 propagation;
	__u64 userns_fd;
};

#ifndef HAVE_MOUNT_SETATTR
static inline int mount_setattr(int dfd, const char *path, unsigned int flags,
				struct lxc_mount_attr *attr, size_t size)
{
	return syscall(__NR_mount_setattr, dfd, path, flags, attr, size);
}
#endif

/*
 * Arguments for how openat2(2) should open the target path. If only @flags and
 * @mode are non-zero, then openat2(2) operates very similarly to openat(2).
 *
 * However, unlike openat(2), unknown or invalid bits in @flags result in
 * -EINVAL rather than being silently ignored. @mode must be zero unless one of
 * {O_CREAT, O_TMPFILE} are set.
 *
 * @flags: O_* flags.
 * @mode: O_CREAT/O_TMPFILE file mode.
 * @resolve: RESOLVE_* flags.
 */
struct lxc_open_how {
	__u64 flags;
	__u64 mode;
	__u64 resolve;
};

/* how->resolve flags for openat2(2). */
#ifndef RESOLVE_NO_XDEV
#define RESOLVE_NO_XDEV		0x01 /* Block mount-point crossings
					(includes bind-mounts). */
#endif

#ifndef RESOLVE_NO_MAGICLINKS
#define RESOLVE_NO_MAGICLINKS	0x02 /* Block traversal through procfs-style
					"magic-links". */
#endif

#ifndef RESOLVE_NO_SYMLINKS
#define RESOLVE_NO_SYMLINKS	0x04 /* Block traversal through all symlinks
					(implies OEXT_NO_MAGICLINKS) */
#endif

#ifndef RESOLVE_BENEATH
#define RESOLVE_BENEATH		0x08 /* Block "lexical" trickery like
					"..", symlinks, and absolute
					paths which escape the dirfd. */
#endif

#ifndef RESOLVE_IN_ROOT
#define RESOLVE_IN_ROOT		0x10 /* Make all jumps to "/" and ".."
					be scoped inside the dirfd
					(similar to chroot(2)). */
#endif

#define PROTECT_LOOKUP_BENEATH  (RESOLVE_BENEATH | RESOLVE_NO_XDEV | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS)
#define PROTECT_LOOKUP_BENEATH_WITH_SYMLINKS (PROTECT_LOOKUP_BENEATH & ~RESOLVE_NO_SYMLINKS)
#define PROTECT_LOOKUP_BENEATH_WITH_MAGICLINKS (PROTECT_LOOKUP_BENEATH & ~(RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS))
#define PROTECT_LOOKUP_BENEATH_XDEV (PROTECT_LOOKUP_BENEATH & ~RESOLVE_NO_XDEV)

#define PROTECT_LOOKUP_ABSOLUTE (PROTECT_LOOKUP_BENEATH & ~RESOLVE_BENEATH)
#define PROTECT_LOOKUP_ABSOLUTE_WITH_SYMLINKS (PROTECT_LOOKUP_ABSOLUTE & ~RESOLVE_NO_SYMLINKS)
#define PROTECT_LOOKUP_ABSOLUTE_WITH_MAGICLINKS (PROTECT_LOOKUP_ABSOLUTE & ~(RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS))
#define PROTECT_LOOKUP_ABSOLUTE_XDEV (PROTECT_LOOKUP_ABSOLUTE & ~RESOLVE_NO_XDEV)

#define PROTECT_OPATH_FILE (O_NOFOLLOW | O_PATH | O_CLOEXEC)
#define PROTECT_OPATH_DIRECTORY (PROTECT_OPATH_FILE | O_DIRECTORY)

#define PROTECT_OPEN_WITH_TRAILING_SYMLINKS (O_CLOEXEC | O_NOCTTY | O_RDONLY)
#define PROTECT_OPEN (PROTECT_OPEN_WITH_TRAILING_SYMLINKS | O_NOFOLLOW)

#define PROTECT_OPEN_W_WITH_TRAILING_SYMLINKS (O_CLOEXEC | O_NOCTTY | O_WRONLY)
#define PROTECT_OPEN_W (PROTECT_OPEN_W_WITH_TRAILING_SYMLINKS | O_NOFOLLOW)

#ifndef HAVE_OPENAT2
static inline int openat2(int dfd, const char *filename, struct lxc_open_how *how, size_t size)
{
	/* When struct open_how is updated we should update lxc as well. */
#ifdef HAVE_STRUCT_OPEN_HOW
	BUILD_BUG_ON(sizeof(struct lxc_open_how) != sizeof(struct open_how));
#endif
	return syscall(__NR_openat2, dfd, filename, (struct open_how *)how, size);
}
#endif /* HAVE_OPENAT2 */

#ifndef CLOSE_RANGE_UNSHARE
#define CLOSE_RANGE_UNSHARE	(1U << 1)
#endif

#ifndef CLOSE_RANGE_CLOEXEC
#define CLOSE_RANGE_CLOEXEC	(1U << 2)
#endif

#ifndef HAVE_CLOSE_RANGE
static inline int close_range(unsigned int fd, unsigned int max_fd, unsigned int flags)
{
	return syscall(__NR_close_range, fd, max_fd, flags);
}
#endif

#ifndef HAVE_SYS_PERSONALITY_H
static inline int personality(unsigned long persona)
{
	return syscall(__NR_personality, persona);
}
#endif

#endif /* __LXC_SYSCALL_WRAPPER_H */

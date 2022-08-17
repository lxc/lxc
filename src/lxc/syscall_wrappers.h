/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_SYSCALL_WRAPPER_H
#define __LXC_SYSCALL_WRAPPER_H

#include "config.h"

#include <asm/unistd.h>
#include <errno.h>
#include <linux/keyctl.h>
#include <sched.h>
#include <stdint.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "macro.h"
#include "syscall_numbers.h"

#ifdef HAVE_LINUX_MEMFD_H
#include <linux/memfd.h>
#endif

#ifdef HAVE_SYS_SIGNALFD_H
#include <sys/signalfd.h>
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

#if !HAVE_MEMFD_CREATE
static inline int memfd_create_lxc(const char *name, unsigned int flags)
{
	return syscall(__NR_memfd_create, name, flags);
}
#define memfd_create memfd_create_lxc
#else
extern int memfd_create(const char *name, unsigned int flags);
#endif

#if !HAVE_PIVOT_ROOT
static inline int pivot_root(const char *new_root, const char *put_old)
{
	return syscall(__NR_pivot_root, new_root, put_old);
}
#else
extern int pivot_root(const char *new_root, const char *put_old);
#endif

/* Define sethostname() if missing from the C library */
#if !HAVE_SETHOSTNAME
static inline int sethostname(const char *name, size_t len)
{
	return syscall(__NR_sethostname, name, len);
}
#endif

/* Define setns() if missing from the C library */
#if !HAVE_SETNS
static inline int setns(int fd, int nstype)
{
	return syscall(__NR_setns, fd, nstype);
}
#endif

#if !HAVE_SYS_SIGNALFD_H
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
#if !HAVE_UNSHARE
static inline int unshare(int flags)
{
	return syscall(__NR_unshare, flags);
}
#else
extern int unshare(int);
#endif

/* Define faccessat() if missing from the C library */
#if !HAVE_FACCESSAT
static int faccessat(int __fd, const char *__file, int __type, int __flag)
{
	return syscall(__NR_faccessat, __fd, __file, __type, __flag);
}
#endif

#ifndef CLOSE_RANGE_UNSHARE
#define CLOSE_RANGE_UNSHARE	(1U << 1)
#endif

#ifndef CLOSE_RANGE_CLOEXEC
#define CLOSE_RANGE_CLOEXEC	(1U << 2)
#endif

#if !HAVE_CLOSE_RANGE
static inline int close_range(unsigned int fd, unsigned int max_fd, unsigned int flags)
{
	return syscall(__NR_close_range, fd, max_fd, flags);
}
#endif

#if !HAVE_SYS_PERSONALITY_H
static inline int personality(unsigned long persona)
{
	return syscall(__NR_personality, persona);
}
#endif

/* arg1 of prctl() */
#ifndef PR_SCHED_CORE
#define PR_SCHED_CORE 62
#endif

/* arg2 of prctl() */
#ifndef PR_SCHED_CORE_GET
#define PR_SCHED_CORE_GET 0
#endif

#ifndef PR_SCHED_CORE_CREATE
#define PR_SCHED_CORE_CREATE 1 /* create unique core_sched cookie */
#endif

#ifndef PR_SCHED_CORE_SHARE_TO
#define PR_SCHED_CORE_SHARE_TO 2 /* push core_sched cookie to pid */
#endif

#ifndef PR_SCHED_CORE_SHARE_FROM
#define PR_SCHED_CORE_SHARE_FROM 3 /* pull core_sched cookie to pid */
#endif

#ifndef PR_SCHED_CORE_MAX
#define PR_SCHED_CORE_MAX 4
#endif

/* arg3 of prctl() */
#ifndef PR_SCHED_CORE_SCOPE_THREAD
#define PR_SCHED_CORE_SCOPE_THREAD 0
#endif

#ifndef PR_SCHED_CORE_SCOPE_THREAD_GROUP
#define PR_SCHED_CORE_SCOPE_THREAD_GROUP 1
#endif

#ifndef PR_SCHED_CORE_SCOPE_PROCESS_GROUP
#define PR_SCHED_CORE_SCOPE_PROCESS_GROUP 2
#endif

#define INVALID_SCHED_CORE_COOKIE ((__u64)-1)

static inline bool core_scheduling_cookie_valid(__u64 cookie)
{
	return (cookie > 0) && (cookie != INVALID_SCHED_CORE_COOKIE);
}

static inline int core_scheduling_cookie_get(pid_t pid, __u64 *cookie)
{
	int ret;

	if (!cookie)
		return ret_errno(EINVAL);

	ret = prctl(PR_SCHED_CORE, PR_SCHED_CORE_GET, pid,
		    PR_SCHED_CORE_SCOPE_THREAD, (unsigned long)cookie);
	if (ret) {
		*cookie = INVALID_SCHED_CORE_COOKIE;
		return -errno;
	}

	return 0;
}

static inline int core_scheduling_cookie_create_threadgroup(pid_t pid)
{
	int ret;

	ret = prctl(PR_SCHED_CORE, PR_SCHED_CORE_CREATE, pid,
		    PR_SCHED_CORE_SCOPE_THREAD_GROUP, 0);
	if (ret)
		return -errno;

	return 0;
}

static inline int core_scheduling_cookie_share_with(pid_t pid)
{
	return prctl(PR_SCHED_CORE, PR_SCHED_CORE_SHARE_FROM, pid,
		     PR_SCHED_CORE_SCOPE_THREAD, 0);
}

#endif /* __LXC_SYSCALL_WRAPPER_H */

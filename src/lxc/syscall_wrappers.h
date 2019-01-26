/* liblxcapi
 *
 * Copyright © 2018 Christian Brauner <christian.brauner@ubuntu.com>.
 * Copyright © 2018 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

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
#ifdef __NR_keyctl
	return syscall(__NR_keyctl, cmd, arg2, arg3, arg4, arg5);
#else
	errno = ENOSYS;
	return -1;
#endif
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
static inline int memfd_create(const char *name, unsigned int flags) {
	#ifndef __NR_memfd_create
		#if defined __i386__
			#define __NR_memfd_create 356
		#elif defined __x86_64__
			#define __NR_memfd_create 319
		#elif defined __arm__
			#define __NR_memfd_create 385
		#elif defined __aarch64__
			#define __NR_memfd_create 279
		#elif defined __s390__
			#define __NR_memfd_create 350
		#elif defined __powerpc__
			#define __NR_memfd_create 360
		#elif defined __sparc__
			#define __NR_memfd_create 348
		#elif defined __blackfin__
			#define __NR_memfd_create 390
		#elif defined __ia64__
			#define __NR_memfd_create 1340
		#elif defined _MIPS_SIM
			#if _MIPS_SIM == _MIPS_SIM_ABI32
				#define __NR_memfd_create 4354
			#endif
			#if _MIPS_SIM == _MIPS_SIM_NABI32
				#define __NR_memfd_create 6318
			#endif
			#if _MIPS_SIM == _MIPS_SIM_ABI64
				#define __NR_memfd_create 5314
			#endif
		#endif
	#endif
	#ifdef __NR_memfd_create
	return syscall(__NR_memfd_create, name, flags);
	#else
	errno = ENOSYS;
	return -1;
	#endif
}
#else
extern int memfd_create(const char *name, unsigned int flags);
#endif

#if !HAVE_PIVOT_ROOT
static int pivot_root(const char *new_root, const char *put_old)
{
#ifdef __NR_pivot_root
	return syscall(__NR_pivot_root, new_root, put_old);
#else
	errno = ENOSYS;
	return -1;
#endif
}
#else
extern int pivot_root(const char *new_root, const char *put_old);
#endif

#if !defined(__NR_setns) && !defined(__NR_set_ns)
	#if defined(__x86_64__)
		#define __NR_setns 308
	#elif defined(__i386__)
		#define __NR_setns 346
	#elif defined(__arm__)
		#define __NR_setns 375
	#elif defined(__aarch64__)
		#define __NR_setns 375
	#elif defined(__powerpc__)
		#define __NR_setns 350
	#elif defined(__s390__)
		#define __NR_setns 339
	#endif
#endif

/* Define sethostname() if missing from the C library */
#ifndef HAVE_SETHOSTNAME
static inline int sethostname(const char *name, size_t len)
{
#ifdef __NR_sethostname
	return syscall(__NR_sethostname, name, len);
#else
	errno = ENOSYS;
	return -1;
#endif
}
#endif

/* Define setns() if missing from the C library */
#ifndef HAVE_SETNS
static inline int setns(int fd, int nstype)
{
#ifdef __NR_setns
	return syscall(__NR_setns, fd, nstype);
#elif defined(__NR_set_ns)
	return syscall(__NR_set_ns, fd, nstype);
#else
	errno = ENOSYS;
	return -1;
#endif
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

#ifndef __NR_signalfd4
/* assume kernel headers are too old */
#if __i386__
#define __NR_signalfd4 327
#elif __x86_64__
#define __NR_signalfd4 289
#elif __powerpc__
#define __NR_signalfd4 313
#elif __s390x__
#define __NR_signalfd4 322
#elif __arm__
#define __NR_signalfd4 355
#elif __mips__ && _MIPS_SIM == _ABIO32
#define __NR_signalfd4 4324
#elif __mips__ && _MIPS_SIM == _ABI64
#define __NR_signalfd4 5283
#elif __mips__ && _MIPS_SIM == _ABIN32
#define __NR_signalfd4 6287
#endif
#endif

#ifndef __NR_signalfd
/* assume kernel headers are too old */
#if __i386__
#define __NR_signalfd 321
#elif __x86_64__
#define __NR_signalfd 282
#elif __powerpc__
#define __NR_signalfd 305
#elif __s390x__
#define __NR_signalfd 316
#elif __arm__
#define __NR_signalfd 349
#elif __mips__ && _MIPS_SIM == _ABIO32
#define __NR_signalfd 4317
#elif __mips__ && _MIPS_SIM == _ABI64
#define __NR_signalfd 5276
#elif __mips__ && _MIPS_SIM == _ABIN32
#define __NR_signalfd 6280
#endif
#endif

static inline int signalfd(int fd, const sigset_t *mask, int flags)
{
	int retval;

	retval = syscall(__NR_signalfd4, fd, mask, _NSIG / 8, flags);
	if (errno == ENOSYS && flags == 0)
		retval = syscall(__NR_signalfd, fd, mask, _NSIG / 8);

	return retval;
}
#endif

/* Define unshare() if missing from the C library */
#ifndef HAVE_UNSHARE
static inline int unshare(int flags)
{
#ifdef __NR_unshare
	return syscall(__NR_unshare, flags);
#else
	errno = ENOSYS;
	return -1;
#endif
}
#else
extern int unshare(int);
#endif

#endif /* __LXC_SYSCALL_WRAPPER_H */

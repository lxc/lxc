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
#include <linux/keyctl.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"

#ifdef HAVE_LINUX_MEMFD_H
#include <linux/memfd.h>
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

#endif /* __LXC_SYSCALL_WRAPPER_H */

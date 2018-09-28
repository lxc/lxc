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

#endif /* __LXC_SYSCALL_WRAPPER_H */

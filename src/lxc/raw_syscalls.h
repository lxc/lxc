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

#ifndef __LXC_RAW_SYSCALL_H
#define __LXC_RAW_SYSCALL_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

/*
 * lxc_raw_clone() - create a new process
 *
 * - fork() behavior:
 *   This function returns 0 in the child and > 0 in the parent.
 *
 * - copy-on-write:
 *   This function does not allocate a new stack and relies on copy-on-write
 *   semantics.
 *
 * - supports subset of ClONE_* flags:
 *   lxc_raw_clone() intentionally only supports a subset of the flags available
 *   to the actual system call. Please refer to the implementation what flags
 *   cannot be used. Also, please don't assume that just because a flag isn't
 *   explicitly checked for as being unsupported that it is supported. If in
 *   doubt or not sufficiently familiar with process creation in the kernel and
 *   interactions with libcs this function should be used.
 *
 * - no pthread_atfork() handlers:
 *   This function circumvents - as much as this this is possible - any libc
 *   wrappers and thus does not run any pthread_atfork() handlers. Make sure
 *   that this is safe to do in the context you are trying to call this
 *   function.
 *
 * - must call lxc_raw_getpid():
 *   The child must use lxc_raw_getpid() to retrieve its pid.
 */
extern pid_t lxc_raw_clone(unsigned long flags);

/*
 * lxc_raw_clone_cb() - create a new process
 *
 * - non-fork() behavior:
 *   Function does return pid of the child or -1 on error. Pass in a callback
 *   function via the "fn" argument that gets executed in the child process.
 *   The "args" argument is passed to "fn".
 *
 * All other comments that apply to lxc_raw_clone() apply to lxc_raw_clone_cb()
 * as well.
 */
extern pid_t lxc_raw_clone_cb(int (*fn)(void *), void *args, unsigned long flags);

extern int lxc_raw_execveat(int dirfd, const char *pathname, char *const argv[],
			    char *const envp[], int flags);

/*
 * Because of older glibc's pid cache (up to 2.25) whenever clone() is called
 * the child must must retrieve it's own pid via lxc_raw_getpid().
 */
static inline pid_t lxc_raw_getpid(void)
{
	return (pid_t)syscall(SYS_getpid);
}

static inline pid_t lxc_raw_gettid(void)
{
#ifdef __NR_gettid
	return syscall(__NR_gettid);
#else
	return lxc_raw_getpid();
#endif
}

#endif /* __LXC_RAW_SYSCALL_H */

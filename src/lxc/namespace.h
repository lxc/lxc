/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2009
 *
 * Authors:
 * Daniel Lezcano <daniel.lezcano at free.fr>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
#ifndef __LXC_NAMESPACE_H
#define __LXC_NAMESPACE_H

#include <sched.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "config.h"

#ifndef CLONE_PARENT_SETTID
#define CLONE_PARENT_SETTID 0x00100000
#endif

#ifndef CLONE_CHILD_CLEARTID
#define CLONE_CHILD_CLEARTID 0x00200000
#endif

#ifndef CLONE_CHILD_SETTID
#define CLONE_CHILD_SETTID 0x01000000
#endif

#ifndef CLONE_VFORK
#define CLONE_VFORK 0x00004000
#endif

#ifndef CLONE_THREAD
#define CLONE_THREAD 0x00010000
#endif

#ifndef CLONE_SETTLS
#define CLONE_SETTLS 0x00080000
#endif

#ifndef CLONE_VM
#define CLONE_VM 0x00000100
#endif

#ifndef CLONE_FILES
#define CLONE_FILES 0x00000400
#endif

#ifndef CLONE_FS
#  define CLONE_FS                0x00000200
#endif
#ifndef CLONE_NEWNS
#  define CLONE_NEWNS             0x00020000
#endif
#ifndef CLONE_NEWCGROUP
#  define CLONE_NEWCGROUP         0x02000000
#endif
#ifndef CLONE_NEWUTS
#  define CLONE_NEWUTS            0x04000000
#endif
#ifndef CLONE_NEWIPC
#  define CLONE_NEWIPC            0x08000000
#endif
#ifndef CLONE_NEWUSER
#  define CLONE_NEWUSER           0x10000000
#endif
#ifndef CLONE_NEWPID
#  define CLONE_NEWPID            0x20000000
#endif
#ifndef CLONE_NEWNET
#  define CLONE_NEWNET            0x40000000
#endif

enum {
	LXC_NS_USER,
	LXC_NS_MNT,
	LXC_NS_PID,
	LXC_NS_UTS,
	LXC_NS_IPC,
	LXC_NS_NET,
	LXC_NS_CGROUP,
	LXC_NS_MAX
};

extern const struct ns_info {
	const char *proc_name;
	int clone_flag;
	const char *flag_name;
	const char *env_name;
} ns_info[LXC_NS_MAX];

#if defined(__ia64__)
int __clone2(int (*__fn) (void *__arg), void *__child_stack_base,
             size_t __child_stack_size, int __flags, void *__arg, ...);
#else
int clone(int (*fn)(void *), void *child_stack,
	int flags, void *arg, ...
	/* pid_t *ptid, struct user_desc *tls, pid_t *ctid */ );
#endif

/**
 * lxc_clone() - create a new process
 *
 * - allocate stack:
 *   This function allocates a new stack the size of page and passes it to the
 *   kernel.
 *
 * - support all CLONE_*flags:
 *   This function supports all CLONE_* flags. If in doubt or not sufficiently
 *   familiar with process creation in the kernel and interactions with libcs
 *   this function should be used.
 *
 * - pthread_atfork() handlers depending on libc:
 *   Whether this function runs pthread_atfork() handlers depends on the
 *   corresponding libc wrapper. glibc currently does not run pthread_atfork()
 *   handlers but does not guarantee that they are not. Other libcs might or
 *   might not run pthread_atfork() handlers. If you require guarantees please
 *   refer to the lxc_raw_clone*() functions below.
 *
 * - should call lxc_raw_getpid():
 *   The child should use lxc_raw_getpid() to retrieve its pid.
 */
extern pid_t lxc_clone(int (*fn)(void *), void *arg, int flags);

/**
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
/**
 * lxc_raw_clone_cb() - create a new process
 *
 * - non-fork() behavior:
 *   Function does return pid of the child or -1 on error. Pass in a callback
 *   function via the "fn" argument that gets executed in the child process. The
 *   "args" argument is passed to "fn".
 *
 * All other comments that apply to lxc_raw_clone() apply to lxc_raw_clone_cb()
 * as well.
 */
extern pid_t lxc_raw_clone_cb(int (*fn)(void *), void *args,
			      unsigned long flags);

extern int lxc_namespace_2_cloneflag(const char *namespace);
extern int lxc_namespace_2_ns_idx(const char *namespace);
extern int lxc_namespace_2_std_identifiers(char *namespaces);
extern int lxc_fill_namespace_flags(char *flaglist, int *flags);

/**
 * Because of older glibc's pid cache (up to 2.25) whenever clone() is called
 * the child must must retrieve it's own pid via lxc_raw_getpid().
 */
static inline pid_t lxc_raw_getpid(void)
{
	return (pid_t) syscall(SYS_getpid);
}

#endif

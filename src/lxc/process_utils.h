/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_PROCESS_UTILS_H
#define __LXC_PROCESS_UTILS_H

#include "config.h"

#include <linux/sched.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "compiler.h"
#include "syscall_numbers.h"

#ifndef CSIGNAL
#define CSIGNAL 0x000000ff /* signal mask to be sent at exit */
#endif

#ifndef CLONE_VM
#define CLONE_VM 0x00000100 /* set if VM shared between processes */
#endif

#ifndef CLONE_FS
#define CLONE_FS 0x00000200 /* set if fs info shared between processes */
#endif

#ifndef CLONE_FILES
#define CLONE_FILES 0x00000400 /* set if open files shared between processes */
#endif

#ifndef CLONE_SIGHAND
#define CLONE_SIGHAND 0x00000800 /* set if signal handlers and blocked signals shared */
#endif

#ifndef CLONE_PIDFD
#define CLONE_PIDFD 0x00001000 /* set if a pidfd should be placed in parent */
#endif

#ifndef CLONE_PTRACE
#define CLONE_PTRACE 0x00002000 /* set if we want to let tracing continue on the child too */
#endif

#ifndef CLONE_VFORK
#define CLONE_VFORK 0x00004000 /* set if the parent wants the child to wake it up on mm_release */
#endif

#ifndef CLONE_PARENT
#define CLONE_PARENT 0x00008000 /* set if we want to have the same parent as the cloner */
#endif

#ifndef CLONE_THREAD
#define CLONE_THREAD 0x00010000 /* Same thread group? */
#endif

#ifndef CLONE_NEWNS
#define CLONE_NEWNS 0x00020000 /* New mount namespace group */
#endif

#ifndef CLONE_SYSVSEM
#define CLONE_SYSVSEM 0x00040000 /* share system V SEM_UNDO semantics */
#endif

#ifndef CLONE_SETTLS
#define CLONE_SETTLS 0x00080000 /* create a new TLS for the child */
#endif

#ifndef CLONE_PARENT_SETTID
#define CLONE_PARENT_SETTID 0x00100000 /* set the TID in the parent */
#endif

#ifndef CLONE_CHILD_CLEARTID
#define CLONE_CHILD_CLEARTID 0x00200000 /* clear the TID in the child */
#endif

#ifndef CLONE_DETACHED
#define CLONE_DETACHED 0x00400000 /* Unused, ignored */
#endif

#ifndef CLONE_UNTRACED
#define CLONE_UNTRACED 0x00800000 /* set if the tracing process can't force CLONE_PTRACE on this clone */
#endif

#ifndef CLONE_CHILD_SETTID
#define CLONE_CHILD_SETTID 0x01000000 /* set the TID in the child */
#endif

#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP 0x02000000 /* New cgroup namespace */
#endif

#ifndef CLONE_NEWUTS
#define CLONE_NEWUTS 0x04000000 /* New utsname namespace */
#endif

#ifndef CLONE_NEWIPC
#define CLONE_NEWIPC 0x08000000 /* New ipc namespace */
#endif

#ifndef CLONE_NEWUSER
#define CLONE_NEWUSER 0x10000000 /* New user namespace */
#endif

#ifndef CLONE_NEWPID
#define CLONE_NEWPID 0x20000000 /* New pid namespace */
#endif

#ifndef CLONE_NEWNET
#define CLONE_NEWNET 0x40000000 /* New network namespace */
#endif

#ifndef CLONE_IO
#define CLONE_IO 0x80000000 /* Clone io context */
#endif

/* Flags for the clone3() syscall. */
#ifndef CLONE_CLEAR_SIGHAND
#define CLONE_CLEAR_SIGHAND 0x100000000ULL /* Clear any signal handler and reset to SIG_DFL. */
#endif

#ifndef CLONE_INTO_CGROUP
#define CLONE_INTO_CGROUP 0x200000000ULL /* Clone into a specific cgroup given the right permissions. */
#endif

/*
 * cloning flags intersect with CSIGNAL so can be used with unshare and clone3
 * syscalls only:
 */
#ifndef CLONE_NEWTIME
#define CLONE_NEWTIME 0x00000080 /* New time namespace */
#endif

/* waitid */
#ifndef P_PIDFD
#define P_PIDFD 3
#endif

#ifndef CLONE_ARGS_SIZE_VER0
#define CLONE_ARGS_SIZE_VER0 64 /* sizeof first published struct */
#endif

#ifndef CLONE_ARGS_SIZE_VER1
#define CLONE_ARGS_SIZE_VER1 80 /* sizeof second published struct */
#endif

#ifndef CLONE_ARGS_SIZE_VER2
#define CLONE_ARGS_SIZE_VER2 88 /* sizeof third published struct */
#endif

#ifndef ptr_to_u64
#define ptr_to_u64(ptr) ((__u64)((uintptr_t)(ptr)))
#endif
#ifndef u64_to_ptr
#define u64_to_ptr(x) ((void *)(uintptr_t)x)
#endif

struct lxc_clone_args {
	__aligned_u64 flags;
	__aligned_u64 pidfd;
	__aligned_u64 child_tid;
	__aligned_u64 parent_tid;
	__aligned_u64 exit_signal;
	__aligned_u64 stack;
	__aligned_u64 stack_size;
	__aligned_u64 tls;
	__aligned_u64 set_tid;
	__aligned_u64 set_tid_size;
	__aligned_u64 cgroup;
};

__returns_twice static inline pid_t lxc_clone3(struct lxc_clone_args *args, size_t size)
{
	return syscall(__NR_clone3, args, size);
}

#if defined(__ia64__)
int __clone2(int (*__fn)(void *__arg), void *__child_stack_base,
	     size_t __child_stack_size, int __flags, void *__arg, ...);
#else
int clone(int (*fn)(void *), void *child_stack, int flags, void *arg, ...
	  /* pid_t *ptid, struct user_desc *tls, pid_t *ctid */);
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
 *   refer to the lxc_raw_clone*() functions in process_utils.{c,h}.
 *
 * - should call lxc_raw_getpid():
 *   The child should use lxc_raw_getpid() to retrieve its pid.
 */
__hidden extern pid_t lxc_clone(int (*fn)(void *), void *arg, int flags, int *pidfd);


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
__hidden extern pid_t lxc_raw_clone(unsigned long flags, int *pidfd);
__hidden extern pid_t lxc_raw_legacy_clone(unsigned long flags, int *pidfd);

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
__hidden extern pid_t lxc_raw_clone_cb(int (*fn)(void *), void *args, unsigned long flags,
				       int *pidfd);

#if !HAVE_EXECVEAT
static inline int execveat(int dirfd, const char *pathname, char *const argv[],
			   char *const envp[], int flags)
{
	return syscall(__NR_execveat, dirfd, pathname, argv, envp, flags);
}
#else
extern int execveat(int dirfd, const char *pathname, char *const argv[],
		    char *const envp[], int flags);
#endif

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
#if __NR_gettid > 0
	return syscall(__NR_gettid);
#else
	return lxc_raw_getpid();
#endif
}

__hidden extern int lxc_raw_pidfd_send_signal(int pidfd, int sig, siginfo_t *info,
					      unsigned int flags);

static inline const char *signal_name(int sig)
{
	const char *s;

#if HAVE_SIGDESCR_NP
	s = sigdescr_np(sig);
#else
	s = "UNSUPPORTED";
#endif
	return s ?: "INVALID_SIGNAL_NUMBER";
}

#endif /* __LXC_PROCESS_UTILS_H */

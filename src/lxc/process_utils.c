/* SPDX-License-Identifier: LGPL-2.1+ */

#include "config.h"

#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "compiler.h"
#include "log.h"
#include "macro.h"
#include "process_utils.h"
#include "syscall_numbers.h"

lxc_log_define(process_utils, lxc);

/*
 * This is based on raw_clone in systemd but adapted to our needs. This uses
 * copy on write semantics and doesn't pass a stack. CLONE_VM is tricky and
 * doesn't really matter to us so disallow it.
 *
 * The nice thing about this is that we get fork() behavior. That is
 * lxc_raw_clone() returns 0 in the child and the child pid in the parent.
 */
__returns_twice pid_t lxc_raw_legacy_clone(unsigned long flags, int *pidfd)
{

#if defined(__s390x__) || defined(__s390__) || defined(__CRIS__)
	/* On s390/s390x and cris the order of the first and second arguments
	 * of the system call is reversed.
	 */
	return syscall(__NR_clone, NULL, flags | SIGCHLD, pidfd);
#elif defined(__sparc__) && defined(__arch64__)
	{
		/*
		 * sparc64 always returns the other process id in %o0, and a
		 * boolean flag whether this is the child or the parent in %o1.
		 * Inline assembly is needed to get the flag returned in %o1.
		 */
		register long g1 asm("g1") = __NR_clone;
		register long o0 asm("o0") = flags | SIGCHLD;
		register long o1 asm("o1") = 0; /* is parent/child indicator */
		register long o2 asm("o2") = (unsigned long)pidfd;
		long is_error, retval, in_child;
		pid_t child_pid;

		asm volatile(
#if defined(__arch64__)
		    "t 0x6d\n\t" /* 64-bit trap */
#else
		    "t 0x10\n\t" /* 32-bit trap */
#endif
		    /*
		     * catch errors: On sparc, the carry bit (csr) in the
		     * processor status register (psr) is used instead of a
		     * full register.
		     */
		    "addx %%g0, 0, %%g1"
		    : "=r"(g1), "=r"(o0), "=r"(o1), "=r"(o2) /* outputs */
		    : "r"(g1), "r"(o0), "r"(o1), "r"(o2)     /* inputs */
		    : "%cc");				     /* clobbers */

		is_error = g1;
		retval = o0;
		in_child = o1;

		if (is_error) {
			errno = retval;
			return -1;
		}

		if (in_child)
			return 0;

		child_pid = retval;
		return child_pid;
	}
#elif defined(__ia64__)
	/* On ia64 the stack and stack size are passed as separate arguments. */
	return syscall(__NR_clone, flags | SIGCHLD, NULL, prctl_arg(0), pidfd);
#else
	return syscall(__NR_clone, flags | SIGCHLD, NULL, pidfd);
#endif
}

__returns_twice pid_t lxc_raw_clone(unsigned long flags, int *pidfd)
{
	pid_t pid;
	struct lxc_clone_args args = {
		.flags		= flags,
		.pidfd		= ptr_to_u64(pidfd),
	};

	if (flags & (CLONE_VM | CLONE_PARENT_SETTID | CLONE_CHILD_SETTID |
		     CLONE_CHILD_CLEARTID | CLONE_SETTLS))
		return ret_errno(EINVAL);

	/* On CLONE_PARENT we inherit the parent's exit signal. */
	if (!(flags & CLONE_PARENT))
		args.exit_signal = SIGCHLD;

	pid = lxc_clone3(&args, CLONE_ARGS_SIZE_VER0);
	if (pid < 0 && errno == ENOSYS) {
		SYSTRACE("Falling back to legacy clone");
		return lxc_raw_legacy_clone(flags, pidfd);
	}

	return pid;
}

pid_t lxc_raw_clone_cb(int (*fn)(void *), void *args, unsigned long flags,
		       int *pidfd)
{
	pid_t pid;

	pid = lxc_raw_clone(flags, pidfd);
	if (pid < 0)
		return -1;

	/*
	 * exit() is not thread-safe and might mess with the parent's signal
	 * handlers and other stuff when exec() fails.
	 */
	if (pid == 0)
		_exit(fn(args));

	return pid;
}

int lxc_raw_pidfd_send_signal(int pidfd, int sig, siginfo_t *info,
			      unsigned int flags)
{
	return syscall(__NR_pidfd_send_signal, pidfd, sig, info, flags);
}

/*
 * Let's use the "standard stack limit" (i.e. glibc thread size default) for
 * stack sizes: 8MB.
 */
#define __LXC_STACK_SIZE (8 * 1024 * 1024)
pid_t lxc_clone(int (*fn)(void *), void *arg, int flags, int *pidfd)
{
	__do_free void *stack = NULL;
	pid_t ret;

	stack = malloc(__LXC_STACK_SIZE);
	if (!stack)
		return syserror_set(-ENOMEM, "Failed to allocate clone stack");

#ifdef __ia64__
	ret = __clone2(fn, stack, __LXC_STACK_SIZE, flags | SIGCHLD, arg, pidfd);
#else
	ret = clone(fn, stack + __LXC_STACK_SIZE, flags | SIGCHLD, arg, pidfd);
#endif
	if (ret < 0)
		SYSERROR("Failed to clone (%#x)", flags);

	return ret;
}

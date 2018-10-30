#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "config.h"
#include "macro.h"
#include "raw_syscalls.h"

int lxc_raw_execveat(int dirfd, const char *pathname, char *const argv[],
		     char *const envp[], int flags)
{
#ifdef __NR_execveat
	syscall(__NR_execveat, dirfd, pathname, argv, envp, flags);
#else
	errno = ENOSYS;
#endif
	return -1;
}

/*
 * This is based on raw_clone in systemd but adapted to our needs. This uses
 * copy on write semantics and doesn't pass a stack. CLONE_VM is tricky and
 * doesn't really matter to us so disallow it.
 *
 * The nice thing about this is that we get fork() behavior. That is
 * lxc_raw_clone() returns 0 in the child and the child pid in the parent.
 */
pid_t lxc_raw_clone(unsigned long flags)
{
	/*
	 * These flags don't interest at all so we don't jump through any hoops
	 * of retrieving them and passing them to the kernel.
	 */
	errno = EINVAL;
	if ((flags & (CLONE_VM | CLONE_PARENT_SETTID | CLONE_CHILD_SETTID |
		      CLONE_CHILD_CLEARTID | CLONE_SETTLS)))
		return -EINVAL;

#if defined(__s390x__) || defined(__s390__) || defined(__CRIS__)
	/* On s390/s390x and cris the order of the first and second arguments
	 * of the system call is reversed.
	 */
	return (int)syscall(__NR_clone, NULL, flags | SIGCHLD);
#elif defined(__sparc__) && defined(__arch64__)
	{
		/*
		 * sparc64 always returns the other process id in %o0, and a
		 * boolean flag whether this is the child or the parent in %o1.
		 * Inline assembly is needed to get the flag returned in %o1.
		 */
		int in_child;
		int child_pid;
		asm volatile("mov %2, %%g1\n\t"
			     "mov %3, %%o0\n\t"
			     "mov 0 , %%o1\n\t"
			     "t 0x6d\n\t"
			     "mov %%o1, %0\n\t"
			     "mov %%o0, %1"
			     : "=r"(in_child), "=r"(child_pid)
			     : "i"(__NR_clone), "r"(flags | SIGCHLD)
			     : "%o1", "%o0", "%g1");

		if (in_child)
			return 0;
		else
			return child_pid;
	}
#elif defined(__ia64__)
	/* On ia64 the stack and stack size are passed as separate arguments. */
	return (int)syscall(__NR_clone, flags | SIGCHLD, NULL, prctl_arg(0));
#else
	return (int)syscall(__NR_clone, flags | SIGCHLD, NULL);
#endif
}

pid_t lxc_raw_clone_cb(int (*fn)(void *), void *args, unsigned long flags)
{
	pid_t pid;

	pid = lxc_raw_clone(flags);
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

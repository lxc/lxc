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

#define _GNU_SOURCE
#include <alloca.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>

#include "log.h"
#include "namespace.h"
#include "utils.h"

lxc_log_define(namespace, lxc);

struct clone_arg {
	int (*fn)(void *);
	void *arg;
};

static int do_clone(void *arg)
{
	struct clone_arg *clone_arg = arg;
	return clone_arg->fn(clone_arg->arg);
}

pid_t lxc_clone(int (*fn)(void *), void *arg, int flags)
{
	struct clone_arg clone_arg = {
		.fn = fn,
		.arg = arg,
	};

	size_t stack_size = lxc_getpagesize();
	void *stack = alloca(stack_size);
	pid_t ret;

#ifdef __ia64__
	ret = __clone2(do_clone, stack, stack_size, flags | SIGCHLD, &clone_arg);
#else
	ret = clone(do_clone, stack  + stack_size, flags | SIGCHLD, &clone_arg);
#endif
	if (ret < 0)
		SYSERROR("Failed to clone (%#x)", flags);

	return ret;
}

/**
 * This is based on raw_clone in systemd but adapted to our needs. This uses
 * copy on write semantics and doesn't pass a stack. CLONE_VM is tricky and
 * doesn't really matter to us so disallow it.
 *
 * The nice thing about this is that we get fork() behavior. That is
 * lxc_raw_clone() returns 0 in the child and the child pid in the parent.
 */
pid_t lxc_raw_clone(unsigned long flags)
{

	/* These flags don't interest at all so we don't jump through any hoopes
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
		/**
		 * sparc64 always returns the other process id in %o0, and
		 * a boolean flag whether this is the child or the parent in
		 * %o1. Inline assembly is needed to get the flag returned
		 * in %o1.
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
	return (int)syscall(__NR_clone, flags | SIGCHLD, NULL, 0);
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

	/* exit() is not thread-safe and might mess with the parent's signal
	 * handlers and other stuff when exec() fails.
	 */
	if (pid == 0)
		_exit(fn(args));

	return pid;
}

/* Leave the user namespace at the first position in the array of structs so
 * that we always attach to it first when iterating over the struct and using
 * setns() to switch namespaces. This especially affects lxc_attach(): Suppose
 * you cloned a new user namespace and mount namespace as an unprivileged user
 * on the host and want to setns() to the mount namespace. This requires you to
 * attach to the user namespace first otherwise the kernel will fail this check:
 *
 *        if (!ns_capable(mnt_ns->user_ns, CAP_SYS_ADMIN) ||
 *            !ns_capable(current_user_ns(), CAP_SYS_CHROOT) ||
 *            !ns_capable(current_user_ns(), CAP_SYS_ADMIN))
 *            return -EPERM;
 *
 *    in
 *
 *        linux/fs/namespace.c:mntns_install().
 */
const struct ns_info ns_info[LXC_NS_MAX] = {
	[LXC_NS_USER]    = { "user",   CLONE_NEWUSER,   "CLONE_NEWUSER",   "LXC_USER_NS"    },
	[LXC_NS_MNT]    =  { "mnt",    CLONE_NEWNS,     "CLONE_NEWNS",     "LXC_MNT_NS"     },
	[LXC_NS_PID]    =  { "pid",    CLONE_NEWPID,    "CLONE_NEWPID",    "LXC_PID_NS"     },
	[LXC_NS_UTS]    =  { "uts",    CLONE_NEWUTS,    "CLONE_NEWUTS",    "LXC_UTS_NS"     },
	[LXC_NS_IPC]    =  { "ipc",    CLONE_NEWIPC,    "CLONE_NEWIPC",    "LXC_IPC_NS"     },
	[LXC_NS_NET]    =  { "net",    CLONE_NEWNET,    "CLONE_NEWNET",    "LXC_NET_NS"     },
	[LXC_NS_CGROUP] =  { "cgroup", CLONE_NEWCGROUP, "CLONE_NEWCGROUP", "LXC_CGROUP_NS"  }
};

int lxc_namespace_2_cloneflag(const char *namespace)
{
	int i;

	for (i = 0; i < LXC_NS_MAX; i++)
		if (!strcasecmp(ns_info[i].proc_name, namespace))
			return ns_info[i].clone_flag;

	ERROR("Invalid namespace name \"%s\"", namespace);
	return -EINVAL;
}

int lxc_namespace_2_ns_idx(const char *namespace)
{
	int i;

	for (i = 0; i < LXC_NS_MAX; i++)
		if (!strcmp(ns_info[i].proc_name, namespace))
			return i;

	ERROR("Invalid namespace name \"%s\"", namespace);
	return -EINVAL;
}

extern int lxc_namespace_2_std_identifiers(char *namespaces)
{
	char **it;
	char *del;

	/* The identifiers for namespaces used with lxc-attach and lxc-unshare
	 * as given on the manpage do not align with the standard identifiers.
	 * This affects network, mount, and uts namespaces. The standard identifiers
	 * are: "mnt", "uts", and "net" whereas lxc-attach and lxc-unshare uses
	 * "MOUNT", "UTSNAME", and "NETWORK". So let's use some cheap memmove()s
	 * to replace them by their standard identifiers.
	 * Let's illustrate this with an example:
	 * Assume the string:
	 *
	 *	"IPC|MOUNT|PID"
	 *
	 * then we memmove()
	 *
	 *	dest: del + 1 == OUNT|PID
	 *	src:  del + 3 == NT|PID
	 */
	if (!namespaces)
		return -1;

	while ((del = strstr(namespaces, "MOUNT")))
		memmove(del + 1, del + 3, strlen(del) - 2);

	for (it = (char *[]){"NETWORK", "UTSNAME", NULL}; it && *it; it++)
		while ((del = strstr(namespaces, *it)))
			memmove(del + 3, del + 7, strlen(del) - 6);

	return 0;
}

int lxc_fill_namespace_flags(char *flaglist, int *flags)
{
	char *token;
	int aflag;

	if (!flaglist) {
		ERROR("At least one namespace is needed.");
		return -1;
	}

	lxc_iterate_parts(token, flaglist, "|") {
		aflag = lxc_namespace_2_cloneflag(token);
		if (aflag < 0)
			return -1;

		*flags |= aflag;
	}

	return 0;
}

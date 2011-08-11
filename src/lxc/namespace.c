/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2009
 *
 * Authors:
 * Daniel Lezcano <dlezcano at fr.ibm.com>
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include <unistd.h>
#include <alloca.h>
#include <errno.h>
#include <signal.h>
#include <syscall.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "namespace.h"
#include "log.h"

#include "setns.h"

lxc_log_define(lxc_namespace, lxc);

struct clone_arg {
	int (*fn)(void *);
	void *arg;
};

int setns(int fd, int nstype)
{
#ifndef __NR_setns
	errno = ENOSYS;
	return -1;
#else
	return syscall(__NR_setns, fd, nstype);
#endif
}

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

	long stack_size = sysconf(_SC_PAGESIZE);
 	void *stack = alloca(stack_size) + stack_size;
	pid_t ret;

#ifdef __ia64__
	ret = __clone2(do_clone, stack,
		       stack_size, flags | SIGCHLD, &clone_arg);
#else
	ret = clone(do_clone, stack, flags | SIGCHLD, &clone_arg);
#endif
	if (ret < 0)
		ERROR("failed to clone(0x%x): %s", flags, strerror(errno));

	return ret;
}

int lxc_attach(pid_t pid)
{
	char path[MAXPATHLEN];
	char *ns[] = { "pid", "mnt", "net", "ipc", "uts" };
	const int size = sizeof(ns) / sizeof(char *);
	int fd[size];
	int i;

	sprintf(path, "/proc/%d/ns", pid);
	if (access(path, X_OK)) {
		ERROR("Does this kernel version support 'attach' ?");
		return -1;
	}

	for (i = 0; i < size; i++) {
		sprintf(path, "/proc/%d/ns/%s", pid, ns[i]);
		fd[i] = open(path, O_RDONLY);
		if (fd[i] < 0) {
			SYSERROR("failed to open '%s'", path);
			return -1;
		}
	}

	for (i = 0; i < size; i++) {
		if (setns(fd[i], 0)) {
			SYSERROR("failed to set namespace '%s'", ns[i]);
			return -1;
		}

		close(fd[i]);
	}

	return 0;
}

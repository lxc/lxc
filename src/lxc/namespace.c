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

lxc_log_define(lxc_namespace, lxc);

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

	long stack_size = sysconf(_SC_PAGESIZE);
	void *stack = alloca(stack_size);
	pid_t ret;

#ifdef __ia64__
	ret = __clone2(do_clone, stack,
		       stack_size, flags | SIGCHLD, &clone_arg);
#else
	ret = clone(do_clone, stack  + stack_size, flags | SIGCHLD, &clone_arg);
#endif
	if (ret < 0)
		ERROR("failed to clone(0x%x): %s", flags, strerror(errno));

	return ret;
}

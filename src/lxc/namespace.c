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

#include <unistd.h>
#include <alloca.h>
#include <errno.h>
#include <signal.h>
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

	size_t stack_size = sysconf(_SC_PAGESIZE);
	void *stack = alloca(stack_size);
	pid_t ret;

#ifdef __ia64__
	ret = __clone2(do_clone, stack,
		       stack_size, flags | SIGCHLD, &clone_arg);
#else
	ret = clone(do_clone, stack  + stack_size, flags | SIGCHLD, &clone_arg);
#endif
	if (ret < 0)
		ERROR("failed to clone (%#x): %s", flags, strerror(errno));

	return ret;
}

static const char * const namespaces_list[] = {
	"MOUNT", "PID", "UTSNAME", "IPC",
	"USER", "NETWORK"
};
static const int cloneflags_list[] = {
	CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWUTS, CLONE_NEWIPC,
	CLONE_NEWUSER, CLONE_NEWNET
};

int lxc_namespace_2_cloneflag(char *namespace)
{
	int i, len;
	len = sizeof(namespaces_list)/sizeof(namespaces_list[0]);
	for (i = 0; i < len; i++)
		if (!strcmp(namespaces_list[i], namespace))
			return cloneflags_list[i];

	ERROR("invalid namespace name %s", namespace);
	return -1;
}

int lxc_fill_namespace_flags(char *flaglist, int *flags)
{
	char *token, *saveptr = NULL;
	int aflag;

	if (!flaglist) {
		ERROR("need at least one namespace to unshare");
		return -1;
	}

	token = strtok_r(flaglist, "|", &saveptr);
	while (token) {

		aflag = lxc_namespace_2_cloneflag(token);
		if (aflag < 0)
			return -1;

		*flags |= aflag;

		token = strtok_r(NULL, "|", &saveptr);
	}
	return 0;
}

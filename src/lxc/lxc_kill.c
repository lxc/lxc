/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2010
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
#include <errno.h>
#include <sys/param.h>
#include <stdlib.h>
#include <signal.h>
#include "commands.h"
#include "arguments.h"
#include "namespace.h"
#include "log.h"

lxc_log_define(lxc_kill_ui, lxc);

static const struct option my_longopts[] = {
	LXC_COMMON_OPTIONS
};

static struct lxc_arguments my_args = {
	.progname = "lxc-kill",
	.help     = "\
--name=NAME SIGNUM\n\
\n\
Sends signal number SIGNUM to the first user process in container NAME\n\
\n\
Options :\n\
  -n, --name=NAME     NAME for name of the container\n",
	.options  = my_longopts,
	.parser   = NULL,
	.checker  = NULL,
};

int main(int argc, char *argv[], char *envp[])
{
	int ret;
	pid_t pid;
	int sig;

	ret = lxc_arguments_parse(&my_args, argc, argv);
	if (ret)
		return ret;

	ret = lxc_log_init(my_args.log_file, my_args.log_priority,
			   my_args.progname, my_args.quiet);
	if (ret)
		return ret;

	if (my_args.argc) {
		sig = atoi(my_args.argv[0]);
		if (!sig || sig >= NSIG) {
			ERROR("'%s' isn't a valid signal number",
			      my_args.argv[0]);
			return -1;
		}
	} else
		sig=SIGKILL;

	pid = get_init_pid(my_args.name);
	if (pid < 0) {
		ERROR("failed to get the init pid");
		return -1;
	}

	ret = kill(pid, sig);
	if (ret < 0) {
		ERROR("failed to kill the init pid");
		return -1;
	}

	return 0;
}

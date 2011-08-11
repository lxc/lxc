/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2008
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
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/types.h>

#include <lxc/lxc.h>
#include <lxc/log.h>
#include <commands.h>
#include "arguments.h"

static bool state;
static bool pid;

static int my_parser(struct lxc_arguments* args, int c, char* arg)
{
	switch (c) {
	case 's': state = true; break;
	case 'p': pid = true; break;
	}
	return 0;
}

static const struct option my_longopts[] = {
	{"state", no_argument, 0, 's'},
	{"pid", no_argument, 0, 'p'},
	LXC_COMMON_OPTIONS,
};

static struct lxc_arguments my_args = {
	.progname = "lxc-info",
	.help     = "\
--name=NAME\n\
\n\
lxc-info display some information about a container with the identifier NAME\n\
\n\
Options :\n\
  -n, --name=NAME   NAME for name of the container\n\
  -s, --state       shows the state of the container\n\
  -p, --pid         shows the process id of the init container\n",
	.options  = my_longopts,
	.parser   = my_parser,
	.checker  = NULL,
};

int main(int argc, char *argv[])
{
	int ret;

	ret = lxc_arguments_parse(&my_args, argc, argv);
	if (ret)
		return 1;

	if (lxc_log_init(my_args.log_file, my_args.log_priority,
			 my_args.progname, my_args.quiet))
		return 1;

	if (!state && !pid)
		state = pid = true;

	if (state) {
		ret = lxc_getstate(my_args.name);
		if (ret < 0)
			return 1;

		printf("state:%10s\n", lxc_state2str(ret));
	}

	if (pid)
		printf("pid:%10d\n", get_init_pid(my_args.name));

	return 0;
}

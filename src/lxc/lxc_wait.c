/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2008
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
#include <stdio.h>
#include <string.h>
#include <libgen.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>

#include <lxc/lxccontainer.h>

#include "lxc.h"
#include "log.h"
#include "arguments.h"

lxc_log_define(lxc_wait_ui, lxc);

static int my_checker(const struct lxc_arguments* args)
{
	if (!args->states) {
		lxc_error(args, "missing state option to wait for.");
		return -1;
	}
	return 0;
}

static int my_parser(struct lxc_arguments* args, int c, char* arg)
{
	switch (c) {
	case 's': args->states = optarg; break;
	case 't': args->timeout = atol(optarg); break;
	}
	return 0;
}

static const struct option my_longopts[] = {
	{"state", required_argument, 0, 's'},
	{"timeout", required_argument, 0, 't'},
	LXC_COMMON_OPTIONS
};

static struct lxc_arguments my_args = {
	.progname = "lxc-wait",
	.help     = "\
--name=NAME --state=STATE\n\
\n\
lxc-wait waits for NAME container state to reach STATE\n\
\n\
Options :\n\
  -n, --name=NAME   NAME of the container\n\
  -s, --state=STATE ORed states to wait for\n\
                    STOPPED, STARTING, RUNNING, STOPPING,\n\
                    ABORTING, FREEZING, FROZEN, THAWED\n\
  -t, --timeout=TMO Seconds to wait for state changes\n",
	.options  = my_longopts,
	.parser   = my_parser,
	.checker  = my_checker,
	.timeout = -1,
};

int main(int argc, char *argv[])
{
	struct lxc_container *c;

	if (lxc_arguments_parse(&my_args, argc, argv))
		return 1;

	if (!my_args.log_file)
		my_args.log_file = "none";

	if (lxc_log_init(my_args.name, my_args.log_file, my_args.log_priority,
			 my_args.progname, my_args.quiet, my_args.lxcpath[0]))
		return 1;
	lxc_log_options_no_override();

	c = lxc_container_new(my_args.name, my_args.lxcpath[0]);
	if (!c)
		return 1;

	if (!c->may_control(c)) {
		fprintf(stderr, "Insufficent privileges to control %s\n", c->name);
		lxc_container_put(c);
		return 1;
	}

	if (!c->wait(c, my_args.states, my_args.timeout)) {
		lxc_container_put(c);
		return 1;
	}
	return 0;
}

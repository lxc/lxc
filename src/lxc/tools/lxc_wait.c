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
#include "tools/arguments.h"

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
  -t, --timeout=TMO Seconds to wait for state changes\n\
  --rcfile=FILE     Load configuration file FILE\n",
	.options  = my_longopts,
	.parser   = my_parser,
	.checker  = my_checker,
	.timeout = -1,
};

int main(int argc, char *argv[])
{
	struct lxc_container *c;
	struct lxc_log log;

	if (lxc_arguments_parse(&my_args, argc, argv))
		exit(EXIT_FAILURE);

	if (!my_args.log_file)
		my_args.log_file = "none";

	log.name = my_args.name;
	log.file = my_args.log_file;
	log.level = my_args.log_priority;
	log.prefix = my_args.progname;
	log.quiet = my_args.quiet;
	log.lxcpath = my_args.lxcpath[0];

	if (lxc_log_init(&log))
		exit(EXIT_FAILURE);
	lxc_log_options_no_override();

	/* REMOVE IN LXC 3.0 */
	setenv("LXC_UPDATE_CONFIG_FORMAT", "1", 0);

	c = lxc_container_new(my_args.name, my_args.lxcpath[0]);
	if (!c)
		exit(EXIT_FAILURE);

	if (!c->may_control(c)) {
		fprintf(stderr, "Insufficent privileges to control %s\n", c->name);
		lxc_container_put(c);
		exit(EXIT_FAILURE);
	}

	if (my_args.rcfile) {
		c->clear_config(c);
		if (!c->load_config(c, my_args.rcfile)) {
			fprintf(stderr, "Failed to load rcfile\n");
			lxc_container_put(c);
			exit(EXIT_FAILURE);
		}
		c->configfile = strdup(my_args.rcfile);
		if (!c->configfile) {
			fprintf(stderr, "Out of memory setting new config filename\n");
			lxc_container_put(c);
			exit(EXIT_FAILURE);
		}
	}

	if (!c->wait(c, my_args.states, my_args.timeout)) {
		lxc_container_put(c);
		exit(EXIT_FAILURE);
	}
	exit(EXIT_SUCCESS);
}

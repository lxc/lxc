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

#define _GNU_SOURCE
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#include <lxc/lxccontainer.h>

#include "arguments.h"
#include "tool_utils.h"

static int my_checker(const struct lxc_arguments* args)
{
	if (!args->argc) {
		lxc_error(args, "missing state object");
		return -1;
	}

	return 0;
}

static const struct option my_longopts[] = {
	LXC_COMMON_OPTIONS
};

static struct lxc_arguments my_args = {
	.progname = "lxc-cgroup",
	.help     = "\
--name=NAME state-object [value]\n\
\n\
Get or set the value of a state object (for example, 'cpuset.cpus')\n\
in the container's cgroup for the corresponding subsystem.\n\
\n\
Options :\n\
  -n, --name=NAME      NAME of the container\n\
  --rcfile=FILE        Load configuration file FILE\n",
	.options  = my_longopts,
	.parser   = NULL,
	.checker  = my_checker,
};

int main(int argc, char *argv[])
{
	char *state_object = NULL, *value = NULL;
	struct lxc_container *c;
	struct lxc_log log;

	if (lxc_arguments_parse(&my_args, argc, argv))
		exit(EXIT_FAILURE);

	/* Only create log if explicitly instructed */
	if (my_args.log_file || my_args.log_priority) {
		log.name = my_args.name;
		log.file = my_args.log_file;
		log.level = my_args.log_priority;
		log.prefix = my_args.progname;
		log.quiet = my_args.quiet;
		log.lxcpath = my_args.lxcpath[0];

		if (lxc_log_init(&log))
			exit(EXIT_FAILURE);
	}

	state_object = my_args.argv[0];

	c = lxc_container_new(my_args.name, my_args.lxcpath[0]);
	if (!c)
		exit(EXIT_FAILURE);

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

	if (!c->may_control(c)) {
		fprintf(stderr, "Insufficent privileges to control %s:%s\n", my_args.lxcpath[0], my_args.name);
		lxc_container_put(c);
		exit(EXIT_FAILURE);
	}

	if (!c->is_running(c)) {
		fprintf(stderr, "'%s:%s' is not running\n", my_args.lxcpath[0], my_args.name);
		lxc_container_put(c);
		exit(EXIT_FAILURE);
	}

	if ((my_args.argc) > 1) {
		value = my_args.argv[1];
		if (!c->set_cgroup_item(c, state_object, value)) {
			fprintf(stderr, "failed to assign '%s' value to '%s' for '%s'\n",
				value, state_object, my_args.name);
			lxc_container_put(c);
			exit(EXIT_FAILURE);
		}
	} else {
		char buffer[TOOL_MAXPATHLEN];
		int ret = c->get_cgroup_item(c, state_object, buffer, TOOL_MAXPATHLEN);
		if (ret < 0) {
			fprintf(stderr, "failed to retrieve value of '%s' for '%s:%s'\n",
			      state_object, my_args.lxcpath[0], my_args.name);
			lxc_container_put(c);
			exit(EXIT_FAILURE);
		}
		printf("%*s", ret, buffer);
	}

	lxc_container_put(c);
	exit(EXIT_SUCCESS);
}

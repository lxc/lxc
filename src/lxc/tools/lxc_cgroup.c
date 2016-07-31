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
#include <unistd.h>
#include <libgen.h>
#include <sys/types.h>

#include <lxc/lxccontainer.h>

#include "lxc.h"
#include "log.h"
#include "arguments.h"

lxc_log_define(lxc_cgroup_ui, lxc);

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
  -n, --name=NAME      NAME of the container",
	.options  = my_longopts,
	.parser   = NULL,
	.checker  = my_checker,
};

int main(int argc, char *argv[])
{
	char *state_object = NULL, *value = NULL;
	struct lxc_container *c;

	if (lxc_arguments_parse(&my_args, argc, argv))
		return 1;

	if (!my_args.log_file)
		my_args.log_file = "none";

	if (lxc_log_init(my_args.name, my_args.log_file, my_args.log_priority,
			 my_args.progname, my_args.quiet, my_args.lxcpath[0]))
		return 1;
	lxc_log_options_no_override();

	state_object = my_args.argv[0];

	c = lxc_container_new(my_args.name, my_args.lxcpath[0]);
	if (!c)
		return 1;

	if (!c->may_control(c)) {
		ERROR("Insufficent privileges to control %s:%s", my_args.lxcpath[0], my_args.name);
		lxc_container_put(c);
		return 1;
	}

	if (!c->is_running(c)) {
		ERROR("'%s:%s' is not running", my_args.lxcpath[0], my_args.name);
		lxc_container_put(c);
		return 1;
	}

	if ((my_args.argc) > 1) {
		value = my_args.argv[1];
		if (!c->set_cgroup_item(c, state_object, value)) {
			ERROR("failed to assign '%s' value to '%s' for '%s'",
				value, state_object, my_args.name);
			lxc_container_put(c);
			return 1;
		}
	} else {
		int len = 4096;
		char buffer[len];
		int ret = c->get_cgroup_item(c, state_object, buffer, len);
		if (ret < 0) {
			ERROR("failed to retrieve value of '%s' for '%s:%s'",
			      state_object, my_args.lxcpath[0], my_args.name);
			lxc_container_put(c);
			return 1;
		}
		printf("%*s", ret, buffer);
	}

	lxc_container_put(c);
	return 0;
}

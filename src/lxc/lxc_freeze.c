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
#include <sys/types.h>
#include <libgen.h>
#include <string.h>

#include <lxc/lxccontainer.h>

#include "lxc.h"
#include "log.h"

#include "arguments.h"

lxc_log_define(lxc_freeze_ui, lxc);

static const struct option my_longopts[] = {
	LXC_COMMON_OPTIONS
};

static struct lxc_arguments my_args = {
	.progname = "lxc-freeze",
	.help     = "\
--name=NAME\n\
\n\
lxc-freeze freezes a container with the identifier NAME\n\
\n\
Options :\n\
  -n, --name=NAME      NAME of the container",
	.options  = my_longopts,
	.parser   = NULL,
	.checker  = NULL,
};

int main(int argc, char *argv[])
{
	struct lxc_container *c;

	if (lxc_arguments_parse(&my_args, argc, argv))
		exit(1);

	if (!my_args.log_file)
		my_args.log_file = "none";

	if (lxc_log_init(my_args.name, my_args.log_file, my_args.log_priority,
			 my_args.progname, my_args.quiet, my_args.lxcpath[0]))
		exit(1);
	lxc_log_options_no_override();

	c = lxc_container_new(my_args.name, my_args.lxcpath[0]);
	if (!c) {
		ERROR("No such container: %s:%s", my_args.lxcpath[0], my_args.name);
		exit(1);
	}

	if (!c->may_control(c)) {
		ERROR("Insufficent privileges to control %s:%s", my_args.lxcpath[0], my_args.name);
		lxc_container_put(c);
		exit(1);
	}

	if (!c->freeze(c)) {
		ERROR("Failed to freeze %s:%s", my_args.lxcpath[0], my_args.name);
		lxc_container_put(c);
		exit(1);
	}

	lxc_container_put(c);

	exit(0);
}

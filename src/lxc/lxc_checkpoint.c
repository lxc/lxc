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
#include <libgen.h>
#include <unistd.h>
#include <sys/types.h>

#include <lxc.h>
#include "arguments.h"

static int my_checker(const struct lxc_arguments* args)
{
	if (!args->argc) {
		lxc_error(args, "missing STATEFILE filename !");
		return -1;
	}
	return 0;
}

static int my_parser(struct lxc_arguments* args, int c, char* arg)
{
	switch (c) {
	case 's': args->stop = 1; break;
	}
	return 0;
}

static const struct option my_longopts[] = {
	{"stop", no_argument, 0, 's'},
	LXC_COMMON_OPTIONS
};

static struct lxc_arguments my_args = {
	.progname = "lxc-checkpoint",
	.help     = "\
--name=NAME STATEFILE\n\
\n\
lxc-checkpoint checkpoints in STATEFILE file the NAME container\n\
\n\
Options :\n\
  -n, --name=NAME      NAME for name of the container\n\
  -s, --stop           stop the container after checkpoint\n",
	.options  = my_longopts,
	.parser   = my_parser,
	.checker  = my_checker,

	.rcfile   = NULL,
};

int main(int argc, char *argv[])
{
	int ret;

	ret = lxc_arguments_parse(&my_args, argc, argv);
	if (ret)
		return 1;

	if (lxc_log_init(my_args.log_file, my_args.log_priority,
			 my_args.progname, my_args.quiet))
		return -1;

	if (lxc_freeze(my_args.name))
		return -1;

	if (lxc_checkpoint(my_args.name, my_args.argv[0], 0))
		goto out;

	if (my_args.stop) {
		if (lxc_stop(my_args.name))
			goto out;
	}

	ret = 0;

out:
	if (lxc_unfreeze(my_args.name))
		return 1;

	return ret;
}

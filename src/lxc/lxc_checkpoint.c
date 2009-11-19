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
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <lxc/lxc.h>
#include <lxc/log.h>
#include <lxc/utils.h>

#include "arguments.h"
#include "config.h"

lxc_log_define(lxc_checkpoint, lxc);

static int my_checker(const struct lxc_arguments* args)
{
	if (!args->statefile) {
		lxc_error(args, "no statefile specified");
		return -1;
	}

	return 0;
}

static int my_parser(struct lxc_arguments* args, int c, char* arg)
{
	switch (c) {
	case 'k': args->flags = LXC_FLAG_HALT; break;
	case 'p': args->flags = LXC_FLAG_PAUSE; break;
	case 'd': args->statefile = arg; break;
	}
	return 0;
}

static const struct option my_longopts[] = {
	{"kill", no_argument, 0, 'k'},
	{"pause", no_argument, 0, 'p'},
	{"directory", required_argument, 0, 'd'},
	LXC_COMMON_OPTIONS
};

static struct lxc_arguments my_args = {
	.progname = "lxc-checkpoint",
	.help     = "\
--name=NAME --directory STATEFILE\n\
\n\
lxc-checkpoint checkpoints in STATEFILE the NAME container\n\
\n\
Options :\n\
  -n, --name=NAME      NAME for name of the container\n\
  -k, --kill           stop the container after checkpoint\n\
  -p, --pause          don't unfreeze the container after the checkpoint\n\
  -d, --directory=STATEFILE where to store the statefile\n",

	.options  = my_longopts,
	.parser   = my_parser,
	.checker  = my_checker,

	.rcfile   = NULL,
};

static int create_statefile(const char *dir)
{
	if (mkdir(dir, 0700) == -1 && errno != EEXIST) {
		ERROR("'%s' creation error : %m", dir);
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int ret;

	ret = lxc_arguments_parse(&my_args, argc, argv);
	if (ret)
		return ret;

	ret = lxc_log_init(my_args.log_file, my_args.log_priority,
			   my_args.progname, my_args.quiet);
	if (ret)
		return ret;

	ret = create_statefile(my_args.statefile);
	if (ret)
		return ret;

	ret = lxc_checkpoint(my_args.name, my_args.statefile, my_args.flags);
	if (ret) {
		ERROR("failed to checkpoint '%s'", my_args.name);
		return ret;
	}

	INFO("'%s' checkpointed", my_args.name);

	return ret;
}

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
#include <libgen.h>
#include <unistd.h>
#include <sys/types.h>

#include <lxc.h>
#include "arguments.h"

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
	case 'k': args->kill = 1; break;
	case 'p': args->pause = 1; break;
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

static int save_config_file(const char *name, const char *dir)
{
	char *src, *dst;
	int ret;

	if (!asprintf(&src, LXCPATH "/%s/config", name)) {
		ERROR("failed to allocate memory");
		return -1;
	}

	if (access(src, F_OK)) {
		free(src);
		return 0;
	}

	if (!asprintf(&dst, "%s/config", dir)) {
		ERROR("failed to allocate memory");
		free(src);
		return -1;
	}

	ret = lxc_copy_file(src, dst);
	if (ret)
		ERROR("failed to copy '%s' to '%s'", src, dst);

	free(src);
	free(dst);

	return ret;
}

int main(int argc, char *argv[])
{
	int ret = -1;

	ret = lxc_arguments_parse(&my_args, argc, argv);
	if (ret)
		return ret;

	ret = lxc_log_init(my_args.log_file, my_args.log_priority,
			   my_args.progname, my_args.quiet);
	if (ret)
		return ret;

	ret = save_config_file(my_args.name, my_args.statefile);
	if (ret) {
		ERROR("failed to save the configuration");
		return ret;
	}

	ret = lxc_checkpoint(my_args.name, -1, 0);
	if (ret) {
		ERROR("failed to checkpoint '%s'", my_args.name);
		return ret;
	}

	INFO("'%s' checkpointed", my_args.name);

	return ret;
}

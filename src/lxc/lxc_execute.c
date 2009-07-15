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
#include <errno.h>
#include <libgen.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>

#include <lxc/lxc.h>
#include "confile.h"
#include "arguments.h"

lxc_log_define(lxc_execute, lxc);

static int my_checker(const struct lxc_arguments* args)
{
	if (!args->argc) {
		lxc_error(args, "missing command to execute !");
		return -1;
	}
	return 0;
}

static int my_parser(struct lxc_arguments* args, int c, char* arg)
{
	switch (c) {
	case 'f': args->rcfile = arg; break;
	}
	return 0;
}

static const struct option my_longopts[] = {
	{"rcfile", required_argument, 0, 'f'},
	LXC_COMMON_OPTIONS
};

static struct lxc_arguments my_args = {
	.progname = "lxc-execute",
	.help     = "\
--name=NAME -- COMMAND\n\
\n\
lxc-execute creates a container with the identifier NAME\n\
and execs COMMAND into this container.\n\
\n\
Options :\n\
  -n, --name=NAME   NAME for name of the container\n\
  -f, --rcfile=FILE Load configuration file FILE\n",
	.options  = my_longopts,
	.parser   = my_parser,
	.checker  = my_checker,
};

int main(int argc, char *argv[])
{
	static char **args;
	char path[MAXPATHLEN];
	int autodestroy = 0;
	int ret = -1;
	struct lxc_conf lxc_conf;

	if (lxc_arguments_parse(&my_args, argc, argv))
		goto out;

	if (lxc_log_init(my_args.log_file, my_args.log_priority,
			 my_args.progname, my_args.quiet))
		goto out;

	if (lxc_conf_init(&lxc_conf))
		goto out;

	if (my_args.rcfile && lxc_config_read(my_args.rcfile, &lxc_conf))
		goto out;

	snprintf(path, MAXPATHLEN, LXCPATH "/%s", my_args.name);
	if (access(path, R_OK)) {
		if (lxc_create(my_args.name, &lxc_conf))
			goto out;
		autodestroy = 1;
	}

	args = lxc_arguments_dup(LXCLIBEXECDIR "/lxc-init", &my_args);
	if (!args)
		goto out;

	ret = lxc_start(my_args.name, args);
out:
	if (autodestroy) {
		if (lxc_destroy(my_args.name)) {
			ERROR("failed to destroy '%s'", my_args.name);
			if (!ret)
				ret = -1;
		}
	}

	return ret;
}


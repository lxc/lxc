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
#include <stdio.h>
#undef _GNU_SOURCE
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <libgen.h>
#include <poll.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include <lxc/lxccontainer.h>

#include "error.h"
#include "lxc.h"
#include "log.h"
#include "mainloop.h"
#include "arguments.h"
#include "commands.h"

lxc_log_define(lxc_console_ui, lxc);

static char etoc(const char *expr)
{
	/* returns "control code" of given expression */
	char c = expr[0] == '^' ? expr[1] : expr[0];
	return 1 + ((c > 'Z') ? (c - 'a') : (c - 'Z'));
}

static int my_parser(struct lxc_arguments* args, int c, char* arg)
{
	switch (c) {
	case 't': args->ttynum = atoi(arg); break;
	case 'e': args->escape = etoc(arg); break;
	}
	return 0;
}

static const struct option my_longopts[] = {
	{"tty", required_argument, 0, 't'},
	{"escape", required_argument, 0, 'e'},
	LXC_COMMON_OPTIONS
};

static struct lxc_arguments my_args = {
	.progname = "lxc-console",
	.help     = "\
--name=NAME [--tty NUMBER]\n\
\n\
lxc-console logs on the container with the identifier NAME\n\
\n\
Options :\n\
  -n, --name=NAME      NAME of the container\n\
  -t, --tty=NUMBER     console tty number\n\
  -e, --escape=PREFIX  prefix for escape command\n",
	.options  = my_longopts,
	.parser   = my_parser,
	.checker  = NULL,
	.ttynum = -1,
	.escape = 1,
};

int main(int argc, char *argv[])
{
	int ret;
	struct lxc_container *c;

	ret = lxc_arguments_parse(&my_args, argc, argv);
	if (ret)
		return EXIT_FAILURE;

	if (!my_args.log_file)
		my_args.log_file = "none";

	ret = lxc_log_init(my_args.name, my_args.log_file, my_args.log_priority,
			   my_args.progname, my_args.quiet, my_args.lxcpath[0]);
	if (ret)
		return EXIT_FAILURE;
	lxc_log_options_no_override();

	c = lxc_container_new(my_args.name, my_args.lxcpath[0]);
	if (!c) {
		fprintf(stderr, "System error loading container\n");
		exit(EXIT_FAILURE);
	}

	if (!c->may_control(c)) {
		fprintf(stderr, "Insufficent privileges to control %s\n", my_args.name);
		lxc_container_put(c);
		exit(EXIT_FAILURE);
	}

	if (!c->is_running(c)) {
		fprintf(stderr, "%s is not running\n", my_args.name);
		lxc_container_put(c);
		exit(EXIT_FAILURE);
	}

	ret = c->console(c, my_args.ttynum, 0, 1, 2, my_args.escape);
	if (ret < 0) {
		lxc_container_put(c);
		exit(EXIT_FAILURE);
	}
	lxc_container_put(c);
	return EXIT_SUCCESS;
}

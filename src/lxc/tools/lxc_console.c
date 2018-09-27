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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <lxc/lxccontainer.h>

#include "arguments.h"
#include "config.h"
#include "log.h"
#include "utils.h"

lxc_log_define(lxc_console, lxc);

static int my_parser(struct lxc_arguments *args, int c, char *arg);
static char etoc(const char *expr);

static const struct option my_longopts[] = {
	{"tty", required_argument, 0, 't'},
	{"escape", required_argument, 0, 'e'},
	LXC_COMMON_OPTIONS
};

static struct lxc_arguments my_args = {
	.progname     = "lxc-console",
	.help         = "\
--name=NAME [--tty NUMBER]\n\
\n\
lxc-console logs on the container with the identifier NAME\n\
\n\
Options :\n\
  -n, --name=NAME      NAME of the container\n\
  -t, --tty=NUMBER     console tty number\n\
  -e, --escape=PREFIX  prefix for escape command\n\
  --rcfile=FILE        Load configuration file FILE\n",
	.options      = my_longopts,
	.parser       = my_parser,
	.checker      = NULL,
	.log_priority = "ERROR",
	.log_file     = "none",
	.ttynum       = -1,
	.escape       = 1,
};

static int my_parser(struct lxc_arguments *args, int c, char *arg)
{
	switch (c) {
	case 't':
		if (lxc_safe_uint(arg, &args->ttynum) < 0)
			return -1;
		break;
	case 'e':
		args->escape = etoc(arg);
		break;
	}

	return 0;
}

static char etoc(const char *expr)
{
	/* returns "control code" of given expression */
	char c = expr[0] == '^' ? expr[1] : expr[0];

	return 1 + ((c > 'Z') ? (c - 'a') : (c - 'Z'));
}

int main(int argc, char *argv[])
{
	int ret;
	struct lxc_container *c;
	struct lxc_log log;

	if (lxc_arguments_parse(&my_args, argc, argv))
		exit(EXIT_FAILURE);

	log.name = my_args.name;
	log.file = my_args.log_file;
	log.level = my_args.log_priority;
	log.prefix = my_args.progname;
	log.quiet = my_args.quiet;
	log.lxcpath = my_args.lxcpath[0];

	if (lxc_log_init(&log))
		exit(EXIT_FAILURE);

	c = lxc_container_new(my_args.name, my_args.lxcpath[0]);
	if (!c) {
		ERROR("System error loading container");
		exit(EXIT_FAILURE);
	}

	if (my_args.rcfile) {
		c->clear_config(c);

		if (!c->load_config(c, my_args.rcfile)) {
			ERROR("Failed to load rcfile");
			lxc_container_put(c);
			exit(EXIT_FAILURE);
		}

		c->configfile = strdup(my_args.rcfile);
		if (!c->configfile) {
			ERROR("Out of memory setting new config filename");
			lxc_container_put(c);
			exit(EXIT_FAILURE);
		}
	}

	if (!c->may_control(c)) {
		ERROR("Insufficent privileges to control %s", my_args.name);
		lxc_container_put(c);
		exit(EXIT_FAILURE);
	}

	if (!c->is_running(c)) {
		ERROR("%s is not running", my_args.name);
		lxc_container_put(c);
		exit(EXIT_FAILURE);
	}

	ret = c->console(c, my_args.ttynum, 0, 1, 2, my_args.escape);
	if (ret < 0) {
		lxc_container_put(c);
		exit(EXIT_FAILURE);
	}

	lxc_container_put(c);
	exit(EXIT_SUCCESS);
}

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
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <lxc/lxccontainer.h>

#include "arguments.h"
#include "commands.h"
#include "error.h"
#include "log.h"
#include "lxc.h"
#include "mainloop.h"
#include "utils.h"

static char etoc(const char *expr)
{
	/* returns "control code" of given expression */
	char c = expr[0] == '^' ? expr[1] : expr[0];
	return 1 + ((c > 'Z') ? (c - 'a') : (c - 'Z'));
}

static int my_parser(struct lxc_arguments* args, int c, char* arg)
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
  -e, --escape=PREFIX  prefix for escape command\n\
  --rcfile=FILE        Load configuration file FILE\n",
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
	struct lxc_log log;

	ret = lxc_arguments_parse(&my_args, argc, argv);
	if (ret)
		return EXIT_FAILURE;

	if (!my_args.log_file)
		my_args.log_file = "none";

	log.name = my_args.name;
	log.file = my_args.log_file;
	log.level = my_args.log_priority;
	log.prefix = my_args.progname;
	log.quiet = my_args.quiet;
	log.lxcpath = my_args.lxcpath[0];

	ret = lxc_log_init(&log);
	if (ret)
		return EXIT_FAILURE;
	lxc_log_options_no_override();

	/* REMOVE IN LXC 3.0 */
	setenv("LXC_UPDATE_CONFIG_FORMAT", "1", 0);

	c = lxc_container_new(my_args.name, my_args.lxcpath[0]);
	if (!c) {
		fprintf(stderr, "System error loading container\n");
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
	exit(EXIT_SUCCESS);
}

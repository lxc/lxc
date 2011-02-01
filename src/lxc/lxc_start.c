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
#undef _GNU_SOURCE
#include <libgen.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <termios.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/param.h>
#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>

#include "log.h"
#include "caps.h"
#include "lxc.h"
#include "conf.h"
#include "cgroup.h"
#include "utils.h"
#include "config.h"
#include "confile.h"
#include "arguments.h"

lxc_log_define(lxc_start_ui, lxc_start);

static struct lxc_list defines;

static int my_parser(struct lxc_arguments* args, int c, char* arg)
{
	switch (c) {
	case 'c': args->console = arg; break;
	case 'd': args->daemonize = 1; break;
	case 'f': args->rcfile = arg; break;
	case 's': return lxc_config_define_add(&defines, arg);
	}
	return 0;
}

static const struct option my_longopts[] = {
	{"daemon", no_argument, 0, 'd'},
	{"rcfile", required_argument, 0, 'f'},
	{"define", required_argument, 0, 's'},
	{"console", required_argument, 0, 'c'},
	LXC_COMMON_OPTIONS
};

static struct lxc_arguments my_args = {
	.progname = "lxc-start",
	.help     = "\
--name=NAME -- COMMAND\n\
\n\
lxc-start start COMMAND in specified container NAME\n\
\n\
Options :\n\
  -n, --name=NAME      NAME for name of the container\n\
  -d, --daemon         daemonize the container\n\
  -f, --rcfile=FILE    Load configuration file FILE\n\
  -c, --console=FILE   Set the file output for the container console\n\
  -s, --define KEY=VAL Assign VAL to configuration variable KEY\n",
	.options   = my_longopts,
	.parser    = my_parser,
	.checker   = NULL,
	.daemonize = 0,
};

int main(int argc, char *argv[])
{
	int err = -1;
	struct lxc_conf *conf;
	char *const *args;
	char *rcfile = NULL;
	char *const default_args[] = {
		"/sbin/init",
		'\0',
	};

	lxc_list_init(&defines);

	if (lxc_caps_init())
		return err;

	if (lxc_arguments_parse(&my_args, argc, argv))
		return err;

	if (!my_args.argc)
		args = default_args; 
	else
		args = my_args.argv;

	if (lxc_log_init(my_args.log_file, my_args.log_priority,
			 my_args.progname, my_args.quiet))
		return err;

	if (putenv("container=lxc")) {
		SYSERROR("failed to set environment variable");
		return err;
	}

	/* rcfile is specified in the cli option */
	if (my_args.rcfile)
		rcfile = (char *)my_args.rcfile;
	else {
		int rc;

		rc = asprintf(&rcfile, LXCPATH "/%s/config", my_args.name);
		if (rc == -1) {
			SYSERROR("failed to allocate memory");
			return err;
		}

		/* container configuration does not exist */
		if (access(rcfile, F_OK)) {
			free(rcfile);
			rcfile = NULL;
		}
	}

	conf = lxc_conf_init();
	if (!conf) {
		ERROR("failed to initialize configuration");
		return err;
	}

	if (rcfile && lxc_config_read(rcfile, conf)) {
		ERROR("failed to read configuration file");
		return err;
	}

	if (lxc_config_define_load(&defines, conf))
		return err;

	if (!rcfile && !strcmp("/sbin/init", args[0])) {
		ERROR("no configuration file for '/sbin/init' (may crash the host)");
		return err;
	}

	if (my_args.console) {

		char *console, fd;

		if (access(my_args.console, W_OK)) {

			fd = creat(my_args.console, 0600);
			if (fd < 0) {
				SYSERROR("failed to touch file '%s'",
					 my_args.console);
				return err;
			}
			close(fd);
		}

		console = realpath(my_args.console, NULL);
		if (!console) {
			SYSERROR("failed to get the real path of '%s'",
				 my_args.console);
			return err;
		}

		conf->console.path = strdup(console);
		if (!conf->console.path) {
			ERROR("failed to dup string '%s'", console);
			return err;
		}

		free(console);
	}

	if (my_args.daemonize && daemon(0, 0)) {
		SYSERROR("failed to daemonize '%s'", my_args.name);
		return err;
	}

	err = lxc_start(my_args.name, args, conf);

	/*
	 * exec ourself, that requires to have all opened fd
	 * with the close-on-exec flag set
	 */
	if (conf->reboot) {
		INFO("rebooting container");
		execvp(argv[0], argv);
		SYSERROR("failed to exec");
		err = -1;
	}

	return err;
}


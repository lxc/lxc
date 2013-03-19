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

static int ensure_path(char **confpath, const char *path)
{
	int err = -1, fd;
	char *fullpath = NULL;

	if (path) {
		if (access(path, W_OK)) {
			fd = creat(path, 0600);
			if (fd < 0) {
				SYSERROR("failed to create '%s'", path);
				goto err;
			}
			close(fd);
		}

		fullpath = realpath(path, NULL);
		if (!fullpath) {
			SYSERROR("failed to get the real path of '%s'", path);
			goto err;
		}

		*confpath = strdup(fullpath);
		if (!*confpath) {
			ERROR("failed to dup string '%s'", fullpath);
			goto err;
		}
	}
	err = 0;

err:
	if (fullpath)
		free(fullpath);
	return err;
}

static int my_parser(struct lxc_arguments* args, int c, char* arg)
{
	switch (c) {
	case 'c': args->console = arg; break;
	case 'L': args->console_log = arg; break;
	case 'd': args->daemonize = 1; args->close_all_fds = 1; break;
	case 'f': args->rcfile = arg; break;
	case 'C': args->close_all_fds = 1; break;
	case 's': return lxc_config_define_add(&defines, arg);
	case 'p': args->pidfile = arg; break;
	}
	return 0;
}

static const struct option my_longopts[] = {
	{"daemon", no_argument, 0, 'd'},
	{"rcfile", required_argument, 0, 'f'},
	{"define", required_argument, 0, 's'},
	{"console", required_argument, 0, 'c'},
	{"console-log", required_argument, 0, 'L'},
	{"close-all-fds", no_argument, 0, 'C'},
	{"pidfile", required_argument, 0, 'p'},
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
  -n, --name=NAME        NAME for name of the container\n\
  -d, --daemon           daemonize the container\n\
  -p, --pidfile=FILE     Create a file with the process id\n\
  -f, --rcfile=FILE      Load configuration file FILE\n\
  -c, --console=FILE     Use specified FILE for the container console\n\
  -L, --console-log=FILE Log container console output to FILE\n\
  -C, --close-all-fds    If any fds are inherited, close them\n\
                         If not specified, exit with failure instead\n\
		         Note: --daemon implies --close-all-fds\n\
  -s, --define KEY=VAL   Assign VAL to configuration variable KEY\n",
	.options   = my_longopts,
	.parser    = my_parser,
	.checker   = NULL,
	.daemonize = 0,
	.pidfile = NULL,
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
	FILE *pid_fp = NULL;

	lxc_list_init(&defines);

	if (lxc_caps_init())
		return err;

	if (lxc_arguments_parse(&my_args, argc, argv))
		return err;

	if (!my_args.argc)
		args = default_args;
	else
		args = my_args.argv;

	if (lxc_log_init(my_args.name, my_args.log_file, my_args.log_priority,
			 my_args.progname, my_args.quiet))
		return err;

	/* rcfile is specified in the cli option */
	if (my_args.rcfile)
		rcfile = (char *)my_args.rcfile;
	else {
		int rc;

		rc = asprintf(&rcfile, "%s/%s/config", my_args.lxcpath, my_args.name);
		if (rc == -1) {
			SYSERROR("failed to allocate memory");
			return err;
		}
		INFO("using rcfile %s", rcfile);

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

	if (ensure_path(&conf->console.path, my_args.console) < 0) {
		ERROR("failed to ensure console path '%s'", my_args.console);
		return err;
	}

	if (ensure_path(&conf->console.log_path, my_args.console_log) < 0) {
		ERROR("failed to ensure console log '%s'", my_args.console_log);
		return err;
	}

	if (my_args.pidfile != NULL) {
		pid_fp = fopen(my_args.pidfile, "w");
		if (pid_fp == NULL) {
			SYSERROR("failed to create pidfile '%s' for '%s'",
				 my_args.pidfile, my_args.name);
			return err;
		}
	}

	if (my_args.daemonize) {
		/* do an early check for needed privs, since otherwise the
		 * user won't see the error */

		if (!lxc_caps_check()) {
			ERROR("Not running with sufficient privilege");
			return err;
		}

		if (daemon(0, 0)) {
			SYSERROR("failed to daemonize '%s'", my_args.name);
			return err;
		}
	}

	if (pid_fp != NULL) {
		if (fprintf(pid_fp, "%d\n", getpid()) < 0) {
			SYSERROR("failed to write '%s'", my_args.pidfile);
			return err;
		}
		fclose(pid_fp);
	}

	if (my_args.close_all_fds)
		conf->close_all_fds = 1;

	err = lxc_start(my_args.name, args, conf, my_args.lxcpath);

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

	if (my_args.pidfile)
		unlink(my_args.pidfile);

	return err;
}


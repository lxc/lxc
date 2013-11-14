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
#include <lxc/lxccontainer.h>
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
			if (fd < 0 && errno != EEXIST) {
				SYSERROR("failed to create '%s'", path);
				goto err;
			}
			if (fd >= 0)
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
	case 'd': args->daemonize = 1; break;
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
	struct lxc_container *c;

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
			 my_args.progname, my_args.quiet, my_args.lxcpath[0]))
		return err;

	const char *lxcpath = my_args.lxcpath[0];

	/*
	 * rcfile possibilities:
	 * 1. rcfile from random path specified in cli option
	 * 2. rcfile not specified, use $lxcpath/$lxcname/config
	 * 3. rcfile not specified and does not exist.
	 */
	/* rcfile is specified in the cli option */
	if (my_args.rcfile) {
		rcfile = (char *)my_args.rcfile;
		c = lxc_container_new(my_args.name, lxcpath);
		if (!c) {
			ERROR("Failed to create lxc_container");
			return err;
		}
		c->clear_config(c);
		if (!c->load_config(c, rcfile)) {
			ERROR("Failed to load rcfile");
			lxc_container_put(c);
			return err;
		}
	} else {
		int rc;

		rc = asprintf(&rcfile, "%s/%s/config", lxcpath, my_args.name);
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
		c = lxc_container_new(my_args.name, lxcpath);
		if (!c) {
			ERROR("Failed to create lxc_container");
			return err;
		}
	}

	/*
	 * We should use set_config_item() over &defines, which would handle
	 * unset c->lxc_conf for us and let us not use lxc_config_define_load()
	 */
	if (!c->lxc_conf)
		c->lxc_conf = lxc_conf_init();
	conf = c->lxc_conf;

	if (lxc_config_define_load(&defines, conf))
		goto out;

	if (!rcfile && !strcmp("/sbin/init", args[0])) {
		ERROR("Executing '/sbin/init' with no configuration file may crash the host");
		goto out;
	}

	if (ensure_path(&conf->console.path, my_args.console) < 0) {
		ERROR("failed to ensure console path '%s'", my_args.console);
		goto out;
	}

	if (ensure_path(&conf->console.log_path, my_args.console_log) < 0) {
		ERROR("failed to ensure console log '%s'", my_args.console_log);
		goto out;
	}

	if (my_args.pidfile != NULL) {
		pid_fp = fopen(my_args.pidfile, "w");
		if (pid_fp == NULL) {
			SYSERROR("failed to create pidfile '%s' for '%s'",
				 my_args.pidfile, my_args.name);
			goto out;
		}
	}

	if (my_args.daemonize) {
		c->want_daemonize(c);
	}

	if (pid_fp != NULL) {
		if (fprintf(pid_fp, "%d\n", getpid()) < 0) {
			SYSERROR("failed to write '%s'", my_args.pidfile);
			goto out;
		}
		fclose(pid_fp);
	}

	if (my_args.close_all_fds)
		c->want_close_all_fds(c);

	err = c->start(c, 0, args) ? 0 : -1;

	if (my_args.pidfile)
		unlink(my_args.pidfile);

out:
	lxc_container_put(c);
	return err;
}


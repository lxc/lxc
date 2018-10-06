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
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <net/if.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <lxc/lxccontainer.h>

#include "arguments.h"
#include "caps.h"
#include "config.h"
#include "confile.h"
#include "log.h"

lxc_log_define(lxc_start, lxc);

static int my_parser(struct lxc_arguments *args, int c, char *arg);
static int ensure_path(char **confpath, const char *path);

static struct lxc_list defines;

static const struct option my_longopts[] = {
	{"daemon", no_argument, 0, 'd'},
	{"foreground", no_argument, 0, 'F'},
	{"rcfile", required_argument, 0, 'f'},
	{"define", required_argument, 0, 's'},
	{"console", required_argument, 0, 'c'},
	{"console-log", required_argument, 0, 'L'},
	{"close-all-fds", no_argument, 0, 'C'},
	{"pidfile", required_argument, 0, 'p'},
	{"share-net", required_argument, 0, OPT_SHARE_NET},
	{"share-ipc", required_argument, 0, OPT_SHARE_IPC},
	{"share-uts", required_argument, 0, OPT_SHARE_UTS},
	{"share-pid", required_argument, 0, OPT_SHARE_PID},
	LXC_COMMON_OPTIONS
};

static struct lxc_arguments my_args = {
	.progname     = "lxc-start",
	.help         = "\
--name=NAME -- COMMAND\n\
\n\
lxc-start start COMMAND in specified container NAME\n\
\n\
Options :\n\
  -n, --name=NAME        NAME of the container\n\
  -d, --daemon           Daemonize the container (default)\n\
  -F, --foreground       Start with the current tty attached to /dev/console\n\
  -p, --pidfile=FILE     Create a file with the process id\n\
  -f, --rcfile=FILE      Load configuration file FILE\n\
  -c, --console=FILE     Use specified FILE for the container console\n\
  -L, --console-log=FILE Log container console output to FILE\n\
  -C, --close-all-fds    If any fds are inherited, close them\n\
                         If not specified, exit with failure instead\n\
                         Note: --daemon implies --close-all-fds\n\
  -s, --define KEY=VAL   Assign VAL to configuration variable KEY\n\
      --share-[net|ipc|uts|pid]=NAME Share a namespace with another container or pid\n\
",
	.options      = my_longopts,
	.parser       = my_parser,
	.checker      = NULL,
	.log_priority = "ERROR",
	.log_file     = "none",
	.daemonize    = 1,
	.pidfile      = NULL,
};

static int my_parser(struct lxc_arguments *args, int c, char *arg)
{
	switch (c) {
	case 'c':
		args->console = arg;
		break;
	case 'L':
		args->console_log = arg;
		break;
	case 'd':
		args->daemonize = 1;
		break;
	case 'F':
		args->daemonize = 0;
		break;
	case 'f':
		args->rcfile = arg;
		break;
	case 'C':
		args->close_all_fds = true;
		break;
	case 's':
		return lxc_config_define_add(&defines, arg);
	case 'p':
		args->pidfile = arg;
		break;
	case OPT_SHARE_NET:
		args->share_ns[LXC_NS_NET] = arg;
		break;
	case OPT_SHARE_IPC:
		args->share_ns[LXC_NS_IPC] = arg;
		break;
	case OPT_SHARE_UTS:
		args->share_ns[LXC_NS_UTS] = arg;
		break;
	case OPT_SHARE_PID:
		args->share_ns[LXC_NS_PID] = arg;
		break;
	}
	return 0;
}

static int ensure_path(char **confpath, const char *path)
{
	int fd;
	char *fullpath = NULL;

	if (path) {
		if (access(path, W_OK)) {
			fd = creat(path, 0600);
			if (fd < 0 && errno != EEXIST) {
				ERROR("Failed to create '%s'", path);
				return -1;
			}

			if (fd >= 0)
				close(fd);
		}

		fullpath = realpath(path, NULL);
		if (!fullpath) {
			ERROR("Failed to get the real path of '%s'", path);
			return -1;
		}

		*confpath = fullpath;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	const char *lxcpath;
	char *const *args;
	struct lxc_container *c;
	struct lxc_log log;
	int err = EXIT_FAILURE;
	char *rcfile = NULL;
	char *const default_args[] = {
		"/sbin/init",
		NULL,
	};

	lxc_list_init(&defines);

	if (lxc_caps_init())
		exit(err);

	if (lxc_arguments_parse(&my_args, argc, argv))
		exit(err);

	if (!my_args.argc)
		args = default_args;
	else
		args = my_args.argv;

	log.name = my_args.name;
	log.file = my_args.log_file;
	log.level = my_args.log_priority;
	log.prefix = my_args.progname;
	log.quiet = my_args.quiet;
	log.lxcpath = my_args.lxcpath[0];

	if (lxc_log_init(&log))
		exit(err);

	lxcpath = my_args.lxcpath[0];
	if (access(lxcpath, O_RDONLY) < 0) {
		ERROR("You lack access to %s", lxcpath);
		exit(err);
	}

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
			exit(err);
		}

		c->clear_config(c);

		if (!c->load_config(c, rcfile)) {
			ERROR("Failed to load rcfile");
			lxc_container_put(c);
			exit(err);
		}

		c->configfile = strdup(my_args.rcfile);
		if (!c->configfile) {
			ERROR("Out of memory setting new config filename");
			goto out;
		}
	} else {
		int rc;

		rc = asprintf(&rcfile, "%s/%s/config", lxcpath, my_args.name);
		if (rc == -1) {
			ERROR("Failed to allocate memory");
			exit(err);
		}

		/* container configuration does not exist */
		if (access(rcfile, F_OK)) {
			free(rcfile);
			rcfile = NULL;
		}

		c = lxc_container_new(my_args.name, lxcpath);
		if (!c) {
			ERROR("Failed to create lxc_container");
			exit(err);
		}
	}

	/* We do not check here whether the container is defined, because we
	 * support volatile containers. Which means the container does not need
	 * to be created for it to be started. You can just pass a configuration
	 * file as argument and start the container right away.
	 */
	if (!c->may_control(c)) {
		ERROR("Insufficent privileges to control %s", c->name);
		goto out;
	}

	if (c->is_running(c)) {
		ERROR("Container is already running");
		err = EXIT_SUCCESS;
		goto out;
	}

	/*
	 * We should use set_config_item() over &defines, which would handle
	 * unset c->lxc_conf for us and let us not use lxc_config_define_load()
	 */
	if (!c->lxc_conf) {
		ERROR("No container config specified");
		goto out;
	}

	if (!lxc_config_define_load(&defines, c))
		goto out;

	if (!rcfile && !strcmp("/sbin/init", args[0])) {
		ERROR("Executing '/sbin/init' with no configuration file may crash the host");
		goto out;
	}

	if (my_args.pidfile)
		if (ensure_path(&c->pidfile, my_args.pidfile) < 0) {
			ERROR("Failed to ensure pidfile '%s'", my_args.pidfile);
			goto out;
		}

	if (my_args.console)
		if (!c->set_config_item(c, "lxc.console.path", my_args.console))
			goto out;

	if (my_args.console_log)
		if (!c->set_config_item(c, "lxc.console.logfile", my_args.console_log))
			goto out;

	if (!lxc_setup_shared_ns(&my_args, c))
		goto out;

	if (!my_args.daemonize)
		c->want_daemonize(c, false);

	if (my_args.close_all_fds)
		c->want_close_all_fds(c, true);

	if (args == default_args)
		err = c->start(c, 0, NULL) ? EXIT_SUCCESS : EXIT_FAILURE;
	else
		err = c->start(c, 0, args) ? EXIT_SUCCESS : EXIT_FAILURE;
	if (err) {
		ERROR("The container failed to start");

		if (my_args.daemonize)
			ERROR("To get more details, run the container in foreground mode");

		ERROR("Additional information can be obtained by setting the "
		      "--logfile and --logpriority options");

		err = c->error_num;
		lxc_container_put(c);
		exit(err);
	}

out:
	lxc_container_put(c);
	exit(err);
}

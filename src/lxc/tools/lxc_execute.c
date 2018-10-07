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
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <lxc/lxccontainer.h>

#include "arguments.h"
#include "caps.h"
#include "config.h"
#include "confile.h"
#include "log.h"
#include "utils.h"

lxc_log_define(lxc_execute, lxc);

static int my_parser(struct lxc_arguments *args, int c, char *arg);
static bool set_argv(struct lxc_container *c, struct lxc_arguments *args);

static struct lxc_list defines;

static const struct option my_longopts[] = {
	{"daemon", no_argument, 0, 'd'},
	{"rcfile", required_argument, 0, 'f'},
	{"define", required_argument, 0, 's'},
	{"uid", required_argument, 0, 'u'},
	{"gid", required_argument, 0, 'g'},
	{"share-net", required_argument, 0, OPT_SHARE_NET},
	{"share-ipc", required_argument, 0, OPT_SHARE_IPC},
	{"share-uts", required_argument, 0, OPT_SHARE_UTS},
	{"share-pid", required_argument, 0, OPT_SHARE_PID},
	LXC_COMMON_OPTIONS
};

static struct lxc_arguments my_args = {
	.progname     = "lxc-execute",
	.help         = "\
--name=NAME -- COMMAND\n\
\n\
lxc-execute creates a container with the identifier NAME\n\
and execs COMMAND into this container.\n\
\n\
Options :\n\
  -n, --name=NAME      NAME of the container\n\
  -d, --daemon         Daemonize the container\n\
  -f, --rcfile=FILE    Load configuration file FILE\n\
  -s, --define KEY=VAL Assign VAL to configuration variable KEY\n\
  -u, --uid=UID        Execute COMMAND with UID inside the container\n\
  -g, --gid=GID        Execute COMMAND with GID inside the container\n",
	.options      = my_longopts,
	.parser       = my_parser,
	.log_priority = "ERROR",
	.log_file     = "none",
	.daemonize    = 0,
};

static int my_parser(struct lxc_arguments *args, int c, char *arg)
{
	int ret;

	switch (c) {
	case 'd':
		args->daemonize = 1;
		break;
	case 'f':
		args->rcfile = arg;
		break;
	case 's':
		ret = lxc_config_define_add(&defines, arg);
		if (ret < 0)
			lxc_config_define_free(&defines);
		break;
	case 'u':
		if (lxc_safe_uint(arg, &args->uid) < 0)
			return -1;
		break;
	case 'g':
		if (lxc_safe_uint(arg, &args->gid) < 0)
			return -1;
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

static bool set_argv(struct lxc_container *c, struct lxc_arguments *args)
{
	int ret;
	char buf[PATH_MAX];
	char **components, **p;

	buf[0] = '\0';
	ret = c->get_config_item(c, "lxc.execute.cmd", buf, PATH_MAX);
	if (ret < 0)
		return false;

	components = lxc_string_split_quoted(buf);
	if (!components)
		return false;

	args->argv = components;

	for (p = components; *p; p++)
		args->argc++;

	return true;
}

int main(int argc, char *argv[])
{
	struct lxc_container *c;
	struct lxc_log log;
	int err = EXIT_FAILURE;
	int ret;
	bool bret;

	lxc_list_init(&defines);

	if (lxc_caps_init())
		exit(err);

	if (lxc_arguments_parse(&my_args, argc, argv))
		exit(err);

	log.name = my_args.name;
	log.file = my_args.log_file;
	log.level = my_args.log_priority;
	log.prefix = my_args.progname;
	log.quiet = my_args.quiet;
	log.lxcpath = my_args.lxcpath[0];

	if (lxc_log_init(&log))
		exit(err);

	c = lxc_container_new(my_args.name, my_args.lxcpath[0]);
	if (!c) {
		ERROR("Failed to create lxc_container");
		exit(err);
	}

	if (my_args.rcfile) {
		c->clear_config(c);

		if (!c->load_config(c, my_args.rcfile)) {
			ERROR("Failed to load rcfile");
			goto out;
		}

		c->configfile = strdup(my_args.rcfile);
		if (!c->configfile) {
			ERROR("Out of memory setting new config filename");
			goto out;
		}
	}

	if (!c->lxc_conf) {
		ERROR("Executing a container with no configuration file may crash the host");
		goto out;
	}

	if (my_args.argc == 0)
		if (!set_argv(c, &my_args)) {
			ERROR("Missing command to execute!");
			goto out;
		}

	bret = lxc_config_define_load(&defines, c);
	if (!bret)
		goto out;

	if (my_args.uid) {
		char buf[256];

		ret = snprintf(buf, 256, "%d", my_args.uid);
		if (ret < 0 || (size_t)ret >= 256)
			goto out;

		bret = c->set_config_item(c, "lxc.init.uid", buf);
		if (!bret)
			goto out;
	}

	if (my_args.gid) {
		char buf[256];

		ret = snprintf(buf, 256, "%d", my_args.gid);
		if (ret < 0 || (size_t)ret >= 256)
			goto out;

		bret = c->set_config_item(c, "lxc.init.gid", buf);
		if (!bret)
			goto out;
	}

	if (!lxc_setup_shared_ns(&my_args, c))
		goto out;

	c->daemonize = my_args.daemonize == 1;

	bret = c->start(c, 1, my_args.argv);
	if (!bret) {
		ERROR("Failed run an application inside container");
		goto out;
	}

	if (c->daemonize) {
		err = EXIT_SUCCESS;
	} else {
		if (WIFEXITED(c->error_num))
			err = WEXITSTATUS(c->error_num);
		else
			/* Try to die with the same signal the task did. */
			kill(0, WTERMSIG(c->error_num));
	}

out:
	lxc_container_put(c);
	exit(err);
}

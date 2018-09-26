/*
 * lxc: linux Container library
 *
 * Authors:
 * Dongsheng Yang <yangds.fnst@cn.fujitsu.com>
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
#include <libgen.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <lxc/lxccontainer.h>

#include "../../include/netns_ifaddrs.h"
#include "arguments.h"
#include "config.h"
#include "log.h"
#include "utils.h"

lxc_log_define(lxc_device, lxc);

static bool is_interface(const char *dev_name, pid_t pid);

static const struct option my_longopts[] = {
	LXC_COMMON_OPTIONS
};

static struct lxc_arguments my_args = {
	.progname     = "lxc-device",
	.help         = "\
--name=NAME -- add|del DEV\n\
\n\
lxc-device attach or detach DEV to or from container.\n\
\n\
Options :\n\
  -n, --name=NAME      NAME of the container\n\
  --rcfile=FILE        Load configuration file FILE\n",
	.options      = my_longopts,
	.parser       = NULL,
	.checker      = NULL,
	.log_priority = "ERROR",
	.log_file     = "none",
};

static bool is_interface(const char *dev_name, pid_t pid)
{
	pid_t p = fork();
	if (p < 0) {
		ERROR("Failed to fork task");
		exit(EXIT_FAILURE);
	}

	if (p == 0) {
		struct netns_ifaddrs *interfaceArray = NULL, *tempIfAddr = NULL;

		if (!switch_to_ns(pid, "net")) {
			ERROR("Failed to enter netns of container");
			_exit(-1);
		}

		/* Grab the list of interfaces */
		if (netns_getifaddrs(&interfaceArray, -1, &(bool){false})) {
			ERROR("Failed to get interfaces list");
			_exit(-1);
		}

		/* Iterate through the interfaces */
		for (tempIfAddr = interfaceArray; tempIfAddr != NULL; tempIfAddr = tempIfAddr->ifa_next) {
			if (strncmp(tempIfAddr->ifa_name, dev_name, strlen(tempIfAddr->ifa_name)) == 0)
				_exit(EXIT_SUCCESS);
		}

		_exit(EXIT_FAILURE);
	}

	if (wait_for_pid(p) == 0)
		return true;

	return false;
}

int main(int argc, char *argv[])
{
	struct lxc_container *c;
	struct lxc_log log;
	char *cmd, *dev_name, *dst_name;
	bool ret = false;

	if (geteuid() != 0) {
		ERROR("%s must be run as root", argv[0]);
		exit(EXIT_FAILURE);
	}

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
		ERROR("%s doesn't exist", my_args.name);
		exit(EXIT_FAILURE);
	}

	if (my_args.rcfile) {
		c->clear_config(c);

		if (!c->load_config(c, my_args.rcfile)) {
			ERROR("Failed to load rcfile");
			goto err;
		}

		c->configfile = strdup(my_args.rcfile);
		if (!c->configfile) {
			ERROR("Out of memory setting new config filename");
			goto err;
		}
	}

	if (!c->is_running(c)) {
		ERROR("Container %s is not running", c->name);
		goto err;
	}

	if (my_args.argc < 2) {
		ERROR("Error: no command given (Please see --help output)");
		goto err;
	}

	cmd = my_args.argv[0];
	dev_name = my_args.argv[1];

	if (my_args.argc < 3)
		dst_name = dev_name;
	else
		dst_name = my_args.argv[2];

	if (strncmp(cmd, "add", strlen(cmd)) == 0) {
		if (is_interface(dev_name, 1))
			ret = c->attach_interface(c, dev_name, dst_name);
		else
			ret = c->add_device_node(c, dev_name, dst_name);
		if (ret != true) {
			ERROR("Failed to add %s to %s", dev_name, c->name);
			goto err;
		}
	} else if (strncmp(cmd, "del", strlen(cmd)) == 0) {
		if (is_interface(dev_name, c->init_pid(c)))
			ret = c->detach_interface(c, dev_name, dst_name);
		else
			ret = c->remove_device_node(c, dev_name, dst_name);
		if (ret != true) {
			ERROR("Failed to del %s from %s", dev_name, c->name);
			goto err;
		}
	} else {
		ERROR("Error: Please use add or del (Please see --help output)");
		goto err;
	}

	exit(EXIT_SUCCESS);

err:
	lxc_container_put(c);
	exit(EXIT_FAILURE);
}

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
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <libgen.h>
#include <string.h>
#include <limits.h>

#include <lxc/lxccontainer.h>

#include "utils.h"
#include "lxc.h"
#include "log.h"

#include "arguments.h"

#if HAVE_IFADDRS_H
#include <ifaddrs.h>
#else
#include <../include/ifaddrs.h>
#endif

lxc_log_define(lxc_device, lxc);

static const struct option my_longopts[] = {
	LXC_COMMON_OPTIONS
};

static struct lxc_arguments my_args = {
	.progname = "lxc-device",
	.help     = "\
--name=NAME -- add|del DEV\n\
\n\
lxc-device attach or detach DEV to or from container.\n\
\n\
Options :\n\
  -n, --name=NAME      NAME of the container",
	.options  = my_longopts,
	.parser   = NULL,
	.checker  = NULL,
};

static bool is_interface(const char* dev_name, pid_t pid)
{
	pid_t p = fork();

	if (p < 0) {
		SYSERROR("failed to fork task.");
		exit(1);
	}

	if (p == 0) {
		struct ifaddrs *interfaceArray = NULL, *tempIfAddr = NULL;

		if (!switch_to_ns(pid, "net")) {
			ERROR("failed to enter netns of container.");
			exit(-1);
		}

		/* Grab the list of interfaces */
		if (getifaddrs(&interfaceArray)) {
			ERROR("failed to get interfaces list");
			exit(-1);
		}

		/* Iterate through the interfaces */
		for (tempIfAddr = interfaceArray; tempIfAddr != NULL; tempIfAddr = tempIfAddr->ifa_next) {
			if (strcmp(tempIfAddr->ifa_name, dev_name) == 0) {
				exit(0);
			}
		}
		exit(1);
	}

	if (wait_for_pid(p) == 0) {
		return true;
	}
	return false;
}

int main(int argc, char *argv[])
{
	struct lxc_container *c;
	char *cmd, *dev_name, *dst_name;
	int ret = 1;

	if (geteuid() != 0) {
		ERROR("%s must be run as root", argv[0]);
		exit(1);
	}

	if (lxc_arguments_parse(&my_args, argc, argv))
		goto err;

	if (!my_args.log_file)
		my_args.log_file = "none";

	if (lxc_log_init(my_args.name, my_args.log_file, my_args.log_priority,
			 my_args.progname, my_args.quiet, my_args.lxcpath[0]))
		goto err;
	lxc_log_options_no_override();

	c = lxc_container_new(my_args.name, my_args.lxcpath[0]);
	if (!c) {
		ERROR("%s doesn't exist", my_args.name);
		goto err;
	}

	if (!c->is_running(c)) {
		ERROR("Container %s is not running.", c->name);
		goto err1;
	}

	if (my_args.argc < 2) {
		ERROR("Error: no command given (Please see --help output)");
		goto err1;
	}

	cmd = my_args.argv[0];
	dev_name = my_args.argv[1];
	if (my_args.argc < 3)
		dst_name = dev_name;
	else
		dst_name = my_args.argv[2];

	if (strcmp(cmd, "add") == 0) {
		if (is_interface(dev_name, 1)) {
			ret = c->attach_interface(c, dev_name, dst_name);
		} else {
			ret = c->add_device_node(c, dev_name, dst_name);
		}
		if (ret != true) {
			ERROR("Failed to add %s to %s.", dev_name, c->name);
			ret = 1;
			goto err1;
		}
		INFO("Add %s to %s.", dev_name, c->name);
	} else if (strcmp(cmd, "del") == 0) {
		if (is_interface(dev_name, c->init_pid(c))) {
			ret = c->detach_interface(c, dev_name, dst_name);
		} else {
			ret = c->remove_device_node(c, dev_name, dst_name);
		}
		if (ret != true) {
			ERROR("Failed to del %s from %s.", dev_name, c->name);
			ret = 1;
			goto err1;
		}
		INFO("Delete %s from %s.", dev_name, c->name);
	} else {
		ERROR("Error: Please use add or del (Please see --help output)");
		goto err1;
	}
	exit(0);
err1:
	lxc_container_put(c);
err:
	exit(ret);
}

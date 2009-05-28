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
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>

#include <lxc/lxc.h>
#include "arguments.h"

lxc_log_define(lxc_destroy, lxc);

static const struct option my_longopts[] = {
	LXC_COMMON_OPTIONS
};

static struct lxc_arguments my_args = {
	.progname = "lxc-destroy",
	.help     = "\
--name=NAME\n\
\n\
lxc-destroy destroy a container with the identifier NAME\n\
\n\
Options :\n\
  -n, --name=NAME   NAME for name of the container\n",
	.options  = my_longopts,
	.parser   = NULL,
	.checker  = NULL,
};

static int remove_config_file(const char *name)
{
	char path[MAXPATHLEN];

	snprintf(path, MAXPATHLEN, LXCPATH "/%s/config", name);

	/* config file does not exists */
	if (access(path, F_OK))
		return 0;

	if (unlink(path)) {
		ERROR("failed to unlink '%s'", path);
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	if (lxc_arguments_parse(&my_args, argc, argv))
		return -1;

	if (lxc_log_init(my_args.log_file, my_args.log_priority,
			 my_args.progname, my_args.quiet))
		return -1;

	if (remove_config_file(my_args.name))
		WARN("failed to remove the configuration file");

	if (lxc_destroy(my_args.name)) {
		ERROR("failed to destroy the container");
		return -1;
	}

	INFO("'%s' destroyed", my_args.name);

	return 0;
}


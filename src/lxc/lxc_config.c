/* lxc_config
 *
 * Copyright © 2012 Serge Hallyn <serge.hallyn@ubuntu.com>.
 * Copyright © 2012 Canonical Ltd.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.

 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.

 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <stdio.h>
#include <string.h>

#include <lxc/lxccontainer.h>

#include "arguments.h"
#include "config.h"
#include "log.h"

lxc_log_define(lxc_config_ui, lxc);

static int my_parser(struct lxc_arguments* args, int c, char* arg);

static const struct option my_longopts[] = {
	{"list", no_argument, 0, 'L'},
	LXC_COMMON_OPTIONS
};

static struct lxc_arguments my_args = {
	.progname = "lxc-config",
	.help     = "\
--list\n\
ITEM\n\
\n\
lxc-config queries the lxc system configuration\n\
\n\
Options :\n\
  -L, --list	list all supported keys\n",
	.options  = my_longopts,
	.parser   = my_parser,
};

struct lxc_config_items {
	char *name;
};

static struct lxc_config_items items[] =
{
	{ .name = "lxc.default_config", },
	{ .name = "lxc.lxcpath", },
	{ .name = "lxc.bdev.lvm.vg", },
	{ .name = "lxc.bdev.lvm.thin_pool", },
	{ .name = "lxc.bdev.zfs.root", },
	{ .name = "lxc.cgroup.use", },
	{ .name = "lxc.cgroup.pattern", },
	{ .name = NULL, },
};

static void list_config_items(void)
{
	struct lxc_config_items *i;

	for (i = &items[0]; i->name; i++)
		printf("%s\n", i->name);
}

int main(int argc, char *argv[])
{
	struct lxc_config_items *i;
	const char *value;

	/*
	 * The lxc parser requires that my_args.name is set. So let's satisfy
	 * that condition by setting a dummy name which is never used.
	 */
	my_args.name  = "";
	if (lxc_arguments_parse(&my_args, argc, argv))
		exit(EXIT_FAILURE);

	if (!my_args.log_file)
		my_args.log_file = "none";

	/*
	 * We set the first argument that usually takes my_args.name to NULL so
	 * that the log is only used when the user specifies a file.
	 */
	if (lxc_log_init(NULL, my_args.log_file, my_args.log_priority,
			 my_args.progname, my_args.quiet, my_args.lxcpath[0]))
		exit(EXIT_FAILURE);
	lxc_log_options_no_override();

	if (my_args.list) {
		list_config_items();
	} else if (my_args.argc == 1) {
		for (i = &items[0]; i->name; i++) {
			if (strcmp(my_args.argv[0], i->name) == 0) {
				value = lxc_get_global_config_item(i->name);
				if (value)
					printf("%s\n", value);
				else if (!my_args.quiet)
					printf("%s is not set.\n", my_args.argv[0]);
				break; /* avoid pointless work */
			}
		}
		if (!i->name && !my_args.quiet)
			printf("Unknown configuration item: %s\n", my_args.argv[0]);
	}

	exit(EXIT_SUCCESS);
}

static int my_parser(struct lxc_arguments *args, int c, char *arg)
{
	switch (c) {
	case 'L':
		args->list = 1;
		break;
	default:
		break;
	}

	return 0;
}


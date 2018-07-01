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

static void usage(char *me)
{
	printf("Usage: %s -l: list all available configuration items\n", me);
	printf("       %s item: print configuration item\n", me);
	exit(EXIT_SUCCESS);
}

static void list_config_items(void)
{
	struct lxc_config_items *i;

	for (i = &items[0]; i->name; i++)
		printf("%s\n", i->name);

	exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[])
{
	struct lxc_config_items *i;
	const char *value;

	if (argc < 2 || strncmp(argv[1], "-h", strlen(argv[1])) == 0 ||
	                strncmp(argv[1], "--help", strlen(argv[1])) == 0)
		usage(argv[0]);

	if (strncmp(argv[1], "-l", strlen(argv[1])) == 0)
		list_config_items();

	for (i = &items[0]; i->name; i++) {
		if (strncmp(argv[1], i->name, strlen(argv[1])) == 0) {
			value = lxc_get_global_config_item(i->name);
			if (value)
				printf("%s\n", value);
			else
				printf("%s is not set.\n", argv[1]);

			exit(EXIT_SUCCESS);
		}
	}

	printf("Unknown configuration item: %s\n", argv[1]);
	exit(EXIT_FAILURE);
}

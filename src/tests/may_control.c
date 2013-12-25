/* control.c
 *
 * Copyright © 2013 Canonical, Inc
 * Author: Serge Hallyn <serge.hallyn@ubuntu.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <lxc/lxccontainer.h>

static void usage(const char *me)
{
	printf("Usage: %s name [lxcpath]\n", me);
	exit(0);
}

int main(int argc, char *argv[])
{
	const char *lxcpath = NULL, *name;
	bool may = false;
	struct lxc_container *c;

	if (argc < 2)
		usage(argv[0]);
	name = argv[1];
	if (argc == 3)
		lxcpath = argv[2];
	c = lxc_container_new(name, lxcpath);
	if (c)
		may = c->may_control(c);
	printf("You may%s control %s\n", may ? "" : " not", name);
	exit(may ? 0 : 1);
}

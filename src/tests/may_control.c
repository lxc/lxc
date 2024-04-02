/* control.c
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <lxc/lxccontainer.h>

static void usage(const char *me)
{
	printf("Usage: %s name [lxcpath]\n", me);
	exit(EXIT_SUCCESS);
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

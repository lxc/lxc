/* liblxcapi
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>

#include <lxc/lxccontainer.h>

#include "lxctest.h"

int main(int argc, char *argv[])
{
	int ret;
	struct lxc_container *c;

	c = lxc_container_new("init-pid", NULL);
	if (!c)
		exit(EXIT_FAILURE);

	ret = c->init_pid(c);
	c->destroy(c);
	lxc_container_put(c);
	/* Return value needs to be -1. Any other negative error code is to be
	 * considered invalid.
	 */
	if (ret != -1)
		exit(EXIT_FAILURE);

	exit(EXIT_SUCCESS);
}

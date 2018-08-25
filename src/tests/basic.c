/* liblxcapi
 *
 * Copyright © 2018 Christian Brauner <christian.brauner@ubuntu.com>.
 * Copyright © 2018 Canonical Ltd.
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

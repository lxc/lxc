/* liblxcapi
 *
 * Copyright © 2016 Alexander Couzens <lynxis@fe80.eu>
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

#include <lxc/lxccontainer.h>

#define MYNAME "load_config_test_valid"
#define MYNAME2 "load_config_test_invalid"

int main(int argc, char *argv[])
{
	struct lxc_container *c = NULL, *c2 = NULL, *c3 = NULL;
	const char *valid_config = "./load_config_test_valid.cfg";
	const char *invalid_config = "./load_config_test_invalid.cfg";
	int ret = 1;

	c = lxc_container_new(MYNAME, NULL);
	if (c->is_defined(c)) {
		lxc_container_put(c);
		fprintf(stderr, "Container already exists. It should not exist already\n");
		exit(EXIT_FAILURE);
	}

	if (!c->load_config(c, valid_config)) {
		lxc_container_put(c);
		fprintf(stderr, "Config %s should be valid, but is invalid!\n", valid_config);
		exit(EXIT_FAILURE);
	}
	lxc_container_put(c);

	c2 = lxc_container_new(MYNAME, NULL);
	if (c2->is_defined(c2)) {
		lxc_container_put(c2);
		fprintf(stderr, "Container already exists. It should not exist already\n");
		exit(EXIT_FAILURE);
	}

	if(!c2->load_config(c2, invalid_config)) {
		lxc_container_put(c2);
		fprintf(stderr, "Config %s should be invalid, but is invalid!\n", invalid_config);
		exit(EXIT_FAILURE);
	}

	lxc_container_put(c2);
	exit(EXIT_SUCCESS);
}

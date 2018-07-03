/* liblxcapi
 *
 * Copyright © 2017 Christian Brauner <christian.brauner@ubuntu.com>.
 * Copyright © 2017 Canonical Ltd.
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

#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "confile.h"
#include "lxc/state.h"
#include "lxctest.h"

int main(int argc, char *argv[])
{
	int fulllen = 0, inlen = 0, ret = EXIT_FAILURE;
	char *key, *keys, *saveptr = NULL;

	fulllen = lxc_list_config_items(NULL, inlen);

	keys = malloc(sizeof(char) * fulllen + 1);
	if (!keys) {
		lxc_error("%s\n", "failed to allocate memory");
		exit(ret);
	}

	if (lxc_list_config_items(keys, fulllen) != fulllen) {
		lxc_error("%s\n", "failed to retrieve configuration keys");
		goto on_error;
	}

	for (key = strtok_r(keys, "\n", &saveptr); key != NULL;
	     key = strtok_r(NULL, "\n", &saveptr)) {
		struct lxc_config_t *config;

		config = lxc_get_config(key);
		if (!config) {
			lxc_error("configuration key \"%s\" not implemented in "
				  "jump table",
				  key);
			goto on_error;
		}

		if (!config->set) {
			lxc_error("configuration key \"%s\" has no set method "
				  "in jump table",
				  key);
			goto on_error;
		}

		if (!config->get) {
			lxc_error("configuration key \"%s\" has no get method "
				  "in jump table",
				  key);
			goto on_error;
		}

		if (!config->clr) {
			lxc_error("configuration key \"%s\" has no clr (clear) "
				  "method in jump table",
				  key);
			goto on_error;
		}
	}

	ret = EXIT_SUCCESS;

on_error:
	free(keys);

	exit(ret);
}

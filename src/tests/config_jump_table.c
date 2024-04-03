/* liblxcapi
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "config.h"

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
#include "state.h"
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

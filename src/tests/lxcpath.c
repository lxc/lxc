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
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "memory_utils.h"

#define MYNAME "lxctest1"

#define TSTERR(x) do { \
	fprintf(stderr, "%d: %s\n", __LINE__, x); \
} while (0)

int main(int argc, char *argv[])
{
	struct lxc_container *c;
	const char *p1;
	__do_free char *p2 = NULL;
	int retval = -1;

	c = lxc_container_new(MYNAME, NULL);
	if (!c) {
		TSTERR("create using default path");
		goto err;
	}

	p1 = c->get_config_path(c);
	p2 = c->config_file_name(c);
	if (!p1 || !p2 || strncmp(p1, p2, strlen(p1))) {
		TSTERR("Bad result for path names");
		goto err;
	}

#define CPATH "/boo"
#define FPATH "/boo/lxctest1/config"
	if (!c->set_config_path(c, "/boo")) {
		TSTERR("Error setting custom path");
		goto err;
	}

	p1 = c->get_config_path(c);
	free(p2);
	p2 = c->config_file_name(c);
	if (strcmp(p1, CPATH) || strcmp(p2, FPATH)) {
		TSTERR("Bad result for path names after set_config_path()");
		goto err;
	}
	lxc_container_put(c);

	c = lxc_container_new(MYNAME, CPATH);
	if (!c) {
		TSTERR("create using custom path");
		goto err;
	}

	p1 = c->get_config_path(c);
	free(p2);
	p2 = c->config_file_name(c);
	if (strcmp(p1, CPATH) || strcmp(p2, FPATH)) {
		TSTERR("Bad result for path names after create with custom path");
		goto err;
	}

	retval = 0;

err:
	lxc_container_put(c);
	return retval;
}

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
#include <errno.h>

#define MYNAME "lxctest1"

int main(int argc, char *argv[])
{
	struct lxc_container *c;
	int ret = 1;

	if ((c = lxc_container_new(MYNAME, NULL)) == NULL) {
		fprintf(stderr, "%d: error opening lxc_container %s\n", __LINE__, MYNAME);
		ret = 1;
		goto out;
	}

	if (c->is_defined(c)) {
		fprintf(stderr, "%d: %s thought it was defined\n", __LINE__, MYNAME);
		goto out;
	}

	if (!c->set_config_item(c, "lxc.net.0.type", "veth")) {
		fprintf(stderr, "%d: failed to set network type\n", __LINE__);
		goto out;
	}

	c->set_config_item(c, "lxc.net.0.link", "lxcbr0");
	c->set_config_item(c, "lxc.net.0.flags", "up");

	if (!c->createl(c, "busybox", NULL, NULL, 0, NULL)) {
		fprintf(stderr, "%d: failed to create a container\n", __LINE__);
		goto out;
	}

	if (!c->is_defined(c)) {
		fprintf(stderr, "%d: %s thought it was not defined\n", __LINE__, MYNAME);
		goto out;
	}

	c->clear_config(c);
	c->load_config(c, NULL);
	c->want_daemonize(c, true);

	if (!c->startl(c, 0, NULL)) {
		fprintf(stderr, "%d: failed to start %s\n", __LINE__, MYNAME);
		goto out;
	}

	/* Wait for init to be ready for SIGPWR */
	sleep(20);

	if (!c->shutdown(c, 120)) {
		fprintf(stderr, "%d: failed to shut down %s\n", __LINE__, MYNAME);
		if (!c->stop(c))
			fprintf(stderr, "%d: failed to kill %s\n", __LINE__, MYNAME);

		goto out;
	}

	if (!c->destroy(c)) {
		fprintf(stderr, "%d: error deleting %s\n", __LINE__, MYNAME);
		goto out;
	}

	if (c->is_defined(c)) {
		fprintf(stderr, "%d: %s thought it was defined\n", __LINE__, MYNAME);
		goto out;
	}

	fprintf(stderr, "all lxc_container tests passed for %s\n", c->name);
	ret = 0;

out:
	if (c && c->is_defined(c))
		c->destroy(c);

	lxc_container_put(c);
	exit(ret);
}

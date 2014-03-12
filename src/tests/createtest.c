/* liblxcapi
 *
 * Copyright © 2012 Serge Hallyn <serge.hallyn@ubuntu.com>.
 * Copyright © 2012 Canonical Ltd.
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

	if (!c->set_config_item(c, "lxc.network.type", "veth")) {
		fprintf(stderr, "%d: failed to set network type\n", __LINE__);
		goto out;
	}
	c->set_config_item(c, "lxc.network.link", "lxcbr0");
	c->set_config_item(c, "lxc.network.flags", "up");
	if (!c->createl(c, "busybox", NULL, NULL, 0, NULL)) {
		fprintf(stderr, "%d: failed to create a trusty container\n", __LINE__);
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

	if (!c->stop(c)) {
		fprintf(stderr, "%d: failed to stop %s\n", __LINE__, MYNAME);
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
	lxc_container_put(c);
	exit(ret);
}

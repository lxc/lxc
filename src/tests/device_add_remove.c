/* DEVICE_add_remove.c
 *
 * Copyright © 2014 S.Çağlar Onur <caglar@10ur.org>
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

#define NAME "device_add_remove_test"
#define DEVICE "/dev/network_latency"

int main(int argc, char *argv[])
{
	int ret = 1;
	struct lxc_container *c;

	c = lxc_container_new(NAME, NULL);
	if (!c) {
		fprintf(stderr, "Unable to instantiate container (%s)...\n", NAME);
		goto out;
	}

	if (!c->create(c, "busybox", NULL, NULL, 1, NULL)) {
		fprintf(stderr, "Creating the container (%s) failed...\n", NAME);
		goto out;
	}

	c->want_daemonize(c, true);

	if (!c->start(c, false, NULL)) {
		fprintf(stderr, "Starting the container (%s) failed...\n", NAME);
		goto out;
	}

	if (!c->add_device_node(c, DEVICE, DEVICE)) {
		fprintf(stderr, "Adding %s to the container (%s) failed...\n", DEVICE, NAME);
		goto out;
	}
	if (!c->remove_device_node(c, DEVICE, DEVICE)) {
		fprintf(stderr, "Removing %s from the container (%s) failed...\n", DEVICE, NAME);
		goto out;
	}

	if (!c->stop(c)) {
		fprintf(stderr, "Stopping the container (%s) failed...\n", NAME);
		goto out;
	}

	if (!c->destroy(c)) {
		fprintf(stderr, "Destroying the container (%s) failed...\n", NAME);
		goto out;
	}
	ret = 0;

out:
	lxc_container_put(c);
	return ret;
}

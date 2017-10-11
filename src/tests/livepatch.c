/* liblxcapi
 *
 * Copyright © 2017 Christian Brauner <christian.brauner@ubuntu.com>.
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

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <lxc/lxccontainer.h>

#include "lxctest.h"

int main(int argc, char *argv[])
{
	char *value;
	struct lxc_container *c;
	int ret = EXIT_FAILURE;

	c = lxc_container_new("livepatch", NULL);
	if (!c) {
		lxc_error("%s", "Failed to create container \"livepatch\"");
		exit(ret);
	}

	if (c->is_defined(c)) {
		lxc_error("%s\n", "Container \"livepatch\" is defined");
		goto on_error_put;
	}

	if (!c->set_config_item(c, "lxc.net.0.type", "veth")) {
		lxc_error("%s\n", "Failed to set network item \"lxc.net.0.type\"");
		goto on_error_put;
	}

	if (!c->set_config_item(c, "lxc.net.0.link", "lxcbr0")) {
		lxc_error("%s\n", "Failed to set network item \"lxc.net.0.link\"");
		goto on_error_put;
	}

	if (!c->set_config_item(c, "lxc.net.0.flags", "up")) {
		lxc_error("%s\n", "Failed to set network item \"lxc.net.0.flags\"");
		goto on_error_put;
	}

	if (!c->set_config_item(c, "lxc.net.0.name", "eth0")) {
		lxc_error("%s\n", "Failed to set network item \"lxc.net.0.name\"");
		goto on_error_put;
	}

	if (!c->createl(c, "busybox", NULL, NULL, 0, NULL)) {
		lxc_error("%s\n", "Failed to create busybox container \"livepatch\"");
		goto on_error_put;
	}

	if (!c->is_defined(c)) {
		lxc_error("%s\n", "Container \"livepatch\" is not defined");
		goto on_error_put;
	}

	c->clear_config(c);

	if (!c->load_config(c, NULL)) {
		lxc_error("%s\n", "Failed to load config for container \"livepatch\"");
		goto on_error_stop;
	}

	if (!c->want_daemonize(c, true)) {
		lxc_error("%s\n", "Failed to mark container \"livepatch\" daemonized");
		goto on_error_stop;
	}

	if (!c->startl(c, 0, NULL)) {
		lxc_error("%s\n", "Failed to start container \"livepatch\" daemonized");
		goto on_error_stop;
	}

	/* Test whether the current value is ok. */
	value = c->get_running_config_item(c, "lxc.net.0.name");
	if (!value) {
		lxc_error("%s\n", "Failed to retrieve running config item \"lxc.net.0.name\"");
		goto on_error_stop;
	}

	if (strcmp(value, "eth0")) {
		lxc_error("Retrieved unexpected value for config item "
			  "\"lxc.net.0.name\": eth0 != %s", value);
		free(value);
		goto on_error_stop;
	}
	free(value);

	/* Change current in-memory value. */
	if (!c->set_running_config_item(c, "lxc.net.0.name", "blabla")) {
		lxc_error("%s\n", "Failed to set running config item "
				  "\"lxc.net.0.name\" to \"blabla\"");
		goto on_error_stop;
	}

	/* Verify change. */
	value = c->get_running_config_item(c, "lxc.net.0.name");
	if (!value) {
		lxc_error("%s\n", "Failed to retrieve running config item \"lxc.net.0.name\"");
		goto on_error_stop;
	}

	if (strcmp(value, "blabla")) {
		lxc_error("Retrieved unexpected value for config item "
			  "\"lxc.net.0.name\": blabla != %s", value);
		free(value);
		goto on_error_stop;
	}
	free(value);

	/* Change current in-memory value. */
	if (!c->set_running_config_item(c, "lxc.net.0.name", "eth0")) {
		lxc_error("%s\n", "Failed to set running config item "
				  "\"lxc.net.0.name\" to \"eth0\"");
		goto on_error_stop;
	}

	/* Add new in-memory value. */
	if (!c->set_running_config_item(c, "lxc.net.1.type", "veth")) {
		lxc_error("%s\n", "Failed to set running config item "
				  "\"lxc.net.1.type\" to \"veth\"");
		goto on_error_stop;
	}

	/* Verify change. */
	value = c->get_running_config_item(c, "lxc.net.1.type");
	if (!value) {
		lxc_error("%s\n", "Failed to retrieve running config item \"lxc.net.1.type\"");
		goto on_error_stop;
	}

	if (strcmp(value, "veth")) {
		lxc_error("Retrieved unexpected value for config item "
			  "\"lxc.net.1.type\": veth != %s", value);
		free(value);
		goto on_error_stop;
	}
	free(value);

	/* Add new in-memory value. */
	if (!c->set_running_config_item(c, "lxc.net.1.flags", "up")) {
		lxc_error("%s\n", "Failed to set running config item "
				  "\"lxc.net.1.flags\" to \"up\"");
		goto on_error_stop;
	}

	/* Verify change. */
	value = c->get_running_config_item(c, "lxc.net.1.flags");
	if (!value) {
		lxc_error("%s\n", "Failed to retrieve running config item \"lxc.net.1.flags\"");
		goto on_error_stop;
	}

	if (strcmp(value, "up")) {
		lxc_error("Retrieved unexpected value for config item "
			  "\"lxc.net.1.flags\": up != %s", value);
		free(value);
		goto on_error_stop;
	}
	free(value);

	/* Add new in-memory value. */
	if (!c->set_running_config_item(c, "lxc.net.1.link", "lxcbr0")) {
		lxc_error("%s\n", "Failed to set running config item "
				  "\"lxc.net.1.link\" to \"lxcbr0\"");
		goto on_error_stop;
	}

	/* Verify change. */
	value = c->get_running_config_item(c, "lxc.net.1.link");
	if (!value) {
		lxc_error("%s\n", "Failed to retrieve running config item \"lxc.net.1.link\"");
		goto on_error_stop;
	}

	if (strcmp(value, "lxcbr0")) {
		lxc_error("Retrieved unexpected value for config item "
			  "\"lxc.net.1.link\": lxcbr0 != %s", value);
		free(value);
		goto on_error_stop;
	}
	free(value);

	if (!c->reboot(c)) {
		lxc_error("%s", "Failed to create container \"livepatch\"");
		goto on_error_stop;
	}

	/* Busybox shouldn't take long to reboot. Sleep for 5s. */
	sleep(5);

	if (!c->is_running(c)) {
		lxc_error("%s\n", "Failed to reboot container \"livepatch\"");
		goto on_error_destroy;
	}

	/* Remove in-memory value. */
	if (!c->set_running_config_item(c, "lxc.net.1.name", "eth1")) {
		lxc_error("%s\n", "Failed to clear running config item "
				  "\"lxc.net.1.name\"");
		goto on_error_stop;
	}

	if (!c->stop(c)) {
		lxc_error("%s\n", "Failed to stop container \"livepatch\"");
		goto on_error_stop;
	}

	if (!c->startl(c, 0, NULL)) {
		lxc_error("%s\n", "Failed to start container \"livepatch\" daemonized");
		goto on_error_destroy;
	}

	/* Remove in-memory value. */
	if (!c->set_running_config_item(c, "lxc.net.1.mtu", "3000")) {
		lxc_error("%s\n", "Failed to set running config item "
				  "\"lxc.net.1.mtu\"");
		goto on_error_stop;
	}

	ret = 0;

on_error_stop:
	if (c->is_running(c) && !c->stop(c))
		lxc_error("%s\n", "Failed to stop container \"livepatch\"");

on_error_destroy:
	if (!c->destroy(c))
		lxc_error("%s\n", "Failed to destroy container \"livepatch\"");

on_error_put:
	lxc_container_put(c);
	exit(ret);
}

/* liblxcapi
 *
 * Copyright © 2021 Christian Brauner <christian.brauner@ubuntu.com>.
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

#include "config.h"

#define __STDC_FORMAT_MACROS

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <lxc/lxccontainer.h>
#include <lxc/attach_options.h>

#ifdef HAVE_STATVFS
#include <sys/statvfs.h>
#endif

#include "lxctest.h"
#include "utils.h"

static int is_read_only(const char *path)
{
#ifdef HAVE_STATVFS
	int ret;
	struct statvfs sb;

	ret = statvfs(path, &sb);
	if (ret < 0)
		return -errno;

	return (sb.f_flag & MS_RDONLY) > 0;
#else
	return -EOPNOTSUPP;
#endif
}

static int sys_mixed(void *payload)
{
	int ret;

	ret = is_read_only("/sys");
	if (ret == -EOPNOTSUPP)
		return 0;

	if (ret <= 0)
		return -1;

	if (is_read_only("/sys/devices/virtual/net"))
		return -1;

	return 0;
}

int main(int argc, char *argv[])
{
	int fret = EXIT_FAILURE;
	lxc_attach_options_t attach_options = LXC_ATTACH_OPTIONS_DEFAULT;
	int ret;
	pid_t pid;
	struct lxc_container *c;

	c = lxc_container_new("sys-mixed", NULL);
	if (!c) {
		lxc_error("%s", "Failed to create container \"sys-mixed\"");
		exit(fret);
	}

	if (c->is_defined(c)) {
		lxc_error("%s\n", "Container \"sys-mixed\" is defined");
		goto on_error_put;
	}

	if (!c->createl(c, "busybox", NULL, NULL, 0, NULL)) {
		lxc_error("%s\n", "Failed to create busybox container \"sys-mixed\"");
		goto on_error_put;
	}

	if (!c->is_defined(c)) {
		lxc_error("%s\n", "Container \"sys-mixed\" is not defined");
		goto on_error_put;
	}

	c->clear_config(c);

	if (!c->set_config_item(c, "lxc.mount.auto", "sys:mixed")) {
		lxc_error("%s\n", "Failed to set config item \"lxc.mount.auto=sys:mixed\"");
		goto on_error_put;
	}

	if (!c->load_config(c, NULL)) {
		lxc_error("%s\n", "Failed to load config for container \"sys-mixed\"");
		goto on_error_stop;
	}

	if (!c->want_daemonize(c, true)) {
		lxc_error("%s\n", "Failed to mark container \"sys-mixed\" daemonized");
		goto on_error_stop;
	}

	if (!c->startl(c, 0, NULL)) {
		lxc_error("%s\n", "Failed to start container \"sys-mixed\" daemonized");
		goto on_error_stop;
	}

	/* Leave some time for the container to write something to the log. */
	sleep(2);

	ret = c->attach(c, sys_mixed, NULL, &attach_options, &pid);
	if (ret < 0) {
		lxc_error("%s\n", "Failed to run function in container \"sys-mixed\"");
		goto on_error_stop;
	}

	ret = wait_for_pid(pid);
	if (ret < 0) {
		lxc_error("%s\n", "Failed to run function in container \"sys-mixed\"");
		goto on_error_stop;
	}

	fret = 0;

on_error_stop:
	if (c->is_running(c) && !c->stop(c))
		lxc_error("%s\n", "Failed to stop container \"sys-mixed\"");

	if (!c->destroy(c))
		lxc_error("%s\n", "Failed to destroy container \"sys-mixed\"");

on_error_put:
	lxc_container_put(c);
	exit(fret);
}

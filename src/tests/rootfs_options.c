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

static int has_mount_properties(const char *path, unsigned int flags)
{
#ifdef HAVE_STATVFS
	int ret;
	struct statvfs sb;

	ret = statvfs(path, &sb);
	if (ret < 0)
		return -errno;

	if ((sb.f_flag & flags) == flags)
		return 0;

	return -EINVAL;

#else
	return -EOPNOTSUPP;
#endif
}

static int rootfs_options(void *payload)
{
	int ret;

	ret = has_mount_properties("/",
				   MS_NODEV |
				   MS_NOSUID |
				   MS_RDONLY);
	if (ret != 0) {
		if (ret == -EOPNOTSUPP)
			return EXIT_SUCCESS;

		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int main(int argc, char *argv[])
{
	int fret = EXIT_FAILURE;
	lxc_attach_options_t attach_options = LXC_ATTACH_OPTIONS_DEFAULT;
	int ret;
	pid_t pid;
	struct lxc_container *c;

	c = lxc_container_new("rootfs-options", NULL);
	if (!c) {
		lxc_error("%s", "Failed to create container \"rootfs-options\"");
		exit(fret);
	}

	if (c->is_defined(c)) {
		lxc_error("%s\n", "Container \"rootfs-options\" is defined");
		goto on_error_put;
	}

	if (!c->createl(c, "busybox", NULL, NULL, 0, NULL)) {
		lxc_error("%s\n", "Failed to create busybox container \"rootfs-options\"");
		goto on_error_put;
	}

	if (!c->is_defined(c)) {
		lxc_error("%s\n", "Container \"rootfs-options\" is not defined");
		goto on_error_put;
	}

	c->clear_config(c);

	if (!c->set_config_item(c, "lxc.rootfs.options", "nodev,nosuid,ro")) {
		lxc_error("%s\n", "Failed to set config item \"lxc.mount.auto=sys:mixed\"");
		goto on_error_put;
	}

	if (!c->load_config(c, NULL)) {
		lxc_error("%s\n", "Failed to load config for container \"rootfs-options\"");
		goto on_error_stop;
	}

	if (!c->want_daemonize(c, true)) {
		lxc_error("%s\n", "Failed to mark container \"rootfs-options\" daemonized");
		goto on_error_stop;
	}

	if (!c->startl(c, 0, NULL)) {
		lxc_error("%s\n", "Failed to start container \"rootfs-options\" daemonized");
		goto on_error_stop;
	}

	/* Leave some time for the container to write something to the log. */
	sleep(2);

	ret = c->attach(c, rootfs_options, NULL, &attach_options, &pid);
	if (ret < 0) {
		lxc_error("%s\n", "Failed to run function in container \"rootfs-options\"");
		goto on_error_stop;
	}

	ret = wait_for_pid(pid);
	if (ret < 0) {
		lxc_error("%s\n", "Function \"rootfs-options\" failed");
		goto on_error_stop;
	}

	fret = 0;

on_error_stop:
	if (c->is_running(c) && !c->stop(c))
		lxc_error("%s\n", "Failed to stop container \"rootfs-options\"");

	if (!c->destroy(c))
		lxc_error("%s\n", "Failed to destroy container \"rootfs-options\"");

on_error_put:
	lxc_container_put(c);
	exit(fret);
}

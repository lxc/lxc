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

#include <alloca.h>
#include <stdio.h>
#include <sched.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <sys/reboot.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "lxc/lxccontainer.h"
#include "lxctest.h"
#include "utils.h"

#ifndef HAVE_STRLCPY
#include "include/strlcpy.h"
#endif

#define TSTNAME "lxc-api-reboot"

int main(int argc, char *argv[])
{
	int i;
	struct lxc_container *c;
	int ret = EXIT_FAILURE;
	struct lxc_log log;
	char template[sizeof(P_tmpdir"/reboot_XXXXXX")];

	(void)strlcpy(template, P_tmpdir"/reboot_XXXXXX", sizeof(template));

	i = lxc_make_tmpfile(template, false);
	if (i < 0) {
		lxc_error("Failed to create temporary log file for container %s\n", TSTNAME);
		exit(EXIT_FAILURE);
	} else {
		lxc_debug("Using \"%s\" as temporary log file for container %s\n", template, TSTNAME);
		close(i);
	}

	log.name = TSTNAME;
	log.file = template;
	log.level = "TRACE";
	log.prefix = "reboot";
	log.quiet = false;
	log.lxcpath = NULL;
	if (lxc_log_init(&log))
		exit(ret);

	/* Test that the reboot() API function properly waits for containers to
	 * restart.
	 */
	c = lxc_container_new(TSTNAME, NULL);
	if (!c) {
		lxc_error("%s", "Failed to create container \"reboot\"");
		exit(ret);
	}

	if (c->is_defined(c)) {
		lxc_error("%s\n", "Container \"reboot\" is defined");
		goto on_error_put;
	}

	if (!c->createl(c, "busybox", NULL, NULL, 0, NULL)) {
		lxc_error("%s\n", "Failed to create busybox container \"reboot\"");
		goto on_error_put;
	}

	if (!c->is_defined(c)) {
		lxc_error("%s\n", "Container \"reboot\" is not defined");
		goto on_error_put;
	}

	c->clear_config(c);

	if (!c->load_config(c, NULL)) {
		lxc_error("%s\n", "Failed to load config for container \"reboot\"");
		goto on_error_stop;
	}

	if (!c->want_daemonize(c, true)) {
		lxc_error("%s\n", "Failed to mark container \"reboot\" daemonized");
		goto on_error_stop;
	}

	if (!c->startl(c, 0, NULL)) {
		lxc_error("%s\n", "Failed to start container \"reboot\" daemonized");
		goto on_error_stop;
	}

	/* reboot 10 times */
	for (i = 0; i < 10; i++) {
		/* Give the init system some time to setup it's signal handlers
		 * otherwise we will wait indefinitely.
		 */
		sleep(5);

		if (!c->reboot2(c, 60 * 5)) {
			lxc_error("%s\n", "Failed to reboot container \"reboot\"");
			goto on_error_stop;
		}

		if (!c->is_running(c)) {
			lxc_error("%s\n", "Failed to reboot container \"reboot\"");
			goto on_error_stop;
		}
		lxc_debug("%s\n", "Container \"reboot\" rebooted successfully");
	}

	/* Give the init system some time to setup it's signal handlers
	 * otherwise we will wait indefinitely.
	 */
	sleep(5);

	/* Test non-blocking reboot2() */
	if (!c->reboot2(c, 0)) {
		lxc_error("%s\n", "Failed to request non-blocking reboot of container \"reboot\"");
		goto on_error_stop;
	}
	lxc_debug("%s\n", "Non-blocking reboot of container \"reboot\" succeeded");

	ret = EXIT_SUCCESS;

on_error_stop:
	if (c->is_running(c) && !c->stop(c))
		lxc_error("%s\n", "Failed to stop container \"reboot\"");

	if (!c->destroy(c))
		lxc_error("%s\n", "Failed to destroy container \"reboot\"");

on_error_put:
	lxc_container_put(c);

	if (ret == EXIT_SUCCESS) {
		lxc_debug("%s\n", "All reboot tests passed");
	} else {
		int fd;

		fd = open(template, O_RDONLY);
		if (fd >= 0) {
			char buf[4096];
			ssize_t buflen;
			while ((buflen = read(fd, buf, 1024)) > 0) {
				buflen = write(STDERR_FILENO, buf, buflen);
				if (buflen <= 0)
					break;
			}
			close(fd);
		}
	}
	(void)unlink(template);

	exit(ret);
}

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

#include "lxccontainer.h"
#include "attach_options.h"

#include "caps.h"
#include "lxctest.h"
#include "utils.h"

#if HAVE_LIBCAP
__u32 *cap_bset_bits = NULL;
__u32 last_cap = 0;

static int capabilities_allow(void *payload)
{
	for (__u32 cap = 0; cap <= last_cap; cap++) {
		bool bret;

		if (!is_set(cap, cap_bset_bits))
			continue;

		if (cap == CAP_MKNOD)
			bret = cap_get_bound(cap) == CAP_SET;
		else
			bret = cap_get_bound(cap) != CAP_SET;
		if (!bret) {
			lxc_error("Capability %d unexpectedly raised or lowered\n", cap);
			return EXIT_FAILURE;
		}
	}

	return EXIT_SUCCESS;
}

static int capabilities_deny(void *payload)
{
	for (__u32 cap = 0; cap <= last_cap; cap++) {
		bool bret;

		if (!is_set(cap, cap_bset_bits))
			continue;

		if (cap == CAP_MKNOD)
			bret = cap_get_bound(cap) != CAP_SET;
		else
			bret = cap_get_bound(cap) == CAP_SET;
		if (!bret) {
			lxc_error("Capability %d unexpectedly raised or lowered\n", cap);
			return EXIT_FAILURE;
		}
	}

	return EXIT_SUCCESS;
}

static int run(int (*test)(void *), bool allow)
{
	int fd_log = -EBADF, fret = -1;
	lxc_attach_options_t attach_options = LXC_ATTACH_OPTIONS_DEFAULT;
	int ret;
	pid_t pid;
	struct lxc_container *c;
	struct lxc_log log;
	char template[sizeof(P_tmpdir"/capabilities_XXXXXX")];

	(void)strlcpy(template, P_tmpdir"/capabilities_XXXXXX", sizeof(template));

	fd_log = lxc_make_tmpfile(template, false);
	if (fd_log < 0) {
		lxc_error("%s", "Failed to create temporary log file for container \"capabilities\"");
		return fret;
	}

	log.name = "capabilities";
	log.file = template;
	log.level = "TRACE";
	log.prefix = "capabilities";
	log.quiet = false;
	log.lxcpath = NULL;

	if (lxc_log_init(&log))
		return fret;

	c = lxc_container_new("capabilities", NULL);
	if (!c) {
		lxc_error("%s\n", "Failed to create container \"capabilities\"");
		return fret;
	}

	if (c->is_defined(c)) {
		lxc_error("%s\n", "Container \"capabilities\" is defined");
		goto on_error_put;
	}

	if (!c->createl(c, "busybox", NULL, NULL, 0, NULL)) {
		lxc_error("%s\n", "Failed to create busybox container \"capabilities\"");
		goto on_error_put;
	}

	if (!c->is_defined(c)) {
		lxc_error("%s\n", "Container \"capabilities\" is not defined");
		goto on_error_destroy;
	}

	if (!c->clear_config_item(c, "lxc.cap.drop")) {
		lxc_error("%s\n", "Failed to clear config item \"lxc.cap.drop\"");
		goto on_error_destroy;
	}

	if (!c->clear_config_item(c, "lxc.cap.keep")) {
		lxc_error("%s\n", "Failed to clear config item \"lxc.cap.drop\"");
		goto on_error_destroy;
	}

	if (allow) {
		if (!c->set_config_item(c, "lxc.cap.keep", "mknod")) {
			lxc_error("%s\n", "Failed to set config item \"lxc.cap.keep=mknod\"");
			goto on_error_destroy;
		}
	} else {
		if (!c->set_config_item(c, "lxc.cap.drop", "mknod")) {
			lxc_error("%s\n", "Failed to set config item \"lxc.cap.drop=mknod\"");
			goto on_error_destroy;
		}
	}

	if (!c->want_daemonize(c, true)) {
		lxc_error("%s\n", "Failed to mark container \"capabilities\" daemonized");
		goto on_error_destroy;
	}

	if (!c->startl(c, 0, NULL)) {
		lxc_error("%s\n", "Failed to start container \"capabilities\" daemonized");
		goto on_error_destroy;
	}

	ret = c->attach(c, test, NULL, &attach_options, &pid);
	if (ret < 0) {
		lxc_error("%s\n", "Failed to run function in container \"capabilities\"");
		goto on_error_stop;
	}

	ret = wait_for_pid(pid);
	if (ret) {
		lxc_error("%s\n", "Function \"capabilities\" failed");
		goto on_error_stop;
	}

	fret = 0;

on_error_stop:
	if (c->is_running(c) && !c->stop(c))
		lxc_error("%s\n", "Failed to stop container \"capabilities\"");

on_error_destroy:
	if (!c->destroy(c))
		lxc_error("%s\n", "Failed to destroy container \"capabilities\"");

on_error_put:
	lxc_container_put(c);

	if (fret == EXIT_SUCCESS) {
		lxc_debug("All capability %s tests passed\n", allow ? "allow" : "deny");
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

	return fret;
}

static void __attribute__((constructor)) capabilities_init(void)
{
	int ret;
	__u32 nr_u32;

	ret = lxc_caps_last_cap(&last_cap);
	if (ret || last_cap > 200)
		_exit(EXIT_FAILURE);

	nr_u32 = BITS_TO_LONGS(last_cap);
	cap_bset_bits = zalloc(nr_u32 * sizeof(__u32));
	if (!cap_bset_bits)
		_exit(EXIT_FAILURE);

	for (__u32 cap_bit = 0; cap_bit <= last_cap; cap_bit++) {
		if (prctl(PR_CAPBSET_READ, prctl_arg(cap_bit)) == 0)
			continue;

		set_bit(cap_bit, cap_bset_bits);
	}
}

static void __attribute__((destructor)) capabilities_exit(void)
{
	free(cap_bset_bits);
}

int main(int argc, char *argv[])
{
	if (run(capabilities_allow, true))
		exit(EXIT_FAILURE);

	if (run(capabilities_deny, false))
		exit(EXIT_FAILURE);

	exit(EXIT_SUCCESS);
}

#else /* !HAVE_LIBCAP */

int main(int argc, char *argv[])
{
	lxc_debug("%s\n", "Capabilities not supported. Skipping.");
	exit(EXIT_SUCCESS);
}
#endif

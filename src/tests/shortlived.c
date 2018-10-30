/* liblxcapi
 *
 * Copyright © 2017 Christian Brauner <christian.brauner@ubuntu.com>.
 * Copyright © 2017 Canonical Ltd.
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
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#include "lxctest.h"
#include "utils.h"

#ifndef HAVE_STRLCPY
#include "include/strlcpy.h"
#endif

#define MYNAME "shortlived"

static int destroy_container(void)
{
	int status, ret;
	pid_t pid = fork();

	if (pid < 0) {
		perror("fork");
		return -1;
	}

	if (pid == 0) {
		execlp("lxc-destroy", "lxc-destroy", "-f", "-n", MYNAME, NULL);
		exit(EXIT_FAILURE);
	}

again:
	ret = waitpid(pid, &status, 0);
	if (ret == -1) {
		if (errno == EINTR)
			goto again;
		perror("waitpid");
		return -1;
	}

	if (ret != pid)
		goto again;

	if (!WIFEXITED(status))  { // did not exit normally
		fprintf(stderr, "%d: lxc-create exited abnormally\n", __LINE__);
		return -1;
	}

	return WEXITSTATUS(status);
}

static int create_container(void)
{
	int status, ret;
	pid_t pid = fork();

	if (pid < 0) {
		perror("fork");
		return -1;
	}

	if (pid == 0) {
		execlp("lxc-create", "lxc-create", "-t", "busybox", "-n", MYNAME, NULL);
		exit(EXIT_FAILURE);
	}

again:
	ret = waitpid(pid, &status, 0);
	if (ret == -1) {
		if (errno == EINTR)
			goto again;

		perror("waitpid");
		return -1;
	}

	if (ret != pid)
		goto again;

	if (!WIFEXITED(status))  { // did not exit normally
		fprintf(stderr, "%d: lxc-create exited abnormally\n", __LINE__);
		return -1;
	}

	return WEXITSTATUS(status);
}

int main(int argc, char *argv[])
{
	int fd, i;
	const char *s;
	bool b;
	struct lxc_container *c;
	struct lxc_log log;
	char template[sizeof(P_tmpdir"/shortlived_XXXXXX")];
	int ret = EXIT_FAILURE;

	(void)strlcpy(template, P_tmpdir"/shortlived_XXXXXX", sizeof(template));

	i = lxc_make_tmpfile(template, false);
	if (i < 0) {
		lxc_error("Failed to create temporary log file for container %s\n", MYNAME);
		exit(EXIT_FAILURE);
	} else {
		lxc_debug("Using \"%s\" as temporary log file for container %s\n", template, MYNAME);
		close(i);
	}

	log.name = MYNAME;
	log.file = template;
	log.level = "TRACE";
	log.prefix = "shortlived";
	log.quiet = false;
	log.lxcpath = NULL;

	if (lxc_log_init(&log))
		exit(EXIT_FAILURE);

	/* test a real container */
	c = lxc_container_new(MYNAME, NULL);
	if (!c) {
		fprintf(stderr, "%d: error creating lxc_container %s\n", __LINE__, MYNAME);
		goto out;
	}

	if (c->is_defined(c)) {
		fprintf(stderr, "%d: %s thought it was defined\n", __LINE__, MYNAME);
		goto out;
	}

	if (create_container() < 0) {
		fprintf(stderr, "%d: failed to create a container\n", __LINE__);
		goto out;
	}

	b = c->is_defined(c);
	if (!b) {
		fprintf(stderr, "%d: %s thought it was not defined\n", __LINE__, MYNAME);
		goto out;
	}

	s = c->state(c);
	if (!s || strcmp(s, "STOPPED")) {
		fprintf(stderr, "%d: %s is in state %s, not in STOPPED.\n", __LINE__, c->name, s ? s : "undefined");
		goto out;
	}

	b = c->load_config(c, NULL);
	if (!b) {
		fprintf(stderr, "%d: %s failed to read its config\n", __LINE__, c->name);
		goto out;
	}

	if (!c->set_config_item(c, "lxc.init.cmd", "echo hello")) {
		fprintf(stderr, "%d: failed setting lxc.init.cmd\n", __LINE__);
		goto out;
	}

	if (!c->set_config_item(c, "lxc.execute.cmd", "echo hello")) {
		fprintf(stderr, "%d: failed setting lxc.execute.cmd\n", __LINE__);
		goto out;
	}

	c->want_daemonize(c, true);

	/* Test whether we can start a really short-lived daemonized container. */
	for (i = 0; i < 10; i++) {
		if (!c->startl(c, 0, NULL)) {
			fprintf(stderr, "%d: %s failed to start on %dth iteration\n", __LINE__, c->name, i);
			goto out;
		}

		if (!c->wait(c, "STOPPED", 30)) {
			fprintf(stderr, "%d: %s failed to wait on %dth iteration\n", __LINE__, c->name, i);
			goto out;
		}
	}

	/* Test whether we can start a really short-lived daemonized container with lxc-init. */
	for (i = 0; i < 10; i++) {
		if (!c->startl(c, 1, NULL)) {
			fprintf(stderr, "%d: %s failed to start on %dth iteration\n", __LINE__, c->name, i);
			goto out;
		}

		if (!c->wait(c, "STOPPED", 30)) {
			fprintf(stderr, "%d: %s failed to wait on %dth iteration\n", __LINE__, c->name, i);
			goto out;
		}
	}

	if (!c->set_config_item(c, "lxc.init.cmd", "you-shall-fail")) {
		fprintf(stderr, "%d: failed setting lxc.init.cmd\n", __LINE__);
		goto out;
	}

	if (!c->set_config_item(c, "lxc.execute.cmd", "you-shall-fail")) {
		fprintf(stderr, "%d: failed setting lxc.init.cmd\n", __LINE__);
		goto out;
	}

	/* Test whether we can start a really short-lived daemonized container. */
	for (i = 0; i < 10; i++) {
		if (c->startl(c, 0, NULL)) {
			fprintf(stderr, "%d: %s failed to start on %dth iteration\n", __LINE__, c->name, i);
			goto out;
		}

		if (!c->wait(c, "STOPPED", 30)) {
			fprintf(stderr, "%d: %s failed to wait on %dth iteration\n", __LINE__, c->name, i);
			goto out;
		}
	}

	/* Test whether we can start a really short-lived daemonized container with lxc-init. */
	for (i = 0; i < 10; i++) {
		/* An container started with lxc-init will always start
		 * successfully unless lxc-init has a bug.
		 */
		if (!c->startl(c, 1, NULL)) {
			fprintf(stderr, "%d: %s failed to start on %dth iteration\n", __LINE__, c->name, i);
			goto out;
		}

		if (!c->wait(c, "STOPPED", 30)) {
			fprintf(stderr, "%d: %s failed to wait on %dth iteration\n", __LINE__, c->name, i);
			goto out;
		}
	}

	c->stop(c);

	fprintf(stderr, "all lxc_container tests passed for %s\n", c->name);
	ret = 0;

out:
	if (c) {
		c->stop(c);
		destroy_container();
	}
	lxc_container_put(c);

	if (ret != 0) {
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

	unlink(template);
	exit(ret);
}

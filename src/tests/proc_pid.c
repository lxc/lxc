/* SPDX-License-Identifier: LGPL-2.1+ */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>

#include "lxccontainer.h"
#include "attach_options.h"

#include "lxctest.h"
#include "utils.h"

#define CONTAINER_NAME "test-proc-pid"
#define PROC_INIT_PATH "/proc/1/oom_score_adj"
#define PROC_SELF_PATH "/proc/self/oom_score_adj"

static int check_oom_score_adj(void *payload)
{
	__do_close int fd = -EBADF;
	char buf[INTTYPE_TO_STRLEN(__s64)];
	ssize_t ret;

	fd = open(PROC_INIT_PATH, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0) {
		lxc_error("Failed to open " PROC_INIT_PATH);
		return EXIT_FAILURE;
	}

	ret = lxc_read_nointr(fd, buf, sizeof(buf));
	if (ret < 0 || (size_t)ret >= sizeof(buf)) {
		lxc_error("Failed to read " PROC_INIT_PATH);
		return EXIT_FAILURE;
	}

	buf[ret] = '\0';
	remove_trailing_newlines(buf);

	if (!strequal(buf,  "-1000")) {
		lxc_error("Unexpected value %s for " PROC_INIT_PATH, buf);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int main(int argc, char *argv[])
{
	int fd_log = -EBADF, fret = EXIT_FAILURE;
	lxc_attach_options_t attach_options = LXC_ATTACH_OPTIONS_DEFAULT;
	int ret;
	pid_t pid;
	struct lxc_container *c;
	struct lxc_log log;
	char template[sizeof(P_tmpdir "/" CONTAINER_NAME "_XXXXXX")];

	if (!file_exists(PROC_SELF_PATH)) {
		lxc_debug("The sysctl path \"" PROC_SELF_PATH "\" needed for this test does not exist. Skipping");
		exit(EXIT_SUCCESS);
	}

	(void)strlcpy(template, P_tmpdir "/" CONTAINER_NAME "_XXXXXX", sizeof(template));

	fd_log = lxc_make_tmpfile(template, false);
	if (fd_log < 0) {
		lxc_error("%s", "Failed to create temporary log file for container \"capabilities\"");
		return fret;
	}

	log.name	= CONTAINER_NAME;
	log.file	= template;
	log.level	= "TRACE";
	log.prefix	= CONTAINER_NAME;
	log.quiet	= false;
	log.lxcpath	= NULL;

	if (lxc_log_init(&log))
		exit(fret);

	c = lxc_container_new(CONTAINER_NAME, NULL);
	if (!c) {
		lxc_error("%s", "Failed to create container " CONTAINER_NAME);
		exit(fret);
	}

	if (c->is_defined(c)) {
		lxc_error("%s\n", "Container " CONTAINER_NAME " is defined");
		goto on_error_put;
	}

	if (!c->createl(c, "busybox", NULL, NULL, 0, NULL)) {
		lxc_error("%s\n", "Failed to create busybox container " CONTAINER_NAME);
		goto on_error_put;
	}

	if (!c->is_defined(c)) {
		lxc_error("%s\n", "Container " CONTAINER_NAME " is not defined");
		goto on_error_destroy;
	}

	if (!c->set_config_item(c, "lxc.mount.auto", "proc:rw")) {
		lxc_error("%s\n", "Failed to set config item \"lxc.mount.auto=proc:rw\"");
		goto on_error_destroy;
	}

	if (!c->clear_config_item(c, "lxc.proc.oom_score_adj")) {
		lxc_error("%s\n", "Failed to clear config item \"lxc.proc.oom_score_adj\"");
		goto on_error_destroy;
	}

	if (!c->set_config_item(c, "lxc.proc.oom_score_adj", "-1000")) {
		lxc_error("%s\n", "Failed to set config item \"lxc.proc.oom_score_adj=-1000\"");
		goto on_error_destroy;
	}

	if (!c->want_daemonize(c, true)) {
		lxc_error("%s\n", "Failed to mark container " CONTAINER_NAME " daemonized");
		goto on_error_destroy;
	}

	if (!c->startl(c, 0, NULL)) {
		lxc_error("%s\n", "Failed to start container " CONTAINER_NAME " daemonized");
		goto on_error_destroy;
	}

	/* Leave some time for the container to write something to the log. */
	sleep(2);

	ret = c->attach(c, check_oom_score_adj, NULL, &attach_options, &pid);
	if (ret < 0) {
		lxc_error("%s\n", "Failed to run function in container " CONTAINER_NAME);
		goto on_error_stop;
	}

	ret = wait_for_pid(pid);
	if (ret < 0) {
		lxc_error("%s\n", "Function "CONTAINER_NAME" failed");
		goto on_error_stop;
	}

	fret = 0;

on_error_stop:
	if (c->is_running(c) && !c->stop(c))
		lxc_error("%s\n", "Failed to stop container " CONTAINER_NAME);

on_error_destroy:
	if (!c->destroy(c))
		lxc_error("%s\n", "Failed to destroy container " CONTAINER_NAME);

on_error_put:
	lxc_container_put(c);

	if (fret == EXIT_SUCCESS) {
		lxc_debug("All \"/proc/<pid>\" tests passed\n");
	} else {
		char buf[4096];
		ssize_t buflen;

		while ((buflen = read(fd_log, buf, 1024)) > 0) {
			buflen = write(STDERR_FILENO, buf, buflen);
			if (buflen <= 0)
				break;
		}
	}
	close_prot_errno_disarm(fd_log);
	(void)unlink(template);

	exit(fret);
}

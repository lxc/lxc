/* liblxcapi
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
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

#include <lxc/lxccontainer.h>

#include "lxctest.h"
#include "utils.h"

int main(int argc, char *argv[])
{
	int ret;
	struct stat st_log_file, st_log_file_after;
	struct lxc_container *c;
	struct lxc_console_log log;
	char log_path[] = "/tmp/console-log-XXXXXX";
	char rotated_log_path[sizeof(log_path) + sizeof(".1")];
	bool do_unlink = false;
	int fret = EXIT_FAILURE;

	c = lxc_container_new("console-log", NULL);
	if (!c) {
		lxc_error("%s", "Failed to create container \"console-log\"");
		exit(fret);
	}

	if (c->is_defined(c)) {
		lxc_error("%s\n", "Container \"console-log\" is defined");
		goto on_error_put;
	}

	ret = mkstemp(log_path);
	if (ret < 0) {
		lxc_error("%s - Failed to create temporary console logfile\n", strerror(errno));
		goto on_error_put;
	}
	close(ret);
	ret = snprintf(rotated_log_path, sizeof(rotated_log_path), "%s.1", log_path);
	if (ret < 0 || (size_t)ret >= sizeof(rotated_log_path)) {
		lxc_error("%s\n", "Failed to construct rotated console logfile path");
		unlink(log_path);
		goto on_error_put;
	}
	do_unlink = true;

	/* Set console ringbuffer size. */
	if (!c->set_config_item(c, "lxc.console.buffer.size", "4096")) {
		lxc_error("%s\n", "Failed to set config item \"lxc.console.buffer.size\"");
		goto on_error_put;
	}

	/* Set console log file. */
	if (!c->set_config_item(c, "lxc.console.logfile", log_path)) {
		lxc_error("%s\n", "Failed to set config item \"lxc.console.logfile\"");
		goto on_error_put;
	}

	if (!c->createl(c, "busybox", NULL, NULL, 0, NULL)) {
		lxc_error("%s\n", "Failed to create busybox container \"console-log\"");
		goto on_error_put;
	}

	if (!c->is_defined(c)) {
		lxc_error("%s\n", "Container \"console-log\" is not defined");
		goto on_error_put;
	}

	c->clear_config(c);

	if (!c->load_config(c, NULL)) {
		lxc_error("%s\n", "Failed to load config for container \"console-log\"");
		goto on_error_stop;
	}

	if (!c->want_daemonize(c, true)) {
		lxc_error("%s\n", "Failed to mark container \"console-log\" daemonized");
		goto on_error_stop;
	}

	if (!c->startl(c, 0, NULL)) {
		lxc_error("%s\n", "Failed to start container \"console-log\" daemonized");
		goto on_error_stop;
	}

	/* Leave some time for the container to write something to the log. */
	sleep(2);

	/* Retrieve the contents of the ringbuffer. */
	log.clear = false;
	log.read_max = &(uint64_t){0};
	log.read = true;

	ret = c->console_log(c, &log);
	if (ret < 0) {
		lxc_error("%s - Failed to retrieve console log \n", strerror(-ret));
		goto on_error_stop;
	} else {
		lxc_debug("Retrieved %" PRIu64
			  " bytes from console log. Contents are \"%s\"\n",
			  *log.read_max, log.data);
		free(log.data);
	}

	/* Leave another two seconds to ensure boot is finished. */
	sleep(2);

	/* Clear the console ringbuffer. */
	log.read_max = &(uint64_t){0};
	log.read = false;
	log.clear = true;
	ret = c->console_log(c, &log);
	if (ret < 0) {
		if (ret != -ENODATA) {
			lxc_error("%s - Failed to retrieve console log\n", strerror(-ret));
			goto on_error_stop;
		}
	}

	if (!c->stop(c)) {
		lxc_error("%s\n", "Failed to stop container \"console-log\"");
		goto on_error_stop;
	}

	if (!c->wait(c, "STOPPED", 5)) {
		lxc_error("%s\n", "Failed waiting for container \"console-log\" to stop");
		goto on_error_stop;
	}

	c->clear_config(c);

	if (!c->load_config(c, NULL)) {
		lxc_error("%s\n", "Failed to load config for container \"console-log\"");
		goto on_error_stop;
	}

	/* Generate more than the ringbuffer size so stop-time truncation is visible. */
	if (!c->set_config_item(c, "lxc.init.cmd",
				"/bin/sh -c 'i=0; while [ $i -lt 1024 ]; do "
				"echo console-log-regression-$i; i=$((i + 1)); "
				"done; exec sleep 30'")) {
		lxc_error("%s\n", "Failed to set init command for console log regression test");
		goto on_error_stop;
	}

	if (!c->startl(c, 0, NULL)) {
		lxc_error("%s\n", "Failed to start container \"console-log\" daemonized");
		goto on_error_destroy;
	}

	/* Leave some time for the container to write something to the log. */
	sleep(2);

	ret = stat(log_path, &st_log_file);
	if (ret < 0) {
		lxc_error("%s - Failed to stat on-disk logfile\n", strerror(errno));
		goto on_error_stop;
	}
	if (st_log_file.st_size <= 4096) {
		lxc_error("%s\n", "Console log regression command wrote too little output");
		goto on_error_stop;
	}

	/* Turn on rotation for the console log file. */
	if (!c->set_config_item(c, "lxc.console.rotate", "1")) {
		lxc_error("%s\n", "Failed to set config item \"lxc.console.rotate\"");
		goto on_error_put;
	}

	if (!c->stop(c)) {
		lxc_error("%s\n", "Failed to stop container \"console-log\"");
		goto on_error_stop;
	}

	if (!c->wait(c, "STOPPED", 5)) {
		lxc_error("%s\n", "Failed waiting for container \"console-log\" to stop");
		goto on_error_stop;
	}

	ret = stat(log_path, &st_log_file_after);
	if (ret < 0) {
		lxc_error("%s - Failed to stat on-disk logfile after stop\n", strerror(errno));
		goto on_error_destroy;
	}
	if (st_log_file_after.st_size < st_log_file.st_size) {
		lxc_error("%s\n", "Console log file shrank when the container stopped");
		goto on_error_destroy;
	}

	if (!c->startl(c, 0, NULL)) {
		lxc_error("%s\n", "Failed to start container \"console-log\" daemonized");
		goto on_error_destroy;
	}

	/* Leave some time for the container to write something to the log. */
	sleep(2);

	fret = 0;

on_error_stop:
	if (c->is_running(c) && !c->stop(c))
		lxc_error("%s\n", "Failed to stop container \"console-log\"");

on_error_destroy:
	if (!c->destroy(c))
		lxc_error("%s\n", "Failed to destroy container \"console-log\"");

on_error_put:
	lxc_container_put(c);
	if (do_unlink) {
		ret = unlink(log_path);
		if (ret < 0 && errno != ENOENT)
			lxc_error("%s - Failed to remove container log file\n",
				  strerror(errno));

		ret = unlink(rotated_log_path);
		if (ret < 0 && errno != ENOENT)
			lxc_error("%s - Failed to remove container log file\n",
				  strerror(errno));
	}
	exit(fret);
}

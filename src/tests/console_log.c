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

#include "lxctest.h"
#include "utils.h"

int main(int argc, char *argv[])
{
	int logfd, ret;
	char buf[4096 + 1];
	ssize_t bytes;
	struct stat st_buffer_log_file, st_log_file, st_log_file_old;
	struct lxc_container *c;
	struct lxc_console_log log;
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

	/* Set console ringbuffer size. */
	if (!c->set_config_item(c, "lxc.console.buffer.size", "4096")) {
		lxc_error("%s\n", "Failed to set config item \"lxc.console.buffer.size\"");
		goto on_error_put;
	}

	/* Set ringbuffer log file. */
	if (!c->set_config_item(c, "lxc.console.buffer.logfile", "/tmp/console-buffer-log.log")) {
		lxc_error("%s\n", "Failed to set config item \"lxc.console.buffer.logfile\"");
		goto on_error_put;
	}

	/* Set console log file. */
	if (!c->set_config_item(c, "lxc.console.logfile", "/tmp/console-log.log")) {
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
	log.write_logfile = false;

	ret = c->console_log(c, &log);
	if (ret < 0) {
		lxc_error("%s - Failed to retrieve console log \n", strerror(-ret));
		goto on_error_stop;
	} else {
		lxc_debug("Retrieved %" PRIu64
			  " bytes from console log. Contents are \"%s\"\n",
			  *log.read_max, log.data);
	}

	/* Leave another two seconds to ensure boot is finished. */
	sleep(2);

	/* Clear the console ringbuffer. */
	log.read_max = &(uint64_t){0};
	log.read = false;
	log.write_logfile = false;
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

	c->clear_config(c);

	if (!c->load_config(c, NULL)) {
		lxc_error("%s\n", "Failed to load config for container \"console-log\"");
		goto on_error_stop;
	}

	if (!c->startl(c, 0, NULL)) {
		lxc_error("%s\n", "Failed to start container \"console-log\" daemonized");
		goto on_error_destroy;
	}

	/* Leave some time for the container to write something to the log. */
	sleep(2);

	log.read_max = &(uint64_t){0};
	log.read = true;
	log.write_logfile = true;
	log.clear = false;
	ret = c->console_log(c, &log);
	if (ret < 0) {
		lxc_error("%s - Failed to retrieve console log \n", strerror(-ret));
		goto on_error_stop;
	} else {
		lxc_debug("Retrieved %" PRIu64
			  " bytes from console log. Contents are \"%s\"\n",
			  *log.read_max, log.data);
	}

	logfd = open("/tmp/console-buffer-log.log", O_RDONLY);
	if (logfd < 0) {
		lxc_error("%s - Failed to open console ringbuffer log file "
			  "\"/tmp/console-buffer-log.log\"\n", strerror(errno));
		goto on_error_stop;
	}

	bytes = lxc_read_nointr(logfd, buf, 4096 + 1);
	close(logfd);
	if (bytes < 0 || ((uint64_t)bytes != *log.read_max)) {
		lxc_error("%s - Failed to read console ringbuffer log file "
			  "\"/tmp/console-buffer-log.log\"\n", strerror(errno));
		goto on_error_stop;
	}

	ret = stat("/tmp/console-buffer-log.log", &st_buffer_log_file);
	if (ret < 0) {
		lxc_error("%s - Failed to stat on-disk logfile\n", strerror(errno));
		goto on_error_stop;
	}

	if ((uint64_t)st_buffer_log_file.st_size != *log.read_max) {
		lxc_error("On-disk logfile size and used ringbuffer size do "
			  "not match: %" PRIu64 " != %" PRIu64 "\n",
			  (uint64_t)st_buffer_log_file.st_size, *log.read_max);
		goto on_error_stop;
	}

	if (memcmp(log.data, buf, *log.read_max)) {
		lxc_error("%s - Contents of in-memory ringbuffer and on-disk "
			  "logfile do not match\n", strerror(errno));
		goto on_error_stop;
	} else {
		lxc_debug("Retrieved %" PRIu64 " bytes from console log and "
			  "console ringbuffer log file. Contents are: \"%s\" - "
			  "\"%s\"\n", *log.read_max, log.data, buf);
	}

	ret = stat("/tmp/console-log.log", &st_log_file);
	if (ret < 0) {
		lxc_error("%s - Failed to stat on-disk logfile\n", strerror(errno));
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

	if (!c->startl(c, 0, NULL)) {
		lxc_error("%s\n", "Failed to start container \"console-log\" daemonized");
		goto on_error_destroy;
	}

	/* Leave some time for the container to write something to the log. */
	sleep(2);

	/* The console log file size must be greater than the console log file
	 * size since we append to the latter and we truncated the former
	 * already.
	 */
	if (st_log_file.st_size <= st_buffer_log_file.st_size) {
		lxc_error("%s - Console log file size was smaller than the "
			  "console buffer log file size: %zu < %zu\n",
			  strerror(errno), (size_t)st_log_file.st_size,
			  (size_t)st_buffer_log_file.st_size);
		goto on_error_stop;
	} else {
		lxc_debug("Console log file size is %zu bytes and console "
			  "buffer log file size is %zu bytes\n",
			  (size_t)st_log_file.st_size,
			  (size_t)st_buffer_log_file.st_size);
	}

	ret = stat("/tmp/console-log.log", &st_log_file);
	if (ret < 0) {
		lxc_error("%s - Failed to stat on-disk logfile\n", strerror(errno));
		goto on_error_stop;
	}

	log.read_max = &(uint64_t){0};
	log.read = false;
	log.write_logfile = false;
	log.clear = true;
	ret = c->console_log(c, &log);
	if (ret < 0) {
		lxc_error("%s - Failed to retrieve console log \n", strerror(-ret));
		goto on_error_stop;
	}

	/* There should now be a rotated log file called
	 * "/tmp/console-log.log.1"
	 */
	ret = stat("/tmp/console-log.log.1", &st_log_file_old);
	if (ret < 0) {
		lxc_error("%s - Failed to stat on-disk logfile\n", strerror(errno));
		goto on_error_stop;
	}

	/* The rotated log file should have the same size as before the
	 * rotation.
	 */
	if (st_log_file.st_size != st_log_file_old.st_size) {
		lxc_error("%s - Console log file size changed during log "
			  "rotation: %zu != %zu\n",
			  strerror(errno), (size_t)st_log_file.st_size,
			  (size_t)st_log_file_old.st_size);
		goto on_error_stop;
	}

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
		ret = unlink("/tmp/console-log.log");
		if (ret < 0)
			lxc_error("%s - Failed to remove container log file\n",
				  strerror(errno));

		ret = unlink("/tmp/console-log.log.1");
		if (ret < 0)
			lxc_error("%s - Failed to remove container log file\n",
				  strerror(errno));
	}
	exit(fret);
}

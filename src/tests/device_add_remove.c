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

#include "lxctest.h"
#include "memory_utils.h"
#include "utils.h"

#ifndef HAVE_STRLCPY
#include "include/strlcpy.h"
#endif

#define NAME "device_add_remove_test"
#define DEVICE "/dev/loop-control"

int main(int argc, char *argv[])
{
	__do_close int fd_log = -EBADF;
	int ret = 1;
	struct lxc_log log = {};
	struct lxc_container *c = NULL;
	char template[sizeof(P_tmpdir"/attach_XXXXXX")];

	(void)strlcpy(template, P_tmpdir"/attach_XXXXXX", sizeof(template));

	fd_log = lxc_make_tmpfile(template, false);
	if (fd_log < 0) {
		lxc_error("Failed to create temporary log file for container %s\n", NAME);
		exit(EXIT_FAILURE);
	}
	log.name = NAME;
	log.file = template;
	log.level = "TRACE";
	log.prefix = "device_add_remove";
	log.quiet = false;
	log.lxcpath = NULL;
	if (lxc_log_init(&log))
		goto out;

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
	if (ret != 0) {
		char buf[4096];
		ssize_t buflen;
		while ((buflen = read(fd_log, buf, 1024)) > 0) {
			buflen = write(STDERR_FILENO, buf, buflen);
			if (buflen <= 0)
				break;
		}
	}
	(void)unlink(template);

	if (c)
		lxc_container_put(c);
	return ret;
}

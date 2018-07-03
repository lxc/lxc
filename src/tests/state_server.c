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
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/reboot.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "lxc/lxccontainer.h"
#include "lxctest.h"

struct thread_args {
	int thread_id;
	int timeout;
	bool success;
	struct lxc_container *c;
};

void *state_wrapper(void *data)
{
	struct thread_args *args = data;

	lxc_debug("Starting state server thread %d\n", args->thread_id);

	args->success = args->c->shutdown(args->c, args->timeout);

	lxc_debug("State server thread %d with shutdown timeout %d returned \"%s\"\n",
		  args->thread_id, args->timeout, args->success ? "SUCCESS" : "FAILED");

	pthread_exit(NULL);
	return NULL;
}

int main(int argc, char *argv[])
{
	int i, j;
	pthread_attr_t attr;
	pthread_t threads[10];
	struct thread_args args[10];
	struct lxc_container *c;
	int ret = EXIT_FAILURE;

	c = lxc_container_new("state-server", NULL);
	if (!c) {
		lxc_error("%s", "Failed to create container \"state-server\"");
		exit(ret);
	}

	if (c->is_defined(c)) {
		lxc_error("%s\n", "Container \"state-server\" is defined");
		goto on_error_put;
	}

	if (!c->createl(c, "busybox", NULL, NULL, 0, NULL)) {
		lxc_error("%s\n", "Failed to create busybox container \"state-server\"");
		goto on_error_put;
	}

	if (!c->is_defined(c)) {
		lxc_error("%s\n", "Container \"state-server\" is not defined");
		goto on_error_put;
	}

	c->clear_config(c);

	if (!c->load_config(c, NULL)) {
		lxc_error("%s\n", "Failed to load config for container \"state-server\"");
		goto on_error_stop;
	}

	if (!c->want_daemonize(c, true)) {
		lxc_error("%s\n", "Failed to mark container \"state-server\" daemonized");
		goto on_error_stop;
	}

	pthread_attr_init(&attr);

	for (j = 0; j < 10; j++) {
		lxc_debug("Starting state server test iteration %d\n", j);

		if (!c->startl(c, 0, NULL)) {
			lxc_error("%s\n", "Failed to start container \"state-server\" daemonized");
			goto on_error_stop;
		}

		sleep(5);

		for (i = 0; i < 10; i++) {
			int ret;

			args[i].thread_id = i;
			args[i].c = c;
			args[i].timeout = -1;
			/* test non-blocking shutdown request */
			if (i == 0)
				args[i].timeout = 0;

			ret = pthread_create(&threads[i], &attr, state_wrapper, (void *) &args[i]);
			if (ret != 0)
				goto on_error_stop;
		}

		for (i = 0; i < 10; i++) {
			int ret;

			ret = pthread_join(threads[i], NULL);
			if (ret != 0)
				goto on_error_stop;

			if (!args[i].success) {
				lxc_error("State server thread %d failed\n", args[i].thread_id);
				goto on_error_stop;
			}
		}
	}

	ret = EXIT_SUCCESS;

on_error_stop:
	if (c->is_running(c) && !c->stop(c))
		lxc_error("%s\n", "Failed to stop container \"state-server\"");

	if (!c->destroy(c))
		lxc_error("%s\n", "Failed to destroy container \"state-server\"");

on_error_put:
	lxc_container_put(c);
	if (ret == EXIT_SUCCESS)
		lxc_debug("%s\n", "All state server tests passed");

	exit(ret);
}

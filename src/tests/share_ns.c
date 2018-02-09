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
	bool success;
	pid_t init_pid;
	char *inherited_ipc_ns;
	char *inherited_net_ns;
};

void *ns_sharing_wrapper(void *data)
{
	int init_pid;
	ssize_t ret;
	char name[100];
	char owning_ns_init_pid[100];
	char proc_ns_path[4096];
	char ns_buf[4096];
	struct lxc_container *c;
	struct thread_args *args = data;

	lxc_debug("Starting namespace sharing thread %d\n", args->thread_id);

	sprintf(name, "share-ns-%d", args->thread_id);
	c = lxc_container_new(name, NULL);
	if (!c) {
		lxc_error("Failed to create container \"%s\"\n", name);
		return NULL;
	}

	if (c->is_defined(c)) {
		lxc_error("Container \"%s\" is defined\n", name);
		goto out;
	}

	if (!c->createl(c, "busybox", NULL, NULL, 0, NULL)) {
		lxc_error("Failed to create busybox container \"%s\"\n", name);
		goto out;
	}

	if (!c->is_defined(c)) {
		lxc_error("Container \"%s\" is not defined\n", name);
		goto out;
	}

	if (!c->load_config(c, NULL)) {
		lxc_error("Failed to load config for container \"%s\"\n", name);
		goto out;
	}

	/* share ipc namespace by container name */
	if (!c->set_config_item(c, "lxc.namespace.share.ipc", "owning-ns")) {
		lxc_error("Failed to set \"lxc.namespace.share.ipc=owning-ns\" for container \"%s\"\n", name);
		goto out;
	}

	/* clear all network configuration */
	if (!c->set_config_item(c, "lxc.net", "")) {
		lxc_error("Failed to set \"lxc.namespace.share.ipc=owning-ns\" for container \"%s\"\n", name);
		goto out;
	}

	if (!c->set_config_item(c, "lxc.net.0.type", "empty")) {
		lxc_error("Failed to set \"lxc.net.0.type=empty\" for container \"%s\"\n", name);
		goto out;
	}

	sprintf(owning_ns_init_pid, "%d", args->init_pid);
	/* share net namespace by pid */
	if (!c->set_config_item(c, "lxc.namespace.share.net", owning_ns_init_pid)) {
		lxc_error("Failed to set \"lxc.namespace.share.net=%s\" for container \"%s\"\n", owning_ns_init_pid, name);
		goto out;
	}

	if (!c->want_daemonize(c, true)) {
		lxc_error("Failed to mark container \"%s\" daemonized\n", name);
		goto out;
	}

	if (!c->startl(c, 0, NULL)) {
		lxc_error("Failed to start container \"%s\" daemonized\n", name);
		goto out;
	}

	init_pid = c->init_pid(c);
	if (init_pid < 0) {
		lxc_error("Failed to retrieve init pid of container \"%s\"\n", name);
		goto out;
	}

	/* Check whether we correctly inherited the ipc namespace. */
	ret = snprintf(proc_ns_path, sizeof(proc_ns_path), "/proc/%d/ns/ipc", init_pid);
	if (ret < 0 || (size_t)ret >= sizeof(proc_ns_path)) {
		lxc_error("Failed to create string for container \"%s\"\n", name);
		goto out;
	}

	ret = readlink(proc_ns_path, ns_buf, sizeof(ns_buf));
	if (ret < 0 || (size_t)ret >= sizeof(ns_buf)) {
		lxc_error("Failed to retrieve ipc namespace for container \"%s\"\n", name);
		goto out;
	}
	ns_buf[ret] = '\0';

	if (strcmp(args->inherited_ipc_ns, ns_buf) != 0) {
		lxc_error("Failed to inherit ipc namespace from container \"owning-ns\": %s != %s\n", args->inherited_ipc_ns, ns_buf);
		goto out;
	}
	lxc_debug("Inherited ipc namespace from container \"owning-ns\": %s == %s\n", args->inherited_ipc_ns, ns_buf);

	/* Check whether we correctly inherited the net namespace. */
	ret = snprintf(proc_ns_path, sizeof(proc_ns_path), "/proc/%d/ns/net", init_pid);
	if (ret < 0 || (size_t)ret >= sizeof(proc_ns_path)) {
		lxc_error("Failed to create string for container \"%s\"\n", name);
		goto out;
	}

	ret = readlink(proc_ns_path, ns_buf, sizeof(ns_buf));
	if (ret < 0 || (size_t)ret >= sizeof(ns_buf)) {
		lxc_error("Failed to retrieve ipc namespace for container \"%s\"\n", name);
		goto out;
	}
	ns_buf[ret] = '\0';

	if (strcmp(args->inherited_net_ns, ns_buf) != 0) {
		lxc_error("Failed to inherit net namespace from container \"owning-ns\": %s != %s\n", args->inherited_net_ns, ns_buf);
		goto out;
	}
	lxc_debug("Inherited net namespace from container \"owning-ns\": %s == %s\n", args->inherited_net_ns, ns_buf);

	args->success = true;

out:
	if (c->is_running(c) && !c->stop(c)) {
		lxc_error("Failed to stop container \"%s\"\n", name);
		goto out;
	}

	if (!c->destroy(c)) {
		lxc_error("Failed to destroy container \"%s\"\n", name);
		goto out;
	}

	pthread_exit(NULL);
	return NULL;
}

int main(int argc, char *argv[])
{
	int i, init_pid, j;
	char proc_ns_path[4096];
	char ipc_ns_buf[4096];
	char net_ns_buf[4096];
	pthread_attr_t attr;
	pthread_t threads[10];
	struct thread_args args[10];
	struct lxc_container *c;
	int ret = EXIT_FAILURE;

	c = lxc_container_new("owning-ns", NULL);
	if (!c) {
		lxc_error("%s", "Failed to create container \"owning-ns\"");
		exit(ret);
	}

	if (c->is_defined(c)) {
		lxc_error("%s\n", "Container \"owning-ns\" is defined");
		goto on_error_put;
	}

	if (!c->createl(c, "busybox", NULL, NULL, 0, NULL)) {
		lxc_error("%s\n", "Failed to create busybox container \"owning-ns\"");
		goto on_error_put;
	}

	if (!c->is_defined(c)) {
		lxc_error("%s\n", "Container \"owning-ns\" is not defined");
		goto on_error_put;
	}

	c->clear_config(c);

	if (!c->load_config(c, NULL)) {
		lxc_error("%s\n", "Failed to load config for container \"owning-ns\"");
		goto on_error_stop;
	}

	if (!c->want_daemonize(c, true)) {
		lxc_error("%s\n", "Failed to mark container \"owning-ns\" daemonized");
		goto on_error_stop;
	}

	if (!c->startl(c, 0, NULL)) {
		lxc_error("%s\n", "Failed to start container \"owning-ns\" daemonized");
		goto on_error_stop;
	}

	init_pid = c->init_pid(c);
	if (init_pid < 0) {
		lxc_error("%s\n", "Failed to retrieve init pid of container \"owning-ns\"");
		goto on_error_stop;
	}

	/* record our ipc namespace */
	ret = snprintf(proc_ns_path, sizeof(proc_ns_path), "/proc/%d/ns/ipc", init_pid);
	if (ret < 0 || (size_t)ret >= sizeof(proc_ns_path)) {
		lxc_error("%s\n", "Failed to create string for container \"owning-ns\"");
		goto on_error_stop;
	}

	ret = readlink(proc_ns_path, ipc_ns_buf, sizeof(ipc_ns_buf));
	if (ret < 0 || (size_t)ret >= sizeof(ipc_ns_buf)) {
		lxc_error("%s\n", "Failed to retrieve ipc namespace for container \"owning-ns\"");
		goto on_error_stop;

	}
	ipc_ns_buf[ret] = '\0';

	/* record our net namespace */
	ret = snprintf(proc_ns_path, sizeof(proc_ns_path), "/proc/%d/ns/net", init_pid);
	if (ret < 0 || (size_t)ret >= sizeof(proc_ns_path)) {
		lxc_error("%s\n", "Failed to create string for container \"owning-ns\"");
		goto on_error_stop;
	}

	ret = readlink(proc_ns_path, net_ns_buf, sizeof(net_ns_buf));
	if (ret < 0 || (size_t)ret >= sizeof(net_ns_buf)) {
		lxc_error("%s\n", "Failed to retrieve ipc namespace for container \"owning-ns\"");
		goto on_error_stop;
	}
	net_ns_buf[ret] = '\0';

	sleep(5);

	pthread_attr_init(&attr);

	for (j = 0; j < 10; j++) {
		lxc_debug("Starting namespace sharing test iteration %d\n", j);

		for (i = 0; i < 10; i++) {
			int ret;

			args[i].thread_id = i;
			args[i].success = false;
			args[i].init_pid = init_pid;
			args[i].inherited_ipc_ns = ipc_ns_buf;
			args[i].inherited_net_ns = net_ns_buf;

			ret = pthread_create(&threads[i], &attr, ns_sharing_wrapper, (void *) &args[i]);
			if (ret != 0)
				goto on_error_stop;
		}

		for (i = 0; i < 10; i++) {
			int ret;

			ret = pthread_join(threads[i], NULL);
			if (ret != 0)
				goto on_error_stop;

			if (!args[i].success) {
				lxc_error("ns sharing thread %d failed\n", args[i].thread_id);
				goto on_error_stop;
			}
		}
	}

	ret = EXIT_SUCCESS;

on_error_stop:
	if (c->is_running(c) && !c->stop(c))
		lxc_error("%s\n", "Failed to stop container \"owning-ns\"");

	if (!c->destroy(c))
		lxc_error("%s\n", "Failed to destroy container \"owning-ns\"");

on_error_put:
	lxc_container_put(c);
	if (ret == EXIT_SUCCESS)
		lxc_debug("%s\n", "All state namespace sharing tests passed");
	exit(ret);
}

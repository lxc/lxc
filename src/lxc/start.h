/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2008
 *
 * Authors:
 * Daniel Lezcano <daniel.lezcano at free.fr>
 * Serge Hallyn <serge@hallyn.com>
 * Christian Brauner <christian.brauner@ubuntu.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
#ifndef __LXC_START_H
#define __LXC_START_H

#include <signal.h>
#include <stdbool.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "conf.h"
#include "namespace.h"
#include "state.h"

struct lxc_handler {
	/* Record the clone for namespaces flags that the container requested.
	 *
	 * @ns_clone_flags
	 * - All clone flags that were requested.
	 *
	 * @ns_on_clone_flags
	 * - The clone flags for namespaces to actually use when calling
	 *   lxc_clone(): After the container has started ns_on_clone_flags will
	 *   list the clone flags that were unshare()ed rather then clone()ed
	 *   because of ordering requirements (e.g. e.g. CLONE_NEWNET and
	 *   CLONE_NEWUSER) or implementation details.
         *
	 * @ns_keep_flags;
	 * - The clone flags for the namespaces that the container will inherit
	 *   from the parent. They are not recorded in the handler itself but
	 *   are present in the container's config.
	 *
	 * @ns_share_flags;
	 * - The clone flags for the namespaces that the container will share
	 *   with another process.  They are not recorded in the handler itself
	 *   but are present in the container's config.
	 */
	struct /* lxc_ns */ {
		int ns_clone_flags;
		int ns_on_clone_flags;
	};

	/* File descriptor to pin the rootfs for privileged containers. */
	int pinfd;

	/* Signal file descriptor. */
	int sigfd;

	/* List of file descriptors referring to the namespaces of the
	 * container. Note that these are not necessarily identical to
	 * the "clone_flags" handler field in case namespace inheritance is
	 * requested.
	 */
	int nsfd[LXC_NS_MAX];

	/* Abstract unix domain SOCK_DGRAM socketpair to pass arbitrary data
	 * between child and parent.
	 */
	int data_sock[2];

	/* The socketpair() fds used to wait on successful daemonized startup. */
	int state_socket_pair[2];

	/* Socketpair to synchronize processes during container creation. */
	int sync_sock[2];

	/* Pointer to the name of the container. Do not free! */
	const char *name;

	/* Pointer to the path the container. Do not free! */
	const char *lxcpath;

	/* Whether the container's startup process euid is 0. */
	bool am_root;

	/* Indicates whether should we close std{in,out,err} on start. */
	bool daemonize;

	/* The child's pid. */
	pid_t pid;

	/* Whether the child has already exited. */
	bool init_died;

	/* The signal mask prior to setting up the signal file descriptor. */
	sigset_t oldmask;

	/* The container's in-memory configuration. */
	struct lxc_conf *conf;

	/* A set of operations to be performed at various stages of the
	 * container's life.
	 */
	struct lxc_operations *ops;

	/* This holds the cgroup information. Note that the data here is
	 * specific to the cgroup driver used.
	 */
	void *cgroup_data;

	/* Data to be passed to handler ops. */
	void *data;

	/* Current state of the container. */
	lxc_state_t state;

	/* The exit status of the container; not defined unless ->init_died ==
	 * true.
	 */
	int exit_status;

	struct cgroup_ops *cgroup_ops;
};

struct execute_args {
	char *init_path;
	int init_fd;
	char *const *argv;
	int quiet;
};

struct lxc_operations {
	int (*start)(struct lxc_handler *, void *);
	int (*post_start)(struct lxc_handler *, void *);
};

extern int lxc_poll(const char *name, struct lxc_handler *handler);
extern int lxc_set_state(const char *name, struct lxc_handler *handler,
			 lxc_state_t state);
extern int lxc_serve_state_clients(const char *name,
				   struct lxc_handler *handler,
				   lxc_state_t state);
extern void lxc_abort(const char *name, struct lxc_handler *handler);
extern struct lxc_handler *lxc_init_handler(const char *name,
					    struct lxc_conf *conf,
					    const char *lxcpath,
					    bool daemonize);
extern void lxc_zero_handler(struct lxc_handler *handler);
extern void lxc_free_handler(struct lxc_handler *handler);
extern int lxc_init(const char *name, struct lxc_handler *handler);
extern void lxc_fini(const char *name, struct lxc_handler *handler);

/* lxc_check_inherited: Check for any open file descriptors and close them if
 *                      requested.
 * @param[in] conf          The container's configuration.
 * @param[in] closeall      Whether we should close all open file descriptors.
 * @param[in] fds_to_ignore Array of file descriptors to ignore.
 * @param[in] len_fds       Length of fds_to_ignore array.
 */
extern int lxc_check_inherited(struct lxc_conf *conf, bool closeall,
			       int *fds_to_ignore, size_t len_fds);
extern int __lxc_start(const char *, struct lxc_handler *,
		       struct lxc_operations *, void *, const char *, bool,
		       int *);

extern int resolve_clone_flags(struct lxc_handler *handler);

#endif

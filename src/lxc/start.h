/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_START_H
#define __LXC_START_H

#include <linux/sched.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "compiler.h"
#include "conf.h"
#include "macro.h"
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
	 * @ns_unshare_flags
	 * - Flags for namespaces that were unshared, not cloned.
	 *
	 * @clone_flags
	 * - ns_on_clone flags | other flags used to create container.
	 */
	struct /* lxc_ns */ {
		unsigned int ns_clone_flags;
		unsigned int ns_on_clone_flags;
		unsigned int ns_unshare_flags;
		__aligned_u64 clone_flags;
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

	/* The child's pidfd. */
	int pidfd;

	/* The grandfather's pid when double-forking. */
	pid_t transient_pid;

	/* The monitor's pid. */
	pid_t monitor_pid;

	int monitor_status_fd;

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

	/* Internal fds that always need to stay open. */
	int keep_fds[3];
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

__hidden extern int lxc_poll(const char *name, struct lxc_handler *handler);
__hidden extern int lxc_set_state(const char *name, struct lxc_handler *handler, lxc_state_t state);
__hidden extern int lxc_serve_state_clients(const char *name, struct lxc_handler *handler,
					    lxc_state_t state);
__hidden extern void lxc_abort(struct lxc_handler *handler);
__hidden extern struct lxc_handler *lxc_init_handler(struct lxc_handler *old, const char *name,
						     struct lxc_conf *conf, const char *lxcpath,
						     bool daemonize);
__hidden extern void lxc_put_handler(struct lxc_handler *handler);
__hidden extern int lxc_init(const char *name, struct lxc_handler *handler);
__hidden extern void lxc_end(struct lxc_handler *handler);

/* lxc_check_inherited: Check for any open file descriptors and close them if
 *                      requested.
 * @param[in] conf          The container's configuration.
 * @param[in] closeall      Whether we should close all open file descriptors.
 * @param[in] fds_to_ignore Array of file descriptors to ignore.
 * @param[in] len_fds       Length of fds_to_ignore array.
 */
__hidden extern int lxc_check_inherited(struct lxc_conf *conf, bool closeall, int *fds_to_ignore,
					size_t len_fds);
static inline int inherit_fds(struct lxc_handler *handler, bool closeall)
{
	return lxc_check_inherited(handler->conf, closeall, handler->keep_fds,
				   ARRAY_SIZE(handler->keep_fds));
}

__hidden extern int __lxc_start(struct lxc_handler *, struct lxc_operations *, void *, const char *,
				bool, int *);

__hidden extern int resolve_clone_flags(struct lxc_handler *handler);

#endif

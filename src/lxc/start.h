/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2008
 *
 * Authors:
 * Daniel Lezcano <daniel.lezcano at free.fr>
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
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdbool.h>

#include "conf.h"
#include "config.h"
#include "state.h"
#include "namespace.h"

struct lxc_handler {
	bool am_root;
	pid_t pid;
	char *name;
	lxc_state_t state;
	int clone_flags;
	int sigfd;
	sigset_t oldmask;
	struct lxc_conf *conf;
	struct lxc_operations *ops;
	void *data;
	int sv[2];
	int pinfd;
	const char *lxcpath;
	void *cgroup_data;

	/* Abstract unix domain SOCK_DGRAM socketpair to pass arbitrary data
	 * between child and parent.
	 */
	int data_sock[2];

	/* indicates whether should we close std{in,out,err} on start */
	bool backgrounded;
	int nsfd[LXC_NS_MAX];
	int netnsfd;
	/* The socketpair() fds used to wait on successful daemonized startup. */
	int state_socket_pair[2];
	struct lxc_list state_clients;
};

struct lxc_operations {
	int (*start)(struct lxc_handler *, void *);
	int (*post_start)(struct lxc_handler *, void *);
};

struct state_client {
	int clientfd;
	lxc_state_t states[MAX_STATE];
};

extern int lxc_poll(const char *name, struct lxc_handler *handler);
extern int lxc_set_state(const char *name, struct lxc_handler *handler, lxc_state_t state);
extern void lxc_abort(const char *name, struct lxc_handler *handler);
extern struct lxc_handler *lxc_init_handler(const char *name,
					    struct lxc_conf *conf,
					    const char *lxcpath,
					    bool daemonize);
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
int __lxc_start(const char *, struct lxc_handler *, struct lxc_operations *,
		void *, const char *, bool);

extern void resolve_clone_flags(struct lxc_handler *handler);
#endif


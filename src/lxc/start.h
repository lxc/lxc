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

#include "config.h"
#include "state.h"
#include "namespace.h"

struct lxc_conf;

struct lxc_handler;

struct lxc_operations {
	int (*start)(struct lxc_handler *, void *);
	int (*post_start)(struct lxc_handler *, void *);
};

struct cgroup_desc;

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
	 */
	struct /* lxc_ns */ {
		int ns_clone_flags;
		int ns_on_clone_flags;
	};

	pid_t pid;
	char *name;
	lxc_state_t state;
	int sigfd;
	sigset_t oldmask;
	struct lxc_conf *conf;
	struct lxc_operations *ops;
	void *data;
	int sv[2];
	int pinfd;
	const char *lxcpath;
	void *cgroup_data;
	int nsfd[LXC_NS_MAX];
};

extern struct lxc_handler *lxc_init(const char *name, struct lxc_conf *, const char *);

extern int lxc_check_inherited(struct lxc_conf *conf, int fd_to_ignore);
int __lxc_start(const char *, struct lxc_conf *, struct lxc_operations *,
		void *, const char *);

#endif


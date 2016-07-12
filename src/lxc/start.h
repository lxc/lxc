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
#include <stdbool.h>

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

enum {
	LXC_NS_MNT,
	LXC_NS_PID,
	LXC_NS_UTS,
	LXC_NS_IPC,
	LXC_NS_USER,
	LXC_NS_NET,
	LXC_NS_CGROUP,
	LXC_NS_MAX
};

struct ns_info {
	const char *proc_name;
	int clone_flag;
};

extern const struct ns_info ns_info[LXC_NS_MAX];

struct lxc_handler {
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
	int ttysock[2]; // socketpair for child->parent tty fd passing
	bool backgrounded; // indicates whether should we close std{in,out,err} on start
	int nsfd[LXC_NS_MAX];
};


extern int lxc_poll(const char *name, struct lxc_handler *handler);
extern int lxc_set_state(const char *name, struct lxc_handler *handler, lxc_state_t state);
extern void lxc_abort(const char *name, struct lxc_handler *handler);
extern struct lxc_handler *lxc_init(const char *name, struct lxc_conf *, const char *);
extern void lxc_fini(const char *name, struct lxc_handler *handler);

extern int lxc_check_inherited(struct lxc_conf *conf, bool closeall, int fd_to_ignore);
int __lxc_start(const char *, struct lxc_conf *, struct lxc_operations *,
		void *, const char *, bool);

extern void resolve_clone_flags(struct lxc_handler *handler);
#endif


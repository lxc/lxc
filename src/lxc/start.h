/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2008
 *
 * Authors:
 * Daniel Lezcano <dlezcano at fr.ibm.com>
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */
#ifndef __lxc_state_h
#define __lxc_state_h

#include <lxc/state.h>
#include <sys/param.h>

struct lxc_conf;

struct start_arg;
struct lxc_handler;

struct lxc_operations {
	int (*start)(struct lxc_handler *, struct start_arg *);
	int (*post_start)(struct lxc_handler *, struct start_arg *, int);
};

struct lxc_handler {
	pid_t pid;
	char *name;
	lxc_state_t state;
	int sigfd;
	char nsgroup[MAXPATHLEN];
	sigset_t oldmask;
	struct lxc_conf *conf;
	struct lxc_operations *ops;
};

struct start_arg {
	const char *name;
	struct lxc_handler *handler;
	int *sv;
	char *const *argv;
	int sfd;
};

extern struct lxc_handler *lxc_init(const char *name, struct lxc_conf *);
extern int lxc_spawn(struct start_arg *start_arg, int restart_flags);

extern int lxc_poll(const char *name, struct lxc_handler *handler);
extern void lxc_abort(const char *name, struct lxc_handler *handler);
extern void lxc_fini(const char *name, struct lxc_handler *handler);
extern int lxc_set_state(const char *, struct lxc_handler *, lxc_state_t);
extern int lxc_check_inherited(int fd_to_ignore);

#endif


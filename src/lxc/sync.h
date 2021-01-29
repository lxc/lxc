/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_SYNC_H
#define __LXC_SYNC_H

#include "compiler.h"

struct lxc_handler;

enum {
	START_SYNC_STARTUP		=  0,
	START_SYNC_CONFIGURE		=  1,
	START_SYNC_POST_CONFIGURE	=  2,
	START_SYNC_CGROUP		=  3,
	START_SYNC_CGROUP_UNSHARE	=  4,
	START_SYNC_CGROUP_LIMITS	=  5,
	START_SYNC_READY_START		=  6,
	START_SYNC_RESTART		=  7,
	START_SYNC_POST_RESTART		=  8,
	SYNC_ERROR			= -1 /* Used to report errors from another process */
};

__hidden extern int lxc_sync_init(struct lxc_handler *handler);
__hidden extern void lxc_sync_fini(struct lxc_handler *);
__hidden extern void lxc_sync_fini_parent(struct lxc_handler *);
__hidden extern void lxc_sync_fini_child(struct lxc_handler *);
__hidden extern int lxc_sync_wake_child(struct lxc_handler *, int);
__hidden extern int lxc_sync_wait_child(struct lxc_handler *, int);
__hidden extern int lxc_sync_wake_parent(struct lxc_handler *, int);
__hidden extern int lxc_sync_wait_parent(struct lxc_handler *, int);
__hidden extern int lxc_sync_barrier_parent(struct lxc_handler *, int);
__hidden extern int lxc_sync_barrier_child(struct lxc_handler *, int);
__hidden extern int sync_wait(int fd, int sequence);
__hidden extern int sync_wake(int fd, int sequence);

#endif /* __LXC_SYNC_H */

/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_SYNC_H
#define __LXC_SYNC_H

#include "compiler.h"

struct lxc_handler;

enum {
	LXC_SYNC_STARTUP	= 0,
	LXC_SYNC_CONFIGURE	= 1,
	LXC_SYNC_POST_CONFIGURE	= 2,
	LXC_SYNC_CGROUP		= 3,
	LXC_SYNC_CGROUP_UNSHARE	= 4,
	LXC_SYNC_CGROUP_LIMITS	= 5,
	LXC_SYNC_READY_START	= 6,
	LXC_SYNC_RESTART	= 7,
	LXC_SYNC_POST_RESTART	= 8,
	LXC_SYNC_ERROR		= -1 /* Used to report errors from another process */
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

#endif /* __LXC_SYNC_H */

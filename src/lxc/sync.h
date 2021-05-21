/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_SYNC_H
#define __LXC_SYNC_H

#include <stdbool.h>

#include "compiler.h"

struct lxc_handler;

enum /* generic */ {
	SYNC_ERROR			= -1 /* Used to report errors from another process */
};

enum /* start */ {
	START_SYNC_STARTUP		=  0,
	START_SYNC_CONFIGURE		=  1,
	START_SYNC_POST_CONFIGURE	=  2,
	START_SYNC_IDMAPPED_MOUNTS	=  3,
	START_SYNC_CGROUP_LIMITS	=  4,
	START_SYNC_FDS			=  5,
	START_SYNC_READY_START		=  6,
	START_SYNC_RESTART		=  7,
	START_SYNC_POST_RESTART		=  8,
};

enum /* attach */ {
	ATTACH_SYNC_CGROUP	= 0,
};

__hidden extern bool lxc_sync_init(struct lxc_handler *handler);
__hidden extern void lxc_sync_fini(struct lxc_handler *);
__hidden extern void lxc_sync_fini_parent(struct lxc_handler *);
__hidden extern void lxc_sync_fini_child(struct lxc_handler *);
__hidden extern bool lxc_sync_wake_child(struct lxc_handler *, int);
__hidden extern bool lxc_sync_wait_child(struct lxc_handler *, int);
__hidden extern bool lxc_sync_wake_parent(struct lxc_handler *, int);
__hidden extern bool lxc_sync_wait_parent(struct lxc_handler *, int);
__hidden extern bool lxc_sync_barrier_parent(struct lxc_handler *, int);
__hidden extern bool lxc_sync_barrier_child(struct lxc_handler *, int);
__hidden extern bool sync_wait(int fd, int sequence);
__hidden extern bool sync_wake(int fd, int sequence);

#endif /* __LXC_SYNC_H */

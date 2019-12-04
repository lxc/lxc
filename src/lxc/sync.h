/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_SYNC_H
#define __LXC_SYNC_H

struct lxc_handler;

enum {
	LXC_SYNC_STARTUP,
	LXC_SYNC_CONFIGURE,
	LXC_SYNC_POST_CONFIGURE,
	LXC_SYNC_CGROUP,
	LXC_SYNC_CGROUP_UNSHARE,
	LXC_SYNC_CGROUP_LIMITS,
	LXC_SYNC_READY_START,
	LXC_SYNC_RESTART,
	LXC_SYNC_POST_RESTART,
	LXC_SYNC_ERROR = -1 /* Used to report errors from another process */
};

int lxc_sync_init(struct lxc_handler *handler);
void lxc_sync_fini(struct lxc_handler *);
void lxc_sync_fini_parent(struct lxc_handler *);
void lxc_sync_fini_child(struct lxc_handler *);
int lxc_sync_wake_child(struct lxc_handler *, int);
int lxc_sync_wait_child(struct lxc_handler *, int);
int lxc_sync_wake_parent(struct lxc_handler *, int);
int lxc_sync_wait_parent(struct lxc_handler *, int);
int lxc_sync_barrier_parent(struct lxc_handler *, int);
int lxc_sync_barrier_child(struct lxc_handler *, int);

#endif

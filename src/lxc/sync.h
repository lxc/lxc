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
#ifndef __lxc_sync_h
#define __lxc_sync_h

struct lxc_handler;

enum {
	LXC_SYNC_CONFIGURE,
	LXC_SYNC_POST_CONFIGURE,
	LXC_SYNC_RESTART,
	LXC_SYNC_POST_RESTART,
};

int lxc_sync_init(struct lxc_handler *handler);
void lxc_sync_fini(struct lxc_handler *);
void lxc_sync_fini_parent(struct lxc_handler *);
void lxc_sync_fini_child(struct lxc_handler *);
int lxc_sync_wake_child(struct lxc_handler *, int);
int lxc_sync_wait_child(struct lxc_handler *, int);
int lxc_sync_wake_parent(struct lxc_handler *, int);
int lxc_sync_barrier_parent(struct lxc_handler *, int);
int lxc_sync_barrier_child(struct lxc_handler *, int);

#endif

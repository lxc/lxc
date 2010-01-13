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

#include <list.h>

struct lxc_epoll_descr {
	int epfd;
	struct lxc_list handlers;
};

typedef int (*lxc_mainloop_callback_t)(int fd, void *data, 
				       struct lxc_epoll_descr *descr);

extern int lxc_mainloop(struct lxc_epoll_descr *descr);

extern int lxc_mainloop_add_handler(struct lxc_epoll_descr *descr, int fd,
				    lxc_mainloop_callback_t callback, 
				    void *data);

extern int lxc_mainloop_del_handler(struct lxc_epoll_descr *descr, int fd);

extern int lxc_mainloop_open(struct lxc_epoll_descr *descr);

extern int lxc_mainloop_close(struct lxc_epoll_descr *descr);

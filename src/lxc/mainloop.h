/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_MAINLOOP_H
#define __LXC_MAINLOOP_H

#include <stdint.h>

#include "compiler.h"
#include "list.h"
#include "memory_utils.h"

#define LXC_MAINLOOP_ERROR -1
#define LXC_MAINLOOP_CONTINUE 0
#define LXC_MAINLOOP_CLOSE 1

struct lxc_epoll_descr {
	int epfd;
	struct lxc_list handlers;
};

typedef int (*lxc_mainloop_callback_t)(int fd, uint32_t event, void *data,
				       struct lxc_epoll_descr *descr);

__hidden extern int lxc_mainloop(struct lxc_epoll_descr *descr, int timeout_ms);

__hidden extern int lxc_mainloop_add_handler_events(struct lxc_epoll_descr *descr, int fd, int events,
						    lxc_mainloop_callback_t callback, void *data);
__hidden extern int lxc_mainloop_add_handler(struct lxc_epoll_descr *descr, int fd,
					     lxc_mainloop_callback_t callback, void *data);

__hidden extern int lxc_mainloop_del_handler(struct lxc_epoll_descr *descr, int fd);

__hidden extern int lxc_mainloop_open(struct lxc_epoll_descr *descr);

__hidden extern void lxc_mainloop_close(struct lxc_epoll_descr *descr);

define_cleanup_function(struct lxc_epoll_descr *, lxc_mainloop_close);

#endif

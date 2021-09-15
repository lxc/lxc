/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_MAINLOOP_H
#define __LXC_MAINLOOP_H

#include "config.h"

#include <stdint.h>

#include "compiler.h"
#include "hlist.h"
#include "memory_utils.h"

#ifdef HAVE_LIBURING
#include <liburing.h>
#endif

#define LXC_MAINLOOP_ERROR -1
#define LXC_MAINLOOP_CONTINUE 0
#define LXC_MAINLOOP_CLOSE 1
#define LXC_MAINLOOP_DISARM 2

typedef enum {
	LXC_MAINLOOP_EPOLL	= 1,
	LXC_MAINLOOP_IO_URING	= 2,
} async_descr_t;

struct lxc_async_descr {
	async_descr_t type;
	union {
		int epfd;
#ifdef HAVE_LIBURING
		struct io_uring *ring;
#endif
	};
	struct list_head handlers;
};

static inline int default_cleanup_handler(int fd, void *data)
{
	return 0;
}

typedef int (*lxc_mainloop_callback_t)(int fd, uint32_t event, void *data,
				       struct lxc_async_descr *descr);

typedef int (*lxc_mainloop_cleanup_t)(int fd, void *data);

__hidden extern int lxc_mainloop(struct lxc_async_descr *descr, int timeout_ms);

__hidden extern int lxc_mainloop_add_handler_events(struct lxc_async_descr *descr, int fd, int events,
						    lxc_mainloop_callback_t callback,
						    lxc_mainloop_cleanup_t cleanup,
						    void *data, const char *name);
__hidden extern int lxc_mainloop_add_handler(struct lxc_async_descr *descr, int fd,
					     lxc_mainloop_callback_t callback,
					     lxc_mainloop_cleanup_t cleanup,
					     void *data, const char *name);
__hidden extern int lxc_mainloop_add_oneshot_handler(struct lxc_async_descr *descr, int fd,
						     lxc_mainloop_callback_t callback,
						     lxc_mainloop_cleanup_t cleanup,
						     void *data, const char *name);

__hidden extern int lxc_mainloop_del_handler(struct lxc_async_descr *descr, int fd);

__hidden extern int lxc_mainloop_open(struct lxc_async_descr *descr);

__hidden extern void lxc_mainloop_close(struct lxc_async_descr *descr);

define_cleanup_function(struct lxc_async_descr *, lxc_mainloop_close);

#endif

/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

#include "config.h"
#include "mainloop.h"

struct mainloop_handler {
	lxc_mainloop_callback_t callback;
	int fd;
	void *data;
};

#define MAX_EVENTS 10

int lxc_mainloop(struct lxc_epoll_descr *descr, int timeout_ms)
{
	int i, nfds, ret;
	struct mainloop_handler *handler;
	struct epoll_event events[MAX_EVENTS];

	for (;;) {
		nfds = epoll_wait(descr->epfd, events, MAX_EVENTS, timeout_ms);
		if (nfds < 0) {
			if (errno == EINTR)
				continue;

			return -1;
		}

		for (i = 0; i < nfds; i++) {
			handler = events[i].data.ptr;

			/* If the handler returns a positive value, exit the
			 * mainloop.
			 */
			ret = handler->callback(handler->fd, events[i].events,
						handler->data, descr);
			if (ret == LXC_MAINLOOP_ERROR)
				return -1;
			if (ret == LXC_MAINLOOP_CLOSE)
				return 0;
		}

		if (nfds == 0)
			return 0;

		if (lxc_list_empty(&descr->handlers))
			return 0;
	}
}

int lxc_mainloop_add_handler(struct lxc_epoll_descr *descr, int fd,
			     lxc_mainloop_callback_t callback, void *data)
{
	struct epoll_event ev;
	struct mainloop_handler *handler;
	struct lxc_list *item;
	if (fd < 0)
		return -1;

	handler = malloc(sizeof(*handler));
	if (!handler)
		return -1;

	handler->callback = callback;
	handler->fd = fd;
	handler->data = data;

	ev.events = EPOLLIN;
	ev.data.ptr = handler;

	if (epoll_ctl(descr->epfd, EPOLL_CTL_ADD, fd, &ev) < 0)
		goto out_free_handler;

	item = malloc(sizeof(*item));
	if (!item)
		goto out_free_handler;

	item->elem = handler;
	lxc_list_add(&descr->handlers, item);
	return 0;

out_free_handler:
	free(handler);
	return -1;
}

int lxc_mainloop_del_handler(struct lxc_epoll_descr *descr, int fd)
{
	struct mainloop_handler *handler;
	struct lxc_list *iterator;

	lxc_list_for_each(iterator, &descr->handlers) {
		handler = iterator->elem;

		if (handler->fd == fd) {
			/* found */
			if (epoll_ctl(descr->epfd, EPOLL_CTL_DEL, fd, NULL))
				return -1;

			lxc_list_del(iterator);
			free(iterator->elem);
			free(iterator);
			return 0;
		}
	}

	return -1;
}

int lxc_mainloop_open(struct lxc_epoll_descr *descr)
{
	/* hint value passed to epoll create */
	descr->epfd = epoll_create1(EPOLL_CLOEXEC);
	if (descr->epfd < 0)
		return -1;

	lxc_list_init(&descr->handlers);
	return 0;
}

int lxc_mainloop_close(struct lxc_epoll_descr *descr)
{
	struct lxc_list *iterator, *next;

	iterator = descr->handlers.next;
	while (iterator != &descr->handlers) {
		next = iterator->next;

		lxc_list_del(iterator);
		free(iterator->elem);
		free(iterator);
		iterator = next;
	}

	if (descr->epfd >= 0)
		return close(descr->epfd);

	return 0;
}

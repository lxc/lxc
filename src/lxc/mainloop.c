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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/epoll.h>

#include "mainloop.h"

struct mainloop_handler {
	lxc_mainloop_callback_t callback;
	int fd;
	void *data;
};

#define MAX_EVENTS 10

int lxc_mainloop(struct lxc_epoll_descr *descr)
{
	int i, nfds;
	struct mainloop_handler *handler;
	struct epoll_event events[MAX_EVENTS];

	for (;;) {

		nfds = epoll_wait(descr->epfd, events, MAX_EVENTS, -1);
		if (nfds < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}

		for (i = 0; i < nfds; i++) {
			handler =
				(struct mainloop_handler *) events[i].data.ptr;

			/* If the handler returns a positive value, exit
			   the mainloop */
			if (handler->callback(handler->fd, handler->data, 
					      descr) > 0)
				return 0;
		}

		if (!descr->nfds)
			return 0;
	}
}

int lxc_mainloop_add_handler(struct lxc_epoll_descr *descr, int fd, 
			     lxc_mainloop_callback_t callback, void *data)
{
	struct epoll_event *ev;
	struct mainloop_handler *handler;

	handler = malloc(sizeof(*handler));
	if (!handler)
		return -1;

	handler->callback = callback;
	handler->fd = fd;
	handler->data = data;

	ev = malloc(sizeof(*descr->ev) * (descr->nfds + 1));
	if (!ev)
		goto out_free;

	memcpy(ev, descr->ev, sizeof(*descr->ev) * (descr->nfds));

	ev[descr->nfds].events = EPOLLIN;
	ev[descr->nfds].data.ptr = handler;

	if (epoll_ctl(descr->epfd, EPOLL_CTL_ADD, fd, &ev[descr->nfds]) < 0) {
		free(ev);
		goto out_free;
	}

	free(descr->ev);
	descr->ev = ev;
	descr->nfds++;
	return 0;

out_free:
	free(handler);
	return -1;
}

int lxc_mainloop_del_handler(struct lxc_epoll_descr *descr, int fd)
{
	struct epoll_event *ev;
	struct mainloop_handler *handler;
	int i, j, idx = 0;

	for (i = 0; i < descr->nfds; i++) {
		
		handler = descr->ev[i].data.ptr;

		if (handler->fd != fd)
			continue;

		if (epoll_ctl(descr->epfd, EPOLL_CTL_DEL, fd, NULL))
			return -1;

		ev = malloc(sizeof(*ev) * (descr->nfds - 1));
		if (!ev)
			return -1;

		for (j = 0; j < descr->nfds; j++) {
			if (i == j)
				continue;
			ev[idx] = descr->ev[j];
			idx++;
		}

		free(descr->ev[i].data.ptr);
		free(descr->ev);
		descr->ev = ev;
		descr->nfds--;
		
		return 0;
	}

	return -1;
}

int lxc_mainloop_open(struct lxc_epoll_descr *descr)
{
	descr->nfds = 0;
	descr->ev = NULL;

	/* hint value passed to epoll create */
	descr->epfd = epoll_create(2);
	if (descr->epfd < 0)
		return -1;

	return 0;
}

int lxc_mainloop_close(struct lxc_epoll_descr *descr)
{
	int i;

	for (i = 0; i < descr->nfds; i++)
		free(descr->ev[i].data.ptr);
	free(descr->ev);

	return close(descr->epfd);
}


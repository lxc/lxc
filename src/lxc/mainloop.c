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

int lxc_mainloop(struct lxc_epoll_descr *descr)
{
	int i, nfds, triggered;
	struct mainloop_handler *handler;

	for (;;) {

		triggered = 0;

		nfds = epoll_wait(descr->epfd, descr->ev, descr->nfds, -1);
		if (nfds < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}

		for (i = 0; i < descr->nfds; i++) {

			if (!(descr->ev[i].events & EPOLLIN) &&
			    !(descr->ev[i].events & EPOLLHUP))
				continue;

			triggered++;
			handler =
			  (struct mainloop_handler *) descr->ev[i].data.ptr;

			/* If the handler returns a positive value, exit
			   the mainloop */
			if (handler->callback(handler->fd, handler->data, 
					      descr) > 0)
				return 0;

			if (triggered == nfds)
				break;
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
	int ret = -1;

	handler = malloc(sizeof(*handler));
	if (!handler)
		return -1;

	handler->callback = callback;
	handler->fd = fd;
	handler->data = data;

	ev = malloc(sizeof(*descr->ev) * (descr->nfds + 1));
	if (!ev)
		goto out_free;

	if (descr->nfds) {
		memcpy(ev, descr->ev, sizeof(*descr->ev) * (descr->nfds));
		free(descr->ev);
	}

	descr->ev = ev;
	descr->ev[descr->nfds].events = EPOLLIN;
	descr->ev[descr->nfds].data.ptr = handler;

	ret = epoll_ctl(descr->epfd, EPOLL_CTL_ADD, fd, 
			&descr->ev[descr->nfds]);

	descr->nfds++;
out:
	return ret;

out_free:
	free(handler);
	goto out;
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
			ev[idx] = descr->ev[idx];
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


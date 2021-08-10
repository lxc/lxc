/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <sys/epoll.h>
#include <unistd.h>

#include "config.h"
#include "log.h"
#include "macro.h"
#include "mainloop.h"

lxc_log_define(mainloop, lxc);

#define CANCEL_RAISED	(1 << 0)
#define CANCEL_RECEIVED (1 << 1)
#define CANCEL_SUCCESS (1 << 2)

struct mainloop_handler {
	struct lxc_list *list;
	int fd;
	void *data;
	lxc_mainloop_callback_t callback;
	lxc_mainloop_cleanup_t cleanup;
	const char *handler_name;
	unsigned int flags;
};

#define MAX_EVENTS 10

static int __io_uring_disarm(struct lxc_async_descr *descr,
			     struct mainloop_handler *handler);

static void delete_handler(struct lxc_async_descr *descr,
			   struct mainloop_handler *handler, bool oneshot)
{
	int ret = 0;
	struct lxc_list *list;

	if (descr->type == LXC_MAINLOOP_IO_URING) {
		/*
		 * For a oneshot handler we don't have to do anything. If we
		 * end up here we know that an event for this handler has been
		 * generated before and since this is a oneshot handler it
		 * means that it has been deactivated. So the only thing we
		 * need to do is to call the registered cleanup handler and
		 * remove the handler from the list.
		 */
		if (!oneshot)
			ret = __io_uring_disarm(descr, handler);
	} else {
		ret = epoll_ctl(descr->epfd, EPOLL_CTL_DEL, handler->fd, NULL);
	}
	if (ret < 0)
		SYSWARN("Failed to delete \"%d\" for \"%s\"", handler->fd, handler->handler_name);

	if (handler->cleanup) {
		ret = handler->cleanup(handler->fd, handler->data);
		if (ret < 0)
			SYSWARN("Failed to call cleanup \"%s\" handler", handler->handler_name);
	}

	list = move_ptr(handler->list);
	lxc_list_del(list);
	free(list->elem);
	free(list);
}

#ifndef HAVE_LIBURING
static inline int __lxc_mainloop_io_uring(struct lxc_async_descr *descr,
					  int timeout_ms)
{
	return ret_errno(ENOSYS);
}

static int __io_uring_arm(struct lxc_async_descr *descr,
			  struct mainloop_handler *handler, bool oneshot)
{
	return ret_errno(ENOSYS);
}

static int __io_uring_disarm(struct lxc_async_descr *descr,
			     struct mainloop_handler *handler)
{
	return ret_errno(ENOSYS);
}

static inline int __io_uring_open(struct lxc_async_descr *descr)
{
	return ret_errno(ENOSYS);
}

#else

static inline int __io_uring_open(struct lxc_async_descr *descr)
{
	int ret;
	*descr = (struct lxc_async_descr){
		.epfd = -EBADF,
	};

	descr->ring = mmap(NULL, sizeof(struct io_uring), PROT_READ | PROT_WRITE,
			   MAP_SHARED | MAP_POPULATE | MAP_ANONYMOUS, -1, 0);
	if (descr->ring == MAP_FAILED)
		return syserror("Failed to mmap io_uring memory");

	ret = io_uring_queue_init(512, descr->ring, IORING_SETUP_SQPOLL);
	if (ret) {
		SYSERROR("Failed to initialize io_uring instance");
		goto on_error;
	}

	ret = io_uring_ring_dontfork(descr->ring);
	if (ret) {
		SYSERROR("Failed to prevent inheritance of io_uring mmaped region");
		goto on_error;
	}

	descr->type = LXC_MAINLOOP_IO_URING;
	TRACE("Created io-uring instance");
	return 0;

on_error:
	ret = munmap(descr->ring, sizeof(struct io_uring));
	if (ret < 0)
		SYSWARN("Failed to unmap io_uring mmaped memory");

	return ret_errno(ENOSYS);
}

static int __io_uring_arm(struct lxc_async_descr *descr,
			  struct mainloop_handler *handler, bool oneshot)
{
	int ret;
	struct io_uring_sqe *sqe;

	sqe = io_uring_get_sqe(descr->ring);
	if (!sqe)
		return syserror_set(ENOENT, "Failed to get submission queue entry");

	io_uring_prep_poll_add(sqe, handler->fd, EPOLLIN);

	/*
	 * Raise IORING_POLL_ADD_MULTI to set up a multishot poll. The same sqe
	 * will now produce multiple cqes. A cqe produced from a multishot sqe
	 * will raise IORING_CQE_F_MORE in cqe->flags.
	 * Some devices can't be used with IORING_POLL_ADD_MULTI. This can only
	 * be detected at completion time. The IORING_CQE_F_MORE flag will not
	 * raised in cqe->flags. This includes terminal devices. So
	 * unfortunately we can't use multishot for them although we really
	 * would like to. But instead we will need to resubmit them. The
	 * io_uring based mainloop will deal cases whwere multishot doesn't
	 * work and resubmit the request. The handler just needs to inform the
	 * mainloop that it wants to keep the handler.
	 */
	if (!oneshot)
		sqe->len |= IORING_POLL_ADD_MULTI;

	io_uring_sqe_set_data(sqe, handler);
	ret = io_uring_submit(descr->ring);
	if (ret < 0) {
		if (!oneshot && ret == -EINVAL) {
			/* The kernel might not yet support multishot. */
			sqe->len &= ~IORING_POLL_ADD_MULTI;
			ret = io_uring_submit(descr->ring);
		}
	}
	if (ret < 0)
		return syserror_ret(ret, "Failed to add \"%s\" handler", handler->handler_name);

	TRACE("Added \"%s\" handler", handler->handler_name);
	return 0;
}

static int __io_uring_disarm(struct lxc_async_descr *descr,
			     struct mainloop_handler *handler)
{
	int ret;
	struct io_uring_sqe *sqe;

	sqe = io_uring_get_sqe(descr->ring);
	if (!sqe)
		return syserror_set(ENOENT,
				    "Failed to get submission queue entry");

	io_uring_prep_poll_remove(sqe, handler);
	handler->flags |= CANCEL_RAISED;
	io_uring_sqe_set_data(sqe, handler);
	ret = io_uring_submit(descr->ring);
	if (ret < 0) {
		handler->flags &= ~CANCEL_RAISED;
		return syserror_ret(ret, "Failed to remove \"%s\" handler",
				    handler->handler_name);
	}

	TRACE("Removed handler \"%s\"", handler->handler_name);
	return ret;
}

static void msec_to_ts(struct __kernel_timespec *ts, unsigned int timeout_ms)
{
	ts->tv_sec = timeout_ms / 1000;
	ts->tv_nsec = (timeout_ms % 1000) * 1000000;
}

static int __lxc_mainloop_io_uring(struct lxc_async_descr *descr, int timeout_ms)
{
	struct __kernel_timespec ts;

	if (timeout_ms >= 0)
		msec_to_ts(&ts, timeout_ms);

	for (;;) {
		int ret;
		__s32 mask = 0;
		bool oneshot = false;
		struct io_uring_cqe *cqe = NULL;
		struct mainloop_handler *handler = NULL;

		if (timeout_ms >= 0)
			ret = io_uring_wait_cqe_timeout(descr->ring, &cqe, &ts);
		else
			ret = io_uring_wait_cqe(descr->ring, &cqe);
		if (ret < 0) {
			if (ret == -EINTR)
				continue;

			if (ret == -ETIME)
				return 0;

			return syserror_ret(ret, "Failed to wait for completion");
		}

		ret	= LXC_MAINLOOP_CONTINUE;
		oneshot = !(cqe->flags & IORING_CQE_F_MORE);
		mask	= cqe->res;
		handler = io_uring_cqe_get_data(cqe);
		io_uring_cqe_seen(descr->ring, cqe);

		switch (mask) {
		case -ECANCELED:
			handler->flags |= CANCEL_RECEIVED;
			TRACE("Canceled \"%s\" handler", handler->handler_name);
			goto out;
		case -ENOENT:
			handler->flags = CANCEL_SUCCESS | CANCEL_RECEIVED;
			TRACE("No sqe for \"%s\" handler", handler->handler_name);
			goto out;
		case -EALREADY:
			TRACE("Repeat sqe remove request for \"%s\" handler", handler->handler_name);
			goto out;
		case 0:
			handler->flags |= CANCEL_SUCCESS;
			TRACE("Removed \"%s\" handler", handler->handler_name);
			goto out;
		default:
			/*
			 * We need to always remove the handler for a
			 * successful oneshot request.
			 */
			if (oneshot)
				handler->flags = CANCEL_SUCCESS | CANCEL_RECEIVED;
		}

		ret = handler->callback(handler->fd, mask, handler->data, descr);
		switch (ret) {
		case LXC_MAINLOOP_CONTINUE:
			/* We're operating in oneshot mode so we need to rearm. */
			if (oneshot && __io_uring_arm(descr, handler, true))
				return -1;
			break;
		case LXC_MAINLOOP_DISARM:
			if (has_exact_flags(handler->flags, (CANCEL_SUCCESS | CANCEL_RECEIVED)))
				delete_handler(descr, handler, oneshot);
			break;
		case LXC_MAINLOOP_CLOSE:
			return log_trace(0, "Closing from \"%s\"", handler->handler_name);
		case LXC_MAINLOOP_ERROR:
			return syserror_ret(-1, "Closing with error from \"%s\"", handler->handler_name);
		}

	out:
		if (lxc_list_empty(&descr->handlers))
			return error_ret(0, "Closing because there are no more handlers");
	}
}
#endif

static int __lxc_mainloop_epoll(struct lxc_async_descr *descr, int timeout_ms)
{
	int i, nfds, ret;
	struct mainloop_handler *handler;
	struct epoll_event events[MAX_EVENTS];

	for (;;) {
		nfds = epoll_wait(descr->epfd, events, MAX_EVENTS, timeout_ms);
		if (nfds < 0) {
			if (errno == EINTR)
				continue;

			return -errno;
		}

		for (i = 0; i < nfds; i++) {
			handler = events[i].data.ptr;

			/* If the handler returns a positive value, exit the
			 * mainloop.
			 */
			ret = handler->callback(handler->fd, events[i].events,
						handler->data, descr);
			switch (ret) {
			case LXC_MAINLOOP_DISARM:
				delete_handler(descr, handler, false);
				__fallthrough;
			case LXC_MAINLOOP_CONTINUE:
				break;
			case LXC_MAINLOOP_CLOSE:
				return 0;
			case LXC_MAINLOOP_ERROR:
				return -1;
			}
		}

		if (nfds == 0)
			return 0;

		if (lxc_list_empty(&descr->handlers))
			return 0;
	}
}

int lxc_mainloop(struct lxc_async_descr *descr, int timeout_ms)
{
	if (descr->type == LXC_MAINLOOP_IO_URING)
		return __lxc_mainloop_io_uring(descr, timeout_ms);

	return __lxc_mainloop_epoll(descr, timeout_ms);
}

static int __lxc_mainloop_add_handler_events(struct lxc_async_descr *descr,
					     int fd, int events,
					     lxc_mainloop_callback_t callback,
					     lxc_mainloop_cleanup_t cleanup,
					     void *data, bool oneshot,
					     const char *handler_name)
{
	__do_free struct mainloop_handler *handler = NULL;
	__do_free struct lxc_list *list = NULL;
	int ret;
	struct epoll_event ev;

	if (fd < 0)
		return ret_errno(EBADF);

	if (!callback || !cleanup || !events || !handler_name)
		return ret_errno(EINVAL);

	handler = zalloc(sizeof(*handler));
	if (!handler)
		return ret_errno(ENOMEM);

	handler->callback	= callback;
	handler->cleanup	= cleanup;
	handler->fd		= fd;
	handler->data		= data;
	handler->handler_name	= handler_name;

	if (descr->type == LXC_MAINLOOP_IO_URING) {
		ret = __io_uring_arm(descr, handler, oneshot);
	} else {
		ev.events	= events;
		ev.data.ptr	= handler;
		ret = epoll_ctl(descr->epfd, EPOLL_CTL_ADD, fd, &ev);
	}
	if (ret < 0)
		return -errno;

	list = lxc_list_new();
	if (!list)
		return ret_errno(ENOMEM);

	handler->list = list;
	lxc_list_add_elem(list, move_ptr(handler));;
	lxc_list_add_tail(&descr->handlers, move_ptr(list));
	return 0;
}

int lxc_mainloop_add_handler_events(struct lxc_async_descr *descr, int fd,
				    int events,
				    lxc_mainloop_callback_t callback,
				    lxc_mainloop_cleanup_t cleanup,
				    void *data, const char *handler_name)
{
	return __lxc_mainloop_add_handler_events(descr, fd, events,
						 callback, cleanup,
						 data, false, handler_name);
}

int lxc_mainloop_add_handler(struct lxc_async_descr *descr, int fd,
			     lxc_mainloop_callback_t callback,
			     lxc_mainloop_cleanup_t cleanup,
			     void *data, const char *handler_name)
{
	return __lxc_mainloop_add_handler_events(descr, fd, EPOLLIN,
						 callback, cleanup,
						 data, false, handler_name);
}

int lxc_mainloop_add_oneshot_handler(struct lxc_async_descr *descr, int fd,
				     lxc_mainloop_callback_t callback,
				     lxc_mainloop_cleanup_t cleanup,
				     void *data, const char *handler_name)
{
	return __lxc_mainloop_add_handler_events(descr, fd, EPOLLIN,
						 callback, cleanup,
						 data, true, handler_name);
}

int lxc_mainloop_del_handler(struct lxc_async_descr *descr, int fd)
{
	int ret;
	struct lxc_list *iterator = NULL;

	lxc_list_for_each(iterator, &descr->handlers) {
		struct mainloop_handler *handler = iterator->elem;

		if (handler->fd != fd)
			continue;

		if (descr->type == LXC_MAINLOOP_IO_URING)
			ret = __io_uring_disarm(descr, handler);
		else
			ret = epoll_ctl(descr->epfd, EPOLL_CTL_DEL, fd, NULL);
		if (ret < 0)
			return syserror("Failed to disarm \"%s\"", handler->handler_name);

		/*
		 * For io_uring the deletion happens at completion time. Either
		 * we get ENOENT if the request was oneshot and it had already
		 * triggered or we get ECANCELED for the original sqe and 0 for
		 * the cancellation request.
		 */
		if (descr->type == LXC_MAINLOOP_EPOLL) {
			lxc_list_del(iterator);
			free(iterator->elem);
			free(iterator);
		}

		return 0;
	}

	return ret_errno(EINVAL);
}

static inline int __epoll_open(struct lxc_async_descr *descr)
{
	*descr = (struct lxc_async_descr){
		.epfd = -EBADF,
	};

	descr->epfd = epoll_create1(EPOLL_CLOEXEC);
	if (descr->epfd < 0)
		return syserror("Failed to create epoll instance");

	descr->type = LXC_MAINLOOP_EPOLL;
	TRACE("Created epoll instance");
	return 0;
}

int lxc_mainloop_open(struct lxc_async_descr *descr)
{
	int ret;

	ret = __io_uring_open(descr);
	if (ret == -ENOSYS)
		ret = __epoll_open(descr);
	if (ret < 0)
		return syserror("Failed to create mainloop instance");

	lxc_list_init(&descr->handlers);
	return 0;
}

void lxc_mainloop_close(struct lxc_async_descr *descr)
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

	if (descr->type == LXC_MAINLOOP_IO_URING) {
#ifdef HAVE_LIBURING
		io_uring_queue_exit(descr->ring);
		munmap(descr->ring, sizeof(struct io_uring));
#else
		ERROR("Unsupported io_uring mainloop");
#endif
	} else {
		close_prot_errno_disarm(descr->epfd);
	}
}

/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2008
 *
 * Authors:
 * Daniel Lezcano <daniel.lezcano at free.fr>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include "sync.h"
#include "log.h"
#include "start.h"

lxc_log_define(lxc_sync, lxc);

static int __sync_wait(int fd, int sequence)
{
	int sync = -1;
	ssize_t ret;

	ret = read(fd, &sync, sizeof(sync));
	if (ret < 0) {
		ERROR("sync wait failure : %m");
		return -1;
	}

	if (!ret)
		return 0;

	if ((size_t)ret != sizeof(sync)) {
		ERROR("unexpected sync size: %zu expected %zu", (size_t)ret, sizeof(sync));
		return -1;
	}

	if (sync == LXC_SYNC_ERROR) {
		ERROR("An error occurred in another process "
		      "(expected sequence number %d)", sequence);
		return -1;
	}

	if (sync != sequence) {
		ERROR("invalid sequence number %d. expected %d",
		      sync, sequence);
		return -1;
	}
	return 0;
}

static int __sync_wake(int fd, int sequence)
{
	int sync = sequence;

	if (write(fd, &sync, sizeof(sync)) < 0) {
		ERROR("sync wake failure : %m");
		return -1;
	}
	return 0;
}

static int __sync_barrier(int fd, int sequence)
{
	if (__sync_wake(fd, sequence))
		return -1;
	return __sync_wait(fd, sequence+1);
}

int lxc_sync_barrier_parent(struct lxc_handler *handler, int sequence)
{
	return __sync_barrier(handler->sv[0], sequence);
}

int lxc_sync_barrier_child(struct lxc_handler *handler, int sequence)
{
	return __sync_barrier(handler->sv[1], sequence);
}

int lxc_sync_wake_parent(struct lxc_handler *handler, int sequence)
{
	return __sync_wake(handler->sv[0], sequence);
}

int lxc_sync_wait_parent(struct lxc_handler *handler, int sequence)
{
	return __sync_wait(handler->sv[0], sequence);
}

int lxc_sync_wait_child(struct lxc_handler *handler, int sequence)
{
	return __sync_wait(handler->sv[1], sequence);
}

int lxc_sync_wake_child(struct lxc_handler *handler, int sequence)
{
	return __sync_wake(handler->sv[1], sequence);
}

int lxc_sync_init(struct lxc_handler *handler)
{
	int ret;

	ret = socketpair(AF_LOCAL, SOCK_STREAM, 0, handler->sv);
	if (ret) {
		SYSERROR("failed to create synchronization socketpair");
		return -1;
	}

	/* Be sure we don't inherit this after the exec */
	fcntl(handler->sv[0], F_SETFD, FD_CLOEXEC);

	return 0;
}

void lxc_sync_fini_child(struct lxc_handler *handler)
{
	if (handler->sv[0] != -1) {
		close(handler->sv[0]);
		handler->sv[0] = -1;
	}
}

void lxc_sync_fini_parent(struct lxc_handler *handler)
{
	if (handler->sv[1] != -1) {
		close(handler->sv[1]);
		handler->sv[1] = -1;
	}
}

void lxc_sync_fini(struct lxc_handler *handler)
{
	lxc_sync_fini_child(handler);
	lxc_sync_fini_parent(handler);
}

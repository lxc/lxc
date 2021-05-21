/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"
#include "log.h"
#include "start.h"
#include "sync.h"
#include "utils.h"

lxc_log_define(sync, lxc);

bool sync_wait(int fd, int sequence)
{
	int sync = -1;
	ssize_t ret;

	ret = lxc_read_nointr(fd, &sync, sizeof(sync));
	if (ret < 0)
		return log_error_errno(false, errno, "Sync wait failure");

	if (!ret)
		return true;

	if ((size_t)ret != sizeof(sync))
		return log_error(false, "Unexpected sync size: %zu expected %zu", (size_t)ret, sizeof(sync));

	if (sync == SYNC_ERROR)
		return log_error(false, "An error occurred in another process (expected sequence number %d)", sequence);

	if (sync != sequence)
		return log_error(false, "Invalid sequence number %d. Expected sequence number %d", sync, sequence);

	return true;
}

bool sync_wake(int fd, int sequence)
{
	int sync = sequence;

	if (lxc_write_nointr(fd, &sync, sizeof(sync)) < 0)
		return log_error_errno(false, errno, "Sync wake failure");

	return true;
}

static bool __sync_barrier(int fd, int sequence)
{
	if (!sync_wake(fd, sequence))
		return false;

	return sync_wait(fd, sequence + 1);
}

static inline const char *start_sync_to_string(int state)
{
	switch (state) {
	case START_SYNC_STARTUP:
		return "startup";
	case START_SYNC_CONFIGURE:
		return "configure";
	case START_SYNC_POST_CONFIGURE:
		return "post-configure";
	case START_SYNC_CGROUP_LIMITS:
		return "cgroup-limits";
	case START_SYNC_IDMAPPED_MOUNTS:
		return "idmapped-mounts";
	case START_SYNC_FDS:
		return "fds";
	case START_SYNC_READY_START:
		return "ready-start";
	case START_SYNC_RESTART:
		return "restart";
	case START_SYNC_POST_RESTART:
		return "post-restart";
	case SYNC_ERROR:
		return "error";
	default:
		return "invalid sync state";
	}
}

bool lxc_sync_barrier_parent(struct lxc_handler *handler, int sequence)
{
	TRACE("Child waking parent with sequence %s and waiting for sequence %s",
	      start_sync_to_string(sequence), start_sync_to_string(sequence + 1));
	return __sync_barrier(handler->sync_sock[0], sequence);
}

bool lxc_sync_barrier_child(struct lxc_handler *handler, int sequence)
{
	TRACE("Parent waking child with sequence %s and waiting with sequence %s",
	      start_sync_to_string(sequence), start_sync_to_string(sequence + 1));
	return __sync_barrier(handler->sync_sock[1], sequence);
}

bool lxc_sync_wake_parent(struct lxc_handler *handler, int sequence)
{
	TRACE("Child waking parent with sequence %s", start_sync_to_string(sequence));
	return sync_wake(handler->sync_sock[0], sequence);
}

bool lxc_sync_wait_parent(struct lxc_handler *handler, int sequence)
{
	TRACE("Child waiting for parent with sequence %s", start_sync_to_string(sequence));
	return sync_wait(handler->sync_sock[0], sequence);
}

bool lxc_sync_wait_child(struct lxc_handler *handler, int sequence)
{
	TRACE("Parent waiting for child with sequence %s", start_sync_to_string(sequence));
	return sync_wait(handler->sync_sock[1], sequence);
}

bool lxc_sync_wake_child(struct lxc_handler *handler, int sequence)
{
	TRACE("Child waking parent with sequence %s", start_sync_to_string(sequence));
	return sync_wake(handler->sync_sock[1], sequence);
}

bool lxc_sync_init(struct lxc_handler *handler)
{
	int ret;

	ret = socketpair(AF_LOCAL, SOCK_STREAM, 0, handler->sync_sock);
	if (ret)
		return log_error_errno(false, errno, "failed to create synchronization socketpair");

	/* Be sure we don't inherit this after the exec */
	ret = fcntl(handler->sync_sock[0], F_SETFD, FD_CLOEXEC);
	if (ret < 0)
		return log_error_errno(false, errno, "Failed to make socket close-on-exec");

	TRACE("Initialized synchronization infrastructure");
	return true;
}

void lxc_sync_fini_child(struct lxc_handler *handler)
{
	close_prot_errno_disarm(handler->sync_sock[0]);
}

void lxc_sync_fini_parent(struct lxc_handler *handler)
{
	close_prot_errno_disarm(handler->sync_sock[1]);
}

void lxc_sync_fini(struct lxc_handler *handler)
{
	lxc_sync_fini_child(handler);
	lxc_sync_fini_parent(handler);
}

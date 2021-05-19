/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_AF_UNIX_H
#define __LXC_AF_UNIX_H

#include <stdio.h>
#include <sys/socket.h>
#include <stddef.h>
#include <sys/un.h>

#include "compiler.h"
#include "macro.h"
#include "memory_utils.h"

#define KERNEL_SCM_MAX_FD 253

/* Allow the caller to set expectations. */

/*
 * UNIX_FDS_ACCEPT_EXACT will only succeed if the exact amount of fds has been
 * received  (unless combined with UNIX_FDS_ACCEPT_NONE).
 */
#define UNIX_FDS_ACCEPT_EXACT ((__u32)(1 << 0)) /* default */

/*
 * UNIX_FDS_ACCEPT_LESS will also succeed if less than the requested number of
 * fd has been received. If the UNIX_FDS_ACCEPT_NONE flag is not raised than at
 * least one fd must be received.
 * */
#define UNIX_FDS_ACCEPT_LESS ((__u32)(1 << 1))

/*
 * UNIX_FDS_ACCEPT_MORE will also succeed if more than the requested number of
 * fds have been received. Any additional fds will be silently closed.  If the
 * UNIX_FDS_ACCEPT_NONE flag is not raised than at least one fd must be
 * received.
 */
#define UNIX_FDS_ACCEPT_MORE ((__u32)(1 << 2)) /* wipe any extra fds */

/*
 * UNIX_FDS_ACCEPT_NONE can be specified with any of the above flags and
 * indicates that the caller will accept no file descriptors to be received.
 */
#define UNIX_FDS_ACCEPT_NONE ((__u32)(1 << 3))

/* UNIX_FDS_ACCEPT_MASK is the value of all the above flags or-ed together. */
#define UNIX_FDS_ACCEPT_MASK (UNIX_FDS_ACCEPT_EXACT | UNIX_FDS_ACCEPT_LESS | UNIX_FDS_ACCEPT_MORE | UNIX_FDS_ACCEPT_NONE)

/* Allow the callee to communicate reality. */

/* UNIX_FDS_RECEIVED_EXACT indicates that the exact number of fds was received. */
#define UNIX_FDS_RECEIVED_EXACT ((__u32)(1 << 16))

/*
 * UNIX_FDS_RECEIVED_LESS indicates that less than the requested number of fd
 * has been received.
 */
#define UNIX_FDS_RECEIVED_LESS ((__u32)(1 << 17))

/*
 * UNIX_FDS_RECEIVED_MORE indicates that more than the requested number of fd
 * has been received.
 */
#define UNIX_FDS_RECEIVED_MORE ((__u32)(1 << 18))

/* UNIX_FDS_RECEIVED_NONE indicates that no fds have been received. */
#define UNIX_FDS_RECEIVED_NONE ((__u32)(1 << 19))

/**
 * Defines a generic struct to receive file descriptors from unix sockets.
 * @fd_count_max : Either the exact or maximum number of file descriptors the
 *                 caller is willing to accept. Must be smaller than
 *                 KERNEL_SCM_MAX_FDs; larger values will be rejected.
 *                 Filled in by the caller.
 * @fd_count_ret : The actually received number of file descriptors.
 *                 Filled in by the callee.
 * @flags        : Flags to negotiate expectations about the number of file
 *                 descriptors to receive.
 *                 Filled in by the caller and callee. The caller's flag space
 *                 is UNIX_FDS_ACCEPT_* other values will be rejected. The
 *                 caller may only set one of {EXACT, LESS, MORE}. In addition
 *                 they can raise the NONE flag. Any combination of {EXACT,
 *                 LESS, MORE} will be rejected.
 *                 The callee's flag space is UNIX_FDS_RECEIVED_*. Only ever
 *                 one of those values will be set.
 * @fd           : Array to store received file descriptors into. Filled by the
 *                 callee on success. If less file descriptors are received
 *                 than requested in @fd_count_max the callee will ensure that
 *                 all additional slots will be set to -EBADF. Nonetheless, the
 *                 caller should only ever use @fd_count_ret to iterate through
 *                 @fd after a successful receive.
 */
struct unix_fds {
	__u32 fd_count_max;
	__u32 fd_count_ret;
	__u32 flags;
	__s32 fd[KERNEL_SCM_MAX_FD];
} __attribute__((aligned(8)));

/* does not enforce \0-termination */
__hidden extern int lxc_abstract_unix_open(const char *path, int type, int flags);
__hidden extern void lxc_abstract_unix_close(int fd);
/* does not enforce \0-termination */
__hidden extern int lxc_abstract_unix_connect(const char *path);

__hidden extern int lxc_abstract_unix_send_fds(int fd, const int *sendfds,
					       int num_sendfds, void *data,
					       size_t size) __access_r(2, 3)
    __access_r(4, 5);

__hidden extern int lxc_abstract_unix_send_fds_iov(int fd, const int *sendfds,
						   int num_sendfds,
						   struct iovec *iov,
						   size_t iovlen)
    __access_r(2, 3);

__hidden extern ssize_t lxc_abstract_unix_recv_fds(int fd,
						   struct unix_fds *ret_fds,
						   void *ret_data,
						   size_t size_ret_data)
    __access_r(3, 4);

__hidden extern ssize_t lxc_abstract_unix_recv_one_fd(int fd, int *ret_fd,
						      void *ret_data,
						      size_t size_ret_data)
    __access_r(3, 4);

__hidden extern int __lxc_abstract_unix_send_two_fds(int fd, int fd_first,
						     int fd_second, void *data,
						     size_t size);

static inline int lxc_abstract_unix_send_two_fds(int fd, int fd_first,
						 int fd_second)
{
	return __lxc_abstract_unix_send_two_fds(fd, fd_first, fd_second, NULL, 0);
}

__hidden extern ssize_t __lxc_abstract_unix_recv_two_fds(int fd, int *fd_first,
							 int *fd_second,
							 void *data, size_t size);

static inline ssize_t lxc_abstract_unix_recv_two_fds(int fd, int *fd_first, int *fd_second)
{
	return __lxc_abstract_unix_recv_two_fds(fd, fd_first, fd_second, NULL, 0);
}

__hidden extern int lxc_unix_send_fds(int fd, int *sendfds, int num_sendfds, void *data, size_t size);

__hidden extern int lxc_abstract_unix_send_credential(int fd, void *data, size_t size)
    __access_r(2, 3);

__hidden extern int lxc_abstract_unix_rcv_credential(int fd, void *data, size_t size)
    __access_w(2, 3);

__hidden extern int lxc_unix_sockaddr(struct sockaddr_un *ret, const char *path);
__hidden extern int lxc_unix_connect(struct sockaddr_un *addr);
__hidden extern int lxc_unix_connect_type(struct sockaddr_un *addr, int type);
__hidden extern int lxc_socket_set_timeout(int fd, int rcv_timeout, int snd_timeout);

static inline void put_unix_fds(struct unix_fds *fds)
{
	if (!IS_ERR_OR_NULL(fds)) {
		for (size_t idx = 0; idx < fds->fd_count_ret; idx++)
			close_prot_errno_disarm(fds->fd[idx]);
	}
}
define_cleanup_function(struct unix_fds *, put_unix_fds);

#endif /* __LXC_AF_UNIX_H */

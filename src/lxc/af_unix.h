/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_AF_UNIX_H
#define __LXC_AF_UNIX_H

#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "compiler.h"

/* does not enforce \0-termination */
__hidden extern int lxc_abstract_unix_open(const char *path, int type, int flags);
__hidden extern void lxc_abstract_unix_close(int fd);
/* does not enforce \0-termination */
__hidden extern int lxc_abstract_unix_connect(const char *path);

__hidden extern int lxc_abstract_unix_send_fds(int fd, int *sendfds, int num_sendfds, void *data,
					       size_t size) __access_r(2, 3) __access_r(4, 5);

__hidden extern int lxc_abstract_unix_send_fds_iov(int fd, int *sendfds, int num_sendfds,
						   struct iovec *iov, size_t iovlen) __access_r(2, 3);

__hidden extern int lxc_abstract_unix_recv_fds(int fd, int *recvfds, int num_recvfds, void *data,
					       size_t size) __access_r(2, 3) __access_r(4, 5);

__hidden extern int lxc_unix_send_fds(int fd, int *sendfds, int num_sendfds, void *data, size_t size);

__hidden extern int lxc_abstract_unix_send_credential(int fd, void *data, size_t size)
    __access_r(2, 3);

__hidden extern int lxc_abstract_unix_rcv_credential(int fd, void *data, size_t size)
    __access_w(2, 3);

__hidden extern int lxc_unix_sockaddr(struct sockaddr_un *ret, const char *path);
__hidden extern int lxc_unix_connect(struct sockaddr_un *addr);
__hidden extern int lxc_unix_connect_type(struct sockaddr_un *addr, int type);
__hidden extern int lxc_socket_set_timeout(int fd, int rcv_timeout, int snd_timeout);

#endif /* __LXC_AF_UNIX_H */

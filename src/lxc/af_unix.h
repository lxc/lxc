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

#ifndef __LXC_AF_UNIX_H
#define __LXC_AF_UNIX_H

#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>

/* does not enforce \0-termination */
extern int lxc_abstract_unix_open(const char *path, int type, int flags);
extern void lxc_abstract_unix_close(int fd);
/* does not enforce \0-termination */
extern int lxc_abstract_unix_connect(const char *path);
extern int lxc_abstract_unix_send_fds(int fd, int *sendfds, int num_sendfds,
				      void *data, size_t size);
extern int lxc_abstract_unix_send_fds_iov(int fd, int *sendfds,
					  int num_sendfds, struct iovec *iov,
					  size_t iovlen);
extern int lxc_unix_send_fds(int fd, int *sendfds, int num_sendfds, void *data,
			     size_t size);
extern int lxc_abstract_unix_recv_fds(int fd, int *recvfds, int num_recvfds,
				      void *data, size_t size);
extern int lxc_abstract_unix_send_credential(int fd, void *data, size_t size);
extern int lxc_abstract_unix_rcv_credential(int fd, void *data, size_t size);
extern int lxc_unix_sockaddr(struct sockaddr_un *ret, const char *path);
extern int lxc_unix_connect(struct sockaddr_un *addr);
extern int lxc_socket_set_timeout(int fd, int rcv_timeout, int snd_timeout);

#endif /* __LXC_AF_UNIX_H */

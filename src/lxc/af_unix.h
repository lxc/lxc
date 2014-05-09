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

extern int lxc_abstract_unix_open(const char *path, int type, int flags);
extern int lxc_abstract_unix_close(int fd);
extern int lxc_abstract_unix_connect(const char *path);
extern int lxc_abstract_unix_send_fd(int fd, int sendfd, void *data, size_t size);
extern int lxc_abstract_unix_recv_fd(int fd, int *recvfd, void *data, size_t size);
extern int lxc_abstract_unix_send_credential(int fd, void *data, size_t size);
extern int lxc_abstract_unix_rcv_credential(int fd, void *data, size_t size);

#endif

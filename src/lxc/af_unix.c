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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>

#include "config.h"
#include "log.h"
#include "memory_utils.h"
#include "raw_syscalls.h"
#include "utils.h"

#ifndef HAVE_STRLCPY
#include "include/strlcpy.h"
#endif

lxc_log_define(af_unix, lxc);

static ssize_t lxc_abstract_unix_set_sockaddr(struct sockaddr_un *addr,
				const char *path)
{
	size_t len;

	if (!addr || !path) {
		errno = EINVAL;
		return -1;
	}

	/* Clear address structure */
	memset(addr, 0, sizeof(*addr));

	addr->sun_family = AF_UNIX;

	len = strlen(&path[1]);

	/* do not enforce \0-termination */
	if (len >= INT_MAX || len >= sizeof(addr->sun_path)) {
		errno = ENAMETOOLONG;
		return -1;
	}

	/* do not enforce \0-termination */
	memcpy(&addr->sun_path[1], &path[1], len);
	return len;
}

int lxc_abstract_unix_open(const char *path, int type, int flags)
{
	int fd, ret;
	ssize_t len;
	struct sockaddr_un addr;

	fd = socket(PF_UNIX, type | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;

	if (!path)
		return fd;

	len = lxc_abstract_unix_set_sockaddr(&addr, path);
	if (len < 0) {
		int saved_errno = errno;
		close(fd);
		errno = saved_errno;
		return -1;
	}

	ret = bind(fd, (struct sockaddr *)&addr,
		   offsetof(struct sockaddr_un, sun_path) + len + 1);
	if (ret < 0) {
		int saved_errno = errno;
		close(fd);
		errno = saved_errno;
		return -1;
	}

	if (type == SOCK_STREAM) {
		ret = listen(fd, 100);
		if (ret < 0) {
			int saved_errno = errno;
			close(fd);
			errno = saved_errno;
			return -1;
		}
	}

	return fd;
}

void lxc_abstract_unix_close(int fd)
{
	close(fd);
}

int lxc_abstract_unix_connect(const char *path)
{
	int fd, ret;
	ssize_t len;
	struct sockaddr_un addr;

	fd = socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;

	len = lxc_abstract_unix_set_sockaddr(&addr, path);
	if (len < 0) {
		int saved_errno = errno;
		close(fd);
		errno = saved_errno;
		return -1;
	}

	ret = connect(fd, (struct sockaddr *)&addr,
		      offsetof(struct sockaddr_un, sun_path) + len + 1);
	if (ret < 0) {
		int saved_errno = errno;
		close(fd);
		errno = saved_errno;
		return -1;
	}

	return fd;
}

int lxc_abstract_unix_send_fds_iov(int fd, int *sendfds, int num_sendfds,
				   struct iovec *iov, size_t iovlen)
{
	__do_free char *cmsgbuf = NULL;
	int ret;
	struct msghdr msg;
	struct cmsghdr *cmsg = NULL;
	size_t cmsgbufsize = CMSG_SPACE(num_sendfds * sizeof(int));

	memset(&msg, 0, sizeof(msg));

	cmsgbuf = malloc(cmsgbufsize);
	if (!cmsgbuf) {
		errno = ENOMEM;
		return -1;
	}

	msg.msg_control = cmsgbuf;
	msg.msg_controllen = cmsgbufsize;

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(num_sendfds * sizeof(int));

	msg.msg_controllen = cmsg->cmsg_len;

	memcpy(CMSG_DATA(cmsg), sendfds, num_sendfds * sizeof(int));

	msg.msg_iov = iov;
	msg.msg_iovlen = iovlen;

again:
	ret = sendmsg(fd, &msg, MSG_NOSIGNAL);
	if (ret < 0)
		if (errno == EINTR)
			goto again;

	return ret;
}

int lxc_abstract_unix_send_fds(int fd, int *sendfds, int num_sendfds,
			       void *data, size_t size)
{
	char buf[1] = {0};
	struct iovec iov = {
		.iov_base = data ? data : buf,
		.iov_len = data ? size : sizeof(buf),
	};
	return lxc_abstract_unix_send_fds_iov(fd, sendfds, num_sendfds, &iov,
					      1);
}

int lxc_unix_send_fds(int fd, int *sendfds, int num_sendfds, void *data,
		      size_t size)
{
	return lxc_abstract_unix_send_fds(fd, sendfds, num_sendfds, data, size);
}

int lxc_abstract_unix_recv_fds(int fd, int *recvfds, int num_recvfds,
			       void *data, size_t size)
{
	__do_free char *cmsgbuf = NULL;
	int ret;
	struct msghdr msg;
	struct iovec iov;
	struct cmsghdr *cmsg = NULL;
	char buf[1] = {0};
	size_t cmsgbufsize = CMSG_SPACE(sizeof(struct ucred)) +
			     CMSG_SPACE(num_recvfds * sizeof(int));

	memset(&msg, 0, sizeof(msg));
	memset(&iov, 0, sizeof(iov));

	cmsgbuf = malloc(cmsgbufsize);
	if (!cmsgbuf) {
		errno = ENOMEM;
		return -1;
	}

	msg.msg_control = cmsgbuf;
	msg.msg_controllen = cmsgbufsize;

	iov.iov_base = data ? data : buf;
	iov.iov_len = data ? size : sizeof(buf);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

again:
	ret = recvmsg(fd, &msg, 0);
	if (ret < 0) {
		if (errno == EINTR)
			goto again;

		goto out;
	}
	if (ret == 0)
		goto out;

	/*
	 * If SO_PASSCRED is set we will always get a ucred message.
	 */
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_type != SCM_RIGHTS)
			continue;

		memset(recvfds, -1, num_recvfds * sizeof(int));
		if (cmsg &&
		    cmsg->cmsg_len == CMSG_LEN(num_recvfds * sizeof(int)) &&
		    cmsg->cmsg_level == SOL_SOCKET)
			memcpy(recvfds, CMSG_DATA(cmsg), num_recvfds * sizeof(int));
		break;
	}

out:
	return ret;
}

int lxc_abstract_unix_send_credential(int fd, void *data, size_t size)
{
	struct msghdr msg = {0};
	struct iovec iov;
	struct cmsghdr *cmsg;
	struct ucred cred = {
	    .pid = lxc_raw_getpid(), .uid = getuid(), .gid = getgid(),
	};
	char cmsgbuf[CMSG_SPACE(sizeof(cred))] = {0};
	char buf[1] = {0};

	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct ucred));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_CREDENTIALS;
	memcpy(CMSG_DATA(cmsg), &cred, sizeof(cred));

	msg.msg_name = NULL;
	msg.msg_namelen = 0;

	iov.iov_base = data ? data : buf;
	iov.iov_len = data ? size : sizeof(buf);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	return sendmsg(fd, &msg, MSG_NOSIGNAL);
}

int lxc_abstract_unix_rcv_credential(int fd, void *data, size_t size)
{
	struct msghdr msg = {0};
	struct iovec iov;
	struct cmsghdr *cmsg;
	struct ucred cred;
	int ret;
	char cmsgbuf[CMSG_SPACE(sizeof(cred))] = {0};
	char buf[1] = {0};

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);

	iov.iov_base = data ? data : buf;
	iov.iov_len = data ? size : sizeof(buf);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	ret = recvmsg(fd, &msg, 0);
	if (ret <= 0)
		goto out;

	cmsg = CMSG_FIRSTHDR(&msg);

	if (cmsg && cmsg->cmsg_len == CMSG_LEN(sizeof(struct ucred)) &&
	    cmsg->cmsg_level == SOL_SOCKET &&
	    cmsg->cmsg_type == SCM_CREDENTIALS) {
		memcpy(&cred, CMSG_DATA(cmsg), sizeof(cred));
		if (cred.uid &&
		    (cred.uid != getuid() || cred.gid != getgid())) {
			INFO("Message denied for '%d/%d'", cred.uid, cred.gid);
			errno = EACCES;
			return -1;
		}
	}

out:
	return ret;
}

int lxc_unix_sockaddr(struct sockaddr_un *ret, const char *path)
{
	size_t len;

	len = strlen(path);
	if (len == 0)
		return minus_one_set_errno(EINVAL);
	if (path[0] != '/' && path[0] != '@')
		return minus_one_set_errno(EINVAL);
	if (path[1] == '\0')
		return minus_one_set_errno(EINVAL);

	if (len + 1 > sizeof(ret->sun_path))
		return minus_one_set_errno(EINVAL);

	*ret = (struct sockaddr_un){
	    .sun_family = AF_UNIX,
	};

	if (path[0] == '@') {
		memcpy(ret->sun_path + 1, path + 1, len);
		return (int)(offsetof(struct sockaddr_un, sun_path) + len);
	}

	memcpy(ret->sun_path, path, len + 1);
	return (int)(offsetof(struct sockaddr_un, sun_path) + len + 1);
}

int lxc_unix_connect(struct sockaddr_un *addr)
{
	__do_close_prot_errno int fd = -EBADF;
	int ret;
	ssize_t len;

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		SYSERROR("Failed to open new AF_UNIX socket");
		return -1;
	}

	if (addr->sun_path[0] == '\0')
		len = strlen(&addr->sun_path[1]);
	else
		len = strlen(&addr->sun_path[0]);

	ret = connect(fd, (struct sockaddr *)addr,
		      offsetof(struct sockaddr_un, sun_path) + len);
	if (ret < 0) {
		SYSERROR("Failed to bind new AF_UNIX socket");
		return -1;
	}

	return move_fd(fd);
}

int lxc_socket_set_timeout(int fd, int rcv_timeout, int snd_timeout)
{
	struct timeval out = {0};
	int ret;

	out.tv_sec = snd_timeout;
	ret = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const void *)&out,
			 sizeof(out));
	if (ret < 0)
		return -1;

	out.tv_sec = rcv_timeout;
	ret = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const void *)&out,
			 sizeof(out));
	if (ret < 0)
		return -1;

	return 0;
}

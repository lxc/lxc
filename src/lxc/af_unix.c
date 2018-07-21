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
#include "config.h"

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

#include "log.h"
#include "utils.h"

#ifndef HAVE_STRLCPY
#include "include/strlcpy.h"
#endif

lxc_log_define(af_unix, lxc);

int lxc_abstract_unix_open(const char *path, int type, int flags)
{
	int fd, ret;
	size_t len;
	struct sockaddr_un addr;

	fd = socket(PF_UNIX, type, 0);
	if (fd < 0)
		return -1;

	/* Clear address structure */
	memset(&addr, 0, sizeof(addr));

	if (!path)
		return fd;

	addr.sun_family = AF_UNIX;

	len = strlen(&path[1]);
	/* do not enforce \0-termination */
	if (len >= sizeof(addr.sun_path)) {
		close(fd);
		errno = ENAMETOOLONG;
		return -1;
	}

	/* do not enforce \0-termination */
	memcpy(&addr.sun_path[1], &path[1], len);

	ret = bind(fd, (struct sockaddr *)&addr,
		   offsetof(struct sockaddr_un, sun_path) + len + 1);
	if (ret < 0) {
		int saved_erron = errno;
		close(fd);
		errno = saved_erron;
		return -1;
	}

	if (type == SOCK_STREAM) {
		ret = listen(fd, 100);
		if (ret < 0) {
			int saved_erron = errno;
			close(fd);
			errno = saved_erron;
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
	size_t len;
	struct sockaddr_un addr;

	fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;

	memset(&addr, 0, sizeof(addr));

	addr.sun_family = AF_UNIX;

	len = strlen(&path[1]);
	/* do not enforce \0-termination */
	if (len >= sizeof(addr.sun_path)) {
		close(fd);
		errno = ENAMETOOLONG;
		return -1;
	}

	/* do not enforce \0-termination */
	memcpy(&addr.sun_path[1], &path[1], len);

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

int lxc_abstract_unix_send_fds(int fd, int *sendfds, int num_sendfds,
			       void *data, size_t size)
{
	int ret;
	struct msghdr msg;
	struct iovec iov;
	struct cmsghdr *cmsg = NULL;
	char buf[1] = {0};
	char *cmsgbuf;
	size_t cmsgbufsize = CMSG_SPACE(num_sendfds * sizeof(int));

	memset(&msg, 0, sizeof(msg));
	memset(&iov, 0, sizeof(iov));

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

	iov.iov_base = data ? data : buf;
	iov.iov_len = data ? size : sizeof(buf);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	ret = sendmsg(fd, &msg, MSG_NOSIGNAL);
	free(cmsgbuf);
	return ret;
}

int lxc_abstract_unix_recv_fds(int fd, int *recvfds, int num_recvfds,
			       void *data, size_t size)
{
	int ret;
	struct msghdr msg;
	struct iovec iov;
	struct cmsghdr *cmsg = NULL;
	char buf[1] = {0};
	char *cmsgbuf;
	size_t cmsgbufsize = CMSG_SPACE(num_recvfds * sizeof(int));

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

	ret = recvmsg(fd, &msg, 0);
	if (ret <= 0)
		goto out;

	cmsg = CMSG_FIRSTHDR(&msg);

	memset(recvfds, -1, num_recvfds * sizeof(int));
	if (cmsg && cmsg->cmsg_len == CMSG_LEN(num_recvfds * sizeof(int)) &&
	    cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS)
		memcpy(recvfds, CMSG_DATA(cmsg), num_recvfds * sizeof(int));

out:
	free(cmsgbuf);
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

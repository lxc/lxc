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
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#define __USE_GNU
#include <sys/socket.h>
#undef __USE_GNU
#include <sys/un.h>

#include "log.h"

lxc_log_define(lxc_af_unix, lxc);

int lxc_af_unix_open(const char *path, int type, int flags)
{
	int fd;
	struct sockaddr_un addr;

	if (flags & O_TRUNC)
		unlink(path);

	fd = socket(PF_UNIX, type, 0);
	if (fd < 0)
		return -1;

	memset(&addr, 0, sizeof(addr));

	if (!path)
		return fd;

	addr.sun_family = AF_UNIX;
	/* copy entire buffer in case of abstract socket */
	memcpy(addr.sun_path, path, 
	       path[0]?strlen(path):sizeof(addr.sun_path));

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr))) {
		close(fd);
		return -1;
	}
	
	if (type == SOCK_STREAM && listen(fd, 100)) {
		close(fd);
		return -1;
	}

	return fd;
}

int lxc_af_unix_close(int fd)
{
	struct sockaddr_un addr;
	socklen_t addrlen;
	
	if (!getsockname(fd, (struct sockaddr *)&addr, &addrlen) && 
	    addr.sun_path[0])
		unlink(addr.sun_path);

	close(fd);

	return 0;
}

int lxc_af_unix_connect(const char *path)
{
	int fd;
	struct sockaddr_un addr;

	fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;

	memset(&addr, 0, sizeof(addr));

	addr.sun_family = AF_UNIX;
	/* copy entire buffer in case of abstract socket */
	memcpy(addr.sun_path, path, 
	       path[0]?strlen(path):sizeof(addr.sun_path));

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr))) {
		close(fd);
		return -1;
	}

	return fd;
}

int lxc_af_unix_send_fd(int fd, int sendfd, void *data, size_t size)
{
        struct msghdr msg = { 0 };
        struct iovec iov;
        struct cmsghdr *cmsg;
        char cmsgbuf[CMSG_SPACE(sizeof(int))];
        char buf[1];
	int *val;

        msg.msg_control = cmsgbuf;
        msg.msg_controllen = sizeof(cmsgbuf);

        cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
	val = (int *)(CMSG_DATA(cmsg));
	*val = sendfd;

        msg.msg_name = NULL;
        msg.msg_namelen = 0;

        iov.iov_base = data ? data : buf;
        iov.iov_len = data ? size : sizeof(buf);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        return sendmsg(fd, &msg, 0);
}

int lxc_af_unix_recv_fd(int fd, int *recvfd, void *data, size_t size)
{
        struct msghdr msg = { 0 };
        struct iovec iov;
        struct cmsghdr *cmsg;
        char cmsgbuf[CMSG_SPACE(sizeof(int))];
        char buf[1];
	int ret, *val;

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

	/* if the message is wrong the variable will not be 
	 * filled and the peer will notified about a problem */
	*recvfd = -1;

        if (cmsg && cmsg->cmsg_len == CMSG_LEN(sizeof(int)) &&
            cmsg->cmsg_level == SOL_SOCKET &&
            cmsg->cmsg_type == SCM_RIGHTS) {
		val = (int *) CMSG_DATA(cmsg);
                *recvfd = *val;
        }
out:
        return ret;
}

int lxc_af_unix_send_credential(int fd, void *data, size_t size)
{
        struct msghdr msg = { 0 };
        struct iovec iov;
        struct cmsghdr *cmsg;
	struct ucred cred = {
		.pid = getpid(),
		.uid = getuid(),
		.gid = getgid(),
	};
        char cmsgbuf[CMSG_SPACE(sizeof(cred))];
        char buf[1];

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

        return sendmsg(fd, &msg, 0);
}

int lxc_af_unix_rcv_credential(int fd, void *data, size_t size)
{
        struct msghdr msg = { 0 };
        struct iovec iov;
        struct cmsghdr *cmsg;
	struct ucred cred;
        char cmsgbuf[CMSG_SPACE(sizeof(cred))];
        char buf[1];
	int ret;

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
		if (cred.uid && (cred.uid != getuid() || cred.gid != getgid())) {
			INFO("message denied for '%d/%d'", cred.uid, cred.gid);
			return -EACCES;
		}
        }
out:
        return ret;
}

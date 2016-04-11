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
#include <sys/socket.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "nl.h"

#define NLMSG_TAIL(nmsg) \
        ((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

extern size_t nlmsg_len(const struct nlmsg *nlmsg)
{
	return nlmsg->nlmsghdr->nlmsg_len - NLMSG_HDRLEN;
}

extern void *nlmsg_data(struct nlmsg *nlmsg)
{
	char *data = ((char *)nlmsg) + NLMSG_HDRLEN;
	if (!nlmsg_len(nlmsg))
		return NULL;
	return data;
}

static int nla_put(struct nlmsg *nlmsg, int attr,
		   const void *data, size_t len)
{
	struct rtattr *rta;
	size_t rtalen = RTA_LENGTH(len);
	size_t tlen = NLMSG_ALIGN(nlmsg->nlmsghdr->nlmsg_len) + RTA_ALIGN(rtalen);

	if (tlen > nlmsg->cap)
		return -ENOMEM;

	rta = NLMSG_TAIL(nlmsg->nlmsghdr);
	rta->rta_type = attr;
	rta->rta_len = rtalen;
	memcpy(RTA_DATA(rta), data, len);
	nlmsg->nlmsghdr->nlmsg_len = tlen;
	return 0;
}

extern int nla_put_buffer(struct nlmsg *nlmsg, int attr,
			  const void *data, size_t size)
{
	return nla_put(nlmsg, attr, data, size);
}

extern int nla_put_string(struct nlmsg *nlmsg, int attr, const char *string)
{
	return nla_put(nlmsg, attr, string, strlen(string) + 1);
}

extern int nla_put_u32(struct nlmsg *nlmsg, int attr, int value)
{
	return nla_put(nlmsg, attr, &value, sizeof(value));
}

extern int nla_put_u16(struct nlmsg *nlmsg, int attr, unsigned short value)
{
	return nla_put(nlmsg, attr, &value, 2);
}

extern int nla_put_attr(struct nlmsg *nlmsg, int attr)
{
	return nla_put(nlmsg, attr, NULL, 0);
}

struct rtattr *nla_begin_nested(struct nlmsg *nlmsg, int attr)
{
	struct rtattr *rtattr = NLMSG_TAIL(nlmsg->nlmsghdr);

	if (nla_put_attr(nlmsg, attr))
		return NULL;

	return rtattr;
}

void nla_end_nested(struct nlmsg *nlmsg, struct rtattr *attr)
{
	attr->rta_len = (void *)NLMSG_TAIL(nlmsg->nlmsghdr) - (void *)attr;
}

extern struct nlmsg *nlmsg_alloc(size_t size)
{
	struct nlmsg *nlmsg;
	size_t len = NLMSG_HDRLEN + NLMSG_ALIGN(size);

	nlmsg = (struct nlmsg *)malloc(sizeof(struct nlmsg));
	if (!nlmsg)
		return NULL;

	nlmsg->nlmsghdr = (struct nlmsghdr *)malloc(len);
	if (!nlmsg->nlmsghdr)
		goto errout;

	memset(nlmsg->nlmsghdr, 0, len);
	nlmsg->cap = len;
	nlmsg->nlmsghdr->nlmsg_len = NLMSG_HDRLEN;

	return nlmsg;
errout:
	free(nlmsg);
	return NULL;
}

extern void *nlmsg_reserve(struct nlmsg *nlmsg, size_t len)
{
	void *buf;
	size_t nlmsg_len = nlmsg->nlmsghdr->nlmsg_len;
	size_t tlen = NLMSG_ALIGN(len);

	if (nlmsg_len + tlen > nlmsg->cap)
		return NULL;

	buf = ((char *)(nlmsg->nlmsghdr)) + nlmsg_len;
	nlmsg->nlmsghdr->nlmsg_len += tlen;

	if (tlen > len)
		memset(buf + len, 0, tlen - len);

	return buf;
}

extern struct nlmsg *nlmsg_alloc_reserve(size_t size)
{
	struct nlmsg *nlmsg;

	nlmsg = nlmsg_alloc(size);
	if (!nlmsg)
		return NULL;

	// just set message length to cap directly
	nlmsg->nlmsghdr->nlmsg_len = nlmsg->cap;
	return nlmsg;
}

extern void nlmsg_free(struct nlmsg *nlmsg)
{
	if (!nlmsg)
		return;

	free(nlmsg->nlmsghdr);
	free(nlmsg);
}

extern int netlink_rcv(struct nl_handler *handler, struct nlmsg *answer)
{
	int ret;
	struct sockaddr_nl nladdr;
	struct iovec iov = {
		.iov_base = answer->nlmsghdr,
		.iov_len = answer->nlmsghdr->nlmsg_len,
	};
	
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	
	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pid = 0;
	nladdr.nl_groups = 0;

again:
	ret = recvmsg(handler->fd, &msg, 0);
	if (ret < 0) {
		if (errno == EINTR)
			goto again;
		return -errno;
	}

	if (!ret)
		return 0;

	if (msg.msg_flags & MSG_TRUNC &&
	    ret == answer->nlmsghdr->nlmsg_len)
		return -EMSGSIZE;

	return ret;
}

extern int netlink_send(struct nl_handler *handler, struct nlmsg *nlmsg)
{
	struct sockaddr_nl nladdr;
	struct iovec iov = {
		.iov_base = nlmsg->nlmsghdr,
		.iov_len = nlmsg->nlmsghdr->nlmsg_len,
	};
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	int ret;
	
	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pid = 0;
	nladdr.nl_groups = 0;

	ret = sendmsg(handler->fd, &msg, 0);
	if (ret < 0)
		return -errno;

	return ret;
}

#ifndef NLMSG_ERROR
#define NLMSG_ERROR                0x2
#endif
extern int netlink_transaction(struct nl_handler *handler,
			       struct nlmsg *request, struct nlmsg *answer)
{
	int ret;

	ret = netlink_send(handler, request);
	if (ret < 0)
		return ret;

	ret = netlink_rcv(handler, answer);
	if (ret < 0)
		return ret;

	if (answer->nlmsghdr->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *err = (struct nlmsgerr*)NLMSG_DATA(answer->nlmsghdr);
		return err->error;
	}

	return 0;
}

extern int netlink_open(struct nl_handler *handler, int protocol)
{
	socklen_t socklen;
	int sndbuf = 32768;
	int rcvbuf = 32768;
	int err;

	memset(handler, 0, sizeof(*handler));

	handler->fd = socket(AF_NETLINK, SOCK_RAW, protocol);
	if (handler->fd < 0)
		return -errno;

	if (setsockopt(handler->fd, SOL_SOCKET, SO_SNDBUF,
		       &sndbuf, sizeof(sndbuf)) < 0)
		goto err_with_errno;

	if (setsockopt(handler->fd, SOL_SOCKET, SO_RCVBUF,
		       &rcvbuf,sizeof(rcvbuf)) < 0)
		goto err_with_errno;

	memset(&handler->local, 0, sizeof(handler->local));
	handler->local.nl_family = AF_NETLINK;
	handler->local.nl_groups = 0;

	if (bind(handler->fd, (struct sockaddr*)&handler->local,
		 sizeof(handler->local)) < 0)
		goto err_with_errno;

	socklen = sizeof(handler->local);
	if (getsockname(handler->fd, (struct sockaddr*)&handler->local,
			&socklen) < 0)
		goto err_with_errno;

	if (socklen != sizeof(handler->local)) {
		err = -EINVAL;
		goto errclose;
	}

	if (handler->local.nl_family != AF_NETLINK) {
		err = -EINVAL;
		goto errclose;
	}

	handler->seq = time(NULL);

	return 0;
err_with_errno:
	err = -errno;
errclose:
	close(handler->fd);
	return err;
}

extern int netlink_close(struct nl_handler *handler)
{
	close(handler->fd);
	handler->fd = -1;
	return 0;
}


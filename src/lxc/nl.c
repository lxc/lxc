/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <errno.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "log.h"
#include "nl.h"

lxc_log_define(nl, lxc);

static size_t nlmsg_len(const struct nlmsg *nlmsg)
{
	return nlmsg->nlmsghdr->nlmsg_len - NLMSG_HDRLEN;
}

void *nlmsg_data(struct nlmsg *nlmsg)
{
	char *data;

	data = ((char *)nlmsg) + NLMSG_HDRLEN;
	if (!nlmsg_len(nlmsg))
		return ret_set_errno(NULL, EINVAL);

	return data;
}

static int nla_put(struct nlmsg *nlmsg, int attr,
		   const void *data, size_t len)
{
	struct rtattr *rta;
	size_t rtalen = RTA_LENGTH(len);
	size_t tlen = NLMSG_ALIGN(nlmsg->nlmsghdr->nlmsg_len) + RTA_ALIGN(rtalen);

	if (tlen > nlmsg->cap)
		return ret_errno(ENOMEM);

	rta = NLMSG_TAIL(nlmsg->nlmsghdr);
	rta->rta_type = attr;
	rta->rta_len = rtalen;
	if (data && len)
		memcpy(RTA_DATA(rta), data, len);
	nlmsg->nlmsghdr->nlmsg_len = tlen;

	return 0;
}

int nla_put_buffer(struct nlmsg *nlmsg, int attr, const void *data, size_t size)
{
	return nla_put(nlmsg, attr, data, size);
}

int nla_put_string(struct nlmsg *nlmsg, int attr, const char *string)
{
	return nla_put(nlmsg, attr, string, strlen(string) + 1);
}

int nla_put_u32(struct nlmsg *nlmsg, int attr, int value)
{
	return nla_put(nlmsg, attr, &value, sizeof(value));
}

int nla_put_u16(struct nlmsg *nlmsg, int attr, unsigned short value)
{
	return nla_put(nlmsg, attr, &value, 2);
}

int nla_put_attr(struct nlmsg *nlmsg, int attr)
{
	return nla_put(nlmsg, attr, NULL, 0);
}

struct rtattr *nla_begin_nested(struct nlmsg *nlmsg, int attr)
{
	struct rtattr *rtattr;

	rtattr = NLMSG_TAIL(nlmsg->nlmsghdr);
	if (nla_put_attr(nlmsg, attr))
		return ret_set_errno(NULL, ENOMEM);

	return rtattr;
}

void nla_end_nested(struct nlmsg *nlmsg, struct rtattr *attr)
{
	attr->rta_len = (void *)NLMSG_TAIL(nlmsg->nlmsghdr) - (void *)attr;
}

struct nlmsg *nlmsg_alloc(size_t size)
{
	__do_free struct nlmsg *nlmsg = NULL;
	size_t len = NLMSG_HDRLEN + NLMSG_ALIGN(size);

	nlmsg = malloc(sizeof(struct nlmsg));
	if (!nlmsg)
		return ret_set_errno(NULL, ENOMEM);

	nlmsg->nlmsghdr = malloc(len);
	if (!nlmsg->nlmsghdr)
		return ret_set_errno(NULL, ENOMEM);

	memset(nlmsg->nlmsghdr, 0, len);
	nlmsg->cap = len;
	nlmsg->nlmsghdr->nlmsg_len = NLMSG_HDRLEN;

	return move_ptr(nlmsg);
}

void *nlmsg_reserve(struct nlmsg *nlmsg, size_t len)
{
	void *buf;
	size_t nlmsg_len = nlmsg->nlmsghdr->nlmsg_len;
	size_t tlen = NLMSG_ALIGN(len);

	if (nlmsg_len + tlen > nlmsg->cap)
		return ret_set_errno(NULL, ENOMEM);

	buf = ((char *)(nlmsg->nlmsghdr)) + nlmsg_len;
	nlmsg->nlmsghdr->nlmsg_len += tlen;

	if (tlen > len)
		memset(buf + len, 0, tlen - len);

	return buf;
}

struct nlmsg *nlmsg_alloc_reserve(size_t size)
{
	struct nlmsg *nlmsg;

	nlmsg = nlmsg_alloc(size);
	if (!nlmsg)
		return ret_set_errno(NULL, ENOMEM);

	/* Just set message length to cap directly. */
	nlmsg->nlmsghdr->nlmsg_len = nlmsg->cap;
	return nlmsg;
}

void nlmsg_free(struct nlmsg *nlmsg)
{
	if (nlmsg) {
		free(nlmsg->nlmsghdr);
		free(nlmsg);
	}
}

int __netlink_recv(struct nl_handler *handler, struct nlmsghdr *nlmsghdr)
{
	int ret;
	struct sockaddr_nl nladdr;
	struct iovec iov = {
	    .iov_base = nlmsghdr,
	    .iov_len = nlmsghdr->nlmsg_len,
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

		return ret_errno(errno);
	}

	if (!ret)
		return 0;

	if (msg.msg_flags & MSG_TRUNC && (ret == nlmsghdr->nlmsg_len))
		return ret_errno(EMSGSIZE);

	return ret;
}

int netlink_rcv(struct nl_handler *handler, struct nlmsg *answer)
{
	return __netlink_recv(handler, answer->nlmsghdr);
}

int __netlink_send(struct nl_handler *handler, struct nlmsghdr *nlmsghdr)
{
	int ret;
	struct sockaddr_nl nladdr;
	struct iovec iov = {
	    .iov_base = nlmsghdr,
	    .iov_len = nlmsghdr->nlmsg_len,
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

	ret = sendmsg(handler->fd, &msg, MSG_NOSIGNAL);
	if (ret < 0)
		return ret_errno(errno);

	return ret;
}

extern int netlink_send(struct nl_handler *handler, struct nlmsg *nlmsg)
{
	return __netlink_send(handler, nlmsg->nlmsghdr);
}

extern int __netlink_transaction(struct nl_handler *handler,
				 struct nlmsghdr *request,
				 struct nlmsghdr *answer)
{
	int ret;

	ret = __netlink_send(handler, request);
	if (ret < 0)
		return ret;

	ret = __netlink_recv(handler, answer);
	if (ret < 0)
		return ret;

	if (answer->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(answer);
		if (err->error < 0)
			return ret_errno(-err->error);
	}

	return 0;
}

extern int netlink_transaction(struct nl_handler *handler,
			       struct nlmsg *request, struct nlmsg *answer)
{
	return __netlink_transaction(handler, request->nlmsghdr,
				     answer->nlmsghdr);
}

extern int netlink_open(struct nl_handler *handler, int protocol)
{
	__do_close int fd = -EBADF;
	socklen_t socklen;
	int sndbuf = 32768;
	int rcvbuf = 32768;

	memset(handler, 0, sizeof(*handler));
	handler->fd = -EBADF;

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, protocol);
	if (fd < 0)
		return ret_errno(errno);

	if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) < 0)
		return ret_errno(errno);

	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf,sizeof(rcvbuf)) < 0)
		return ret_errno(errno);

	memset(&handler->local, 0, sizeof(handler->local));
	handler->local.nl_family = AF_NETLINK;
	handler->local.nl_groups = 0;

	if (bind(fd, (struct sockaddr*)&handler->local, sizeof(handler->local)) < 0)
		return ret_errno(errno);

	socklen = sizeof(handler->local);
	if (getsockname(fd, (struct sockaddr*)&handler->local, &socklen) < 0)
		return ret_errno(errno);

	if (socklen != sizeof(handler->local))
		return ret_errno(EINVAL);

	if (handler->local.nl_family != AF_NETLINK)
		return ret_errno(EINVAL);

	handler->seq = time(NULL);
	handler->fd = move_fd(fd);
	return 0;
}

extern void netlink_close(struct nl_handler *handler)
{
	close_prot_errno_disarm(handler->fd);
}

int addattr(struct nlmsghdr *n, size_t maxlen, int type, const void *data,
	    size_t alen)
{
	int len = RTA_LENGTH(alen);
	struct rtattr *rta;

	if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen)
		return ret_errno(EMSGSIZE);

	rta = NLMSG_TAIL(n);
	rta->rta_type = type;
	rta->rta_len = len;
	if (alen)
		memcpy(RTA_DATA(rta), data, alen);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);

	return 0;
}

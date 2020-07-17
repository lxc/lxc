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
#include <unistd.h>

#include "config.h"
#include "nl.h"
#include "rtnl.h"

int rtnetlink_open(struct rtnl_handler *handler)
{
	return netlink_open(&handler->nlh, NETLINK_ROUTE);
}

void rtnetlink_close(struct rtnl_handler *handler)
{
	netlink_close(&handler->nlh);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"

int rtnetlink_rcv(struct rtnl_handler *handler, struct rtnlmsg *rtnlmsg)
{
	return netlink_rcv(&handler->nlh, (struct nlmsg *)&rtnlmsg->nlmsghdr);
}

int rtnetlink_send(struct rtnl_handler *handler, struct rtnlmsg *rtnlmsg)
{

	return netlink_send(&handler->nlh, (struct nlmsg *)&rtnlmsg->nlmsghdr);
}

int rtnetlink_transaction(struct rtnl_handler *handler, struct rtnlmsg *request,
			  struct rtnlmsg *answer)
{
	return netlink_transaction(&handler->nlh,
				   (struct nlmsg *)&request->nlmsghdr,
				   (struct nlmsg *)&answer->nlmsghdr);
}

#pragma GCC diagnostic pop

struct rtnlmsg *rtnlmsg_alloc(size_t size)
{
	/*
	size_t len;

	len = NLMSG_LENGTH(NLMSG_ALIGN(sizeof(struct rtnlmsghdr))) + size;
	return (struct rtnlmsg *)nlmsg_alloc(len);
	*/

	return NULL;
}

void rtnlmsg_free(struct rtnlmsg *rtnlmsg) { free(rtnlmsg); }

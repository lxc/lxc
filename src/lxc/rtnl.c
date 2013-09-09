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
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "nl.h"
#include "rtnl.h"

extern int rtnetlink_open(struct rtnl_handler *handler)
{
	return netlink_open(&handler->nlh, NETLINK_ROUTE);
}

extern int rtnetlink_close(struct rtnl_handler *handler)
{
	return netlink_close(&handler->nlh);
}

extern int rtnetlink_rcv(struct rtnl_handler *handler, struct rtnlmsg *rtnlmsg)
{
	return netlink_rcv(&handler->nlh, (struct nlmsg *)&rtnlmsg->nlmsghdr);
}

extern int rtnetlink_send(struct rtnl_handler *handler, struct rtnlmsg *rtnlmsg)
{

	return netlink_send(&handler->nlh, (struct nlmsg *)&rtnlmsg->nlmsghdr);
}

extern int rtnetlink_transaction(struct rtnl_handler *handler,
			  struct rtnlmsg *request, struct rtnlmsg *answer)
{
	return netlink_transaction(&handler->nlh, (struct nlmsg *)&request->nlmsghdr,
				   (struct nlmsg *)&answer->nlmsghdr);
}

extern struct rtnlmsg *rtnlmsg_alloc(size_t size)
{
/* 	size_t len = NLMSG_LENGTH(NLMSG_ALIGN(sizeof(struct rtnlmsghdr))) + size; */
/* 	return  (struct rtnlmsg *)nlmsg_alloc(len); */
	return NULL;
}

extern void rtnlmsg_free(struct rtnlmsg *rtnlmsg)
{
	free(rtnlmsg);
}

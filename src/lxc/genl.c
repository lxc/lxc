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
#include <linux/genetlink.h>
#include <linux/rtnetlink.h>

#include "nl.h"
#include "genl.h"

static int genetlink_resolve_family(const char *family)
{
	struct nl_handler handler;
	struct nlattr *attr;
	struct genlmsg *request, *reply;
	struct genlmsghdr *genlmsghdr;

	int len, ret;

	request = genlmsg_alloc(GENLMSG_GOOD_SIZE);
	if (!request)
		return -ENOMEM;
		
	reply = genlmsg_alloc(GENLMSG_GOOD_SIZE);
	if (!reply) {
		genlmsg_free(request);
		return -ENOMEM;
	}

	request->nlmsghdr.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	request->nlmsghdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	request->nlmsghdr.nlmsg_type = GENL_ID_CTRL;

	genlmsghdr = NLMSG_DATA(&request->nlmsghdr);
	genlmsghdr->cmd = CTRL_CMD_GETFAMILY;

	ret = netlink_open(&handler, NETLINK_GENERIC);
	if (ret)
		goto out;

	ret = nla_put_string((struct nlmsg *)&request->nlmsghdr,
			     CTRL_ATTR_FAMILY_NAME, family);
	if (ret)
		goto out_close;

	ret = netlink_transaction(&handler, (struct nlmsg *)&request->nlmsghdr,
				  (struct nlmsg *)&reply->nlmsghdr);
	if (ret < 0)
		goto out_close;

	genlmsghdr = NLMSG_DATA(&reply->nlmsghdr);
	len = reply->nlmsghdr.nlmsg_len;

	ret = -ENOMSG;
	if (reply->nlmsghdr.nlmsg_type !=  GENL_ID_CTRL)
		goto out_close;

	if (genlmsghdr->cmd != CTRL_CMD_NEWFAMILY)
		goto out_close;

	ret = -EMSGSIZE;
	len -= NLMSG_LENGTH(GENL_HDRLEN);
	if (len < 0)
		goto out_close;
	
	attr = (struct nlattr *)GENLMSG_DATA(reply);
	attr = (struct nlattr *)((char *)attr + NLA_ALIGN(attr->nla_len));
	
	ret = -ENOMSG;
	if (attr->nla_type != CTRL_ATTR_FAMILY_ID)
		goto out_close;

	ret =  *(__u16 *) NLA_DATA(attr);
out_close:
	netlink_close(&handler);
out:
	genlmsg_free(request);
	genlmsg_free(reply);
	return ret;
}

extern int genetlink_open(struct genl_handler *handler, const char *family)
{
	int ret;
	handler->family = genetlink_resolve_family(family);
	if (handler->family < 0)
		return handler->family;

	ret = netlink_open(&handler->nlh, NETLINK_GENERIC);

	return ret;
}

extern int genetlink_close(struct genl_handler *handler)
{
	return netlink_close(&handler->nlh);
}

extern int genetlink_rcv(struct genl_handler *handler, struct genlmsg *genlmsg)
{
	return netlink_rcv(&handler->nlh, (struct nlmsg *)&genlmsg->nlmsghdr);
}

extern int genetlink_send(struct genl_handler *handler, struct genlmsg *genlmsg)
{

	return netlink_send(&handler->nlh, (struct nlmsg *)&genlmsg->nlmsghdr);
}

extern int genetlink_transaction(struct genl_handler *handler,
			  struct genlmsg *request, struct genlmsg *answer)
{
	return netlink_transaction(&handler->nlh, (struct nlmsg *)&request->nlmsghdr,
				   (struct nlmsg *)&answer->nlmsghdr);
}

extern struct genlmsg *genlmsg_alloc(size_t size)
{
	size_t len = NLMSG_LENGTH(GENL_HDRLEN) + size;
	return  (struct genlmsg *)nlmsg_alloc(len);
}

extern void genlmsg_free(struct genlmsg *genlmsg)
{
	free(genlmsg);
}

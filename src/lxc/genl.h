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
#ifndef __LXC_GENL_H
#define __LXC_GENL_H

/*
 * Use this as a good size to allocate generic netlink messages
 */
#define GENLMSG_GOOD_SIZE NLMSG_GOOD_SIZE
#define GENLMSG_DATA(glh) ((void *)(NLMSG_DATA(glh) + GENL_HDRLEN))

/*
 * struct genl_handler : the structure which store the netlink handler
 *  and the family number resulting of the auto-generating id family
 *  for the generic netlink protocol
 *
 * @nlh: the netlink socket handler
 * @family: the generic netlink family assigned number
 */
struct genl_handler
{
	struct nl_handler nlh;
	int family;
};

/*
 * struct genlmsg : the struct containing the generic netlink message
 *  format
 *
 * @nlmsghdr: a netlink message header
 * @genlmsghdr: a generic netlink message header pointer
 *
 */
/* __attribute__ ((aligned(4))); */
struct genlmsg {
	struct nlmsghdr nlmsghdr;
	struct genlmsghdr genlmsghdr;
};

static inline int genetlink_len(const struct genlmsg *genlmsg)
{
	return ((genlmsg->nlmsghdr.nlmsg_len) - GENL_HDRLEN - NLMSG_HDRLEN);
}

/*
 * genetlink_open : resolve family number id and open a generic netlink socket
 *
 * @handler: a struct genl_handler pointer
 * @family: the family name of the generic netlink protocol
 *
 * Returns 0 on success, < 0 otherwise
 */
int genetlink_open(struct genl_handler *handler, const char *family);

/*
 * genetlink_close : close a generic netlink socket
 *
 * @handler: the handler of the socket to be closed
 *
 * Returns 0 on success, < 0 otherwise
 */
int genetlink_close(struct genl_handler *handler);

/*
 * genetlink_rcv : receive a generic netlink socket, it is up
 *  to the caller to manage the allocation of the generic netlink message
 *
 * @handler: the handler of the generic netlink socket
 * @genlmsg: the pointer to a generic netlink message pre-allocated
 *
 * Returns 0 on success, < 0 otherwise
 */
int genetlink_rcv(struct genl_handler *handler, struct genlmsg *genlmsg);

/*
 * genetlink_send : send a generic netlink socket, it is up
 *  to the caller to manage the allocation of the generic netlink message
 *
 * @handler: the handler of the generic netlink socket
 * @genlmsg: the pointer to a generic netlink message pre-allocated
 *
 * Returns 0 on success, < 0 otherwise
 */
int genetlink_send(struct genl_handler *handler, struct genlmsg *genlmsg);

struct genlmsg *genlmsg_alloc(size_t size);

void genlmsg_free(struct genlmsg *genlmsg);

/*
 * genetlink_transaction : send and receive a generic netlink message in one shot
 *
 * @handler: the handler of the generic netlink socket
 * @request: a generic netlink message containing the request to be sent
 * @answer: a pre-allocated generic netlink message to receive the response
 *
 * Returns 0 on success, < 0 otherwise
 */
int genetlink_transaction(struct genl_handler *handler,
			  struct genlmsg *request, struct genlmsg *answer);
#endif

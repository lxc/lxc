/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_RTNL_H
#define __LXC_RTNL_H

/*
 * Use this as a good size to allocate route netlink messages
 */
#define RTNLMSG_GOOD_SIZE NLMSG_GOOD_SIZE
#define RTNLMSG_DATA(glh) ((void *)(NLMSG_DATA(glh) + RTNL_HDRLEN))

/*
 * struct genl_handler : the structure which store the netlink handler
 *  and the family number
 *
 * @nlh: the netlink socket handler
 */
struct rtnl_handler {
	struct nl_handler nlh;
};

/*
 * struct rtnlmsg : the struct containing the route netlink message
 *  format
 *
 * @nlmsghdr: a netlink message header
 * @rtnlmsghdr: a route netlink message header pointer
 *
 */
struct rtnlmsg {
	struct nlmsghdr nlmsghdr;
};

/*
 * rtnetlink_open : open a route netlink socket
 *
 * @handler: a struct rtnl_handler pointer
 *
 * Returns 0 on success, < 0 otherwise
 */
extern int rtnetlink_open(struct rtnl_handler *handler);

/*
 * genetlink_close : close a route netlink socket
 *
 * @handler: the handler of the socket to be closed
 */
extern void rtnetlink_close(struct rtnl_handler *handler);

/*
 * rtnetlink_rcv : receive a route netlink socket, it is up
 *  to the caller to manage the allocation of the route netlink message
 *
 * @handler: the handler of the route netlink socket
 * @rtnlmsg: the pointer to a route netlink message pre-allocated
 *
 * Returns 0 on success, < 0 otherwise
 */
extern int rtnetlink_rcv(struct rtnl_handler *handler, struct rtnlmsg *rtnlmsg);

/*
 * rtnetlink_send : send a route netlink socket, it is up
 *  to the caller to manage the allocation of the route netlink message
 *
 * @handler: the handler of the route netlink socket
 * @rtnlmsg: the pointer to a netlink message pre-allocated
 *
 * Returns 0 on success, < 0 otherwise
 */
extern int rtnetlink_send(struct rtnl_handler *handler,
			  struct rtnlmsg *rtnlmsg);

struct genlmsg *genlmsg_alloc(size_t size);

extern void rtnlmsg_free(struct rtnlmsg *rtnlmsg);

/*
 * rtnetlink_transaction : send and receive a route netlink message in one shot
 *
 * @handler: the handler of the route netlink socket
 * @request: a route netlink message containing the request to be sent
 * @answer: a pre-allocated route netlink message to receive the response
 *
 * Returns 0 on success, < 0 otherwise
 */
extern int rtnetlink_transaction(struct rtnl_handler *handler,
				 struct rtnlmsg *request,
				 struct rtnlmsg *answer);

#endif /* __LXC_RTNL_H */

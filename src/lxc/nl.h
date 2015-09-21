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
#ifndef __LXC_NL_H
#define __LXC_NL_H

/*
 * Use this as a good size to allocate generic netlink messages
 */
#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif
#define NLMSG_GOOD_SIZE (2*PAGE_SIZE)
#define NLMSG_TAIL(nmsg) \
        ((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))
#define NLA_DATA(na) ((void *)((char*)(na) + NLA_HDRLEN))
#define NLA_NEXT_ATTR(attr) ((void *)((char *)attr) + NLA_ALIGN(attr->nla_len))

/*
 * struct nl_handler : the handler for netlink sockets, this structure
 *  is used all along the netlink socket life cycle to specify the
 *  netlink socket to be used.
 *
 * @fd: the file descriptor of the netlink socket
 * @seq: the sequence number of the netlink messages
 * @local: the bind address
 * @peer: the peer address
 */
struct nl_handler {
	int fd;
	int seq;
	struct sockaddr_nl local;
	struct sockaddr_nl peer;
};

/*
 * struct nlmsg : the netlink message structure. This message is to be used to
 *  be allocated with netlink_alloc.
 *
 * @nlmsghdr: a pointer to a netlink message header
 * @cap: capacity of the netlink message, this is the initially allocated size
 * 		and later operations (e.g. reserve and put) can not exceed this limit.
 */
struct nlmsg {
	struct nlmsghdr *nlmsghdr;
	ssize_t cap;
};

/*
 * netlink_open : open a netlink socket, the function will
 *  fill the handler with the right value
 *
 * @handler: a netlink handler to be used all along the netlink
 *  socket life cycle
 * @protocol: specify the protocol to be used when opening the
 *  netlink socket
 *
 * Return 0 on success, < 0 otherwise
 */
int netlink_open(struct nl_handler *handler, int protocol);

/*
 * netlink_close : close a netlink socket, after this call,
 *  the handler is no longer valid
 *
 * @handler: a handler to the netlink socket
 *
 * Returns 0 on success, < 0 otherwise
 */
int netlink_close(struct nl_handler *handler);

/*
 * netlink_rcv : receive a netlink message from the kernel.
 *  It is up to the caller to manage the allocation of the
 *  netlink message
 *
 * @handler: a handler to the netlink socket
 * @nlmsg: a netlink message
 *
 * Returns 0 on success, < 0 otherwise
 */
int netlink_rcv(struct nl_handler *handler, struct nlmsg *nlmsg);

/*
 * netlink_send: send a netlink message to the kernel. It is up
 *  to the caller to manage the allocate of the netlink message
 *
 * @handler: a handler to the netlink socket
 * @nlmsg: a netlink message
 *
 * Returns 0 on success, < 0 otherwise
 */
int netlink_send(struct nl_handler *handler, struct nlmsg *nlmsg);

/*
 * netlink_transaction: send a request to the kernel and read the response.
 *  This is useful for transactional protocol. It is up to the caller
 *  to manage the allocation of the netlink message.
 *
 * @handler: a handler to a opened netlink socket
 * @request: a netlink message pointer containing the request
 * @answer: a netlink message pointer to receive the result
 *
 * Returns 0 on success, < 0 otherwise
 */
int netlink_transaction(struct nl_handler *handler,
			struct nlmsg *request, struct nlmsg *anwser);

/*
 * nla_put_string: copy a null terminated string to a netlink message
 *  attribute
 *
 * @nlmsg: the netlink message to be filled
 * @attr: the attribute name of the string
 * @string: a null terminated string to be copied to the netlink message
 *
 * Returns 0 on success, < 0 otherwise
 */
int nla_put_string(struct nlmsg *nlmsg, int attr, const char *string);

/*
 * nla_put_buffer: copy a buffer with a specified size to a netlink
 * message attribute
 *
 * @nlmsg: the netlink message to be filled
 * @attr: the attribute name of the string
 * @data: a pointer to a buffer
 * @size: the size of the buffer
 *
 * Returns 0 on success, < 0 otherwise
 */
int nla_put_buffer(struct nlmsg *nlmsg, int attr,
		   const void *data, size_t size);

/*
 * nla_put_u32: copy an integer to a netlink message attribute
 *
 * @nlmsg: the netlink message to be filled
 * @attr: the attribute name of the integer
 * @string: an integer  to be copied to the netlink message
 *
 * Returns 0 on success, < 0 otherwise
 */
int nla_put_u32(struct nlmsg *nlmsg, int attr, int value);

/*
 * nla_put_u16: copy an integer to a netlink message attribute
 *
 * @nlmsg: the netlink message to be filled
 * @attr: the attribute name of the unsigned 16-bit value
 * @value: 16-bit attribute data value to be copied to the netlink message
 *
 * Returns 0 on success, < 0 otherwise
 */
int nla_put_u16(struct nlmsg *nlmsg, int attr, unsigned short value);

/*
 * nla_put_attr: add an attribute name to a netlink
 *
 * @nlmsg: the netlink message to be filled
 * @attr: the attribute name of the integer
 *
 * Returns 0 on success, < 0 otherwise
 */
int nla_put_attr(struct nlmsg *nlmsg, int attr);

/*
 * nla_begin_nested: begin the nesting attribute
 *
 * @nlmsg: the netlink message to be filled
 * @attr: the netsted attribute name
 *
 * Returns current nested pointer to be reused
 * to nla_end_nested.
 */
struct rtattr *nla_begin_nested(struct nlmsg *nlmsg, int attr);

/*
 * nla_end_nested: end the nesting attribute
 *
 * @nlmsg: the netlink message
 * @nested: the nested pointer
 *
 * Returns the current
 */
void nla_end_nested(struct nlmsg *nlmsg, struct rtattr *attr);

/*
 * nlmsg_allocate : allocate a netlink message. The netlink format message
 *  is a header, a padding, a payload and a padding again.
 *  When a netlink message is allocated, the size specify the
 *  payload we want. So the real size of the allocated message
 *  is sizeof(header) + sizeof(padding) + payloadsize + sizeof(padding),
 *  in other words, the function will allocate more than specified. When
 *  the buffer is allocated, the content is zeroed.
 *  The function will also fill the field nlmsg_len with NLMSG_HDRLEN.
 *  If the allocation must be for the specified size, just use malloc.
 *
 * @size: the capacity of the payload to be allocated
 *
 * Returns a pointer to the newly allocated netlink message, NULL otherwise
 */
struct nlmsg *nlmsg_alloc(size_t size);

/*
 * nlmsg_alloc_reserve: like nlmsg_alloc(), but reserve the whole payload
 *  after allocated, that is, the field nlmsg_len be set to the capacity
 *  of nlmsg. Often used to allocate a message for the reply.
 *
 * @size: the capacity of the payload to be allocated.
 */
struct nlmsg *nlmsg_alloc_reserve(size_t size);

/*
 * Reserve room for additional data at the tail of a netlink message
 *
 * @nlmsg: the netlink message
 * @len: length of additional data to reserve room for
 *
 * Returns a pointer to newly reserved room or NULL
 */
void *nlmsg_reserve(struct nlmsg *nlmsg, size_t len);

/*
 * nlmsg_free : free a previously allocate message
 *
 * @nlmsg: the netlink message to be freed
 */
void nlmsg_free(struct nlmsg *nlmsg);

/*
 * nlmsg_data : returns a pointer to the data contained in the netlink message
 *
 * @nlmsg : the netlink message to get the data
 *
 * Returns a pointer to the netlink data or NULL if there is no data
 */
void *nlmsg_data(struct nlmsg *nlmsg);


#endif

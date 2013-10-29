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
#define _GNU_SOURCE
#include <stdio.h>
#undef _GNU_SOURCe
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <linux/if_bridge.h>

#include "nl.h"
#include "network.h"
#include "conf.h"
#include "lxclock.h"

#ifndef IFLA_LINKMODE
#  define IFLA_LINKMODE 17
#endif

#ifndef IFLA_LINKINFO
#  define IFLA_LINKINFO 18
#endif

#ifndef IFLA_NET_NS_PID
#  define IFLA_NET_NS_PID 19
#endif

#ifndef IFLA_INFO_KIND
# define IFLA_INFO_KIND 1
#endif

#ifndef IFLA_VLAN_ID
# define IFLA_VLAN_ID 1
#endif

#ifndef IFLA_INFO_DATA
#  define IFLA_INFO_DATA 2
#endif

#ifndef VETH_INFO_PEER
# define VETH_INFO_PEER 1
#endif

#ifndef IFLA_MACVLAN_MODE
# define IFLA_MACVLAN_MODE 1
#endif

struct link_req {
	struct nlmsg nlmsg;
	struct ifinfomsg ifinfomsg;
};

struct ip_req {
	struct nlmsg nlmsg;
	struct ifaddrmsg ifa;
};

struct rt_req {
	struct nlmsg nlmsg;
	struct rtmsg rt;
};

int lxc_netdev_move_by_index(int ifindex, pid_t pid)
{
	struct nl_handler nlh;
	struct nlmsg *nlmsg = NULL;
	struct link_req *link_req;
	int err;

	err = netlink_open(&nlh, NETLINK_ROUTE);
	if (err)
		return err;

	err = -ENOMEM;
	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg)
		goto out;

	link_req = (struct link_req *)nlmsg;
	link_req->ifinfomsg.ifi_family = AF_UNSPEC;
	link_req->ifinfomsg.ifi_index = ifindex;
	nlmsg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	nlmsg->nlmsghdr.nlmsg_flags = NLM_F_REQUEST|NLM_F_ACK;
	nlmsg->nlmsghdr.nlmsg_type = RTM_NEWLINK;

	if (nla_put_u32(nlmsg, IFLA_NET_NS_PID, pid))
		goto out;

	err = netlink_transaction(&nlh, nlmsg, nlmsg);
out:
	netlink_close(&nlh);
	nlmsg_free(nlmsg);
	return err;
}

int lxc_netdev_delete_by_index(int ifindex)
{
	struct nl_handler nlh;
	struct nlmsg *nlmsg = NULL, *answer = NULL;
	struct link_req *link_req;
	int err;

	err = netlink_open(&nlh, NETLINK_ROUTE);
	if (err)
		return err;

	err = -ENOMEM;
	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg)
		goto out;

	answer = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!answer)
		goto out;

	link_req = (struct link_req *)nlmsg;
	link_req->ifinfomsg.ifi_family = AF_UNSPEC;
	link_req->ifinfomsg.ifi_index = ifindex;
	nlmsg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	nlmsg->nlmsghdr.nlmsg_flags = NLM_F_ACK|NLM_F_REQUEST;
	nlmsg->nlmsghdr.nlmsg_type = RTM_DELLINK;

	err = netlink_transaction(&nlh, nlmsg, answer);
out:
	netlink_close(&nlh);
	nlmsg_free(answer);
	nlmsg_free(nlmsg);
	return err;
}

int lxc_netdev_delete_by_name(const char *name)
{
	int index;

	index = if_nametoindex(name);
	if (!index)
		return -EINVAL;

	return lxc_netdev_delete_by_index(index);
}

int lxc_netdev_rename_by_index(int ifindex, const char *newname)
{
	struct nl_handler nlh;
	struct nlmsg *nlmsg = NULL, *answer = NULL;
	struct link_req *link_req;
	int len, err;

	err = netlink_open(&nlh, NETLINK_ROUTE);
	if (err)
		return err;

	len = strlen(newname);
	if (len == 1 || len >= IFNAMSIZ)
		goto out;

	err = -ENOMEM;
	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg)
		goto out;

	answer = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!answer)
		goto out;

	link_req = (struct link_req *)nlmsg;
	link_req->ifinfomsg.ifi_family = AF_UNSPEC;
	link_req->ifinfomsg.ifi_index = ifindex;
	nlmsg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	nlmsg->nlmsghdr.nlmsg_flags = NLM_F_ACK|NLM_F_REQUEST;
	nlmsg->nlmsghdr.nlmsg_type = RTM_NEWLINK;

	if (nla_put_string(nlmsg, IFLA_IFNAME, newname))
		goto out;

	err = netlink_transaction(&nlh, nlmsg, answer);
out:
	netlink_close(&nlh);
	nlmsg_free(answer);
	nlmsg_free(nlmsg);
	return err;
}

int lxc_netdev_rename_by_name(const char *oldname, const char *newname)
{
	int len, index;

	len = strlen(oldname);
	if (len == 1 || len >= IFNAMSIZ)
		return -EINVAL;

	index = if_nametoindex(oldname);
	if (!index)
		return -EINVAL;

	return lxc_netdev_rename_by_index(index, newname);
}

static int netdev_set_flag(const char *name, int flag)
{
	struct nl_handler nlh;
	struct nlmsg *nlmsg = NULL, *answer = NULL;
	struct link_req *link_req;
	int index, len, err;

	err = netlink_open(&nlh, NETLINK_ROUTE);
	if (err)
		return err;

	err = -EINVAL;
	len = strlen(name);
	if (len == 1 || len >= IFNAMSIZ)
		goto out;

	err = -ENOMEM;
	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg)
		goto out;

	answer = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!answer)
		goto out;

	err = -EINVAL;
	index = if_nametoindex(name);
	if (!index)
		goto out;

	link_req = (struct link_req *)nlmsg;
	link_req->ifinfomsg.ifi_family = AF_UNSPEC;
	link_req->ifinfomsg.ifi_index = index;
	link_req->ifinfomsg.ifi_change |= IFF_UP;
	link_req->ifinfomsg.ifi_flags |= flag;
	nlmsg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	nlmsg->nlmsghdr.nlmsg_flags = NLM_F_REQUEST|NLM_F_ACK;
	nlmsg->nlmsghdr.nlmsg_type = RTM_NEWLINK;

	err = netlink_transaction(&nlh, nlmsg, answer);
out:
	netlink_close(&nlh);
	nlmsg_free(nlmsg);
	nlmsg_free(answer);
	return err;
}

int lxc_netdev_set_mtu(const char *name, int mtu)
{
	struct nl_handler nlh;
	struct nlmsg *nlmsg = NULL, *answer = NULL;
	struct link_req *link_req;
	int index, len, err;

	err = netlink_open(&nlh, NETLINK_ROUTE);
	if (err)
		return err;

	err = -EINVAL;
	len = strlen(name);
	if (len == 1 || len >= IFNAMSIZ)
		goto out;

	err = -ENOMEM;
	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg)
		goto out;

	answer = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!answer)
		goto out;

	err = -EINVAL;
	index = if_nametoindex(name);
	if (!index)
		goto out;

	link_req = (struct link_req *)nlmsg;
	link_req->ifinfomsg.ifi_family = AF_UNSPEC;
	link_req->ifinfomsg.ifi_index = index;
	nlmsg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	nlmsg->nlmsghdr.nlmsg_flags = NLM_F_REQUEST|NLM_F_ACK;
	nlmsg->nlmsghdr.nlmsg_type = RTM_NEWLINK;

	if (nla_put_u32(nlmsg, IFLA_MTU, mtu))
		goto out;

	err = netlink_transaction(&nlh, nlmsg, answer);
out:
	netlink_close(&nlh);
	nlmsg_free(nlmsg);
	nlmsg_free(answer);
	return err;
}

int lxc_netdev_up(const char *name)
{
	return netdev_set_flag(name, IFF_UP);
}

int lxc_netdev_down(const char *name)
{
	return netdev_set_flag(name, 0);
}

int lxc_veth_create(const char *name1, const char *name2)
{
	struct nl_handler nlh;
	struct nlmsg *nlmsg = NULL, *answer = NULL;
	struct link_req *link_req;
	struct rtattr *nest1, *nest2, *nest3;
	int len, err;

	err = netlink_open(&nlh, NETLINK_ROUTE);
	if (err)
		return err;

	err = -EINVAL;
	len = strlen(name1);
	if (len == 1 || len >= IFNAMSIZ)
		goto out;

	len = strlen(name2);
	if (len == 1 || len >= IFNAMSIZ)
		goto out;

	err = -ENOMEM;
	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg)
		goto out;

	answer = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!answer)
		goto out;

	link_req = (struct link_req *)nlmsg;
	link_req->ifinfomsg.ifi_family = AF_UNSPEC;
	nlmsg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	nlmsg->nlmsghdr.nlmsg_flags =
		NLM_F_REQUEST|NLM_F_CREATE|NLM_F_EXCL|NLM_F_ACK;
	nlmsg->nlmsghdr.nlmsg_type = RTM_NEWLINK;

	err = -EINVAL;
	nest1 = nla_begin_nested(nlmsg, IFLA_LINKINFO);
	if (!nest1)
		goto out;

	if (nla_put_string(nlmsg, IFLA_INFO_KIND, "veth"))
		goto out;

	nest2 = nla_begin_nested(nlmsg, IFLA_INFO_DATA);
	if (!nest2)
		goto out;

	nest3 = nla_begin_nested(nlmsg, VETH_INFO_PEER);
	if (!nest3)
		goto out;

	nlmsg->nlmsghdr.nlmsg_len += sizeof(struct ifinfomsg);

	if (nla_put_string(nlmsg, IFLA_IFNAME, name2))
		goto out;

	nla_end_nested(nlmsg, nest3);

	nla_end_nested(nlmsg, nest2);

	nla_end_nested(nlmsg, nest1);

	if (nla_put_string(nlmsg, IFLA_IFNAME, name1))
		goto out;

	err = netlink_transaction(&nlh, nlmsg, answer);
out:
	netlink_close(&nlh);
	nlmsg_free(answer);
	nlmsg_free(nlmsg);
	return err;
}

/* XXX: merge with lxc_macvlan_create */
int lxc_vlan_create(const char *master, const char *name, unsigned short vlanid)
{
	struct nl_handler nlh;
	struct nlmsg *nlmsg = NULL, *answer = NULL;
	struct link_req *link_req;
	struct rtattr *nest, *nest2;
	int lindex, len, err;

	err = netlink_open(&nlh, NETLINK_ROUTE);
	if (err)
		return err;

	err = -EINVAL;
	len = strlen(master);
	if (len == 1 || len >= IFNAMSIZ)
		goto err3;

	len = strlen(name);
	if (len == 1 || len >= IFNAMSIZ)
		goto err3;

	err = -ENOMEM;
	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg)
		goto err3;

	answer = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!answer)
		goto err2;

	err = -EINVAL;
	lindex = if_nametoindex(master);
	if (!lindex)
		goto err1;

	link_req = (struct link_req *)nlmsg;
	link_req->ifinfomsg.ifi_family = AF_UNSPEC;
	nlmsg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	nlmsg->nlmsghdr.nlmsg_flags =
		NLM_F_REQUEST|NLM_F_CREATE|NLM_F_EXCL|NLM_F_ACK;
	nlmsg->nlmsghdr.nlmsg_type = RTM_NEWLINK;

	nest = nla_begin_nested(nlmsg, IFLA_LINKINFO);
	if (!nest)
		goto err1;

	if (nla_put_string(nlmsg, IFLA_INFO_KIND, "vlan"))
		goto err1;

	nest2 = nla_begin_nested(nlmsg, IFLA_INFO_DATA);
	if (!nest2)
		goto err1;

	if (nla_put_u16(nlmsg, IFLA_VLAN_ID, vlanid))
		goto err1;

	nla_end_nested(nlmsg, nest2);

	nla_end_nested(nlmsg, nest);

	if (nla_put_u32(nlmsg, IFLA_LINK, lindex))
		goto err1;

	if (nla_put_string(nlmsg, IFLA_IFNAME, name))
		goto err1;

	err = netlink_transaction(&nlh, nlmsg, answer);
err1:
	nlmsg_free(answer);
err2:
	nlmsg_free(nlmsg);
err3:
	netlink_close(&nlh);
	return err;
}

int lxc_macvlan_create(const char *master, const char *name, int mode)
{
	struct nl_handler nlh;
	struct nlmsg *nlmsg = NULL, *answer = NULL;
	struct link_req *link_req;
	struct rtattr *nest, *nest2;
	int index, len, err;

	err = netlink_open(&nlh, NETLINK_ROUTE);
	if (err)
		return err;

	err = -EINVAL;
	len = strlen(master);
	if (len == 1 || len >= IFNAMSIZ)
		goto out;

	len = strlen(name);
	if (len == 1 || len >= IFNAMSIZ)
		goto out;

	err = -ENOMEM;
	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg)
		goto out;

	answer = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!answer)
		goto out;

	err = -EINVAL;
	index = if_nametoindex(master);
	if (!index)
		goto out;

	link_req = (struct link_req *)nlmsg;
	link_req->ifinfomsg.ifi_family = AF_UNSPEC;
	nlmsg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	nlmsg->nlmsghdr.nlmsg_flags =
		NLM_F_REQUEST|NLM_F_CREATE|NLM_F_EXCL|NLM_F_ACK;
	nlmsg->nlmsghdr.nlmsg_type = RTM_NEWLINK;

	nest = nla_begin_nested(nlmsg, IFLA_LINKINFO);
	if (!nest)
		goto out;

	if (nla_put_string(nlmsg, IFLA_INFO_KIND, "macvlan"))
		goto out;

	if (mode) {
		nest2 = nla_begin_nested(nlmsg, IFLA_INFO_DATA);
		if (!nest2)
			goto out;

		if (nla_put_u32(nlmsg, IFLA_MACVLAN_MODE, mode))
			goto out;

		nla_end_nested(nlmsg, nest2);
	}

	nla_end_nested(nlmsg, nest);

	if (nla_put_u32(nlmsg, IFLA_LINK, index))
		goto out;

	if (nla_put_string(nlmsg, IFLA_IFNAME, name))
		goto out;

	err = netlink_transaction(&nlh, nlmsg, answer);
out:
	netlink_close(&nlh);
	nlmsg_free(answer);
	nlmsg_free(nlmsg);
	return err;
}

static int proc_sys_net_write(const char *path, const char *value)
{
	int fd, err = 0;

	process_lock();
	fd = open(path, O_WRONLY);
	process_unlock();
	if (fd < 0)
		return -errno;

	if (write(fd, value, strlen(value)) < 0)
		err = -errno;

	process_lock();
	close(fd);
	process_unlock();
	return err;
}

static int ip_forward_set(const char *ifname, int family, int flag)
{
	char path[MAXPATHLEN];
	int rc;

	if (family != AF_INET && family != AF_INET6)
		return -EINVAL;

	rc = snprintf(path, MAXPATHLEN, "/proc/sys/net/%s/conf/%s/forwarding",
		 family == AF_INET?"ipv4":"ipv6" , ifname);
	if (rc >= MAXPATHLEN)
		return -E2BIG;

	return proc_sys_net_write(path, flag?"1":"0");
}

int lxc_ip_forward_on(const char *ifname, int family)
{
	return ip_forward_set(ifname, family, 1);
}

int lxc_ip_forward_off(const char *ifname, int family)
{
	return ip_forward_set(ifname, family, 0);
}

static int neigh_proxy_set(const char *ifname, int family, int flag)
{
	char path[MAXPATHLEN];
	int ret;

	if (family != AF_INET && family != AF_INET6)
		return -EINVAL;

	ret = snprintf(path, MAXPATHLEN, "/proc/sys/net/%s/conf/%s/%s",
		family == AF_INET?"ipv4":"ipv6" , ifname,
		family == AF_INET?"proxy_arp":"proxy_ndp");
	if (ret < 0 || ret >= MAXPATHLEN)
		return -E2BIG;

	return proc_sys_net_write(path, flag?"1":"0");
}

int lxc_neigh_proxy_on(const char *name, int family)
{
	return neigh_proxy_set(name, family, 1);
}

int lxc_neigh_proxy_off(const char *name, int family)
{
	return neigh_proxy_set(name, family, 0);
}

int lxc_convert_mac(char *macaddr, struct sockaddr *sockaddr)
{
	unsigned char *data;
	char c;
	int i = 0;
	unsigned val;

	sockaddr->sa_family = ARPHRD_ETHER;
	data = (unsigned char *)sockaddr->sa_data;

	while ((*macaddr != '\0') && (i < ETH_ALEN)) {
	    val = 0;
	    c = *macaddr++;
	    if (isdigit(c))
		    val = c - '0';
	    else if (c >= 'a' && c <= 'f')
		    val = c - 'a' + 10;
	    else if (c >= 'A' && c <= 'F')
		    val = c - 'A' + 10;
	    else {
		    return -EINVAL;
	    }
	    val <<= 4;
	    c = *macaddr;
	    if (isdigit(c))
		    val |= c - '0';
	    else if (c >= 'a' && c <= 'f')
		    val |= c - 'a' + 10;
	    else if (c >= 'A' && c <= 'F')
		    val |= c - 'A' + 10;
	    else if (c == ':' || c == 0)
		    val >>= 4;
	    else {
		    return -EINVAL;
	    }
	    if (c != 0)
		    macaddr++;
	    *data++ = (unsigned char) (val & 0377);
	    i++;

	    if (*macaddr == ':')
		    macaddr++;
	}

	return 0;
}

static int ip_addr_add(int family, int ifindex,
		       void *addr, void *bcast, void *acast, int prefix)
{
	struct nl_handler nlh;
	struct nlmsg *nlmsg = NULL, *answer = NULL;
	struct ip_req *ip_req;
	int addrlen;
	int err;

	addrlen = family == AF_INET ? sizeof(struct in_addr) :
		sizeof(struct in6_addr);

	err = netlink_open(&nlh, NETLINK_ROUTE);
	if (err)
		return err;

	err = -ENOMEM;
	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg)
		goto out;

	answer = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!answer)
		goto out;

	ip_req = (struct ip_req *)nlmsg;
        ip_req->nlmsg.nlmsghdr.nlmsg_len =
		NLMSG_LENGTH(sizeof(struct ifaddrmsg));
        ip_req->nlmsg.nlmsghdr.nlmsg_flags =
		NLM_F_ACK|NLM_F_REQUEST|NLM_F_CREATE|NLM_F_EXCL;
        ip_req->nlmsg.nlmsghdr.nlmsg_type = RTM_NEWADDR;
	ip_req->ifa.ifa_prefixlen = prefix;
        ip_req->ifa.ifa_index = ifindex;
        ip_req->ifa.ifa_family = family;
	ip_req->ifa.ifa_scope = 0;
	
	err = -EINVAL;
	if (nla_put_buffer(nlmsg, IFA_LOCAL, addr, addrlen))
		goto out;

	if (nla_put_buffer(nlmsg, IFA_ADDRESS, addr, addrlen))
		goto out;

	if (nla_put_buffer(nlmsg, IFA_BROADCAST, bcast, addrlen))
		goto out;

	/* TODO : multicast, anycast with ipv6 */
	err = -EPROTONOSUPPORT;
	if (family == AF_INET6 &&
	    (memcmp(bcast, &in6addr_any, sizeof(in6addr_any)) ||
	     memcmp(acast, &in6addr_any, sizeof(in6addr_any))))
		goto out;

	err = netlink_transaction(&nlh, nlmsg, answer);
out:
	netlink_close(&nlh);
	nlmsg_free(answer);
	nlmsg_free(nlmsg);
	return err;
}

int lxc_ipv6_addr_add(int ifindex, struct in6_addr *addr,
		      struct in6_addr *mcast,
		      struct in6_addr *acast, int prefix)
{
	return ip_addr_add(AF_INET6, ifindex, addr, mcast, acast, prefix);
}

int lxc_ipv4_addr_add(int ifindex, struct in_addr *addr,
		      struct in_addr *bcast, int prefix)
{
	return ip_addr_add(AF_INET, ifindex, addr, bcast, NULL, prefix);
}

/* Find an IFA_LOCAL (or IFA_ADDRESS if not IFA_LOCAL is present)
 * address from the given RTM_NEWADDR message.  Allocates memory for the
 * address and stores that pointer in *res (so res should be an
 * in_addr** or in6_addr**).
 */
static int ifa_get_local_ip(int family, struct ip_req *ip_info, void** res) {
	struct rtattr *rta = IFA_RTA(&ip_info->ifa);
	int attr_len = IFA_PAYLOAD(&ip_info->nlmsg.nlmsghdr);
	int addrlen;

	if (ip_info->ifa.ifa_family != family)
		return 0;

	addrlen = family == AF_INET ? sizeof(struct in_addr) :
		sizeof(struct in6_addr);

	/* Loop over the rtattr's in this message */
	while(RTA_OK(rta, attr_len)) {
		/* Found a local address for the requested interface,
		 * return it. */
		if (rta->rta_type == IFA_LOCAL || rta->rta_type == IFA_ADDRESS) {
			/* Sanity check. The family check above should
			 * make sure the address length is correct, but
			 * check here just in case */
			if (RTA_PAYLOAD(rta) != addrlen)
				return -1;

			/* We might have found an IFA_ADDRESS before,
			 * which we now overwrite with an IFA_LOCAL. */
			if (!*res) {
				*res = malloc(addrlen);
				if (!*res)
					return -1;
			}

			memcpy(*res, RTA_DATA(rta), addrlen);

			if (rta->rta_type == IFA_LOCAL)
				break;
		}
		rta = RTA_NEXT(rta, attr_len);
	}
	return 0;
}

static int ip_addr_get(int family, int ifindex, void **res)
{
	struct nl_handler nlh;
	struct nlmsg *nlmsg = NULL, *answer = NULL;
	struct ip_req *ip_req, *ip_info;
	struct nlmsghdr *msg;
	int err;
	int recv_len = 0, answer_len;
	int readmore = 0;

	err = netlink_open(&nlh, NETLINK_ROUTE);
	if (err)
		return err;

	err = -ENOMEM;
	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg)
		goto out;

	answer = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!answer)
		goto out;

	/* Save the answer buffer length, since it will be overwritten
	 * on the first receive (and we might need to receive more than
	 * once. */
	answer_len = answer->nlmsghdr.nlmsg_len;

	ip_req = (struct ip_req *)nlmsg;
	ip_req->nlmsg.nlmsghdr.nlmsg_len =
		NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	ip_req->nlmsg.nlmsghdr.nlmsg_flags = NLM_F_REQUEST|NLM_F_ROOT;
	ip_req->nlmsg.nlmsghdr.nlmsg_type = RTM_GETADDR;
	ip_req->ifa.ifa_family = family;

	/* Send the request for addresses, which returns all addresses
	 * on all interfaces. */
	err = netlink_send(&nlh, nlmsg);
	if (err < 0)
		goto out;

	do {
		/* Restore the answer buffer length, it might have been
		 * overwritten by a previous receive. */
		answer->nlmsghdr.nlmsg_len = answer_len;

		/* Get the (next) batch of reply messages */
		err = netlink_rcv(&nlh, answer);
		if (err < 0)
			goto out;

		recv_len = err;
		err = 0;

		/* Satisfy the typing for the netlink macros */
		msg = &answer->nlmsghdr;

		while (NLMSG_OK(msg, recv_len)) {
			/* Stop reading if we see an error message */
			if (msg->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *errmsg = (struct nlmsgerr*)NLMSG_DATA(msg);
				err = errmsg->error;
				goto out;
			}

			/* Stop reading if we see a NLMSG_DONE message */
			if (msg->nlmsg_type == NLMSG_DONE) {
				readmore = 0;
				break;
			}

			if (msg->nlmsg_type != RTM_NEWADDR) {
				err = -1;
				goto out;
			}

			ip_info = (struct ip_req *)msg;
			if (ip_info->ifa.ifa_index == ifindex) {
				if (ifa_get_local_ip(family, ip_info, res) < 0) {
					err = -1;
					goto out;
				}

				/* Found a result, stop searching */
				if (*res)
					goto out;
			}

			/* Keep reading more data from the socket if the
			 * last message had the NLF_F_MULTI flag set */
			readmore = (msg->nlmsg_flags & NLM_F_MULTI);

			/* Look at the next message received in this buffer */
			msg = NLMSG_NEXT(msg, recv_len);
		}
	} while (readmore);

	/* If we end up here, we didn't find any result, so signal an
	 * error */
	err = -1;

out:
	netlink_close(&nlh);
	nlmsg_free(answer);
	nlmsg_free(nlmsg);
	return err;
}

int lxc_ipv6_addr_get(int ifindex, struct in6_addr **res)
{
	return ip_addr_get(AF_INET6, ifindex, (void**)res);
}

int lxc_ipv4_addr_get(int ifindex, struct in_addr** res)
{
	return ip_addr_get(AF_INET, ifindex, (void**)res);
}

static int ip_gateway_add(int family, int ifindex, void *gw)
{
	struct nl_handler nlh;
	struct nlmsg *nlmsg = NULL, *answer = NULL;
	struct rt_req *rt_req;
	int addrlen;
	int err;

	addrlen = family == AF_INET ? sizeof(struct in_addr) :
		sizeof(struct in6_addr);

	err = netlink_open(&nlh, NETLINK_ROUTE);
	if (err)
		return err;

	err = -ENOMEM;
	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg)
		goto out;

	answer = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!answer)
		goto out;

	rt_req = (struct rt_req *)nlmsg;
	rt_req->nlmsg.nlmsghdr.nlmsg_len =
		NLMSG_LENGTH(sizeof(struct rtmsg));
	rt_req->nlmsg.nlmsghdr.nlmsg_flags =
		NLM_F_ACK|NLM_F_REQUEST|NLM_F_CREATE|NLM_F_EXCL;
	rt_req->nlmsg.nlmsghdr.nlmsg_type = RTM_NEWROUTE;
	rt_req->rt.rtm_family = family;
	rt_req->rt.rtm_table = RT_TABLE_MAIN;
	rt_req->rt.rtm_scope = RT_SCOPE_UNIVERSE;
	rt_req->rt.rtm_protocol = RTPROT_BOOT;
	rt_req->rt.rtm_type = RTN_UNICAST;
	/* "default" destination */
	rt_req->rt.rtm_dst_len = 0;

	err = -EINVAL;
	if (nla_put_buffer(nlmsg, RTA_GATEWAY, gw, addrlen))
		goto out;

	/* Adding the interface index enables the use of link-local
	 * addresses for the gateway */
	if (nla_put_u32(nlmsg, RTA_OIF, ifindex))
		goto out;

	err = netlink_transaction(&nlh, nlmsg, answer);
out:
	netlink_close(&nlh);
	nlmsg_free(answer);
	nlmsg_free(nlmsg);
	return err;
}

int lxc_ipv4_gateway_add(int ifindex, struct in_addr *gw)
{
	return ip_gateway_add(AF_INET, ifindex, gw);
}

int lxc_ipv6_gateway_add(int ifindex, struct in6_addr *gw)
{
	return ip_gateway_add(AF_INET6, ifindex, gw);
}

static int ip_route_dest_add(int family, int ifindex, void *dest)
{
	struct nl_handler nlh;
	struct nlmsg *nlmsg = NULL, *answer = NULL;
	struct rt_req *rt_req;
	int addrlen;
	int err;
	
	addrlen = family == AF_INET ? sizeof(struct in_addr) :
		sizeof(struct in6_addr);
	
	err = netlink_open(&nlh, NETLINK_ROUTE);
	if (err)
		return err;
	
	err = -ENOMEM;
	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg)
		goto out;
	
	answer = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!answer)
		goto out;
	
	rt_req = (struct rt_req *)nlmsg;
	rt_req->nlmsg.nlmsghdr.nlmsg_len =
		NLMSG_LENGTH(sizeof(struct rtmsg));
	rt_req->nlmsg.nlmsghdr.nlmsg_flags =
		NLM_F_ACK|NLM_F_REQUEST|NLM_F_CREATE|NLM_F_EXCL;
	rt_req->nlmsg.nlmsghdr.nlmsg_type = RTM_NEWROUTE;
	rt_req->rt.rtm_family = family;
	rt_req->rt.rtm_table = RT_TABLE_MAIN;
	rt_req->rt.rtm_scope = RT_SCOPE_LINK;
	rt_req->rt.rtm_protocol = RTPROT_BOOT;
	rt_req->rt.rtm_type = RTN_UNICAST;
	rt_req->rt.rtm_dst_len = addrlen*8;
	
	err = -EINVAL;
	if (nla_put_buffer(nlmsg, RTA_DST, dest, addrlen))
		goto out;
	if (nla_put_u32(nlmsg, RTA_OIF, ifindex))
		goto out;
	err = netlink_transaction(&nlh, nlmsg, answer);
out:
	netlink_close(&nlh);
	nlmsg_free(answer);
	nlmsg_free(nlmsg);
	return err;
}

int lxc_ipv4_dest_add(int ifindex, struct in_addr *dest)
{
	return ip_route_dest_add(AF_INET, ifindex, dest);
}

int lxc_ipv6_dest_add(int ifindex, struct in6_addr *dest)
{
	return ip_route_dest_add(AF_INET6, ifindex, dest);
}

/*
 * There is a lxc_bridge_attach, but no need of a bridge detach
 * as automatically done by kernel when a netdev is deleted.
 */
int lxc_bridge_attach(const char *bridge, const char *ifname)
{
	int fd, index, err;
	struct ifreq ifr;

	if (strlen(ifname) >= IFNAMSIZ)
		return -EINVAL;

	index = if_nametoindex(ifname);
	if (!index)
		return -EINVAL;

	process_lock();
	fd = socket(AF_INET, SOCK_STREAM, 0);
	process_unlock();
	if (fd < 0)
		return -errno;

	strncpy(ifr.ifr_name, bridge, IFNAMSIZ);
	ifr.ifr_ifindex = index;
	err = ioctl(fd, SIOCBRADDIF, &ifr);
	process_lock();
	close(fd);
	process_unlock();
	if (err)
		err = -errno;

	return err;
}

static char* lxc_network_types[LXC_NET_MAXCONFTYPE + 1] = {
	[LXC_NET_VETH]    = "veth",
	[LXC_NET_MACVLAN] = "macvlan",
	[LXC_NET_VLAN]    = "vlan",
	[LXC_NET_PHYS]    = "phys",
	[LXC_NET_EMPTY]   = "empty",
};

const char *lxc_net_type_to_str(int type)
{
	if (type < 0 || type > LXC_NET_MAXCONFTYPE)
		return NULL;
	return lxc_network_types[type];
}

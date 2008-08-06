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
#include <nl.h>
#include <network.h>

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

#ifndef IFLA_INFO_DATA
#  define IFLA_INFO_DATA 2
#endif

#ifndef VETH_INFO_PEER
# define VETH_INFO_PEER 1
#endif

struct link_req {
	struct nlmsg nlmsg;
	struct ifinfomsg ifinfomsg;
};

struct ip_req {
	struct nlmsg nlmsg;
	struct ifaddrmsg ifa;
};

int device_move(const char *name, pid_t pid)
{
	struct nl_handler nlh;
	struct nlmsg *nlmsg = NULL;
	struct link_req *link_req;
	int index, len, err = -1;

	if (netlink_open(&nlh, NETLINK_ROUTE))
		return -1;

	len = strlen(name);
	if (len == 1 || len > IFNAMSIZ)
		goto out;

	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg)
		goto out;

	index = if_nametoindex(name);
	if (!index)
		goto out;

	link_req = (struct link_req *)nlmsg;
	link_req->ifinfomsg.ifi_family = AF_UNSPEC;
	link_req->ifinfomsg.ifi_index = index;
	nlmsg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	nlmsg->nlmsghdr.nlmsg_flags = NLM_F_REQUEST|NLM_F_ACK;
	nlmsg->nlmsghdr.nlmsg_type = RTM_NEWLINK;

	if (nla_put_u32(nlmsg, IFLA_NET_NS_PID, pid))
		goto out;

	if (nla_put_string(nlmsg, IFLA_IFNAME, name))
		goto out;

	if (netlink_transaction(&nlh, nlmsg, nlmsg))
		goto out;

	err = 0;
out:
	netlink_close(&nlh);
	nlmsg_free(nlmsg);
	return err;
}

extern int device_delete(const char *name)
{
	struct nl_handler nlh;
	struct nlmsg *nlmsg = NULL, *answer = NULL;
	struct link_req *link_req;
	int index, len, err = -1;

	if (netlink_open(&nlh, NETLINK_ROUTE))
		return -1;

	len = strlen(name);
	if (len == 1 || len > IFNAMSIZ)
		goto out;

	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg)
		goto out;

	answer = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!answer)
		goto out;

	index = if_nametoindex(name);
	if (!index)
		goto out;

	link_req = (struct link_req *)nlmsg;
	link_req->ifinfomsg.ifi_family = AF_UNSPEC;
	link_req->ifinfomsg.ifi_index = index;
	nlmsg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	nlmsg->nlmsghdr.nlmsg_flags = NLM_F_ACK|NLM_F_REQUEST;
	nlmsg->nlmsghdr.nlmsg_type = RTM_DELLINK;

	if (nla_put_string(nlmsg, IFLA_IFNAME, name))
		goto out;

	if (netlink_transaction(&nlh, nlmsg, answer))
		goto out;

	err = 0;
out:
	netlink_close(&nlh);
	nlmsg_free(answer);
	nlmsg_free(nlmsg);
	return err;
}

static int device_set_flag(const char *name, int flag)
{
	struct nl_handler nlh;
	struct nlmsg *nlmsg = NULL, *answer = NULL;
	struct link_req *link_req;
	int index, len, err = -1;

	if (netlink_open(&nlh, NETLINK_ROUTE))
		return -1;

	len = strlen(name);
	if (len == 1 || len > IFNAMSIZ)
		goto out;

	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg)
		goto out;

	answer = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!answer)
		goto out;

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
	if (err < 0)
		goto out;

	err = 0;
out:
	netlink_close(&nlh);
	nlmsg_free(nlmsg);
	nlmsg_free(answer);
	return err;
}

int device_up(const char *name)
{
	return device_set_flag(name, IFF_UP);
}

int device_down(const char *name)
{
	return device_set_flag(name, 0);
}

int device_rename(const char *oldname, const char *newname)
{
	struct nl_handler nlh;
	struct nlmsg *nlmsg = NULL, *answer = NULL;
	struct link_req *link_req;
	int index, len, err = -1;

	if (netlink_open(&nlh, NETLINK_ROUTE))
		return -1;

	len = strlen(oldname);
	if (len == 1 || len > IFNAMSIZ)
		goto out;

	len = strlen(newname);
	if (len == 1 || len > IFNAMSIZ)
		goto out;

	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg)
		goto out;

	answer = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!answer)
		goto out;

	index = if_nametoindex(oldname);
	if (!index)
		goto out;

	link_req = (struct link_req *)nlmsg;
	link_req->ifinfomsg.ifi_family = AF_UNSPEC;
	link_req->ifinfomsg.ifi_index = index;
	nlmsg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	nlmsg->nlmsghdr.nlmsg_flags = NLM_F_ACK|NLM_F_REQUEST;
	nlmsg->nlmsghdr.nlmsg_type = RTM_NEWLINK;

	if (nla_put_string(nlmsg, IFLA_IFNAME, newname))
		goto out;

	if (netlink_transaction(&nlh, nlmsg, answer))
		goto out;

	err = 0;
out:
	netlink_close(&nlh);
	nlmsg_free(answer);
	nlmsg_free(nlmsg);
	return err;
}

int veth_create(const char *name1, const char *name2)
{
	struct nl_handler nlh;
	struct nlmsg *nlmsg = NULL, *answer = NULL;
	struct link_req *link_req;
	struct rtattr *nest1, *nest2, *nest3;
	int len, err = -1;

	if (netlink_open(&nlh, NETLINK_ROUTE))
		return -1;

	len = strlen(name1);
	if (len == 1 || len > IFNAMSIZ)
		goto out;

	len = strlen(name2);
	if (len == 1 || len > IFNAMSIZ)
		goto out;

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

	if (netlink_transaction(&nlh, nlmsg, answer))
		goto out;

	err = 0;
out:
	netlink_close(&nlh);
	nlmsg_free(answer);
	nlmsg_free(nlmsg);
	return err;
}

int macvlan_create(const char *master, const char *name)
{
	struct nl_handler nlh;
	struct nlmsg *nlmsg = NULL, *answer = NULL;
	struct link_req *link_req;
	struct rtattr *nest;
	int index, len, err = -1;

	if (netlink_open(&nlh, NETLINK_ROUTE))
		return -1;

	len = strlen(master);
	if (len == 1 || len > IFNAMSIZ)
		goto out;

	len = strlen(name);
	if (len == 1 || len > IFNAMSIZ)
		goto out;

	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg)
		goto out;

	answer = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!answer)
		goto out;

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

	nla_end_nested(nlmsg, nest);

	if (nla_put_u32(nlmsg, IFLA_LINK, index))
		goto out;

	if (nla_put_string(nlmsg, IFLA_IFNAME, name))
		goto out;

	if (netlink_transaction(&nlh, nlmsg, answer))
		goto out;

	err = 0;
out:
	netlink_close(&nlh);
	nlmsg_free(answer);
	nlmsg_free(nlmsg);
	return err;
}

static int proc_sys_net_write(const char *path, const char *value)
{
	int fd, err = 0;

	fd = open(path, O_WRONLY);
	if (fd < 0)
		return -errno;

	if (write(fd, value, strlen(value)) < 0)
		err = -errno;

	close(fd);
	return err;
}

static int ip_forward_set(const char *ifname, int family, int flag)
{
	char *path;
	int ret;

	if (family != AF_INET && family != AF_INET6)
		return -1;

	asprintf(&path, "/proc/sys/net/%s/conf/%s/forwarding", 
		 family == AF_INET?"ipv4":"ipv6" , ifname);

	ret = proc_sys_net_write(path, flag?"1":"0");
	free(path);

	return ret;
}

int ip_forward_on(const char *ifname, int family)
{
	return ip_forward_set(ifname, family, 1);
}

int ip_forward_off(const char *ifname, int family)
{
	return ip_forward_set(ifname, family, 0);
}

static int neigh_proxy_set(const char *ifname, int family, int flag)
{
	char path[MAXPATHLEN];

	if (family != AF_INET && family != AF_INET6)
		return -1;

	sprintf(path, "/proc/sys/net/%s/conf/%s/%s", 
		family == AF_INET?"ipv4":"ipv6" , ifname, 
		family == AF_INET?"proxy_arp":"proxy_ndp");

	return proc_sys_net_write(path, flag?"1":"0");
}

int neigh_proxy_on(const char *name, int family)
{
	return neigh_proxy_set(name, family, 1);
}

int neigh_proxy_off(const char *name, int family)
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
	    return -1;
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
	    return -1;
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

int ip_addr_add(const char *ifname, const char *addr, 
		int prefix, const char *bcast)
{
	struct nl_handler nlh;
	struct in_addr in_addr;
/* 	struct in_addr in_bcast; */
	struct nlmsg *nlmsg = NULL, *answer = NULL;
	struct ip_req *ip_req;
	int ifindex, err = -1;

	if (netlink_open(&nlh, NETLINK_ROUTE))
		return -1;

	if (inet_pton(AF_INET, addr, (void *)&in_addr) < 0)
		goto out;

/* 	if (inet_pton(AF_INET, bcast, (void *)&in_bcast) < 0) */
/* 			goto out; */

	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg)
		goto out;

	answer = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!answer)
		goto out;

	ifindex = if_nametoindex(ifname);
	if (!ifindex)
		goto out;

	ip_req = (struct ip_req *)nlmsg;
        ip_req->nlmsg.nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
        ip_req->nlmsg.nlmsghdr.nlmsg_flags =
		NLM_F_ACK|NLM_F_REQUEST|NLM_F_CREATE|NLM_F_EXCL;
        ip_req->nlmsg.nlmsghdr.nlmsg_type = RTM_NEWADDR;
	ip_req->ifa.ifa_prefixlen = prefix;
        ip_req->ifa.ifa_index = ifindex;
        ip_req->ifa.ifa_family = AF_INET;
	ip_req->ifa.ifa_scope = 0;
	
	if (nla_put_buffer(nlmsg, IFA_LOCAL, &in_addr, sizeof(in_addr)))
		goto out;

	if (nla_put_buffer(nlmsg, IFA_ADDRESS, &in_addr, sizeof(in_addr)))
		goto out;

/* 	if (in_bcast.s_addr != INADDR_ANY) */
/* 		if (nla_put_buffer(nlmsg, IFA_BROADCAST, &in_bcast, */
/* 				   sizeof(in_bcast))) */
/* 			goto out; */

	if (netlink_transaction(&nlh, nlmsg, answer))
		goto out;

	err = 0;
out:
	netlink_close(&nlh);
	nlmsg_free(answer);
	nlmsg_free(nlmsg);
	return err;
}

int ip6_addr_add(const char *ifname, const char *addr, 
		int prefix, const char *bcast)
{
	struct nl_handler nlh;
	struct in6_addr in6_addr;
/* 	struct in6_addr in6_bcast; */
	struct nlmsg *nlmsg = NULL, *answer = NULL;
	struct ip_req *ip_req;
	int ifindex, err = -1;

	if (netlink_open(&nlh, NETLINK_ROUTE))
		return -1;

	if (inet_pton(AF_INET6, addr, (void *)&in6_addr) < 0)
		goto out;


/* 	if (inet_pton(AF_INET6, bcast, (void *)&in6_bcast) < 0) */
/* 			goto out; */

	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg)
		goto out;

	answer = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!answer)
		goto out;

	ifindex = if_nametoindex(ifname);
	if (!ifindex)
		goto out;

	ip_req = (struct ip_req *)nlmsg;
        ip_req->nlmsg.nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
        ip_req->nlmsg.nlmsghdr.nlmsg_flags =
		NLM_F_ACK|NLM_F_REQUEST|NLM_F_CREATE|NLM_F_EXCL;
        ip_req->nlmsg.nlmsghdr.nlmsg_type = RTM_NEWADDR;
	ip_req->ifa.ifa_prefixlen = prefix;
        ip_req->ifa.ifa_index = ifindex;
        ip_req->ifa.ifa_family = AF_INET6;
	ip_req->ifa.ifa_scope = 0;
	
	if (nla_put_buffer(nlmsg, IFA_LOCAL, &in6_addr, sizeof(in6_addr)))
		goto out;

	if (nla_put_buffer(nlmsg, IFA_ADDRESS, &in6_addr, sizeof(in6_addr)))
		goto out;

/* 	if (in6_bcast.s6_addr != in6addr_any.s6_addr) */
/* 		if (nla_put_buffer(nlmsg, IFA_BROADCAST, &in6_bcast, */
/* 				   sizeof(in6_bcast))) */
/* 			goto out; */

	if (netlink_transaction(&nlh, nlmsg, answer))
		goto out;

	err = 0;
out:
	netlink_close(&nlh);
	nlmsg_free(answer);
	nlmsg_free(nlmsg);
	return err;
}

static int bridge_add_del_interface(const char *bridge, 
				    const char *ifname, int detach)
{
	int fd, index, err;
	struct ifreq ifr;

	if (strlen(ifname) > IFNAMSIZ)
		return -1;

	index = if_nametoindex(ifname);
	if (!index)
		return -1;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;

	strncpy(ifr.ifr_name, bridge, IFNAMSIZ);
	ifr.ifr_ifindex = index;
	err = ioctl(fd, detach?SIOCBRDELIF:SIOCBRADDIF, &ifr);
	close(fd);

	return err;
}

int bridge_attach(const char *bridge, const char *ifname)
{
	return bridge_add_del_interface(bridge, ifname, 0);
}

int bridge_detach(const char *bridge, const char *ifname)
{
	return bridge_add_del_interface(bridge, ifname, 1);
}

int lxc_configure_veth(const char *veth1, const char *veth2, const char *bridge)
{
	int err = -1;
	if (veth_create(veth1, veth2)) {
		fprintf(stderr, "failed to create veth interfaces %s/%s\n",
			veth1, veth2);
		return -1;
	}

	if (bridge_attach(bridge, veth1)) {
		fprintf(stderr, "failed to attach %s to %s\n", 
			veth1, bridge);
		goto err;
	}

	err = 0;
out:
	return err;
err:
	device_delete(veth1);
	goto out;
}

int lxc_configure_macvlan(const char *link, const char *peer)
{
	if (macvlan_create(link, peer)) {
		fprintf(stderr, "failed to create %s", peer);
		return -1;
	}
	return 0;
}

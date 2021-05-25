/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "../include/netns_ifaddrs.h"
#include "af_unix.h"
#include "conf.h"
#include "config.h"
#include "file_utils.h"
#include "log.h"
#include "macro.h"
#include "memory_utils.h"
#include "network.h"
#include "nl.h"
#include "process_utils.h"
#include "string_utils.h"
#include "syscall_wrappers.h"
#include "utils.h"

#ifndef HAVE_STRLCPY
#include "include/strlcpy.h"
#endif

lxc_log_define(network, lxc);

typedef int (*netdev_configure_server_cb)(struct lxc_handler *, struct lxc_netdev *);
typedef int (*netdev_configure_container_cb)(struct lxc_netdev *);
typedef int (*netdev_shutdown_server_cb)(struct lxc_handler *, struct lxc_netdev *);

const struct lxc_network_info {
	const char *name;
	const char template[IFNAMSIZ];
	size_t template_len;
} lxc_network_info[LXC_NET_MAXCONFTYPE + 1] = {
	[LXC_NET_EMPTY]		= { "empty",		"emptXXXXXX",  STRLITERALLEN("emptXXXXXX")	},
	[LXC_NET_VETH]    	= { "veth",		"vethXXXXXX",  STRLITERALLEN("vethXXXXXX")	},
	[LXC_NET_MACVLAN] 	= { "macvlan",		"macvXXXXXX",  STRLITERALLEN("macvXXXXXX")	},
	[LXC_NET_IPVLAN]  	= { "ipvlan",		"ipvlXXXXXX",  STRLITERALLEN("ipvlXXXXXX")	},
	[LXC_NET_PHYS]    	= { "phys",		"physXXXXXX",  STRLITERALLEN("physXXXXXX")	},
	[LXC_NET_VLAN]    	= { "vlan",		"vlanXXXXXX",  STRLITERALLEN("vlanXXXXXX")	},
	[LXC_NET_NONE]    	= { "none",		"noneXXXXXX",  STRLITERALLEN("noneXXXXXX")	},
	[LXC_NET_MAXCONFTYPE]	= { NULL,		"",	       0				}
};

const char *lxc_net_type_to_str(int type)
{
	if (type < 0 || type > LXC_NET_MAXCONFTYPE)
		return NULL;

	return lxc_network_info[type].name;
}

static const char padchar[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

char *lxc_ifname_alnum_case_sensitive(char *template)
{
	char name[IFNAMSIZ];
	size_t i = 0;
#ifdef HAVE_RAND_R
	unsigned int seed;

	seed = randseed(false);
#else

	(void)randseed(true);
#endif

	if (strlen(template) >= IFNAMSIZ)
		return NULL;

	/* Generate random names until we find one that doesn't exist. */
	for (;;) {
		name[0] = '\0';
		(void)strlcpy(name, template, IFNAMSIZ);

		for (i = 0; i < strlen(name); i++) {
			if (name[i] == 'X') {
#ifdef HAVE_RAND_R
				name[i] = padchar[rand_r(&seed) % strlen(padchar)];
#else
				name[i] = padchar[rand() % strlen(padchar)];
#endif
			}
		}

		if (if_nametoindex(name) == 0)
			break;
	}

	(void)strlcpy(template, name, strlen(template) + 1);

	return template;
}
static const char loop_device[] = "lo";

static int lxc_ip_route_dest(__u16 nlmsg_type, int family, int ifindex, void *dest, unsigned int netmask)
{
	call_cleaner(nlmsg_free) struct nlmsg *answer = NULL, *nlmsg = NULL;
	struct nl_handler nlh;
	call_cleaner(netlink_close) struct nl_handler *nlh_ptr = &nlh;
	int addrlen, err;
	struct rtmsg *rt;

	addrlen = family == AF_INET ? sizeof(struct in_addr)
				    : sizeof(struct in6_addr);

	err = netlink_open(nlh_ptr, NETLINK_ROUTE);
	if (err)
		return err;

	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg)
		return -ENOMEM;

	answer = nlmsg_alloc_reserve(NLMSG_GOOD_SIZE);
	if (!answer)
		return -ENOMEM;

	nlmsg->nlmsghdr->nlmsg_flags =
	    NLM_F_ACK | NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
	nlmsg->nlmsghdr->nlmsg_type = nlmsg_type;

	rt = nlmsg_reserve(nlmsg, sizeof(struct rtmsg));
	if (!rt)
		return -ENOMEM;

	rt->rtm_family = family;
	rt->rtm_table = RT_TABLE_MAIN;
	rt->rtm_scope = RT_SCOPE_LINK;
	rt->rtm_protocol = RTPROT_BOOT;
	rt->rtm_type = RTN_UNICAST;
	rt->rtm_dst_len = netmask;

	if (nla_put_buffer(nlmsg, RTA_DST, dest, addrlen))
		return -EINVAL;

	if (nla_put_u32(nlmsg, RTA_OIF, ifindex))
		return -EINVAL;

	return netlink_transaction(nlh_ptr, nlmsg, answer);
}

static int lxc_ipv4_dest_add(int ifindex, struct in_addr *dest, unsigned int netmask)
{
	return lxc_ip_route_dest(RTM_NEWROUTE, AF_INET, ifindex, dest, netmask);
}

static int lxc_ipv6_dest_add(int ifindex, struct in6_addr *dest, unsigned int netmask)
{
	return lxc_ip_route_dest(RTM_NEWROUTE, AF_INET6, ifindex, dest, netmask);
}

static int lxc_ipv4_dest_del(int ifindex, struct in_addr *dest, unsigned int netmask)
{
	return lxc_ip_route_dest(RTM_DELROUTE, AF_INET, ifindex, dest, netmask);
}

static int lxc_ipv6_dest_del(int ifindex, struct in6_addr *dest, unsigned int netmask)
{
	return lxc_ip_route_dest(RTM_DELROUTE, AF_INET6, ifindex, dest, netmask);
}

static int lxc_setup_ipv4_routes(struct lxc_list *ip, int ifindex)
{
	struct lxc_list *iterator;
	int err;

	lxc_list_for_each(iterator, ip) {
		struct lxc_inetdev *inetdev = iterator->elem;

		err = lxc_ipv4_dest_add(ifindex, &inetdev->addr, inetdev->prefix);
		if (err)
			return log_error_errno(-1, -err, "Failed to setup ipv4 route for network device with ifindex %d", ifindex);
	}

	return 0;
}

static int lxc_setup_ipv6_routes(struct lxc_list *ip, int ifindex)
{
	struct lxc_list *iterator;
	int err;

	lxc_list_for_each(iterator, ip) {
		struct lxc_inet6dev *inet6dev = iterator->elem;

		err = lxc_ipv6_dest_add(ifindex, &inet6dev->addr, inet6dev->prefix);
		if (err)
			return log_error_errno(-1, -err, "Failed to setup ipv6 route for network device with ifindex %d", ifindex);
	}

	return 0;
}

static int setup_ipv4_addr_routes(struct lxc_list *ip, int ifindex)
{
	struct lxc_list *iterator;
	int err;

	lxc_list_for_each(iterator, ip) {
		struct lxc_inetdev *inetdev = iterator->elem;

		err = lxc_ipv4_dest_add(ifindex, &inetdev->addr, 32);

		if (err)
			return log_error_errno(-1, err, "Failed to setup ipv4 address route for network device with eifindex %d", ifindex);
	}

	return 0;
}

static int setup_ipv6_addr_routes(struct lxc_list *ip, int ifindex)
{
	struct lxc_list *iterator;
	int err;

	lxc_list_for_each(iterator, ip) {
		struct lxc_inet6dev *inet6dev = iterator->elem;

		err = lxc_ipv6_dest_add(ifindex, &inet6dev->addr, 128);
		if (err)
			return log_error_errno(-1, err, "Failed to setup ipv6 address route for network device with eifindex %d", ifindex);
	}

	return 0;
}

static int lxc_ip_neigh_proxy(__u16 nlmsg_type, int family, int ifindex, void *dest)
{
	call_cleaner(nlmsg_free) struct nlmsg *answer = NULL, *nlmsg = NULL;
	struct nl_handler nlh;
	call_cleaner(netlink_close) struct nl_handler *nlh_ptr = &nlh;
	int addrlen, err;
	struct ndmsg *rt;

	addrlen = family == AF_INET ? sizeof(struct in_addr) : sizeof(struct in6_addr);

	err = netlink_open(nlh_ptr, NETLINK_ROUTE);
	if (err)
		return err;

	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg)
		return -ENOMEM;

	answer = nlmsg_alloc_reserve(NLMSG_GOOD_SIZE);
	if (!answer)
		return -ENOMEM;

	nlmsg->nlmsghdr->nlmsg_flags = NLM_F_ACK | NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
	nlmsg->nlmsghdr->nlmsg_type = nlmsg_type;

	rt = nlmsg_reserve(nlmsg, sizeof(struct ndmsg));
	if (!rt)
		return -ENOMEM;

	rt->ndm_ifindex = ifindex;
	rt->ndm_flags = NTF_PROXY;
	rt->ndm_type = NDA_DST;
	rt->ndm_family = family;

	if (nla_put_buffer(nlmsg, NDA_DST, dest, addrlen))
		return -EINVAL;

	return netlink_transaction(nlh_ptr, nlmsg, answer);
}

static int lxc_is_ip_forwarding_enabled(const char *ifname, int family)
{
	int ret;
	char path[PATH_MAX];
	char buf[1] = "";

	if (family != AF_INET && family != AF_INET6)
		return ret_set_errno(-1, EINVAL);

	ret = strnprintf(path, sizeof(path), "/proc/sys/net/%s/conf/%s/%s",
			 family == AF_INET ? "ipv4" : "ipv6", ifname,
			 "forwarding");
	if (ret < 0)
		return ret_set_errno(-1, E2BIG);

	return lxc_read_file_expect(path, buf, 1, "1");
}

struct bridge_vlan_info {
	__u16 flags;
	__u16 vid;
};

static int lxc_bridge_vlan(unsigned int ifindex, unsigned short operation, unsigned short vlan_id, bool tagged)
{
	call_cleaner(nlmsg_free) struct nlmsg *answer = NULL, *nlmsg = NULL;
	struct nl_handler nlh;
	call_cleaner(netlink_close) struct nl_handler *nlh_ptr = &nlh;
	int err;
	struct ifinfomsg *ifi;
	struct rtattr *nest;
	unsigned short bridge_flags = 0;
	struct bridge_vlan_info vlan_info;

	err = netlink_open(nlh_ptr, NETLINK_ROUTE);
	if (err)
		return err;

	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg)
		return ret_errno(ENOMEM);

	answer = nlmsg_alloc_reserve(NLMSG_GOOD_SIZE);
	if (!answer)
		return ret_errno(ENOMEM);

	nlmsg->nlmsghdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlmsg->nlmsghdr->nlmsg_type = operation;

	ifi = nlmsg_reserve(nlmsg, sizeof(struct ifinfomsg));
	if (!ifi)
		return ret_errno(ENOMEM);
	ifi->ifi_family = AF_BRIDGE;
	ifi->ifi_index = ifindex;

	nest = nla_begin_nested(nlmsg, IFLA_AF_SPEC);
	if (!nest)
		return ret_errno(ENOMEM);

	bridge_flags |= BRIDGE_FLAGS_MASTER;
	if (nla_put_u16(nlmsg, IFLA_BRIDGE_FLAGS, bridge_flags))
		return ret_errno(ENOMEM);

	vlan_info.vid = vlan_id;
	vlan_info.flags = 0;
	if (!tagged)
		vlan_info.flags = BRIDGE_VLAN_INFO_PVID | BRIDGE_VLAN_INFO_UNTAGGED;

	if (nla_put_buffer(nlmsg, IFLA_BRIDGE_VLAN_INFO, &vlan_info, sizeof(struct bridge_vlan_info)))
		return ret_errno(ENOMEM);

	nla_end_nested(nlmsg, nest);

	return netlink_transaction(nlh_ptr, nlmsg, answer);
}

static int lxc_bridge_vlan_add(unsigned int ifindex, unsigned short vlan_id, bool tagged)
{
	return lxc_bridge_vlan(ifindex, RTM_SETLINK, vlan_id, tagged);
}

static int lxc_bridge_vlan_del(unsigned int ifindex, unsigned short vlan_id)
{
	return lxc_bridge_vlan(ifindex, RTM_DELLINK, vlan_id, false);
}

static int lxc_bridge_vlan_add_tagged(unsigned int ifindex, struct lxc_list *vlan_ids)
{
	struct lxc_list *iterator;
	int err;

	lxc_list_for_each(iterator, vlan_ids) {
		unsigned short vlan_id = PTR_TO_USHORT(iterator->elem);

		err = lxc_bridge_vlan_add(ifindex, vlan_id, true);
		if (err)
			return log_error_errno(-1, -err, "Failed to add tagged vlan \"%u\" to ifindex \"%d\"", vlan_id, ifindex);
	}

	return 0;
}

static int validate_veth(struct lxc_netdev *netdev)
{
	if (netdev->priv.veth_attr.mode != VETH_MODE_BRIDGE || is_empty_string(netdev->link)) {
		/* Check that veth.vlan.id isn't being used in non bridge veth.mode. */
		if (netdev->priv.veth_attr.vlan_id_set)
			return log_error_errno(-1, EINVAL, "Cannot use veth vlan.id when not in bridge mode or no bridge link specified");

		/* Check that veth.vlan.tagged.id isn't being used in non bridge veth.mode. */
		if (lxc_list_len(&netdev->priv.veth_attr.vlan_tagged_ids) > 0)
			return log_error_errno(-1, EINVAL, "Cannot use veth vlan.id when not in bridge mode or no bridge link specified");
	}

	if (netdev->priv.veth_attr.vlan_id_set) {
		struct lxc_list *it;
		lxc_list_for_each(it, &netdev->priv.veth_attr.vlan_tagged_ids) {
			unsigned short i = PTR_TO_USHORT(it->elem);
			if (i == netdev->priv.veth_attr.vlan_id)
				return log_error_errno(-1, EINVAL, "Cannot use same veth vlan.id \"%u\" in vlan.tagged.id", netdev->priv.veth_attr.vlan_id);
		}
	}

	return 0;
}

static int setup_veth_native_bridge_vlan(char *veth1, struct lxc_netdev *netdev)
{
	int err, rc, veth1index;
	char path[STRLITERALLEN("/sys/class/net//bridge/vlan_filtering") + IFNAMSIZ + 1];
	char buf[5]; /* Sufficient size to fit max VLAN ID (4094) and null char. */

	/* Skip setup if no VLAN options are specified. */
	if (!netdev->priv.veth_attr.vlan_id_set && lxc_list_len(&netdev->priv.veth_attr.vlan_tagged_ids) <= 0)
		return 0;

	/* Check vlan filtering is enabled on parent bridge. */
	rc = strnprintf(path, sizeof(path), "/sys/class/net/%s/bridge/vlan_filtering", netdev->link);
	if (rc < 0)
		return -1;

	rc = lxc_read_from_file(path, buf, sizeof(buf));
	if (rc < 0)
		return log_error_errno(rc, errno, "Failed reading from \"%s\"", path);

	buf[rc - 1] = '\0';

	if (!strequal(buf, "1"))
		return log_error_errno(-1, EPERM, "vlan_filtering is not enabled on \"%s\"", netdev->link);

	/* Get veth1 ifindex for use with netlink. */
	veth1index = if_nametoindex(veth1);
	if (!veth1index)
		return log_error_errno(-1, errno, "Failed getting ifindex of \"%s\"", netdev->link);

	/* Configure untagged VLAN settings on bridge port if specified. */
	if (netdev->priv.veth_attr.vlan_id_set) {
		unsigned short default_pvid;

		/* Get the bridge's default VLAN PVID. */
		rc = strnprintf(path, sizeof(path), "/sys/class/net/%s/bridge/default_pvid", netdev->link);
		if (rc < 0)
			return -1;

		rc = lxc_read_from_file(path, buf, sizeof(buf));
		if (rc < 0)
			return log_error_errno(rc, errno, "Failed reading from \"%s\"", path);

		buf[rc - 1] = '\0';
		err = get_u16(&default_pvid, buf, 0);
		if (err)
			return log_error_errno(-1, EINVAL, "Failed parsing default_pvid of \"%s\"", netdev->link);

		/* If the default PVID on the port is not the specified untagged VLAN, then delete it. */
		if (default_pvid != netdev->priv.veth_attr.vlan_id) {
			err = lxc_bridge_vlan_del(veth1index, default_pvid);
			if (err)
				return log_error_errno(err, errno, "Failed to delete default untagged vlan \"%u\" on \"%s\"", default_pvid, veth1);
		}

		if (netdev->priv.veth_attr.vlan_id > BRIDGE_VLAN_NONE) {
			err = lxc_bridge_vlan_add(veth1index, netdev->priv.veth_attr.vlan_id, false);
			if (err)
				return log_error_errno(err, errno, "Failed to add untagged vlan \"%u\" on \"%s\"", netdev->priv.veth_attr.vlan_id, veth1);
		}
	}

	/* Configure tagged VLAN settings on bridge port if specified. */
	err = lxc_bridge_vlan_add_tagged(veth1index, &netdev->priv.veth_attr.vlan_tagged_ids);
	if (err)
		return log_error_errno(err, errno, "Failed to add tagged vlans on \"%s\"", veth1);

	return 0;
}

struct ovs_veth_vlan_args {
	const char *nic;
	const char *vlan_mode;	/* Port VLAN mode. */
	short vlan_id;		/* PVID VLAN ID. */
	char *trunks;		/* Comma delimited list of tagged VLAN IDs. */
};

static inline void free_ovs_veth_vlan_args(struct ovs_veth_vlan_args *args)
{
	free_disarm(args->trunks);
}

static int lxc_ovs_setup_bridge_vlan_exec(void *data)
{
	struct ovs_veth_vlan_args *args = data;
       __do_free char *vlan_mode = NULL, *tag = NULL, *trunks = NULL;

	if (!args->vlan_mode)
		return ret_errno(EINVAL);

	vlan_mode = must_concat(NULL, "vlan_mode=", args->vlan_mode, (char *)NULL);

	if (args->vlan_id > BRIDGE_VLAN_NONE) {
		char buf[5];
		int rc;

		rc = strnprintf(buf, sizeof(buf), "%u", args->vlan_id);
		if (rc < 0)
			return log_error_errno(-1, EINVAL, "Failed to parse ovs bridge vlan \"%d\"", args->vlan_id);

		tag = must_concat(NULL, "tag=", buf, (char *)NULL);
	}

	if (args->trunks)
		trunks = must_concat(NULL, "trunks=", args->trunks, (char *)NULL);

	/* Detect the combination of vlan_id and trunks specified and convert to ovs-vsctl command. */
	if (tag && trunks)
		execlp("ovs-vsctl", "ovs-vsctl", "set", "port", args->nic, vlan_mode, tag, trunks, (char *)NULL);
	else if (tag)
		execlp("ovs-vsctl", "ovs-vsctl", "set", "port", args->nic, vlan_mode, tag, (char *)NULL);
	else if (trunks)
		execlp("ovs-vsctl", "ovs-vsctl", "set", "port", args->nic, vlan_mode, trunks, (char *)NULL);
	else
		return -EINVAL;

	return -errno;
}

static int setup_veth_ovs_bridge_vlan(char *veth1, struct lxc_netdev *netdev)
{
	int taggedLength = lxc_list_len(&netdev->priv.veth_attr.vlan_tagged_ids);
	struct ovs_veth_vlan_args args;
	args.nic = veth1;
	args.vlan_mode = NULL;
	args.vlan_id = BRIDGE_VLAN_NONE;
	args.trunks = NULL;

	/* Skip setup if no VLAN options are specified. */
	if (!netdev->priv.veth_attr.vlan_id_set && taggedLength <= 0)
		return 0;

	/* Configure untagged VLAN settings on bridge port if specified. */
	if (netdev->priv.veth_attr.vlan_id_set) {
		if (netdev->priv.veth_attr.vlan_id == BRIDGE_VLAN_NONE && taggedLength <= 0)
			return log_error_errno(-1, EINVAL, "Cannot use vlan.id=none with openvswitch bridges when not using vlan.tagged.id");

		/* Configure the untagged 'native' membership settings of the port if VLAN ID specified.
		 * Also set the vlan_mode=access, which will drop any tagged frames.
		 * Order is important here, as vlan_mode is set to "access", assuming that vlan.tagged.id is not
		 * used. If vlan.tagged.id is specified, then we expect it to also change the vlan_mode as needed.
		 */
		if (netdev->priv.veth_attr.vlan_id > BRIDGE_VLAN_NONE) {
			args.vlan_mode = "access";
			args.vlan_id = netdev->priv.veth_attr.vlan_id;
		}
	}

	if (taggedLength > 0) {
		args.vlan_mode = "trunk"; /* Default to only allowing tagged frames (drop untagged frames). */

		if (netdev->priv.veth_attr.vlan_id > BRIDGE_VLAN_NONE) {
			/* If untagged vlan mode isn't "none" then allow untagged frames for port's 'native' VLAN. */
			args.vlan_mode  = "native-untagged";
		}

		struct lxc_list *iterator;
		lxc_list_for_each(iterator, &netdev->priv.veth_attr.vlan_tagged_ids) {
			unsigned short vlan_id = PTR_TO_USHORT(iterator->elem);
			char buf[5]; /* Sufficient size to fit max VLAN ID (4094) null char. */
			int rc;

			rc = strnprintf(buf, sizeof(buf), "%u", vlan_id);
			if (rc < 0) {
				free_ovs_veth_vlan_args(&args);
				return log_error_errno(-1, EINVAL, "Failed to parse tagged vlan \"%u\" for interface \"%s\"", vlan_id, veth1);
			}

			if (args.trunks)
				args.trunks = must_concat(NULL, args.trunks, buf, ",", (char *)NULL);
			else
				args.trunks = must_concat(NULL, buf, ",", (char *)NULL);
		}
	}

	if (args.vlan_mode) {
		int ret;
		char cmd_output[PATH_MAX];

		ret = run_command(cmd_output, sizeof(cmd_output), lxc_ovs_setup_bridge_vlan_exec, (void *)&args);
		if (ret < 0) {
			free_ovs_veth_vlan_args(&args);
			return log_error_errno(-1, ret, "Failed to setup openvswitch vlan on port \"%s\": %s", args.nic, cmd_output);
		}
	}

	free_ovs_veth_vlan_args(&args);
	return 0;
}

static int netdev_configure_server_veth(struct lxc_handler *handler, struct lxc_netdev *netdev)
{
	int err;
	unsigned int mtu = 1500;
	char *veth1, *veth2;
	char veth1buf[IFNAMSIZ], veth2buf[IFNAMSIZ];

	err = validate_veth(netdev);
	if (err)
		return err;

	if (!is_empty_string(netdev->priv.veth_attr.pair)) {
		veth1 = netdev->priv.veth_attr.pair;
		if (handler->conf->reboot)
			lxc_netdev_delete_by_name(veth1);
	} else {
		err = strnprintf(veth1buf, sizeof(veth1buf), "vethXXXXXX");
		if (err < 0)
			return -1;

		veth1 = lxc_ifname_alnum_case_sensitive(veth1buf);
		if (!veth1)
			return -1;

		/* store away for deconf */
		memcpy(netdev->priv.veth_attr.veth1, veth1, IFNAMSIZ);
	}

	err = strnprintf(veth2buf, sizeof(veth2buf), "vethXXXXXX");
	if (err < 0)
		return -1;

	veth2 = lxc_ifname_alnum_case_sensitive(veth2buf);
	if (!veth2)
		return -1;

	/* if mtu is specified in config then use that, otherwise inherit from link device if provided. */
	if (netdev->mtu) {
		if (lxc_safe_uint(netdev->mtu, &mtu))
			return log_error_errno(-1, errno, "Failed to parse mtu");
	} else if (!is_empty_string(netdev->link)) {
		int ifindex_mtu;

		ifindex_mtu = if_nametoindex(netdev->link);
		if (ifindex_mtu) {
			mtu = netdev_get_mtu(ifindex_mtu);
			INFO("Retrieved mtu %d from %s", mtu, netdev->link);
		}
	}

	err = lxc_veth_create(veth1, veth2, handler->pid, mtu);
	if (err)
		return log_error_errno(-1, -err, "Failed to create veth pair \"%s\" and \"%s\"", veth1, veth2);

	/*
	 * Veth devices are directly created in the container's network
	 * namespace so the device doesn't need to be moved into the
	 * container's network namespace. Make this explicit by setting the
	 * devices ifindex to 0.
	 */
	netdev->ifindex = 0;

	strlcpy(netdev->created_name, veth2, IFNAMSIZ);

	 /*
	  * Since the device won't be moved transient name generation won't
	  * happen. But the transient name is needed for the container to
	  * retrieve the ifindex for the device.
	  */
	strlcpy(netdev->transient_name, veth2, IFNAMSIZ);

	/*
	 * Changing the high byte of the mac address to 0xfe, the bridge interface
	 * will always keep the host's mac address and not take the mac address
	 * of a container.
	 */
	err = setup_private_host_hw_addr(veth1);
	if (err) {
		errno = -err;
		SYSERROR("Failed to change mac address of host interface \"%s\"", veth1);
		goto out_delete;
	}

	/* Retrieve ifindex of the host's veth device. */
	netdev->priv.veth_attr.ifindex = if_nametoindex(veth1);
	if (!netdev->priv.veth_attr.ifindex) {
		ERROR("Failed to retrieve ifindex for \"%s\"", veth1);
		goto out_delete;
	}

	if (mtu) {
		err = lxc_netdev_set_mtu(veth1, mtu);
		if (err) {
			errno = -err;
			SYSERROR("Failed to set mtu \"%d\" for veth pair \"%s\" ", mtu, veth1);
			goto out_delete;
		}
	}

	if (!is_empty_string(netdev->link) && netdev->priv.veth_attr.mode == VETH_MODE_BRIDGE) {
		if (!lxc_nic_exists(netdev->link)) {
			SYSERROR("Failed to attach \"%s\" to bridge \"%s\", bridge interface doesn't exist", veth1, netdev->link);
			goto out_delete;
		}

		err = lxc_bridge_attach(netdev->link, veth1);
		if (err) {
			errno = -err;
			SYSERROR("Failed to attach \"%s\" to bridge \"%s\"", veth1, netdev->link);
			goto out_delete;
		}
		INFO("Attached \"%s\" to bridge \"%s\"", veth1, netdev->link);

		if (is_ovs_bridge(netdev->link)) {
			err = setup_veth_ovs_bridge_vlan(veth1, netdev);
			if (err) {
				SYSERROR("Failed to setup openvswitch bridge vlan on \"%s\"", veth1);
				lxc_ovs_delete_port(netdev->link, veth1);
				goto out_delete;
			}
		} else {
			err = setup_veth_native_bridge_vlan(veth1, netdev);
			if (err) {
				SYSERROR("Failed to setup native bridge vlan on \"%s\"", veth1);
				goto out_delete;
			}
		}
	}

	err = lxc_netdev_up(veth1);
	if (err) {
		errno = -err;
		SYSERROR("Failed to set \"%s\" up", veth1);
		goto out_delete;
	}

	/* setup ipv4 routes on the host interface */
	if (lxc_setup_ipv4_routes(&netdev->priv.veth_attr.ipv4_routes, netdev->priv.veth_attr.ifindex)) {
		ERROR("Failed to setup ipv4 routes for network device \"%s\"", veth1);
		goto out_delete;
	}

	/* setup ipv6 routes on the host interface */
	if (lxc_setup_ipv6_routes(&netdev->priv.veth_attr.ipv6_routes, netdev->priv.veth_attr.ifindex)) {
		ERROR("Failed to setup ipv6 routes for network device \"%s\"", veth1);
		goto out_delete;
	}

	if (netdev->priv.veth_attr.mode == VETH_MODE_ROUTER) {
		/* sleep for a short period of time to work around a bug that intermittently prevents IP neighbour
		   proxy entries from being added using lxc_ip_neigh_proxy below. When the issue occurs the entries
		   appear to be added successfully but then do not appear in the proxy list. The length of time
		   slept doesn't appear to be important, only that the process sleeps for a short period of time.
		*/
		nanosleep((const struct timespec[]){{0, 1000}}, NULL);

		if (netdev->ipv4_gateway) {
			char bufinet4[INET_ADDRSTRLEN];
			if (!inet_ntop(AF_INET, netdev->ipv4_gateway, bufinet4, sizeof(bufinet4))) {
				SYSERROR("Failed to convert gateway ipv4 address on \"%s\"", veth1);
				goto out_delete;
			}

			err = lxc_ip_forwarding_on(veth1, AF_INET);
			if (err) {
				SYSERROR("Failed to activate ipv4 forwarding on \"%s\"", veth1);
				goto out_delete;
			}

			err = lxc_ip_neigh_proxy(RTM_NEWNEIGH, AF_INET, netdev->priv.veth_attr.ifindex, netdev->ipv4_gateway);
			if (err) {
				SYSERROR("Failed to add gateway ipv4 proxy on \"%s\"", veth1);
				goto out_delete;
			}
		}

		if (netdev->ipv6_gateway) {
			char bufinet6[INET6_ADDRSTRLEN];

			if (!inet_ntop(AF_INET6, netdev->ipv6_gateway, bufinet6, sizeof(bufinet6))) {
				SYSERROR("Failed to convert gateway ipv6 address on \"%s\"", veth1);
				goto out_delete;
			}

			/* Check for sysctl net.ipv6.conf.all.forwarding=1
			   Kernel requires this to route any packets for IPv6.
			*/
			err = lxc_is_ip_forwarding_enabled("all", AF_INET6);
			if (err) {
				SYSERROR("Requires sysctl net.ipv6.conf.all.forwarding=1");
				goto out_delete;
			}

			err = lxc_ip_forwarding_on(veth1, AF_INET6);
			if (err) {
				SYSERROR("Failed to activate ipv6 forwarding on \"%s\"", veth1);
				goto out_delete;
			}

			err = lxc_neigh_proxy_on(veth1, AF_INET6);
			if (err) {
				SYSERROR("Failed to activate proxy ndp on \"%s\"", veth1);
				goto out_delete;
			}

			err = lxc_ip_neigh_proxy(RTM_NEWNEIGH, AF_INET6, netdev->priv.veth_attr.ifindex, netdev->ipv6_gateway);
			if (err) {
				SYSERROR("Failed to add gateway ipv6 proxy on \"%s\"", veth1);
				goto out_delete;
			}
		}

		/* setup ipv4 address routes on the host interface */
		err = setup_ipv4_addr_routes(&netdev->ipv4, netdev->priv.veth_attr.ifindex);
		if (err) {
			SYSERROR("Failed to setup ip address routes for network device \"%s\"", veth1);
			goto out_delete;
		}

		/* setup ipv6 address routes on the host interface */
		err = setup_ipv6_addr_routes(&netdev->ipv6, netdev->priv.veth_attr.ifindex);
		if (err) {
			SYSERROR("Failed to setup ip address routes for network device \"%s\"", veth1);
			goto out_delete;
		}
	}

	if (netdev->upscript) {
		char *argv[] = {
		    "veth",
		    netdev->link,
		    veth1,
		    NULL,
		};

		err = run_script_argv(handler->name,
				handler->conf->hooks_version, "net",
				netdev->upscript, "up", argv);
		if (err < 0)
			goto out_delete;
	}

	DEBUG("Instantiated veth tunnel \"%s <--> %s\"", veth1, veth2);

	return 0;

out_delete:
	lxc_netdev_delete_by_name(veth1);
	return -1;
}

static int netdev_configure_server_macvlan(struct lxc_handler *handler, struct lxc_netdev *netdev)
{
	char peer[IFNAMSIZ];
	int err;

	if (is_empty_string(netdev->link)) {
		ERROR("No link for macvlan network device specified");
		return -1;
	}

	err = strnprintf(peer, sizeof(peer), "mcXXXXXX");
	if (err < 0)
		return -1;

	if (!lxc_ifname_alnum_case_sensitive(peer))
		return -1;

	err = lxc_macvlan_create(netdev->link, peer,
				 netdev->priv.macvlan_attr.mode);
	if (err) {
		errno = -err;
		SYSERROR("Failed to create macvlan interface \"%s\" on \"%s\"",
		         peer, netdev->link);
		goto on_error;
	}

	strlcpy(netdev->created_name, peer, IFNAMSIZ);

	netdev->ifindex = if_nametoindex(peer);
	if (!netdev->ifindex) {
		ERROR("Failed to retrieve ifindex for \"%s\"", peer);
		goto on_error;
	}

	if (netdev->mtu) {
		unsigned int mtu;

		err = lxc_safe_uint(netdev->mtu, &mtu);
		if (err < 0) {
			errno = -err;
			SYSERROR("Failed to parse mtu \"%s\" for interface \"%s\"", netdev->mtu, peer);
			goto on_error;
		}

		err = lxc_netdev_set_mtu(peer, mtu);
		if (err < 0) {
			errno = -err;
			SYSERROR("Failed to set mtu \"%s\" for interface \"%s\"", netdev->mtu, peer);
			goto on_error;
		}
	}

	if (netdev->upscript) {
		char *argv[] = {
		    "macvlan",
		    netdev->link,
		    NULL,
		};

		err = run_script_argv(handler->name,
				handler->conf->hooks_version, "net",
				netdev->upscript, "up", argv);
		if (err < 0)
			goto on_error;
	}

	DEBUG("Instantiated macvlan \"%s\" with ifindex %d and mode %d",
	      peer, netdev->ifindex, netdev->priv.macvlan_attr.mode);

	return 0;

on_error:
	lxc_netdev_delete_by_name(peer);
	return -1;
}

static int lxc_ipvlan_create(const char *parent, const char *name, int mode, int isolation)
{
	call_cleaner(nlmsg_free) struct nlmsg *answer = NULL, *nlmsg = NULL;
	struct nl_handler nlh;
	call_cleaner(netlink_close) struct nl_handler *nlh_ptr = &nlh;
	int err, index, len;
	struct ifinfomsg *ifi;
	struct rtattr *nest, *nest2;

	len = strlen(parent);
	if (len == 1 || len >= IFNAMSIZ)
		return ret_errno(EINVAL);

	len = strlen(name);
	if (len == 1 || len >= IFNAMSIZ)
		return ret_errno(EINVAL);

	index = if_nametoindex(parent);
	if (!index)
		return ret_errno(EINVAL);

	err = netlink_open(nlh_ptr, NETLINK_ROUTE);
	if (err)
		return err;

	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg)
		return ret_errno(ENOMEM);

	answer = nlmsg_alloc_reserve(NLMSG_GOOD_SIZE);
	if (!answer)
		return ret_errno(ENOMEM);

	nlmsg->nlmsghdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
	nlmsg->nlmsghdr->nlmsg_type = RTM_NEWLINK;

	ifi = nlmsg_reserve(nlmsg, sizeof(struct ifinfomsg));
	if (!ifi)
		return ret_errno(ENOMEM);
	ifi->ifi_family = AF_UNSPEC;

	nest = nla_begin_nested(nlmsg, IFLA_LINKINFO);
	if (!nest)
		return ret_errno(EPROTO);

	if (nla_put_string(nlmsg, IFLA_INFO_KIND, "ipvlan"))
		return ret_errno(EPROTO);

	nest2 = nla_begin_nested(nlmsg, IFLA_INFO_DATA);
	if (!nest2)
		return ret_errno(EPROTO);

	if (nla_put_u16(nlmsg, IFLA_IPVLAN_MODE, mode))
		return ret_errno(EPROTO);

	/* if_link.h does not define the isolation flag value for bridge mode (unlike IPVLAN_F_PRIVATE and
	 * IPVLAN_F_VEPA) so we define it as 0 and only send mode if mode >0 as default mode is bridge anyway
	 * according to ipvlan docs.
	 */
	if (isolation > 0 && nla_put_u16(nlmsg, IFLA_IPVLAN_ISOLATION, isolation))
		return ret_errno(EPROTO);

	nla_end_nested(nlmsg, nest2);
	nla_end_nested(nlmsg, nest);

	if (nla_put_u32(nlmsg, IFLA_LINK, index))
		return ret_errno(EPROTO);

	if (nla_put_string(nlmsg, IFLA_IFNAME, name))
		return ret_errno(EPROTO);

	return netlink_transaction(nlh_ptr, nlmsg, answer);
}

static int netdev_configure_server_ipvlan(struct lxc_handler *handler, struct lxc_netdev *netdev)
{
	char peer[IFNAMSIZ];
	int err;

	if (is_empty_string(netdev->link)) {
		ERROR("No link for ipvlan network device specified");
		return -1;
	}

	err = strnprintf(peer, sizeof(peer), "ipXXXXXX");
	if (err < 0)
		return -1;

	if (!lxc_ifname_alnum_case_sensitive(peer))
		return -1;

	err = lxc_ipvlan_create(netdev->link, peer, netdev->priv.ipvlan_attr.mode,
				netdev->priv.ipvlan_attr.isolation);
	if (err) {
		SYSERROR("Failed to create ipvlan interface \"%s\" on \"%s\"",
			 peer, netdev->link);
		goto on_error;
	}

	strlcpy(netdev->created_name, peer, IFNAMSIZ);

	netdev->ifindex = if_nametoindex(peer);
	if (!netdev->ifindex) {
		ERROR("Failed to retrieve ifindex for \"%s\"", peer);
		goto on_error;
	}

	if (netdev->mtu) {
		unsigned int mtu;

		err = lxc_safe_uint(netdev->mtu, &mtu);
		if (err < 0) {
			errno = -err;
			SYSERROR("Failed to parse mtu \"%s\" for interface \"%s\"", netdev->mtu, peer);
			goto on_error;
		}

		err = lxc_netdev_set_mtu(peer, mtu);
		if (err < 0) {
			errno = -err;
			SYSERROR("Failed to set mtu \"%s\" for interface \"%s\"", netdev->mtu, peer);
			goto on_error;
		}
	}

	if (netdev->upscript) {
		char *argv[] = {
		    "ipvlan",
		    netdev->link,
		    NULL,
		};

		err = run_script_argv(handler->name, handler->conf->hooks_version,
				      "net", netdev->upscript, "up", argv);
		if (err < 0)
			goto on_error;
	}

	DEBUG("Instantiated ipvlan \"%s\" with ifindex %d and mode %d", peer,
	      netdev->ifindex, netdev->priv.macvlan_attr.mode);

	return 0;

on_error:
	lxc_netdev_delete_by_name(peer);
	return -1;
}

static int netdev_configure_server_vlan(struct lxc_handler *handler, struct lxc_netdev *netdev)
{
	char peer[IFNAMSIZ];
	int err;
	static uint16_t vlan_cntr = 0;

	if (is_empty_string(netdev->link)) {
		ERROR("No link for vlan network device specified");
		return -1;
	}

	err = strnprintf(peer, sizeof(peer), "vlan%d-%d",
			 netdev->priv.vlan_attr.vid, vlan_cntr++);
	if (err < 0)
		return -1;

	err = lxc_vlan_create(netdev->link, peer, netdev->priv.vlan_attr.vid);
	if (err) {
		errno = -err;
		SYSERROR("Failed to create vlan interface \"%s\" on \"%s\"",
		         peer, netdev->link);
		return -1;
	}

	strlcpy(netdev->created_name, peer, IFNAMSIZ);

	netdev->ifindex = if_nametoindex(peer);
	if (!netdev->ifindex) {
		ERROR("Failed to retrieve ifindex for \"%s\"", peer);
		goto on_error;
	}

	if (netdev->mtu) {
		unsigned int mtu;

		err = lxc_safe_uint(netdev->mtu, &mtu);
		if (err < 0) {
			errno = -err;
			SYSERROR("Failed to parse mtu \"%s\" for interface \"%s\"", netdev->mtu, peer);
			goto on_error;
		}

		err = lxc_netdev_set_mtu(peer, mtu);
		if (err < 0) {
			errno = -err;
			SYSERROR("Failed to set mtu \"%s\" for interface \"%s\"", netdev->mtu, peer);
			goto on_error;
		}
	}

	if (netdev->upscript) {
		char *argv[] = {
		    "vlan",
		    netdev->link,
		    NULL,
		};

		err = run_script_argv(handler->name, handler->conf->hooks_version,
				      "net", netdev->upscript, "up", argv);
		if (err < 0) {
			goto on_error;
		}
	}

	DEBUG("Instantiated vlan \"%s\" with ifindex \"%d\"", peer,
	      netdev->ifindex);

	return 0;

on_error:
	lxc_netdev_delete_by_name(peer);
	return -1;
}

static int netdev_configure_server_phys(struct lxc_handler *handler, struct lxc_netdev *netdev)
{
	int err, mtu_orig = 0;

	if (is_empty_string(netdev->link))
		return log_error_errno(-1, errno, "No link for physical interface specified");

	/*
	 * Note that we're retrieving the container's ifindex in the host's
	 * network namespace because we need it to move the device from the
	 * host's network namespace to the container's network namespace later
	 * on.
	 * Note that netdev->link will contain the name of the physical network
	 * device in the host's namespace.
	 */
	netdev->ifindex = if_nametoindex(netdev->link);
	if (!netdev->ifindex)
		return log_error_errno(-1, errno, "Failed to retrieve ifindex for \"%s\"", netdev->link);

	strlcpy(netdev->created_name, netdev->link, IFNAMSIZ);
	if (is_empty_string(netdev->name))
		(void)strlcpy(netdev->name, netdev->link, IFNAMSIZ);

	/*
	 * Store the ifindex of the host's network device in the host's
	 * namespace.
	 */
	netdev->priv.phys_attr.ifindex = netdev->ifindex;

	/*
	 * Get original device MTU setting and store for restoration after
	 * container shutdown.
	 */
	mtu_orig = netdev_get_mtu(netdev->ifindex);
	if (mtu_orig < 0)
		return log_error_errno(-1, -mtu_orig, "Failed to get original mtu for interface \"%s\"", netdev->link);

	netdev->priv.phys_attr.mtu = mtu_orig;

	if (netdev->mtu) {
		unsigned int mtu;

		err = lxc_safe_uint(netdev->mtu, &mtu);
		if (err < 0)
			return log_error_errno(-1, -err, "Failed to parse mtu \"%s\" for interface \"%s\"", netdev->mtu, netdev->link);

		err = lxc_netdev_set_mtu(netdev->link, mtu);
		if (err < 0)
			return log_error_errno(-1, -err, "Failed to set mtu \"%s\" for interface \"%s\"", netdev->mtu, netdev->link);
	}

	if (netdev->upscript) {
		char *argv[] = {
		    "phys",
		    netdev->link,
		    NULL,
		};

		err = run_script_argv(handler->name, handler->conf->hooks_version,
				      "net", netdev->upscript, "up", argv);
		if (err < 0)
			return -1;
	}

	DEBUG("Instantiated phys \"%s\" with ifindex \"%d\"", netdev->link,
	      netdev->ifindex);

	return 0;
}

static int netdev_configure_server_empty(struct lxc_handler *handler, struct lxc_netdev *netdev)
{
	int ret;
	char *argv[] = {
	    "empty",
	    NULL,
	};

	netdev->ifindex = 0;
	if (!netdev->upscript)
		return 0;

	ret = run_script_argv(handler->name, handler->conf->hooks_version,
			      "net", netdev->upscript, "up", argv);
	if (ret < 0)
		return -1;

	return 0;
}

static int netdev_configure_server_none(struct lxc_handler *handler, struct lxc_netdev *netdev)
{
	netdev->ifindex = 0;
	return 0;
}

static netdev_configure_server_cb netdev_configure_server[LXC_NET_MAXCONFTYPE + 1] = {
	[LXC_NET_VETH]    = netdev_configure_server_veth,
	[LXC_NET_MACVLAN] = netdev_configure_server_macvlan,
	[LXC_NET_IPVLAN]  = netdev_configure_server_ipvlan,
	[LXC_NET_VLAN]    = netdev_configure_server_vlan,
	[LXC_NET_PHYS]    = netdev_configure_server_phys,
	[LXC_NET_EMPTY]   = netdev_configure_server_empty,
	[LXC_NET_NONE]    = netdev_configure_server_none,
};

static int __netdev_configure_container_common(struct lxc_netdev *netdev)
{
	char current_ifname[IFNAMSIZ];

	netdev->ifindex = if_nametoindex(netdev->transient_name);
	if (!netdev->ifindex)
		return log_error_errno(-1,
				       errno, "Failed to retrieve ifindex for network device with name %s",
				       netdev->transient_name);

	if (is_empty_string(netdev->name))
		(void)strlcpy(netdev->name, "eth%d", IFNAMSIZ);

	if (!strequal(netdev->transient_name, netdev->name)) {
		int ret;

		ret = lxc_netdev_rename_by_name(netdev->transient_name, netdev->name);
		if (ret)
			return log_error_errno(-1, -ret, "Failed to rename network device \"%s\" to \"%s\"",
					       netdev->transient_name, netdev->name);

		TRACE("Renamed network device from \"%s\" to \"%s\"", netdev->transient_name, netdev->name);
	}

	/*
	 * Re-read the name of the interface because its name has changed and
	 * would be automatically allocated by the system
	 */
	if (!if_indextoname(netdev->ifindex, current_ifname))
		return log_error_errno(-1, errno, "Failed get name for network device with ifindex %d", netdev->ifindex);

	/*
	 * Now update the recorded name of the network device to reflect the
	 * name of the network device in the child's network namespace. We will
	 * later on send this information back to the parent.
	 */
	(void)strlcpy(netdev->name, current_ifname, IFNAMSIZ);
	netdev->transient_name[0] = '\0';

	return 0;
}

static int netdev_configure_container_veth(struct lxc_netdev *netdev)
{

	return __netdev_configure_container_common(netdev);
}

static int netdev_configure_container_macvlan(struct lxc_netdev *netdev)
{
	return __netdev_configure_container_common(netdev);
}

static int netdev_configure_container_ipvlan(struct lxc_netdev *netdev)
{
	return __netdev_configure_container_common(netdev);
}

static int netdev_configure_container_vlan(struct lxc_netdev *netdev)
{
	return __netdev_configure_container_common(netdev);
}

static int netdev_configure_container_phys(struct lxc_netdev *netdev)
{
	return __netdev_configure_container_common(netdev);
}

static int netdev_configure_container_empty(struct lxc_netdev *netdev)
{
	return 0;
}

static int netdev_configure_container_none(struct lxc_netdev *netdev)
{
	return 0;
}

static netdev_configure_container_cb netdev_configure_container[LXC_NET_MAXCONFTYPE + 1] = {
	[LXC_NET_VETH]    = netdev_configure_container_veth,
	[LXC_NET_MACVLAN] = netdev_configure_container_macvlan,
	[LXC_NET_IPVLAN]  = netdev_configure_container_ipvlan,
	[LXC_NET_VLAN]    = netdev_configure_container_vlan,
	[LXC_NET_PHYS]    = netdev_configure_container_phys,
	[LXC_NET_EMPTY]   = netdev_configure_container_empty,
	[LXC_NET_NONE]    = netdev_configure_container_none,
};

static int netdev_shutdown_server_veth(struct lxc_handler *handler, struct lxc_netdev *netdev)
{
	int ret;
	char *argv[] = {
	    "veth",
	    netdev->link,
	    NULL,
	    NULL,
	};

	if (!netdev->downscript)
		return 0;

	if (!is_empty_string(netdev->priv.veth_attr.pair))
		argv[2] = netdev->priv.veth_attr.pair;
	else
		argv[2] = netdev->priv.veth_attr.veth1;

	ret = run_script_argv(handler->name,
			handler->conf->hooks_version, "net",
			netdev->downscript, "down", argv);
	if (ret < 0)
		return -1;

	return 0;
}

static int netdev_shutdown_server_macvlan(struct lxc_handler *handler, struct lxc_netdev *netdev)
{
	int ret;
	char *argv[] = {
		"macvlan",
		netdev->link,
		NULL,
	};

	if (!netdev->downscript)
		return 0;

	ret = run_script_argv(handler->name, handler->conf->hooks_version,
			      "net", netdev->downscript, "down", argv);
	if (ret < 0)
		return -1;

	return 0;
}

static int netdev_shutdown_server_ipvlan(struct lxc_handler *handler, struct lxc_netdev *netdev)
{
	int ret;
	char *argv[] = {
		"ipvlan",
		netdev->link,
		NULL,
	};

	if (!netdev->downscript)
		return 0;

	ret = run_script_argv(handler->name, handler->conf->hooks_version,
			      "net", netdev->downscript, "down", argv);
	if (ret < 0)
		return -1;

	return 0;
}

static int netdev_shutdown_server_vlan(struct lxc_handler *handler, struct lxc_netdev *netdev)
{
	int ret;
	char *argv[] = {
	    "vlan",
	    netdev->link,
	    NULL,
	};

	if (!netdev->downscript)
		return 0;

	ret = run_script_argv(handler->name, handler->conf->hooks_version,
			      "net", netdev->downscript, "down", argv);
	if (ret < 0)
		return -1;

	return 0;
}

static int netdev_shutdown_server_phys(struct lxc_handler *handler, struct lxc_netdev *netdev)
{
	int ret;
	char *argv[] = {
	    "phys",
	    netdev->link,
	    NULL,
	};

	if (!netdev->downscript)
		return 0;

	ret = run_script_argv(handler->name, handler->conf->hooks_version,
			      "net", netdev->downscript, "down", argv);
	if (ret < 0)
		return -1;

	return 0;
}

static int netdev_shutdown_server_empty(struct lxc_handler *handler, struct lxc_netdev *netdev)
{
	int ret;
	char *argv[] = {
	    "empty",
	    NULL,
	};

	if (!netdev->downscript)
		return 0;

	ret = run_script_argv(handler->name, handler->conf->hooks_version,
			      "net", netdev->downscript, "down", argv);
	if (ret < 0)
		return -1;

	return 0;
}

static int netdev_shutdown_server_none(struct lxc_handler *handler, struct lxc_netdev *netdev)
{
	return 0;
}

static netdev_shutdown_server_cb netdev_deconf[LXC_NET_MAXCONFTYPE + 1] = {
	[LXC_NET_VETH]    = netdev_shutdown_server_veth,
	[LXC_NET_MACVLAN] = netdev_shutdown_server_macvlan,
	[LXC_NET_IPVLAN]  = netdev_shutdown_server_ipvlan,
	[LXC_NET_VLAN]    = netdev_shutdown_server_vlan,
	[LXC_NET_PHYS]    = netdev_shutdown_server_phys,
	[LXC_NET_EMPTY]   = netdev_shutdown_server_empty,
	[LXC_NET_NONE]    = netdev_shutdown_server_none,
};

static int lxc_netdev_move_by_index_fd(int ifindex, int fd, const char *ifname)
{
	call_cleaner(nlmsg_free) struct nlmsg *nlmsg = NULL;
	struct nl_handler nlh;
	call_cleaner(netlink_close) struct nl_handler *nlh_ptr = &nlh;
	int err;
	struct ifinfomsg *ifi;

	err = netlink_open(nlh_ptr, NETLINK_ROUTE);
	if (err)
		return err;

	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg)
		return ret_errno(ENOMEM);

	nlmsg->nlmsghdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlmsg->nlmsghdr->nlmsg_type = RTM_NEWLINK;

	ifi = nlmsg_reserve(nlmsg, sizeof(struct ifinfomsg));
	if (!ifi)
		return ret_errno(ENOMEM);

	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index = ifindex;

	if (nla_put_u32(nlmsg, IFLA_NET_NS_FD, fd))
		return ret_errno(ENOMEM);

	if (!is_empty_string(ifname) && nla_put_string(nlmsg, IFLA_IFNAME, ifname))
		return ret_errno(ENOMEM);

	return netlink_transaction(nlh_ptr, nlmsg, nlmsg);
}

int lxc_netdev_move_by_index(int ifindex, pid_t pid, const char *ifname)
{
	call_cleaner(nlmsg_free) struct nlmsg *nlmsg = NULL;
	struct nl_handler nlh;
	call_cleaner(netlink_close) struct nl_handler *nlh_ptr = &nlh;
	int err;
	struct ifinfomsg *ifi;

	err = netlink_open(nlh_ptr, NETLINK_ROUTE);
	if (err)
		return err;

	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg)
		return ret_errno(ENOMEM);

	nlmsg->nlmsghdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlmsg->nlmsghdr->nlmsg_type = RTM_NEWLINK;

	ifi = nlmsg_reserve(nlmsg, sizeof(struct ifinfomsg));
	if (!ifi)
		return ret_errno(ENOMEM);

	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index = ifindex;

	if (nla_put_u32(nlmsg, IFLA_NET_NS_PID, pid))
		return ret_errno(ENOMEM);

	if (!is_empty_string(ifname) && nla_put_string(nlmsg, IFLA_IFNAME, ifname))
		return ret_errno(ENOMEM);

	return netlink_transaction(nlh_ptr, nlmsg, nlmsg);
}

/* If we are asked to move a wireless interface, then we must actually move its
 * phyN device. Detect that condition and return the physname here. The physname
 * will be passed to lxc_netdev_move_wlan() which will free it when done.
 */
#define PHYSNAME "/sys/class/net/%s/phy80211/name"
char *is_wlan(const char *ifname)
{
	__do_fclose FILE *f = NULL;
	__do_free char *path = NULL, *physname = NULL;
	int i, ret;
	long physlen;
	size_t len;

	len = strlen(ifname) + strlen(PHYSNAME) - 1;
	path = must_realloc(NULL, len + 1);
	ret = strnprintf(path, len, PHYSNAME, ifname);
	if (ret < 0)
		return NULL;

	f = fopen(path, "re");
	if (!f)
		return NULL;

	/* Feh - sb.st_size is always 4096. */
	fseek(f, 0, SEEK_END);
	physlen = ftell(f);
	fseek(f, 0, SEEK_SET);
	if (physlen < 0)
		return NULL;

	physname = malloc(physlen + 1);
	if (!physname)
		return NULL;

	memset(physname, 0, physlen + 1);
	ret = fread(physname, 1, physlen, f);
	if (ret < 0)
		return NULL;

	for (i = 0; i < physlen; i++) {
		if (physname[i] == '\n')
			physname[i] = '\0';

		if (physname[i] == '\0')
			break;
	}

	return move_ptr(physname);
}

static int lxc_netdev_rename_by_name_in_netns(pid_t pid, const char *old,
					      const char *new)
{
	pid_t fpid;

	fpid = fork();
	if (fpid < 0)
		return -1;

	if (fpid != 0)
		return wait_for_pid(fpid);

	if (!switch_to_ns(pid, "net"))
		return -1;

	_exit(lxc_netdev_rename_by_name(old, new));
}

int lxc_netdev_move_wlan(char *physname, const char *ifname, pid_t pid,
				const char *newname)
{
	__do_free char *cmd = NULL;
	pid_t fpid;

	/* Move phyN into the container.  TODO - do this using netlink.
	 * However, IIUC this involves a bit more complicated work to talk to
	 * the 80211 module, so for now just call out to iw.
	 */
	cmd = on_path("iw", NULL);
	if (!cmd) {
		ERROR("Couldn't find the application iw in PATH");
		return -1;
	}

	fpid = fork();
	if (fpid < 0)
		return -1;

	if (fpid == 0) {
		char pidstr[30];
		sprintf(pidstr, "%d", pid);
		execlp("iw", "iw", "phy", physname, "set", "netns", pidstr, (char *)NULL);
		_exit(EXIT_FAILURE);
	}

	if (wait_for_pid(fpid))
		return -1;

	if (newname)
		return lxc_netdev_rename_by_name_in_netns(pid, ifname, newname);

	return 0;
}

int lxc_netdev_move_by_name(const char *ifname, pid_t pid, const char* newname)
{
	__do_free char *physname = NULL;
	int index;

	if (!ifname)
		return -EINVAL;

	index = if_nametoindex(ifname);
	if (!index)
		return -EINVAL;

	physname = is_wlan(ifname);
	if (physname)
		return lxc_netdev_move_wlan(physname, ifname, pid, newname);

	return lxc_netdev_move_by_index(index, pid, newname);
}

int lxc_netdev_delete_by_index(int ifindex)
{
	call_cleaner(nlmsg_free) struct nlmsg *answer = NULL, *nlmsg = NULL;
	struct nl_handler nlh;
	call_cleaner(netlink_close) struct nl_handler *nlh_ptr = &nlh;
	int err;
	struct ifinfomsg *ifi;

	err = netlink_open(nlh_ptr, NETLINK_ROUTE);
	if (err)
		return err;

	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg)
		return ret_errno(ENOMEM);

	answer = nlmsg_alloc_reserve(NLMSG_GOOD_SIZE);
	if (!answer)
		return ret_errno(ENOMEM);

	nlmsg->nlmsghdr->nlmsg_flags = NLM_F_ACK | NLM_F_REQUEST;
	nlmsg->nlmsghdr->nlmsg_type = RTM_DELLINK;

	ifi = nlmsg_reserve(nlmsg, sizeof(struct ifinfomsg));
	if (!ifi)
		return ret_errno(ENOMEM);

	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index = ifindex;

	return netlink_transaction(nlh_ptr, nlmsg, answer);
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
	call_cleaner(nlmsg_free) struct nlmsg *answer = NULL, *nlmsg = NULL;
	struct nl_handler nlh;
	call_cleaner(netlink_close) struct nl_handler *nlh_ptr = &nlh;
	int err, len;
	struct ifinfomsg *ifi;

	err = netlink_open(nlh_ptr, NETLINK_ROUTE);
	if (err)
		return err;

	len = strlen(newname);
	if (len == 1 || len >= IFNAMSIZ)
		return ret_errno(EINVAL);

	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg)
		return ret_errno(ENOMEM);

	answer = nlmsg_alloc_reserve(NLMSG_GOOD_SIZE);
	if (!answer)
		return ret_errno(ENOMEM);

	nlmsg->nlmsghdr->nlmsg_flags = NLM_F_ACK | NLM_F_REQUEST;
	nlmsg->nlmsghdr->nlmsg_type = RTM_NEWLINK;

	ifi = nlmsg_reserve(nlmsg, sizeof(struct ifinfomsg));
	if (!ifi)
		return ret_errno(ENOMEM);

	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index = ifindex;

	if (nla_put_string(nlmsg, IFLA_IFNAME, newname))
		return ret_errno(ENOMEM);

	return netlink_transaction(nlh_ptr, nlmsg, answer);
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

int netdev_set_flag(const char *name, int flag)
{
	call_cleaner(nlmsg_free) struct nlmsg *answer = NULL, *nlmsg = NULL;
	struct nl_handler nlh;
	call_cleaner(netlink_close) struct nl_handler *nlh_ptr = &nlh;
	int err, index, len;
	struct ifinfomsg *ifi;

	err = netlink_open(nlh_ptr, NETLINK_ROUTE);
	if (err)
		return err;

	len = strlen(name);
	if (len == 1 || len >= IFNAMSIZ)
		return ret_errno(EINVAL);

	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg)
		return ret_errno(ENOMEM);

	answer = nlmsg_alloc_reserve(NLMSG_GOOD_SIZE);
	if (!answer)
		return ret_errno(ENOMEM);

	index = if_nametoindex(name);
	if (!index)
		return ret_errno(EINVAL);

	nlmsg->nlmsghdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlmsg->nlmsghdr->nlmsg_type = RTM_NEWLINK;

	ifi = nlmsg_reserve(nlmsg, sizeof(struct ifinfomsg));
	if (!ifi)
		return ret_errno(ENOMEM);

	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index = index;
	ifi->ifi_change |= IFF_UP;
	ifi->ifi_flags |= flag;

	return netlink_transaction(nlh_ptr, nlmsg, answer);
}

static int netdev_get_flag(const char *name, int *flag)
{
	call_cleaner(nlmsg_free) struct nlmsg *answer = NULL, *nlmsg = NULL;
	struct nl_handler nlh;
	call_cleaner(netlink_close) struct nl_handler *nlh_ptr = &nlh;
	int err, index, len;
	struct ifinfomsg *ifi;

	if (!name)
		return ret_errno(EINVAL);

	err = netlink_open(nlh_ptr, NETLINK_ROUTE);
	if (err)
		return err;

	len = strlen(name);
	if (len == 1 || len >= IFNAMSIZ)
		return ret_errno(EINVAL);

	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg)
		return ret_errno(ENOMEM);

	answer = nlmsg_alloc_reserve(NLMSG_GOOD_SIZE);
	if (!answer)
		return ret_errno(ENOMEM);

	index = if_nametoindex(name);
	if (!index)
		return ret_errno(EINVAL);

	nlmsg->nlmsghdr->nlmsg_flags = NLM_F_REQUEST;
	nlmsg->nlmsghdr->nlmsg_type = RTM_GETLINK;

	ifi = nlmsg_reserve(nlmsg, sizeof(struct ifinfomsg));
	if (!ifi)
		return ret_errno(ENOMEM);

	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index = index;

	err = netlink_transaction(nlh_ptr, nlmsg, answer);
	if (err)
		return ret_set_errno(-1, errno);

	ifi = NLMSG_DATA(answer->nlmsghdr);

	*flag = ifi->ifi_flags;
	return err;
}

/*
 * \brief Check a interface is up or not.
 *
 * \param name: name for the interface.
 *
 * \return int.
 * 0 means interface is down.
 * 1 means interface is up.
 * Others means error happened, and ret-value is the error number.
 */
int lxc_netdev_isup(const char *name)
{
	int err;
	int flag = 0;

	err = netdev_get_flag(name, &flag);
	if (err)
		return err;

	if (flag & IFF_UP)
		return 1;

	return 0;
}

int netdev_get_mtu(int ifindex)
{
	call_cleaner(nlmsg_free) struct nlmsg *answer = NULL, *nlmsg = NULL;
	struct nl_handler nlh;
	call_cleaner(netlink_close) struct nl_handler *nlh_ptr = &nlh;
	int readmore = 0, recv_len = 0;
	int answer_len, err, res;
	struct ifinfomsg *ifi;
	struct nlmsghdr *msg;

	err = netlink_open(nlh_ptr, NETLINK_ROUTE);
	if (err)
		return err;

	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg)
		return ret_errno(ENOMEM);

	answer = nlmsg_alloc_reserve(NLMSG_GOOD_SIZE);
	if (!answer)
		return ret_errno(ENOMEM);

	/* Save the answer buffer length, since it will be overwritten
	 * on the first receive (and we might need to receive more than
	 * once.
	 */
	answer_len = answer->nlmsghdr->nlmsg_len;

	nlmsg->nlmsghdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlmsg->nlmsghdr->nlmsg_type = RTM_GETLINK;

	ifi = nlmsg_reserve(nlmsg, sizeof(struct ifinfomsg));
	if (!ifi)
		return ret_errno(ENOMEM);

	ifi->ifi_family = AF_UNSPEC;

	/* Send the request for addresses, which returns all addresses
	 * on all interfaces. */
	err = netlink_send(nlh_ptr, nlmsg);
	if (err < 0)
		return ret_set_errno(-1, errno);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"

	do {
		/* Restore the answer buffer length, it might have been
		 * overwritten by a previous receive.
		 */
		answer->nlmsghdr->nlmsg_len = answer_len;

		/* Get the (next) batch of reply messages */
		err = netlink_rcv(nlh_ptr, answer);
		if (err < 0)
			return ret_set_errno(-1, errno);

		recv_len = err;

		/* Satisfy the typing for the netlink macros */
		msg = answer->nlmsghdr;

		while (NLMSG_OK(msg, recv_len)) {
			/* Stop reading if we see an error message */
			if (msg->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *errmsg = (struct nlmsgerr *)NLMSG_DATA(msg);
				return ret_set_errno(errmsg->error, errno);
			}

			/* Stop reading if we see a NLMSG_DONE message */
			if (msg->nlmsg_type == NLMSG_DONE) {
				readmore = 0;
				break;
			}

			ifi = NLMSG_DATA(msg);
			if (ifi->ifi_index == ifindex) {
				struct rtattr *rta = IFLA_RTA(ifi);
				int attr_len = msg->nlmsg_len - NLMSG_LENGTH(sizeof(*ifi));

				res = 0;
				while (RTA_OK(rta, attr_len)) {
					/*
					 * Found a local address for the
					 * requested interface, return it.
					 */
					if (rta->rta_type == IFLA_MTU) {
						memcpy(&res, RTA_DATA(rta), sizeof(int));
						return res;
					}

					rta = RTA_NEXT(rta, attr_len);
				}
			}

			/* Keep reading more data from the socket if the last
			 * message had the NLF_F_MULTI flag set.
			 */
			readmore = (msg->nlmsg_flags & NLM_F_MULTI);

			/* Look at the next message received in this buffer. */
			msg = NLMSG_NEXT(msg, recv_len);
		}
	} while (readmore);

#pragma GCC diagnostic pop

	/* If we end up here, we didn't find any result, so signal an error. */
	return -1;
}

int lxc_netdev_set_mtu(const char *name, int mtu)
{
	call_cleaner(nlmsg_free) struct nlmsg *answer = NULL, *nlmsg = NULL;
	struct nl_handler nlh;
	call_cleaner(netlink_close) struct nl_handler *nlh_ptr = &nlh;
	int err, len;
	struct ifinfomsg *ifi;

	err = netlink_open(nlh_ptr, NETLINK_ROUTE);
	if (err)
		return err;

	len = strlen(name);
	if (len == 1 || len >= IFNAMSIZ)
		return ret_errno(EINVAL);

	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg)
		return ret_errno(ENOMEM);

	answer = nlmsg_alloc_reserve(NLMSG_GOOD_SIZE);
	if (!answer)
		return ret_errno(ENOMEM);

	nlmsg->nlmsghdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlmsg->nlmsghdr->nlmsg_type = RTM_NEWLINK;

	ifi = nlmsg_reserve(nlmsg, sizeof(struct ifinfomsg));
	if (!ifi)
		return ret_errno(ENOMEM);

	ifi->ifi_family = AF_UNSPEC;

	if (nla_put_string(nlmsg, IFLA_IFNAME, name))
		return ret_errno(ENOMEM);

	if (nla_put_u32(nlmsg, IFLA_MTU, mtu))
		return ret_errno(ENOMEM);

	return netlink_transaction(nlh_ptr, nlmsg, answer);
}

int lxc_netdev_up(const char *name)
{
	return netdev_set_flag(name, IFF_UP);
}

int lxc_netdev_down(const char *name)
{
	return netdev_set_flag(name, 0);
}

int lxc_veth_create(const char *name1, const char *name2, pid_t pid, unsigned int mtu)
{
	call_cleaner(nlmsg_free) struct nlmsg *answer = NULL, *nlmsg = NULL;
	struct nl_handler nlh;
	call_cleaner(netlink_close) struct nl_handler *nlh_ptr = &nlh;
	int err, len;
	struct ifinfomsg *ifi;
	struct rtattr *nest1, *nest2, *nest3;

	err = netlink_open(nlh_ptr, NETLINK_ROUTE);
	if (err)
		return err;

	len = strlen(name1);
	if (len == 1 || len >= IFNAMSIZ)
		return ret_errno(EINVAL);

	len = strlen(name2);
	if (len == 1 || len >= IFNAMSIZ)
		return ret_errno(EINVAL);

	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg)
		return ret_errno(ENOMEM);

	answer = nlmsg_alloc_reserve(NLMSG_GOOD_SIZE);
	if (!answer)
		return ret_errno(ENOMEM);

	nlmsg->nlmsghdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
	nlmsg->nlmsghdr->nlmsg_type = RTM_NEWLINK;

	ifi = nlmsg_reserve(nlmsg, sizeof(struct ifinfomsg));
	if (!ifi)
		return ret_errno(ENOMEM);

	ifi->ifi_family = AF_UNSPEC;

	nest1 = nla_begin_nested(nlmsg, IFLA_LINKINFO);
	if (!nest1)
		return ret_errno(EINVAL);

	if (nla_put_string(nlmsg, IFLA_INFO_KIND, "veth"))
		return ret_errno(ENOMEM);

	nest2 = nla_begin_nested(nlmsg, IFLA_INFO_DATA);
	if (!nest2)
		return ret_errno(ENOMEM);

	nest3 = nla_begin_nested(nlmsg, VETH_INFO_PEER);
	if (!nest3)
		return ret_errno(ENOMEM);

	ifi = nlmsg_reserve(nlmsg, sizeof(struct ifinfomsg));
	if (!ifi)
		return ret_errno(ENOMEM);

	if (nla_put_string(nlmsg, IFLA_IFNAME, name2))
		return ret_errno(ENOMEM);

	if (mtu > 0 && nla_put_u32(nlmsg, IFLA_MTU, mtu))
		return ret_errno(ENOMEM);

	if (pid > 0 && nla_put_u32(nlmsg, IFLA_NET_NS_PID, pid))
		return ret_errno(ENOMEM);

	nla_end_nested(nlmsg, nest3);
	nla_end_nested(nlmsg, nest2);
	nla_end_nested(nlmsg, nest1);

	if (nla_put_string(nlmsg, IFLA_IFNAME, name1))
		return ret_errno(ENOMEM);

	return netlink_transaction(nlh_ptr, nlmsg, answer);
}

/* TODO: merge with lxc_macvlan_create */
int lxc_vlan_create(const char *parent, const char *name, unsigned short vlanid)
{
	call_cleaner(nlmsg_free) struct nlmsg *answer = NULL, *nlmsg = NULL;
	struct nl_handler nlh;
	call_cleaner(netlink_close) struct nl_handler *nlh_ptr = &nlh;
	int err, len, lindex;
	struct ifinfomsg *ifi;
	struct rtattr *nest, *nest2;

	err = netlink_open(nlh_ptr, NETLINK_ROUTE);
	if (err)
		return err;

	len = strlen(parent);
	if (len == 1 || len >= IFNAMSIZ)
		return ret_errno(EINVAL);

	len = strlen(name);
	if (len == 1 || len >= IFNAMSIZ)
		return ret_errno(EINVAL);

	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg)
		return ret_errno(ENOMEM);

	answer = nlmsg_alloc_reserve(NLMSG_GOOD_SIZE);
	if (!answer)
		return ret_errno(ENOMEM);

	lindex = if_nametoindex(parent);
	if (!lindex)
		return ret_errno(EINVAL);

	nlmsg->nlmsghdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
	nlmsg->nlmsghdr->nlmsg_type = RTM_NEWLINK;

	ifi = nlmsg_reserve(nlmsg, sizeof(struct ifinfomsg));
	if (!ifi)
		return ret_errno(ENOMEM);

	ifi->ifi_family = AF_UNSPEC;

	nest = nla_begin_nested(nlmsg, IFLA_LINKINFO);
	if (!nest)
		return ret_errno(ENOMEM);

	if (nla_put_string(nlmsg, IFLA_INFO_KIND, "vlan"))
		return ret_errno(ENOMEM);

	nest2 = nla_begin_nested(nlmsg, IFLA_INFO_DATA);
	if (!nest2)
		return ret_errno(ENOMEM);

	if (nla_put_u16(nlmsg, IFLA_VLAN_ID, vlanid))
		return ret_errno(ENOMEM);

	nla_end_nested(nlmsg, nest2);
	nla_end_nested(nlmsg, nest);

	if (nla_put_u32(nlmsg, IFLA_LINK, lindex))
		return ret_errno(ENOMEM);

	if (nla_put_string(nlmsg, IFLA_IFNAME, name))
		return ret_errno(ENOMEM);

	return netlink_transaction(nlh_ptr, nlmsg, answer);
}

int lxc_macvlan_create(const char *parent, const char *name, int mode)
{
	call_cleaner(nlmsg_free) struct nlmsg *answer = NULL, *nlmsg = NULL;
	struct nl_handler nlh;
	call_cleaner(netlink_close) struct nl_handler *nlh_ptr = &nlh;
	int err, index, len;
	struct ifinfomsg *ifi;
	struct rtattr *nest, *nest2;

	err = netlink_open(nlh_ptr, NETLINK_ROUTE);
	if (err)
		return err;

	len = strlen(parent);
	if (len == 1 || len >= IFNAMSIZ)
		return ret_errno(EINVAL);

	len = strlen(name);
	if (len == 1 || len >= IFNAMSIZ)
		return ret_errno(EINVAL);

	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg)
		return ret_errno(ENOMEM);

	answer = nlmsg_alloc_reserve(NLMSG_GOOD_SIZE);
	if (!answer)
		return ret_errno(ENOMEM);

	index = if_nametoindex(parent);
	if (!index)
		return ret_errno(EINVAL);

	nlmsg->nlmsghdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
	nlmsg->nlmsghdr->nlmsg_type = RTM_NEWLINK;

	ifi = nlmsg_reserve(nlmsg, sizeof(struct ifinfomsg));
	if (!ifi)
		return ret_errno(ENOMEM);

	ifi->ifi_family = AF_UNSPEC;

	nest = nla_begin_nested(nlmsg, IFLA_LINKINFO);
	if (!nest)
		return ret_errno(ENOMEM);

	if (nla_put_string(nlmsg, IFLA_INFO_KIND, "macvlan"))
		return ret_errno(ENOMEM);

	if (mode) {
		nest2 = nla_begin_nested(nlmsg, IFLA_INFO_DATA);
		if (!nest2)
			return ret_errno(ENOMEM);

		if (nla_put_u32(nlmsg, IFLA_MACVLAN_MODE, mode))
			return ret_errno(ENOMEM);

		nla_end_nested(nlmsg, nest2);
	}

	nla_end_nested(nlmsg, nest);

	if (nla_put_u32(nlmsg, IFLA_LINK, index))
		return ret_errno(ENOMEM);

	if (nla_put_string(nlmsg, IFLA_IFNAME, name))
		return ret_errno(ENOMEM);

	return netlink_transaction(nlh_ptr, nlmsg, answer);
}

static int proc_sys_net_write(const char *path, const char *value)
{
	int fd;
	int err = 0;

	fd = open(path, O_WRONLY);
	if (fd < 0)
		return -errno;

	if (lxc_write_nointr(fd, value, strlen(value)) < 0)
		err = -errno;

	close(fd);
	return err;
}

static int ip_forwarding_set(const char *ifname, int family, int flag)
{
	int ret;
	char path[PATH_MAX];

	if (family != AF_INET && family != AF_INET6)
		return -EINVAL;

	ret = strnprintf(path, sizeof(path), "/proc/sys/net/%s/conf/%s/%s",
			 family == AF_INET ? "ipv4" : "ipv6", ifname,
			 "forwarding");
	if (ret < 0)
		return -E2BIG;

	return proc_sys_net_write(path, flag ? "1" : "0");
}

int lxc_ip_forwarding_on(const char *name, int family)
{
	return ip_forwarding_set(name, family, 1);
}

int lxc_ip_forwarding_off(const char *name, int family)
{
	return ip_forwarding_set(name, family, 0);
}

static int neigh_proxy_set(const char *ifname, int family, int flag)
{
	int ret;
	char path[PATH_MAX];

	if (family != AF_INET && family != AF_INET6)
		return -EINVAL;

	ret = strnprintf(path, sizeof(path), "/proc/sys/net/%s/conf/%s/%s",
			 family == AF_INET ? "ipv4" : "ipv6", ifname,
			 family == AF_INET ? "proxy_arp" : "proxy_ndp");
	if (ret < 0)
		return -E2BIG;

	return proc_sys_net_write(path, flag ? "1" : "0");
}

static int lxc_is_ip_neigh_proxy_enabled(const char *ifname, int family)
{
	int ret;
	char path[PATH_MAX];
	char buf[1] = "";

	if (family != AF_INET && family != AF_INET6)
		return ret_set_errno(-1, EINVAL);

	ret = strnprintf(path, sizeof(path), "/proc/sys/net/%s/conf/%s/%s",
			 family == AF_INET ? "ipv4" : "ipv6", ifname,
			 family == AF_INET ? "proxy_arp" : "proxy_ndp");
	if (ret < 0)
		return ret_set_errno(-1, E2BIG);

	return lxc_read_file_expect(path, buf, 1, "1");
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
	int i = 0;
	unsigned val;
	char c;
	unsigned char *data;

	sockaddr->sa_family = ARPHRD_ETHER;
	data = (unsigned char *)sockaddr->sa_data;

	while ((*macaddr != '\0') && (i < ETH_ALEN)) {
		c = *macaddr++;
		if (isdigit(c))
			val = c - '0';
		else if (c >= 'a' && c <= 'f')
			val = c - 'a' + 10;
		else if (c >= 'A' && c <= 'F')
			val = c - 'A' + 10;
		else
			return -EINVAL;

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
		else
			return -EINVAL;
		if (c != 0)
			macaddr++;
		*data++ = (unsigned char)(val & 0377);
		i++;

		if (*macaddr == ':')
			macaddr++;
	}

	return 0;
}

static int ip_addr_add(int family, int ifindex, void *addr, void *bcast,
		       void *acast, int prefix)
{
	call_cleaner(nlmsg_free) struct nlmsg *answer = NULL, *nlmsg = NULL;
	struct nl_handler nlh;
	call_cleaner(netlink_close) struct nl_handler *nlh_ptr = &nlh;
	int addrlen, err;
	struct ifaddrmsg *ifa;

	addrlen = family == AF_INET ? sizeof(struct in_addr)
				    : sizeof(struct in6_addr);

	err = netlink_open(nlh_ptr, NETLINK_ROUTE);
	if (err)
		return err;

	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg)
		return ret_errno(ENOMEM);

	answer = nlmsg_alloc_reserve(NLMSG_GOOD_SIZE);
	if (!answer)
		return ret_errno(ENOMEM);

	nlmsg->nlmsghdr->nlmsg_flags = NLM_F_ACK | NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
	nlmsg->nlmsghdr->nlmsg_type = RTM_NEWADDR;

	ifa = nlmsg_reserve(nlmsg, sizeof(struct ifaddrmsg));
	if (!ifa)
		return ret_errno(ENOMEM);

	ifa->ifa_prefixlen = prefix;
	ifa->ifa_index = ifindex;
	ifa->ifa_family = family;
	ifa->ifa_scope = 0;

	if (nla_put_buffer(nlmsg, IFA_LOCAL, addr, addrlen))
		return ret_errno(EINVAL);

	if (nla_put_buffer(nlmsg, IFA_ADDRESS, addr, addrlen))
		return ret_errno(EINVAL);

	if (nla_put_buffer(nlmsg, IFA_BROADCAST, bcast, addrlen))
		return ret_errno(EINVAL);

	/* TODO: multicast, anycast with ipv6 */
	if (family == AF_INET6 &&
	    (memcmp(bcast, &in6addr_any, sizeof(in6addr_any)) ||
	     memcmp(acast, &in6addr_any, sizeof(in6addr_any))))
		return ret_errno(EPROTONOSUPPORT);

	return netlink_transaction(nlh_ptr, nlmsg, answer);
}

int lxc_ipv6_addr_add(int ifindex, struct in6_addr *addr,
		      struct in6_addr *mcast, struct in6_addr *acast,
		      int prefix)
{
	return ip_addr_add(AF_INET6, ifindex, addr, mcast, acast, prefix);
}

int lxc_ipv4_addr_add(int ifindex, struct in_addr *addr, struct in_addr *bcast,
		      int prefix)
{
	return ip_addr_add(AF_INET, ifindex, addr, bcast, NULL, prefix);
}

/* Find an IFA_LOCAL (or IFA_ADDRESS if not IFA_LOCAL is present) address from
 * the given RTM_NEWADDR message. Allocates memory for the address and stores
 * that pointer in *res (so res should be an in_addr** or in6_addr**).
 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"

static int ifa_get_local_ip(int family, struct nlmsghdr *msg, void **res)
{
	int addrlen;
	struct ifaddrmsg *ifa = NLMSG_DATA(msg);
	struct rtattr *rta = IFA_RTA(ifa);
	int attr_len = NLMSG_PAYLOAD(msg, sizeof(struct ifaddrmsg));

	if (ifa->ifa_family != family)
		return 0;

	addrlen = family == AF_INET ? sizeof(struct in_addr)
				    : sizeof(struct in6_addr);

	/* Loop over the rtattr's in this message */
	while (RTA_OK(rta, attr_len)) {
		/* Found a local address for the requested interface,
		 * return it.
		 */
		if (rta->rta_type == IFA_LOCAL ||
		    rta->rta_type == IFA_ADDRESS) {
			/* Sanity check. The family check above should make sure
			 * the address length is correct, but check here just in
			 * case.
			 */
			if (RTA_PAYLOAD(rta) != addrlen)
				return -1;

			/* We might have found an IFA_ADDRESS before, which we
			 * now overwrite with an IFA_LOCAL.
			 */
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

#pragma GCC diagnostic pop

static int ip_addr_get(int family, int ifindex, void **res)
{
	call_cleaner(nlmsg_free) struct nlmsg *answer = NULL, *nlmsg = NULL;
	struct nl_handler nlh;
	call_cleaner(netlink_close) struct nl_handler *nlh_ptr = &nlh;
	int answer_len, err;
	struct ifaddrmsg *ifa;
	struct nlmsghdr *msg;
	int readmore = 0, recv_len = 0;

	err = netlink_open(nlh_ptr, NETLINK_ROUTE);
	if (err)
		return err;

	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg)
		return ret_errno(ENOMEM);

	answer = nlmsg_alloc_reserve(NLMSG_GOOD_SIZE);
	if (!answer)
		return ret_errno(ENOMEM);

	/* Save the answer buffer length, since it will be overwritten on the
	 * first receive (and we might need to receive more than once).
	 */
	answer_len = answer->nlmsghdr->nlmsg_len;

	nlmsg->nlmsghdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT;
	nlmsg->nlmsghdr->nlmsg_type = RTM_GETADDR;

	ifa = nlmsg_reserve(nlmsg, sizeof(struct ifaddrmsg));
	if (!ifa)
		return ret_errno(ENOMEM);

	ifa->ifa_family = family;

	/* Send the request for addresses, which returns all addresses on all
	 * interfaces.
	 */
	err = netlink_send(nlh_ptr, nlmsg);
	if (err < 0)
		return ret_set_errno(err, errno);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"

	do {
		/* Restore the answer buffer length, it might have been
		 * overwritten by a previous receive.
		 */
		answer->nlmsghdr->nlmsg_len = answer_len;

		/* Get the (next) batch of reply messages. */
		err = netlink_rcv(nlh_ptr, answer);
		if (err < 0)
			return ret_set_errno(err, errno);

		recv_len = err;
		err = 0;

		/* Satisfy the typing for the netlink macros. */
		msg = answer->nlmsghdr;

		while (NLMSG_OK(msg, recv_len)) {
			/* Stop reading if we see an error message. */
			if (msg->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *errmsg = (struct nlmsgerr *)NLMSG_DATA(msg);
				return ret_set_errno(errmsg->error, errno);
			}

			/* Stop reading if we see a NLMSG_DONE message. */
			if (msg->nlmsg_type == NLMSG_DONE) {
				readmore = 0;
				break;
			}

			if (msg->nlmsg_type != RTM_NEWADDR)
				return ret_errno(EINVAL);

			ifa = (struct ifaddrmsg *)NLMSG_DATA(msg);
			if (ifa->ifa_index == ifindex) {
				if (ifa_get_local_ip(family, msg, res) < 0)
					return ret_errno(EINVAL);

				/* Found a result, stop searching. */
				if (*res)
					return 0;
			}

			/* Keep reading more data from the socket if the last
			 * message had the NLF_F_MULTI flag set.
			 */
			readmore = (msg->nlmsg_flags & NLM_F_MULTI);

			/* Look at the next message received in this buffer. */
			msg = NLMSG_NEXT(msg, recv_len);
		}
	} while (readmore);

#pragma GCC diagnostic pop

	/* If we end up here, we didn't find any result, so signal an
	 * error.
	 */
	return -1;
}

int lxc_ipv6_addr_get(int ifindex, struct in6_addr **res)
{
	return ip_addr_get(AF_INET6, ifindex, (void **)res);
}

int lxc_ipv4_addr_get(int ifindex, struct in_addr **res)
{
	return ip_addr_get(AF_INET, ifindex, (void **)res);
}

static int ip_gateway_add(int family, int ifindex, void *gw)
{
	call_cleaner(nlmsg_free) struct nlmsg *answer = NULL, *nlmsg = NULL;
	struct nl_handler nlh;
	call_cleaner(netlink_close) struct nl_handler *nlh_ptr = &nlh;
	int addrlen, err;
	struct rtmsg *rt;

	addrlen = family == AF_INET ? sizeof(struct in_addr)
				    : sizeof(struct in6_addr);

	err = netlink_open(nlh_ptr, NETLINK_ROUTE);
	if (err)
		return err;

	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg)
		return ret_errno(ENOMEM);

	answer = nlmsg_alloc_reserve(NLMSG_GOOD_SIZE);
	if (!answer)
		return ret_errno(ENOMEM);

	nlmsg->nlmsghdr->nlmsg_flags = NLM_F_ACK | NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
	nlmsg->nlmsghdr->nlmsg_type = RTM_NEWROUTE;

	rt = nlmsg_reserve(nlmsg, sizeof(struct rtmsg));
	if (!rt)
		return ret_errno(ENOMEM);

	rt->rtm_family = family;
	rt->rtm_table = RT_TABLE_MAIN;
	rt->rtm_scope = RT_SCOPE_UNIVERSE;
	rt->rtm_protocol = RTPROT_BOOT;
	rt->rtm_type = RTN_UNICAST;
	/* "default" destination */
	rt->rtm_dst_len = 0;

	/* If gateway address not supplied, then a device route will be created instead */
	if (gw && nla_put_buffer(nlmsg, RTA_GATEWAY, gw, addrlen))
		return ret_errno(ENOMEM);

	/* Adding the interface index enables the use of link-local
	 * addresses for the gateway.
	 */
	if (nla_put_u32(nlmsg, RTA_OIF, ifindex))
		return ret_errno(EINVAL);

	return netlink_transaction(nlh_ptr, nlmsg, answer);
}

int lxc_ipv4_gateway_add(int ifindex, struct in_addr *gw)
{
	return ip_gateway_add(AF_INET, ifindex, gw);
}

int lxc_ipv6_gateway_add(int ifindex, struct in6_addr *gw)
{
	return ip_gateway_add(AF_INET6, ifindex, gw);
}
bool is_ovs_bridge(const char *bridge)
{
	int ret;
	struct stat sb;
	char brdirname[22 + IFNAMSIZ + 1] = {0};

	ret = strnprintf(brdirname, 22 + IFNAMSIZ + 1,
			 "/sys/class/net/%s/bridge", bridge);
	if (ret < 0)
		return false;

	ret = stat(brdirname, &sb);
	if (ret < 0 && errno == ENOENT)
		return true;

	return false;
}

struct ovs_veth_args {
	const char *bridge;
	const char *nic;
};

/* Called from a background thread - when nic goes away, remove it from the
 * bridge.
 */
static int lxc_ovs_delete_port_exec(void *data)
{
	struct ovs_veth_args *args = data;

	execlp("ovs-vsctl", "ovs-vsctl", "del-port", args->bridge, args->nic, (char *)NULL);
	return -1;
}

int lxc_ovs_delete_port(const char *bridge, const char *nic)
{
	int ret;
	char cmd_output[PATH_MAX];
	struct ovs_veth_args args;

	args.bridge = bridge;
	args.nic = nic;
	ret = run_command(cmd_output, sizeof(cmd_output),
			  lxc_ovs_delete_port_exec, (void *)&args);
	if (ret < 0)
		return log_error(-1, "Failed to delete \"%s\" from openvswitch bridge \"%s\": %s", nic, bridge, cmd_output);

	return 0;
}

static int lxc_ovs_attach_bridge_exec(void *data)
{
	struct ovs_veth_args *args = data;

	execlp("ovs-vsctl", "ovs-vsctl", "add-port", args->bridge, args->nic, (char *)NULL);
	return -1;
}

static int lxc_ovs_attach_bridge(const char *bridge, const char *nic)
{
	int ret;
	char cmd_output[PATH_MAX];
	struct ovs_veth_args args;

	args.bridge = bridge;
	args.nic = nic;
	ret = run_command(cmd_output, sizeof(cmd_output),
			  lxc_ovs_attach_bridge_exec, (void *)&args);
	if (ret < 0)
		return log_error(-1, "Failed to attach \"%s\" to openvswitch bridge \"%s\": %s", nic, bridge, cmd_output);

	return 0;
}

int lxc_bridge_attach(const char *bridge, const char *ifname)
{
	int err, fd, index;
	size_t retlen;
	struct ifreq ifr;

	if (strlen(ifname) >= IFNAMSIZ)
		return -EINVAL;

	index = if_nametoindex(ifname);
	if (!index)
		return -EINVAL;

	if (is_ovs_bridge(bridge))
		return lxc_ovs_attach_bridge(bridge, ifname);

	fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	retlen = strlcpy(ifr.ifr_name, bridge, IFNAMSIZ);
	if (retlen >= IFNAMSIZ) {
		close(fd);
		return -E2BIG;
	}

	ifr.ifr_name[IFNAMSIZ - 1] = '\0';
	ifr.ifr_ifindex = index;
	err = ioctl(fd, SIOCBRADDIF, &ifr);
	close(fd);
	if (err)
		err = -errno;

	return err;
}

int setup_private_host_hw_addr(char *veth1)
{
	__do_close int sockfd = -EBADF;
	int err;
	struct ifreq ifr;

	sockfd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (sockfd < 0)
		return -errno;

	err = strnprintf((char *)ifr.ifr_name, IFNAMSIZ, "%s", veth1);
	if (err < 0)
		return err;

	err = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
	if (err < 0)
		return -errno;

	ifr.ifr_hwaddr.sa_data[0] = 0xfe;
	err = ioctl(sockfd, SIOCSIFHWADDR, &ifr);
	if (err < 0)
		return -errno;

	return 0;
}

int lxc_find_gateway_addresses(struct lxc_handler *handler)
{
	struct lxc_list *network = &handler->conf->network;
	struct lxc_list *iterator;
	struct lxc_netdev *netdev;
	int link_index;

	lxc_list_for_each(iterator, network) {
		netdev = iterator->elem;

		if (!netdev->ipv4_gateway_auto && !netdev->ipv6_gateway_auto)
			continue;

		if (netdev->type != LXC_NET_VETH && netdev->type != LXC_NET_MACVLAN)
			return log_error_errno(-1, EINVAL, "Automatic gateway detection is only supported for veth and macvlan");

		if (is_empty_string(netdev->link)) {
			return log_error_errno(-1, errno, "Automatic gateway detection needs a link interface");
		}

		link_index = if_nametoindex(netdev->link);
		if (!link_index)
			return -EINVAL;

		if (netdev->ipv4_gateway_auto) {
			if (lxc_ipv4_addr_get(link_index, &netdev->ipv4_gateway))
				return log_error_errno(-1, errno, "Failed to automatically find ipv4 gateway address from link interface \"%s\"", netdev->link);
		}

		if (netdev->ipv6_gateway_auto) {
			if (lxc_ipv6_addr_get(link_index, &netdev->ipv6_gateway))
				return log_error_errno(-1, errno, "Failed to automatically find ipv6 gateway address from link interface \"%s\"", netdev->link);
		}
	}

	return 0;
}

#define LXC_USERNIC_PATH LIBEXECDIR "/lxc/lxc-user-nic"
static int lxc_create_network_unpriv_exec(const char *lxcpath,
					  const char *lxcname,
					  struct lxc_netdev *netdev, pid_t pid,
					  unsigned int hooks_version)
{
	int ret;
	pid_t child;
	int bytes, pipefd[2];
	char *token, *saveptr = NULL;
	char netdev_link[IFNAMSIZ];
	char buffer[PATH_MAX] = {0};
	size_t retlen;

	if (netdev->type != LXC_NET_VETH)
		return log_error_errno(-1, errno,
				       "Network type %d not support for unprivileged use",
				       netdev->type);

	ret = pipe(pipefd);
	if (ret < 0)
		return log_error_errno(-1, errno, "Failed to create pipe");

	child = fork();
	if (child < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		return log_error_errno(-1, errno, "Failed to create new process");
	}

	if (child == 0) {
		char pidstr[INTTYPE_TO_STRLEN(pid_t)];

		close(pipefd[0]);

		ret = dup2(pipefd[1], STDOUT_FILENO);
		if (ret >= 0)
			ret = dup2(pipefd[1], STDERR_FILENO);
		close(pipefd[1]);
		if (ret < 0) {
			SYSERROR("Failed to duplicate std{err,out} file descriptor");
			_exit(EXIT_FAILURE);
		}

		if (!is_empty_string(netdev->link))
			retlen = strlcpy(netdev_link, netdev->link, IFNAMSIZ);
		else
			retlen = strlcpy(netdev_link, "none", IFNAMSIZ);
		if (retlen >= IFNAMSIZ) {
			SYSERROR("Invalid network device name");
			_exit(EXIT_FAILURE);
		}

		ret = strnprintf(pidstr, sizeof(pidstr), "%d", pid);
		if (ret < 0)
			_exit(EXIT_FAILURE);
		pidstr[sizeof(pidstr) - 1] = '\0';

		INFO("Execing lxc-user-nic create %s %s %s veth %s %s", lxcpath,
		     lxcname, pidstr, netdev_link, !is_empty_string(netdev->name) ? netdev->name : "(null)");
		if (!is_empty_string(netdev->name))
			execlp(LXC_USERNIC_PATH, LXC_USERNIC_PATH, "create",
			       lxcpath, lxcname, pidstr, "veth", netdev_link,
			       netdev->name, (char *)NULL);
		else
			execlp(LXC_USERNIC_PATH, LXC_USERNIC_PATH, "create",
			       lxcpath, lxcname, pidstr, "veth", netdev_link,
			       (char *)NULL);
		SYSERROR("Failed to execute lxc-user-nic");
		_exit(EXIT_FAILURE);
	}

	/* close the write-end of the pipe */
	close(pipefd[1]);

	bytes = lxc_read_nointr(pipefd[0], &buffer, sizeof(buffer));
	if (bytes < 0) {
		SYSERROR("Failed to read from pipe file descriptor");
		close(pipefd[0]);
	} else {
		buffer[bytes - 1] = '\0';
	}

	ret = wait_for_pid(child);
	close(pipefd[0]);
	if (ret != 0 || bytes < 0)
		return log_error(-1, "lxc-user-nic failed to configure requested network: %s",
				 buffer[0] != '\0' ? buffer : "(null)");
	TRACE("Received output \"%s\" from lxc-user-nic", buffer);

	/* netdev->name */
	token = strtok_r(buffer, ":", &saveptr);
	if (!token)
		return log_error(-1, "Failed to parse lxc-user-nic output");

	/*
	 * lxc-user-nic will take care of proper network device naming. So
	 * netdev->name and netdev->transient_name need to be identical to not
	 * trigger another rename later on.
	 */
	retlen = strlcpy(netdev->name, token, IFNAMSIZ);
	if (retlen < IFNAMSIZ) {
		retlen = strlcpy(netdev->transient_name, token, IFNAMSIZ);
		if (retlen < IFNAMSIZ)
			retlen = strlcpy(netdev->created_name, token, IFNAMSIZ);
	}
	if (retlen >= IFNAMSIZ)
		return log_error_errno(-1, E2BIG,
				       "Container side veth device name returned by lxc-user-nic is too long");

	/* netdev->ifindex */
	token = strtok_r(NULL, ":", &saveptr);
	if (!token)
		return log_error(-1, "Failed to parse lxc-user-nic output");

	ret = lxc_safe_int(token, &netdev->ifindex);
	if (ret < 0)
		return log_error_errno(-1, -ret,
				       "Failed to convert string \"%s\" to integer", token);

	/* netdev->priv.veth_attr.veth1 */
	token = strtok_r(NULL, ":", &saveptr);
	if (!token)
		return log_error(-1, "Failed to parse lxc-user-nic output");

	retlen = strlcpy(netdev->priv.veth_attr.veth1, token, IFNAMSIZ);
	if (retlen >= IFNAMSIZ)
		return log_error_errno(-1, E2BIG,
				       "Host side veth device name returned by lxc-user-nic is too long");

	/* netdev->priv.veth_attr.ifindex */
	token = strtok_r(NULL, ":", &saveptr);
	if (!token)
		return log_error(-1, "Failed to parse lxc-user-nic output");

	ret = lxc_safe_int(token, &netdev->priv.veth_attr.ifindex);
	if (ret < 0)
		return log_error_errno(-1, -ret,
				       "Failed to convert string \"%s\" to integer", token);

	if (netdev->upscript) {
		char *argv[] = {
			"veth",
			netdev->link,
			netdev->priv.veth_attr.veth1,
			NULL,
		};

		ret = run_script_argv(lxcname, hooks_version, "net",
				      netdev->upscript, "up", argv);
		if (ret < 0)
			return -1;
	}

	return 0;
}

static int lxc_delete_network_unpriv_exec(const char *lxcpath, const char *lxcname,
					  struct lxc_netdev *netdev,
					  const char *netns_path)
{
	int bytes, ret;
	pid_t child;
	int pipefd[2];
	char buffer[PATH_MAX] = {};

	if (netdev->type != LXC_NET_VETH)
		return log_error_errno(-1, EINVAL, "Network type %d not support for unprivileged use", netdev->type);

	ret = pipe(pipefd);
	if (ret < 0)
		return log_error_errno(-1, errno, "Failed to create pipe");

	child = fork();
	if (child < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		return log_error_errno(-1, errno, "Failed to create new process");
	}

	if (child == 0) {
		char *hostveth;

		close(pipefd[0]);

		ret = dup2(pipefd[1], STDOUT_FILENO);
		if (ret >= 0)
			ret = dup2(pipefd[1], STDERR_FILENO);
		close(pipefd[1]);
		if (ret < 0) {
			SYSERROR("Failed to duplicate std{err,out} file descriptor");
			_exit(EXIT_FAILURE);
		}

		if (!is_empty_string(netdev->priv.veth_attr.pair))
			hostveth = netdev->priv.veth_attr.pair;
		else
			hostveth = netdev->priv.veth_attr.veth1;
		if (is_empty_string(hostveth)) {
			SYSERROR("Host side veth device name is missing");
			_exit(EXIT_FAILURE);
		}

		if (is_empty_string(netdev->link)) {
			SYSERROR("Network link for network device \"%s\" is missing", netdev->priv.veth_attr.veth1);
			_exit(EXIT_FAILURE);
		}

		INFO("Execing lxc-user-nic delete %s %s %s veth %s %s", lxcpath,
		     lxcname, netns_path, netdev->link, hostveth);
		execlp(LXC_USERNIC_PATH, LXC_USERNIC_PATH, "delete", lxcpath,
		       lxcname, netns_path, "veth", netdev->link, hostveth,
		       (char *)NULL);
		SYSERROR("Failed to exec lxc-user-nic.");
		_exit(EXIT_FAILURE);
	}

	close(pipefd[1]);

	bytes = lxc_read_nointr(pipefd[0], &buffer, sizeof(buffer));
	if (bytes < 0) {
		SYSERROR("Failed to read from pipe file descriptor.");
		close(pipefd[0]);
	} else {
		buffer[bytes - 1] = '\0';
	}

	ret = wait_for_pid(child);
	close_prot_errno_disarm(pipefd[0]);
	if (ret != 0 || bytes < 0)
		return log_error_errno(-1, errno, "lxc-user-nic failed to delete requested network: %s",
				       !is_empty_string(buffer) ? buffer : "(null)");

	return 0;
}

static bool lxc_delete_network_unpriv(struct lxc_handler *handler)
{
	int ret;
	struct lxc_list *iterator;
	struct lxc_list *network = &handler->conf->network;
	/* strlen("/proc/") = 6
	 * +
	 * INTTYPE_TO_STRLEN(pid_t)
	 * +
	 * strlen("/fd/") = 4
	 * +
	 * INTTYPE_TO_STRLEN(int)
	 * +
	 * \0
	 */
	char netns_path[6 + INTTYPE_TO_STRLEN(pid_t) + 4 + INTTYPE_TO_STRLEN(int) + 1];

	*netns_path = '\0';

	if (handler->nsfd[LXC_NS_NET] < 0)
		return log_debug(false, "Cannot not guarantee safe deletion of network devices. Manual cleanup maybe needed");

	ret = strnprintf(netns_path, sizeof(netns_path), "/proc/%d/fd/%d",
			 lxc_raw_getpid(), handler->nsfd[LXC_NS_NET]);
	if (ret < 0)
		return false;

	lxc_list_for_each(iterator, network) {
		char *hostveth = NULL;
		struct lxc_netdev *netdev = iterator->elem;

		/* We can only delete devices whose ifindex we have. If we don't
		 * have the index it means that we didn't create it.
		 */
		if (!netdev->ifindex)
			continue;

		if (netdev->type == LXC_NET_PHYS) {
			ret = lxc_netdev_rename_by_index(netdev->ifindex,
							 netdev->link);
			if (ret < 0)
				WARN("Failed to rename interface with index %d to its initial name \"%s\"",
				     netdev->ifindex, netdev->link);
			else
				TRACE("Renamed interface with index %d to its initial name \"%s\"",
				      netdev->ifindex, netdev->link);

			ret = netdev_deconf[netdev->type](handler, netdev);
			if (ret < 0)
				WARN("Failed to deconfigure interface with index %d and initial name \"%s\"",
				     netdev->ifindex, netdev->link);
			goto clear_ifindices;
		}

		ret = netdev_deconf[netdev->type](handler, netdev);
		if (ret < 0)
			WARN("Failed to deconfigure network device");

		if (netdev->type != LXC_NET_VETH)
			goto clear_ifindices;

		if (is_empty_string(netdev->link) || !is_ovs_bridge(netdev->link))
			goto clear_ifindices;

		if (!is_empty_string(netdev->priv.veth_attr.pair))
			hostveth = netdev->priv.veth_attr.pair;
		else
			hostveth = netdev->priv.veth_attr.veth1;
		if (is_empty_string(hostveth))
			goto clear_ifindices;

		ret = lxc_delete_network_unpriv_exec(handler->lxcpath,
						     handler->name, netdev,
						     netns_path);
		if (ret < 0) {
			WARN("Failed to remove port \"%s\" from openvswitch bridge \"%s\"", hostveth, netdev->link);
			goto clear_ifindices;
		}
		INFO("Removed interface \"%s\" from \"%s\"", hostveth, netdev->link);

clear_ifindices:
		/*
		 * We need to clear any ifindices we recorded so liblxc won't
		 * have cached stale data which would cause it to fail on
		 * reboot where we don't re-read the on-disk config file.
		 */
		netdev->ifindex = 0;
		if (netdev->type == LXC_NET_PHYS) {
			netdev->priv.phys_attr.ifindex = 0;
		} else if (netdev->type == LXC_NET_VETH) {
			netdev->priv.veth_attr.veth1[0] = '\0';
			netdev->priv.veth_attr.ifindex = 0;
		}
	}

	return true;
}

static int lxc_setup_l2proxy(struct lxc_netdev *netdev) {
	struct lxc_list *cur, *next;
	struct lxc_inetdev *inet4dev;
	struct lxc_inet6dev *inet6dev;
	char bufinet4[INET_ADDRSTRLEN], bufinet6[INET6_ADDRSTRLEN];
	int err = 0;
	unsigned int lo_ifindex = 0, link_ifindex = 0;

	link_ifindex = if_nametoindex(netdev->link);
	if (link_ifindex == 0)
		return log_error_errno(-1, errno, "Failed to retrieve ifindex for \"%s\" l2proxy setup", netdev->link);


	/* If IPv4 addresses are specified, then check that sysctl is configured correctly. */
	if (!lxc_list_empty(&netdev->ipv4)) {
		/* Check for net.ipv4.conf.[link].forwarding=1 */
		if (lxc_is_ip_forwarding_enabled(netdev->link, AF_INET) < 0)
			return log_error_errno(-1, EINVAL, "Requires sysctl net.ipv4.conf.%s.forwarding=1", netdev->link);
	}

	/* If IPv6 addresses are specified, then check that sysctl is configured correctly. */
	if (!lxc_list_empty(&netdev->ipv6)) {
		/* Check for net.ipv6.conf.[link].proxy_ndp=1 */
		if (lxc_is_ip_neigh_proxy_enabled(netdev->link, AF_INET6) < 0)
			return log_error_errno(-1, EINVAL, "Requires sysctl net.ipv6.conf.%s.proxy_ndp=1", netdev->link);

		/* Check for net.ipv6.conf.[link].forwarding=1 */
		if (lxc_is_ip_forwarding_enabled(netdev->link, AF_INET6) < 0)
			return log_error_errno(-1, EINVAL, "Requires sysctl net.ipv6.conf.%s.forwarding=1", netdev->link);
	}

	/* Perform IPVLAN specific checks. */
	if (netdev->type == LXC_NET_IPVLAN) {
		/* Check mode is l3s as other modes do not work with l2proxy. */
		if (netdev->priv.ipvlan_attr.mode != IPVLAN_MODE_L3S)
			return log_error_errno(-1, EINVAL, "Requires ipvlan mode on dev \"%s\" be l3s when used with l2proxy", netdev->link);

		/* Retrieve local-loopback interface index for use with IPVLAN static routes. */
		lo_ifindex = if_nametoindex(loop_device);
		if (lo_ifindex == 0)
			return log_error_errno(-1, EINVAL, "Failed to retrieve ifindex for \"%s\" routing cleanup", loop_device);
	}

	lxc_list_for_each_safe(cur, &netdev->ipv4, next) {
		inet4dev = cur->elem;
		if (!inet_ntop(AF_INET, &inet4dev->addr, bufinet4, sizeof(bufinet4)))
			return ret_set_errno(-1, -errno);

		if (lxc_ip_neigh_proxy(RTM_NEWNEIGH, AF_INET, link_ifindex, &inet4dev->addr) < 0)
			return ret_set_errno(-1, EINVAL);

		/* IPVLAN requires a route to local-loopback to trigger l2proxy. */
		if (netdev->type == LXC_NET_IPVLAN) {
			err = lxc_ipv4_dest_add(lo_ifindex, &inet4dev->addr, 32);
			if (err < 0)
				return log_error_errno(-1, -err, "Failed to add ipv4 dest \"%s\" for network device \"%s\"", bufinet4, loop_device);
		}
	}

	lxc_list_for_each_safe(cur, &netdev->ipv6, next) {
		inet6dev = cur->elem;
		if (!inet_ntop(AF_INET6, &inet6dev->addr, bufinet6, sizeof(bufinet6)))
			return ret_set_errno(-1, -errno);

		if (lxc_ip_neigh_proxy(RTM_NEWNEIGH, AF_INET6, link_ifindex, &inet6dev->addr) < 0)
			return ret_set_errno(-1, EINVAL);

		/* IPVLAN requires a route to local-loopback to trigger l2proxy. */
		if (netdev->type == LXC_NET_IPVLAN) {
			err = lxc_ipv6_dest_add(lo_ifindex, &inet6dev->addr, 128);
			if (err < 0)
				return log_error_errno(-1, -err, "Failed to add ipv6 dest \"%s\" for network device \"%s\"", bufinet6, loop_device);
		}
	}

	return 0;
}

static int lxc_delete_ipv4_l2proxy(struct in_addr *ip, char *link, unsigned int lo_ifindex)
{
	char bufinet4[INET_ADDRSTRLEN];
	bool had_error = false;
	unsigned int link_ifindex = 0;

	if (!inet_ntop(AF_INET, ip, bufinet4, sizeof(bufinet4)))
		return log_error_errno(-1, EINVAL, "Failed to convert IP for l2proxy ipv4 removal on dev \"%s\"", link);

	/* If a local-loopback ifindex supplied remove the static route to the lo device. */
	if (lo_ifindex > 0) {
		if (lxc_ipv4_dest_del(lo_ifindex, ip, 32) < 0) {
			had_error = true;
			ERROR("Failed to delete ipv4 dest \"%s\" for network ifindex \"%u\"", bufinet4, lo_ifindex);
		}
	}

	/* If link is supplied remove the IP neigh proxy entry for this IP on the device. */
	if (!is_empty_string(link)) {
		link_ifindex = if_nametoindex(link);
		if (link_ifindex == 0)
			return log_error_errno(-1, EINVAL, "Failed to retrieve ifindex for \"%s\" l2proxy cleanup", link);

		if (lxc_ip_neigh_proxy(RTM_DELNEIGH, AF_INET, link_ifindex, ip) < 0)
			had_error = true;
	}

	if (had_error)
		return ret_set_errno(-1, EINVAL);

	return 0;
}

static int lxc_delete_ipv6_l2proxy(struct in6_addr *ip, char *link, unsigned int lo_ifindex)
{
	char bufinet6[INET6_ADDRSTRLEN];
	bool had_error = false;
	unsigned int link_ifindex = 0;

	if (!inet_ntop(AF_INET6, ip, bufinet6, sizeof(bufinet6)))
		return log_error_errno(-1, EINVAL, "Failed to convert IP for l2proxy ipv6 removal on dev \"%s\"", link);

	/* If a local-loopback ifindex supplied remove the static route to the lo device. */
	if (lo_ifindex > 0) {
		if (lxc_ipv6_dest_del(lo_ifindex, ip, 128) < 0) {
			had_error = true;
			ERROR("Failed to delete ipv6 dest \"%s\" for network ifindex \"%u\"", bufinet6, lo_ifindex);
		}
	}

	/* If link is supplied remove the IP neigh proxy entry for this IP on the device. */
	if (!is_empty_string(link)) {
		link_ifindex = if_nametoindex(link);
		if (link_ifindex == 0) {
			ERROR("Failed to retrieve ifindex for \"%s\" l2proxy cleanup", link);
			return ret_set_errno(-1, EINVAL);
		}

		if (lxc_ip_neigh_proxy(RTM_DELNEIGH, AF_INET6, link_ifindex, ip) < 0)
			had_error = true;
	}

	if (had_error)
		return ret_set_errno(-1, EINVAL);

	return 0;
}

static int lxc_delete_l2proxy(struct lxc_netdev *netdev) {
	unsigned int lo_ifindex = 0;
	unsigned int errCount = 0;
	struct lxc_list *cur, *next;
	struct lxc_inetdev *inet4dev;
	struct lxc_inet6dev *inet6dev;

	/* Perform IPVLAN specific checks. */
	if (netdev->type == LXC_NET_IPVLAN) {
		/* Retrieve local-loopback interface index for use with IPVLAN static routes. */
		lo_ifindex = if_nametoindex(loop_device);
		if (lo_ifindex == 0) {
			errCount++;
			ERROR("Failed to retrieve ifindex for \"%s\" routing cleanup", loop_device);
		}
	}

	lxc_list_for_each_safe(cur, &netdev->ipv4, next) {
		inet4dev = cur->elem;
		if (lxc_delete_ipv4_l2proxy(&inet4dev->addr, netdev->link, lo_ifindex) < 0)
			errCount++;
	}

	lxc_list_for_each_safe(cur, &netdev->ipv6, next) {
		inet6dev = cur->elem;
		if (lxc_delete_ipv6_l2proxy(&inet6dev->addr, netdev->link, lo_ifindex) < 0)
			errCount++;
	}

	if (errCount > 0)
		return ret_set_errno(-1, EINVAL);

	return 0;
}

static int lxc_create_network_priv(struct lxc_handler *handler)
{
	struct lxc_list *iterator;
	struct lxc_list *network = &handler->conf->network;

	lxc_list_for_each(iterator, network) {
		struct lxc_netdev *netdev = iterator->elem;

		if (netdev->type < 0 || netdev->type > LXC_NET_MAXCONFTYPE)
			return log_error_errno(-1, EINVAL, "Invalid network configuration type %d", netdev->type);

		/* Setup l2proxy entries if enabled and used with a link property */
		if (netdev->l2proxy && !is_empty_string(netdev->link)) {
			if (lxc_setup_l2proxy(netdev))
				return log_error_errno(-1, errno, "Failed to setup l2proxy");
		}

		if (netdev_configure_server[netdev->type](handler, netdev))
			return log_error_errno(-1, errno, "Failed to create network device");
	}

	return 0;
}

/*
 * LXC moves network devices into the target namespace based on their created
 * name. The created name can either be randomly generated for e.g. veth
 * devices or it can be the name of the existing device in the server's
 * namespaces. This is e.g. the case when moving physical devices. However this
 * can lead to weird clashes. Consider we have a network namespace that has the
 * following devices:

 * 4: eth1: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
 *    link/ether 00:16:3e:91:d3:ae brd ff:ff:ff:ff:ff:ff permaddr 00:16:3e:e7:5d:10
 *    altname enp7s0
 * 5: eth2: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
 *    link/ether 00:16:3e:e7:5d:10 brd ff:ff:ff:ff:ff:ff permaddr 00:16:3e:91:d3:ae
 *    altname enp8s0
 *
 * and the user generates the following network config for their container:
 *
 *  lxc.net.0.type = phys
 *  lxc.net.0.name = eth1
 *  lxc.net.0.link = eth2
 *
 *  lxc.net.1.type = phys
 *  lxc.net.1.name = eth2
 *  lxc.net.1.link = eth1
 *
 * This would cause LXC to move the devices eth1 and eth2 from the server's
 * network namespace into the container's network namespace:
 *
 * 24: eth1: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
 *     link/ether 00:16:3e:91:d3:ae brd ff:ff:ff:ff:ff:ff permaddr 00:16:3e:e7:5d:10
 *     altname enp7s0
 * 25: eth2: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
 *     link/ether 00:16:3e:e7:5d:10 brd ff:ff:ff:ff:ff:ff permaddr 00:16:3e:91:d3:ae
 *      altname enp8s0
 *
 * According to the network config above we now need to rename the network
 * devices in the container's network namespace. Let's say we start with
 * renaming eth2 to eth1. This would immediately lead to a clash since the
 * container's network namespace already contains a network device with that
 * name. Renaming the other device would have the same problem.
 *
 * There are multiple ways to fix this but I'm concerned with keeping the logic
 * somewhat reasonable which is why we simply start creating transient device
 * names that are unique which we'll use to move and rename the network device
 * in the container's network namespace at the same time. And then we rename
 * based on those random devices names to the target name.
 *
 * Note that the transient name is based on the type of network device as
 * specified in the LXC config. However, that doesn't mean it's correct. LXD
 * passes veth devices and a range of other network devices (e.g. Infiniband
 * VFs etc.) via LXC_NET_PHYS even though they're not really "physical" in the
 * sense we like to think about it so you might see a veth device being
 * assigned a "physXXXXXX" transient name. That's not a problem.
 */
static int create_transient_name(struct lxc_netdev *netdev)
{
	const struct lxc_network_info *info;

	if (!is_empty_string(netdev->transient_name))
		return syserror_set(-EINVAL, "Network device already had a transient name %s",
				    netdev->transient_name);

	info = &lxc_network_info[netdev->type];
	strlcpy(netdev->transient_name, info->template, info->template_len + 1);

	if (!lxc_ifname_alnum_case_sensitive(netdev->transient_name))
		return syserror_set(-EINVAL, "Failed to create transient name for network device %s", netdev->created_name);

	TRACE("Created transient name %s for network device", netdev->transient_name);
	return 0;
}

int lxc_network_move_created_netdev_priv(struct lxc_handler *handler)
{
	pid_t pid = handler->pid;
	struct lxc_list *network = &handler->conf->network;
	struct lxc_list *iterator;

	if (am_guest_unpriv())
		return 0;

	lxc_list_for_each(iterator, network) {
		__do_free char *physname = NULL;
		int ret;
		struct lxc_netdev *netdev = iterator->elem;

		/*
		* Veth devices are directly created in the container's network
		* namespace so the device doesn't need to be moved into the
		* container's network namespace. The transient name will
		* already have been set above when we created the veth tunnel.
		*
		* Other than this special case this also catches all
		* LXC_NET_EMPTY and LXC_NET_NONE devices.
		 */
		if (!netdev->ifindex)
			continue;

		ret = create_transient_name(netdev);
		if (ret < 0)
			return ret;

		if (netdev->type == LXC_NET_PHYS)
			physname = is_wlan(netdev->link);

		if (physname)
			ret = lxc_netdev_move_wlan(physname, netdev->link, pid, netdev->transient_name);
		else
			ret = lxc_netdev_move_by_index(netdev->ifindex, pid, netdev->transient_name);
		if (ret)
			return log_error_errno(-1, -ret, "Failed to move network device \"%s\" with ifindex %d to network namespace %d and rename to %s",
					       netdev->created_name, netdev->ifindex, pid, netdev->transient_name);

		DEBUG("Moved network device \"%s\" with ifindex %d to network namespace of %d and renamed to %s",
		      maybe_empty(netdev->created_name), netdev->ifindex, pid, netdev->transient_name);
	}

	return 0;
}

static int network_requires_advanced_setup(int type)
{
	if (type == LXC_NET_EMPTY)
		return false;

	if (type == LXC_NET_NONE)
		return false;

	return true;
}

static int lxc_create_network_unpriv(struct lxc_handler *handler)
{
	int hooks_version = handler->conf->hooks_version;
	const char *lxcname = handler->name;
	const char *lxcpath = handler->lxcpath;
	struct lxc_list *network = &handler->conf->network;
	pid_t pid = handler->pid;
	struct lxc_list *iterator;

	lxc_list_for_each(iterator, network) {
		struct lxc_netdev *netdev = iterator->elem;

		if (!network_requires_advanced_setup(netdev->type))
			continue;

		if (netdev->type != LXC_NET_VETH)
			return log_error_errno(-1, EINVAL, "Networks of type %s are not supported by unprivileged containers",
					       lxc_net_type_to_str(netdev->type));

		if (netdev->mtu)
			INFO("mtu ignored due to insufficient privilege");

		if (lxc_create_network_unpriv_exec(lxcpath, lxcname, netdev,
						   pid, hooks_version))
			return -1;
	}

	return 0;
}

static bool lxc_delete_network_priv(struct lxc_handler *handler)
{
	int ret;
	struct lxc_list *iterator;
	struct lxc_list *network = &handler->conf->network;

	lxc_list_for_each(iterator, network) {
		char *hostveth = NULL;
		struct lxc_netdev *netdev = iterator->elem;

		/* We can only delete devices whose ifindex we have. If we don't
		 * have the index it means that we didn't create it.
		 */
		if (!netdev->ifindex)
			continue;

		/*
		 * If the network device has been moved back from the
		 * containers network namespace, update the ifindex.
		 */
		netdev->ifindex = if_nametoindex(netdev->name);

		/* Delete l2proxy entries if enabled and used with a link property */
		if (netdev->l2proxy && !is_empty_string(netdev->link)) {
			if (lxc_delete_l2proxy(netdev))
				WARN("Failed to delete all l2proxy config");
				/* Don't return, let the network be cleaned up as normal. */
		}

		if (netdev->type == LXC_NET_PHYS) {
			/* Physical interfaces are initially returned to the parent namespace
			 * with their transient name to avoid collisions
			 */
			netdev->ifindex = if_nametoindex(netdev->transient_name);
			ret = lxc_netdev_rename_by_index(netdev->ifindex, netdev->link);
			if (ret < 0)
				WARN("Failed to rename interface with index %d "
				     "from \"%s\" to its initial name \"%s\"",
				     netdev->ifindex, netdev->name, netdev->link);
			else {
				TRACE("Renamed interface with index %d from "
				      "\"%s\" to its initial name \"%s\"",
				      netdev->ifindex, netdev->name,
				      netdev->link);

				/* Restore original MTU */
				ret = lxc_netdev_set_mtu(netdev->link, netdev->priv.phys_attr.mtu);
				if (ret < 0) {
					WARN("Failed to set interface \"%s\" to its initial mtu \"%d\"",
						netdev->link, netdev->priv.phys_attr.mtu);
				} else {
					TRACE("Restored interface \"%s\" to its initial mtu \"%d\"",
						netdev->link, netdev->priv.phys_attr.mtu);
				}
			}

			ret = netdev_deconf[netdev->type](handler, netdev);
			if (ret < 0)
				WARN("Failed to deconfigure interface with index %d and initial name \"%s\"",
				     netdev->ifindex, netdev->link);
			goto clear_ifindices;
		}

		ret = netdev_deconf[netdev->type](handler, netdev);
		if (ret < 0)
			WARN("Failed to deconfigure network device");

		if (netdev->type != LXC_NET_VETH)
			goto clear_ifindices;

		/* Explicitly delete host veth device to prevent lingering
		 * devices. We had issues in LXD around this.
		 */
		if (!is_empty_string(netdev->priv.veth_attr.pair))
			hostveth = netdev->priv.veth_attr.pair;
		else
			hostveth = netdev->priv.veth_attr.veth1;
		if (is_empty_string(hostveth))
			goto clear_ifindices;

		if (is_empty_string(netdev->link) || !is_ovs_bridge(netdev->link)) {
			ret = lxc_netdev_delete_by_name(hostveth);
			if (ret < 0)
				WARN("Failed to remove interface \"%s\" from \"%s\"", hostveth, netdev->link);

			INFO("Removed interface \"%s\" from \"%s\"", hostveth, netdev->link);
		} else if (!is_empty_string(netdev->link)) {
			ret = lxc_ovs_delete_port(netdev->link, hostveth);
			if (ret < 0)
				WARN("Failed to remove port \"%s\" from openvswitch bridge \"%s\"", hostveth, netdev->link);

			INFO("Removed port \"%s\" from openvswitch bridge \"%s\"", hostveth, netdev->link);
		}

clear_ifindices:
		/* We need to clear any ifindices we recorded so liblxc won't
		 * have cached stale data which would cause it to fail on reboot
		 * we're we don't re-read the on-disk config file.
		 */
		netdev->ifindex = 0;
		if (netdev->type == LXC_NET_PHYS) {
			netdev->priv.phys_attr.ifindex = 0;
		} else if (netdev->type == LXC_NET_VETH) {
			netdev->priv.veth_attr.veth1[0] = '\0';
			netdev->priv.veth_attr.ifindex = 0;
		}

		/* Clear transient name */
		if (!is_empty_string (netdev->transient_name))
		{
			netdev->transient_name[0] = '\0';
		}
	}

	return true;
}

int lxc_requests_empty_network(struct lxc_handler *handler)
{
	struct lxc_list *network = &handler->conf->network;
	struct lxc_list *iterator;
	bool found_none = false, found_nic = false;

	if (lxc_list_empty(network))
		return 0;

	lxc_list_for_each (iterator, network) {
		struct lxc_netdev *netdev = iterator->elem;

		if (netdev->type == LXC_NET_NONE)
			found_none = true;
		else
			found_nic = true;
	}

	if (found_none && !found_nic)
		return 1;

	return 0;
}

/* try to move physical nics to the init netns */
int lxc_restore_phys_nics_to_netns(struct lxc_handler *handler)
{
	__do_close int oldfd = -EBADF;
	int netnsfd = handler->nsfd[LXC_NS_NET];
	struct lxc_conf *conf = handler->conf;
	int ret;
	char ifname[IFNAMSIZ];
	struct lxc_list *iterator;

	/*
	 * If we weren't asked to clone a new network namespace, there's
	 * nothing to restore.
	 */
	if (!(handler->ns_clone_flags & CLONE_NEWNET))
		return 0;

	/* We need CAP_NET_ADMIN in the parent namespace in order to setns() to
	 * the parent network namespace. We won't have this capability if we are
	 * unprivileged.
	 */
	if (!handler->am_root)
		return 0;

	TRACE("Moving physical network devices back to parent network namespace");

	oldfd = lxc_preserve_ns(handler->monitor_pid, "net");
	if (oldfd < 0)
		return log_error_errno(-1, errno, "Failed to preserve network namespace");

	ret = setns(netnsfd, CLONE_NEWNET);
	if (ret < 0)
		return log_error_errno(-1, errno, "Failed to enter network namespace");

	lxc_list_for_each(iterator, &conf->network) {
		struct lxc_netdev *netdev = iterator->elem;

		if (netdev->type != LXC_NET_PHYS)
			continue;

		/* Retrieve the name of the interface in the container's network
		 * namespace.
		 */
		if (!if_indextoname(netdev->ifindex, ifname)) {
			WARN("No interface corresponding to ifindex %d", netdev->ifindex);
			continue;
		}

		/* Restore physical interfaces to host's network namespace with its transient name
		 * to avoid collisions with the host's other interfaces.
		 */
		ret = lxc_netdev_move_by_index_fd(netdev->ifindex, oldfd, netdev->transient_name);
		if (ret < 0)
			WARN("Error moving network device \"%s\" back to network namespace", ifname);
		else
			TRACE("Moved network device \"%s\" back to network namespace", ifname);
	}

	ret = setns(oldfd, CLONE_NEWNET);
	if (ret < 0)
		return log_error_errno(-1, errno, "Failed to enter network namespace");

	return 0;
}

static int setup_hw_addr(char *hwaddr, const char *ifname)
{
	__do_close int fd = -EBADF;
	struct sockaddr sockaddr;
	struct ifreq ifr;
	int ret;

	ret = lxc_convert_mac(hwaddr, &sockaddr);
	if (ret)
		return log_error_errno(-1, -ret, "Mac address \"%s\" conversion failed", hwaddr);

	memcpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_name[IFNAMSIZ-1] = '\0';
	memcpy((char *) &ifr.ifr_hwaddr, (char *) &sockaddr, sizeof(sockaddr));

	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;

	ret = ioctl(fd, SIOCSIFHWADDR, &ifr);
	if (ret)
		SYSERROR("Failed to perform ioctl");

	DEBUG("Mac address \"%s\" on \"%s\" has been setup", hwaddr, ifr.ifr_name);

	return ret;
}

static int setup_ipv4_addr(struct lxc_list *ip, int ifindex)
{
	struct lxc_list *iterator;
	int err;

	lxc_list_for_each(iterator, ip) {
		struct lxc_inetdev *inetdev = iterator->elem;

		err = lxc_ipv4_addr_add(ifindex, &inetdev->addr,
					&inetdev->bcast, inetdev->prefix);
		if (err)
			return log_error_errno(-1, -err, "Failed to setup ipv4 address for network device with ifindex %d", ifindex);
	}

	return 0;
}

static int setup_ipv6_addr(struct lxc_list *ip, int ifindex)
{
	struct lxc_list *iterator;
	int err;

	lxc_list_for_each(iterator, ip) {
		struct lxc_inet6dev *inet6dev = iterator->elem;

		err = lxc_ipv6_addr_add(ifindex, &inet6dev->addr,
					&inet6dev->mcast, &inet6dev->acast,
					inet6dev->prefix);
		if (err)
			return log_error_errno(-1, -err, "Failed to setup ipv6 address for network device with ifindex %d", ifindex);
	}

	return 0;
}

static int lxc_network_setup_in_child_namespaces_common(struct lxc_netdev *netdev)
{
	int err;
	char bufinet4[INET_ADDRSTRLEN], bufinet6[INET6_ADDRSTRLEN];

	/* empty network namespace */
	if (!netdev->ifindex && netdev->flags & IFF_UP) {
		err = lxc_netdev_up("lo");
		if (err)
			return log_error_errno(-1, -err, "Failed to set the loopback network device up");
	}

	/* set a mac address */
	if (netdev->hwaddr && setup_hw_addr(netdev->hwaddr, netdev->name))
		return log_error_errno(-1, errno, "Failed to setup hw address for network device \"%s\"", netdev->name);

	/* setup ipv4 addresses on the interface */
	if (setup_ipv4_addr(&netdev->ipv4, netdev->ifindex))
		return log_error_errno(-1, errno, "Failed to setup ip addresses for network device \"%s\"", netdev->name);

	/* setup ipv6 addresses on the interface */
	if (setup_ipv6_addr(&netdev->ipv6, netdev->ifindex))
		return log_error_errno(-1, errno, "Failed to setup ipv6 addresses for network device \"%s\"", netdev->name);

	/* set the network device up */
	if (netdev->flags & IFF_UP) {
		err = lxc_netdev_up(netdev->name);
		if (err)
			return log_error_errno(-1, -err, "Failed to set network device \"%s\" up", netdev->name);

		/* the network is up, make the loopback up too */
		err = lxc_netdev_up("lo");
		if (err)
			return log_error_errno(-1, -err, "Failed to set the loopback network device up");
	}

	/* setup ipv4 gateway on the interface */
	if (netdev->ipv4_gateway || netdev->ipv4_gateway_dev) {
		if (!(netdev->flags & IFF_UP))
			return log_error(-1, "Cannot add ipv4 gateway for network device \"%s\" when not bringing up the interface", netdev->name);

		if (lxc_list_empty(&netdev->ipv4))
			return log_error(-1, "Cannot add ipv4 gateway for network device \"%s\" when not assigning an address", netdev->name);

		/* Setup device route if ipv4_gateway_dev is enabled */
		if (netdev->ipv4_gateway_dev) {
			err = lxc_ipv4_gateway_add(netdev->ifindex, NULL);
			if (err < 0)
				return log_error_errno(-1, -err, "Failed to setup ipv4 gateway to network device \"%s\"", netdev->name);
		} else {
			/* Check the gateway address is valid */
			if (!inet_ntop(AF_INET, netdev->ipv4_gateway, bufinet4, sizeof(bufinet4)))
				return ret_set_errno(-1, errno);

			/* Try adding a default route to the gateway address */
			err = lxc_ipv4_gateway_add(netdev->ifindex, netdev->ipv4_gateway);
			if (err < 0) {
				/* If adding the default route fails, this could be because the
				 * gateway address is in a different subnet to the container's address.
				 * To work around this, we try adding a static device route to the
				 * gateway address first, and then try again.
				 */
				err = lxc_ipv4_dest_add(netdev->ifindex, netdev->ipv4_gateway, 32);
				if (err < 0)
					return log_error_errno(-1, -err, "Failed to add ipv4 dest \"%s\" for network device \"%s\"", bufinet4, netdev->name);

				err = lxc_ipv4_gateway_add(netdev->ifindex, netdev->ipv4_gateway);
				if (err < 0)
					return log_error_errno(-1, -err, "Failed to setup ipv4 gateway \"%s\" for network device \"%s\"", bufinet4, netdev->name);
			}
		}
	}

	/* setup ipv6 gateway on the interface */
	if (netdev->ipv6_gateway || netdev->ipv6_gateway_dev) {
		if (!(netdev->flags & IFF_UP))
			return log_error(-1, "Cannot add ipv6 gateway for network device \"%s\" when not bringing up the interface", netdev->name);

		if (lxc_list_empty(&netdev->ipv6) && !IN6_IS_ADDR_LINKLOCAL(netdev->ipv6_gateway))
			return log_error(-1, "Cannot add ipv6 gateway for network device \"%s\" when not assigning an address", netdev->name);

		/* Setup device route if ipv6_gateway_dev is enabled */
		if (netdev->ipv6_gateway_dev) {
			err = lxc_ipv6_gateway_add(netdev->ifindex, NULL);
			if (err < 0)
				return log_error_errno(-1, -err, "Failed to setup ipv6 gateway to network device \"%s\"", netdev->name);
		} else {
			/* Check the gateway address is valid */
			if (!inet_ntop(AF_INET6, netdev->ipv6_gateway, bufinet6, sizeof(bufinet6)))
				return ret_set_errno(-1, errno);

			/* Try adding a default route to the gateway address */
			err = lxc_ipv6_gateway_add(netdev->ifindex, netdev->ipv6_gateway);
			if (err < 0) {
				/* If adding the default route fails, this could be because the
				 * gateway address is in a different subnet to the container's address.
				 * To work around this, we try adding a static device route to the
				 * gateway address first, and then try again.
				 */
				err = lxc_ipv6_dest_add(netdev->ifindex, netdev->ipv6_gateway, 128);
				if (err < 0)
					return log_error_errno(-1, errno, "Failed to add ipv6 dest \"%s\" for network device \"%s\"", bufinet6, netdev->name);

				err = lxc_ipv6_gateway_add(netdev->ifindex, netdev->ipv6_gateway);
				if (err < 0)
					return log_error_errno(-1, -err, "Failed to setup ipv6 gateway \"%s\" for network device \"%s\"", bufinet6, netdev->name);
			}
		}
	}

	DEBUG("Network device \"%s\" has been setup", netdev->name);

	return 0;
}

/**
 * Consider the following network layout:
 *
 *  lxc.net.0.type = phys
 *  lxc.net.0.link = eth2
 *  lxc.net.0.name = eth%d
 *
 *  lxc.net.1.type = phys
 *  lxc.net.1.link = eth1
 *  lxc.net.1.name = eth0
 *
 * If we simply follow this order and create the first network first the kernel
 * will allocate eth0 for the first network but the second network requests
 * that eth1 be renamed to eth0 in the container's network namespace which
 * would lead to a clash.
 *
 * Note, we don't handle cases like:
 *
 *  lxc.net.0.type = phys
 *  lxc.net.0.link = eth2
 *  lxc.net.0.name = eth0
 *
 *  lxc.net.1.type = phys
 *  lxc.net.1.link = eth1
 *  lxc.net.1.name = eth0
 *
 * That'll brutally fail of course but there's nothing we can do about it.
 */
int lxc_setup_network_in_child_namespaces(const struct lxc_conf *conf,
					  struct lxc_list *network)
{
	struct lxc_list *iterator;
	bool needs_second_pass = false;

	if (lxc_list_empty(network))
		return 0;

	/* Configure all devices that have a specific target name. */
	lxc_list_for_each(iterator, network) {
		struct lxc_netdev *netdev = iterator->elem;
		int ret;

		if (is_empty_string(netdev->name) || strequal(netdev->name, "eth%d")) {
			needs_second_pass = true;
			continue;
		}

		ret = netdev_configure_container[netdev->type](netdev);
		if (!ret)
			ret = lxc_network_setup_in_child_namespaces_common(netdev);
		if (ret)
			return log_error_errno(-1, errno, "Failed to setup netdev");
	}
	INFO("Finished setting up network devices with caller assigned names");

	if (needs_second_pass) {
		/* Configure all devices that have a kernel assigned name. */
		lxc_list_for_each(iterator, network) {
			struct lxc_netdev *netdev = iterator->elem;
			int ret;

			if (!is_empty_string(netdev->name) && !strequal(netdev->name, "eth%d"))
				continue;

			ret = netdev_configure_container[netdev->type](netdev);
			if (!ret)
				ret = lxc_network_setup_in_child_namespaces_common(netdev);
			if (ret)
				return log_error_errno(-1, errno, "Failed to setup netdev");
		}
		INFO("Finished setting up network devices with kernel assigned names");
	}

	return 0;
}

int lxc_network_send_to_child(struct lxc_handler *handler)
{
	struct lxc_list *iterator;
	struct lxc_list *network = &handler->conf->network;
	int data_sock = handler->data_sock[0];

	lxc_list_for_each(iterator, network) {
		int ret;
		struct lxc_netdev *netdev = iterator->elem;

		if (!network_requires_advanced_setup(netdev->type))
			continue;

		ret = lxc_send_nointr(data_sock, netdev->name, IFNAMSIZ, MSG_NOSIGNAL);
		if (ret < 0)
			return -1;

		ret = lxc_send_nointr(data_sock, netdev->transient_name, IFNAMSIZ, MSG_NOSIGNAL);
		if (ret < 0)
			return -1;

		TRACE("Sent network device name \"%s\" to child", netdev->transient_name);
	}

	return 0;
}

int lxc_network_recv_from_parent(struct lxc_handler *handler)
{
	struct lxc_list *iterator;
	struct lxc_list *network = &handler->conf->network;
	int data_sock = handler->data_sock[1];

	lxc_list_for_each(iterator, network) {
		int ret;
		struct lxc_netdev *netdev = iterator->elem;

		if (!network_requires_advanced_setup(netdev->type))
			continue;

		ret = lxc_recv_nointr(data_sock, netdev->name, IFNAMSIZ, 0);
		if (ret < 0)
			return -1;

		ret = lxc_recv_nointr(data_sock, netdev->transient_name, IFNAMSIZ, 0);
		if (ret < 0)
			return -1;

		TRACE("Received network device name \"%s\" from parent", netdev->transient_name);
	}

	return 0;
}

int lxc_network_send_name_and_ifindex_to_parent(struct lxc_handler *handler)
{
	struct lxc_list *iterator, *network;
	int data_sock = handler->data_sock[0];

	if (!handler->am_root)
		return 0;

	network = &handler->conf->network;
	lxc_list_for_each(iterator, network) {
		int ret;
		struct lxc_netdev *netdev = iterator->elem;

		/* Send network device name in the child's namespace to parent. */
		ret = lxc_send_nointr(data_sock, netdev->name, IFNAMSIZ, MSG_NOSIGNAL);
		if (ret < 0)
			return -1;

		/* Send network device ifindex in the child's namespace to
		 * parent.
		 */
		ret = lxc_send_nointr(data_sock, &netdev->ifindex, sizeof(netdev->ifindex), MSG_NOSIGNAL);
		if (ret < 0)
			return -1;
	}

	if (!lxc_list_empty(network))
		TRACE("Sent network device names and ifindices to parent");

	return 0;
}

int lxc_network_recv_name_and_ifindex_from_child(struct lxc_handler *handler)
{
	struct lxc_list *iterator, *network;
	int data_sock = handler->data_sock[1];

	if (!handler->am_root)
		return 0;

	network = &handler->conf->network;
	lxc_list_for_each(iterator, network) {
		int ret;
		struct lxc_netdev *netdev = iterator->elem;

		/* Receive network device name in the child's namespace to
		 * parent.
		 */
		ret = lxc_recv_nointr(data_sock, netdev->name, IFNAMSIZ, 0);
		if (ret < 0)
			return -1;

		/* Receive network device ifindex in the child's namespace to
		 * parent.
		 */
		ret = lxc_recv_nointr(data_sock, &netdev->ifindex, sizeof(netdev->ifindex), 0);
		if (ret < 0)
			return -1;
	}

	return 0;
}

void lxc_delete_network(struct lxc_handler *handler)
{
	bool bret;

	/*
	 * Always expose namespace fd paths to network down hooks via
	 * environment variables. No need to complicate things by passing them
	 * as additional hook arguments.
	 */
	lxc_expose_namespace_environment(handler);

	if (handler->am_root)
		bret = lxc_delete_network_priv(handler);
	else
		bret = lxc_delete_network_unpriv(handler);
	if (!bret)
		DEBUG("Failed to delete network devices");
	else
		DEBUG("Deleted network devices");
}

int lxc_netns_set_nsid(int fd)
{
	int ret;
	char buf[NLMSG_ALIGN(sizeof(struct nlmsghdr)) +
		 NLMSG_ALIGN(sizeof(struct rtgenmsg)) +
		 NLMSG_ALIGN(1024)];
	struct nl_handler nlh;
	call_cleaner(netlink_close) struct nl_handler *nlh_ptr = &nlh;
	struct nlmsghdr *hdr;
	struct rtgenmsg *msg;
	const __s32 ns_id = -1;
	const __u32 netns_fd = fd;

	ret = netlink_open(nlh_ptr, NETLINK_ROUTE);
	if (ret < 0)
		return -1;

	memset(buf, 0, sizeof(buf));

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
	hdr = (struct nlmsghdr *)buf;
	msg = (struct rtgenmsg *)NLMSG_DATA(hdr);
#pragma GCC diagnostic pop

	hdr->nlmsg_len = NLMSG_LENGTH(sizeof(*msg));
	hdr->nlmsg_type = RTM_NEWNSID;
	hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	hdr->nlmsg_pid = 0;
	hdr->nlmsg_seq = RTM_NEWNSID;
	msg->rtgen_family = AF_UNSPEC;

	ret = addattr(hdr, 1024, __LXC_NETNSA_FD, &netns_fd, sizeof(netns_fd));
	if (ret < 0)
		return ret_errno(ENOMEM);

	ret = addattr(hdr, 1024, __LXC_NETNSA_NSID, &ns_id, sizeof(ns_id));
	if (ret < 0)
		return ret_errno(ENOMEM);

	return __netlink_transaction(nlh_ptr, hdr, hdr);
}

static int parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{

	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));

	while (RTA_OK(rta, len)) {
		unsigned short type = rta->rta_type;

		if ((type <= max) && (!tb[type]))
			tb[type] = rta;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
		rta = RTA_NEXT(rta, len);
#pragma GCC diagnostic pop
	}

	return 0;
}

static inline __s32 rta_getattr_s32(const struct rtattr *rta)
{
	return *(__s32 *)RTA_DATA(rta);
}

#ifndef NETNS_RTA
#define NETNS_RTA(r) \
	((struct rtattr *)(((char *)(r)) + NLMSG_ALIGN(sizeof(struct rtgenmsg))))
#endif

int lxc_netns_get_nsid(int fd)
{
	struct nl_handler nlh;
	call_cleaner(netlink_close) struct nl_handler *nlh_ptr = &nlh;
	int ret;
	ssize_t len;
	char buf[NLMSG_ALIGN(sizeof(struct nlmsghdr)) +
		 NLMSG_ALIGN(sizeof(struct rtgenmsg)) +
		 NLMSG_ALIGN(1024)];
	struct rtattr *tb[__LXC_NETNSA_MAX + 1];
	struct nlmsghdr *hdr;
	struct rtgenmsg *msg;
	__u32 netns_fd = fd;

	ret = netlink_open(nlh_ptr, NETLINK_ROUTE);
	if (ret < 0)
		return -1;

	memset(buf, 0, sizeof(buf));

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
	hdr = (struct nlmsghdr *)buf;
	msg = (struct rtgenmsg *)NLMSG_DATA(hdr);
#pragma GCC diagnostic pop

	hdr->nlmsg_len = NLMSG_LENGTH(sizeof(*msg));
	hdr->nlmsg_type = RTM_GETNSID;
	hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	hdr->nlmsg_pid = 0;
	hdr->nlmsg_seq = RTM_GETNSID;
	msg->rtgen_family = AF_UNSPEC;

	ret = addattr(hdr, 1024, __LXC_NETNSA_FD, &netns_fd, sizeof(netns_fd));
	if (ret < 0)
		return ret_errno(ENOMEM);

	ret = __netlink_transaction(nlh_ptr, hdr, hdr);
	if (ret < 0)
		return -1;

	msg = NLMSG_DATA(hdr);
	len = hdr->nlmsg_len - NLMSG_SPACE(sizeof(*msg));
	if (len < 0)
		return ret_errno(EINVAL);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
	parse_rtattr(tb, __LXC_NETNSA_MAX, NETNS_RTA(msg), len);
	if (tb[__LXC_NETNSA_NSID])
		return rta_getattr_s32(tb[__LXC_NETNSA_NSID]);
#pragma GCC diagnostic pop

	return -1;
}

int lxc_create_network(struct lxc_handler *handler)
{
	int ret;

	if (handler->am_root) {
		ret = lxc_create_network_priv(handler);
		if (ret)
			return -1;

		return lxc_network_move_created_netdev_priv(handler);
	}

	return lxc_create_network_unpriv(handler);
}

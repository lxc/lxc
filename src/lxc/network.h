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
#ifndef __LXC_NETWORK_H
#define __LXC_NETWORK_H

#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "list.h"

struct lxc_conf;
struct lxc_handler;
struct lxc_netdev;

enum {
	LXC_NET_EMPTY,
	LXC_NET_VETH,
	LXC_NET_MACVLAN,
	LXC_NET_PHYS,
	LXC_NET_VLAN,
	LXC_NET_NONE,
	LXC_NET_MAXCONFTYPE,
};

/*
 * Defines the structure to configure an ipv4 address
 * @address   : ipv4 address
 * @broadcast : ipv4 broadcast address
 * @mask      : network mask
 */
struct lxc_inetdev {
	struct in_addr addr;
	struct in_addr bcast;
	unsigned int prefix;
};

struct lxc_route {
	struct in_addr addr;
};

/*
 * Defines the structure to configure an ipv6 address
 * @flags     : set the address up
 * @address   : ipv6 address
 * @broadcast : ipv6 broadcast address
 * @mask      : network mask
 */
struct lxc_inet6dev {
	struct in6_addr addr;
	struct in6_addr mcast;
	struct in6_addr acast;
	unsigned int prefix;
};

struct lxc_route6 {
	struct in6_addr addr;
};

/* Contains information about the host side veth device.
 * @pair    : Name of the host side veth device.
 *            If the user requested that the host veth device be created with a
 *            specific names this field will be set. If this field is set @veth1
 *            is not set.
 * @veth1   : Name of the host side veth device.
 *            If the user did not request that the host veth device be created
 *            with a specific name this field will be set. If this field is set
 *            @pair is not set.
 * @ifindex : Ifindex of the network device.
 */
struct ifla_veth {
	char pair[IFNAMSIZ];
	char veth1[IFNAMSIZ];
	int ifindex;
};

struct ifla_vlan {
	unsigned int   flags;
	unsigned int   fmask;
	unsigned short   vid;
	unsigned short   pad;
};

struct ifla_macvlan {
	int mode; /* private, vepa, bridge, passthru */
};

/* Contains information about the physical network device as seen from the host.
 * @ifindex : The ifindex of the physical network device in the host's network
 *            namespace.
 */
struct ifla_phys {
	int ifindex;
};

union netdev_p {
	struct ifla_macvlan macvlan_attr;
	struct ifla_phys phys_attr;
	struct ifla_veth veth_attr;
	struct ifla_vlan vlan_attr;
};

/*
 * Defines a structure to configure a network device
 * @idx               : network counter
 * @ifindex           : ifindex of the network device
 *                      Note that this is the ifindex of the network device in
 *                      the container's network namespace. If the network device
 *                      consists of a pair of network devices (e.g. veth pairs
 *                      attached to a network bridge) then this index cannot be
 *                      used to identify or modify the host veth device. See
 *                      struct ifla_veth for the host side information.
 * @type              : network type (veth, macvlan, vlan, ...)
 * @flags             : flag of the network device (IFF_UP, ... )
 * @link              : lxc.net.[i].link, name of bridge or host iface to attach
 *                      if any
 * @name              : lxc.net.[i].name, name of iface on the container side
 * @hwaddr            : mac address
 * @mtu               : maximum transmission unit
 * @priv              : information specific to the specificed network type
 *                      Note that this is a union so whether accessing a struct
 *                      is possible is dependent on the network type.
 * @ipv4              : a list of ipv4 addresses to be set on the network device
 * @ipv6              : a list of ipv6 addresses to be set on the network device
 * @ipv4_gateway_auto : whether the ipv4 gateway is to be automatically gathered
 *                      from the associated @link
 * @ipv4_gateway      : ipv4 gateway
 * @ipv6_gateway_auto : whether the ipv6 gateway is to be automatically gathered
 *                      from the associated @link
 * @ipv6_gateway      : ipv6 gateway
 * @upscript          : a script filename to be executed during interface
 *                      configuration
 * @downscript        : a script filename to be executed during interface
 *                      destruction
 */
struct lxc_netdev {
	ssize_t idx;
	int ifindex;
	int type;
	int flags;
	char link[IFNAMSIZ];
	char name[IFNAMSIZ];
	char *hwaddr;
	char *mtu;
	union netdev_p priv;
	struct lxc_list ipv4;
	struct lxc_list ipv6;
	bool ipv4_gateway_auto;
	struct in_addr *ipv4_gateway;
	bool ipv6_gateway_auto;
	struct in6_addr *ipv6_gateway;
	char *upscript;
	char *downscript;
};

/* Convert a string mac address to a socket structure. */
extern int lxc_convert_mac(char *macaddr, struct sockaddr *sockaddr);

/* Move a device between namespaces. */
extern int lxc_netdev_move_by_index(int ifindex, pid_t pid, const char *ifname);
extern int lxc_netdev_move_by_name(const char *ifname, pid_t pid,
				   const char *newname);

/* Delete a network device. */
extern int lxc_netdev_delete_by_name(const char *name);
extern int lxc_netdev_delete_by_index(int ifindex);

/* Change the device name. */
extern int lxc_netdev_rename_by_name(const char *oldname, const char *newname);
extern int lxc_netdev_rename_by_index(int ifindex, const char *newname);

extern int netdev_set_flag(const char *name, int flag);

/* Set the device network up or down. */
extern int lxc_netdev_isup(const char *name);
extern int lxc_netdev_up(const char *name);
extern int lxc_netdev_down(const char *name);

/* Change the mtu size for the specified device. */
extern int lxc_netdev_set_mtu(const char *name, int mtu);

/* Create a virtual network devices. */
extern int lxc_veth_create(const char *name1, const char *name2);
extern int lxc_macvlan_create(const char *master, const char *name, int mode);
extern int lxc_vlan_create(const char *master, const char *name,
			   unsigned short vid);

/* Set ip address. */
extern int lxc_ipv6_addr_add(int ifindex, struct in6_addr *addr,
			     struct in6_addr *mcast,
			     struct in6_addr *acast, int prefix);

extern int lxc_ipv4_addr_add(int ifindex, struct in_addr *addr,
			     struct in_addr *bcast, int prefix);

/* Get ip address. */
extern int lxc_ipv4_addr_get(int ifindex, struct in_addr **res);
extern int lxc_ipv6_addr_get(int ifindex, struct in6_addr **res);

/* Set a destination route to an interface. */
extern int lxc_ipv4_dest_add(int ifindex, struct in_addr *dest);
extern int lxc_ipv6_dest_add(int ifindex, struct in6_addr *dest);

/* Set default route. */
extern int lxc_ipv4_gateway_add(int ifindex, struct in_addr *gw);
extern int lxc_ipv6_gateway_add(int ifindex, struct in6_addr *gw);

/* Attach an interface to the bridge. */
extern int lxc_bridge_attach(const char *bridge, const char *ifname);
extern int lxc_ovs_delete_port(const char *bridge, const char *nic);

extern bool is_ovs_bridge(const char *bridge);

/* Create default gateway. */
extern int lxc_route_create_default(const char *addr, const char *ifname,
				    int gateway);

/* Delete default gateway. */
extern int lxc_route_delete_default(const char *addr, const char *ifname,
				    int gateway);

/* Activate neighbor proxying. */
extern int lxc_neigh_proxy_on(const char *name, int family);

/* Disable neighbor proxying. */
extern int lxc_neigh_proxy_off(const char *name, int family);

/* Generate a new unique network interface name.
 * Allocated memory must be freed by caller.
 */
extern char *lxc_mkifname(char *template);

extern const char *lxc_net_type_to_str(int type);
extern int setup_private_host_hw_addr(char *veth1);
extern int netdev_get_mtu(int ifindex);
extern int lxc_create_network_priv(struct lxc_handler *handler);
extern int lxc_network_move_created_netdev_priv(const char *lxcpath,
						const char *lxcname,
						struct lxc_list *network,
						pid_t pid);
extern void lxc_delete_network(struct lxc_handler *handler);
extern int lxc_find_gateway_addresses(struct lxc_handler *handler);
extern int lxc_create_network_unpriv(const char *lxcpath, const char *lxcname,
				     struct lxc_list *network, pid_t pid, unsigned int hook_version);
extern int lxc_requests_empty_network(struct lxc_handler *handler);
extern int lxc_restore_phys_nics_to_netns(struct lxc_handler *handler);
extern int lxc_setup_network_in_child_namespaces(const struct lxc_conf *conf,
						 struct lxc_list *network);
extern int lxc_network_send_veth_names_to_child(struct lxc_handler *handler);
extern int lxc_network_recv_veth_names_from_parent(struct lxc_handler *handler);
extern int lxc_network_send_name_and_ifindex_to_parent(struct lxc_handler *handler);
extern int lxc_network_recv_name_and_ifindex_from_child(struct lxc_handler *handler);
extern int lxc_netns_set_nsid(int netns_fd);

#endif /* __LXC_NETWORK_H */

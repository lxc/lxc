/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_NETWORK_H
#define __LXC_NETWORK_H

#include "config.h"

#include <arpa/inet.h>
#include <linux/types.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

#include "compiler.h"
#include "hlist.h"
#include "list.h"

struct lxc_conf;
struct lxc_handler;
struct lxc_netdev;

enum {
	LXC_NET_EMPTY,
	LXC_NET_VETH,
	LXC_NET_MACVLAN,
	LXC_NET_IPVLAN,
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
	struct list_head head;
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
	struct list_head head;
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
	struct list_head ipv4_routes;
	struct list_head ipv6_routes;
	int mode; /* bridge, router */
	int n_rxqueues;
	int n_txqueues;
	short vlan_id;
	bool vlan_id_set;
	struct lxc_list vlan_tagged_ids;
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

struct ifla_ipvlan {
	int mode; /* l3, l3s, l2 */
	int isolation; /* bridge, private, vepa */
};

/* Contains information about the physical network device as seen from the host.
 * @ifindex : The ifindex of the physical network device in the host's network
 *            namespace.
 */
struct ifla_phys {
	int ifindex;
	int mtu;
};

union netdev_p {
	struct ifla_macvlan macvlan_attr;
	struct ifla_ipvlan ipvlan_attr;
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
 * @name	      : lxc.net.[i].name, name of iface on the container side
 * @created_name      : the name with which this interface got created before
 *			being renamed to final_name.
 *			Currenly only used for veth devices.
 * @transient_name    : temporary name to avoid namespace collisions
 * @hwaddr            : mac address
 * @mtu               : maximum transmission unit
 * @priv              : information specific to the specificed network type
 *                      Note that this is a union so whether accessing a struct
 *                      is possible is dependent on the network type.
 * @ipv4              : a list of ipv4 addresses to be set on the network device
 * @ipv6              : a list of ipv6 addresses to be set on the network device
 * @ipv4_gateway_auto : whether the ipv4 gateway is to be automatically gathered
 *                      from the associated @link
 * @ipv4_gateway_dev  : whether the ipv4 gateway is to be set as a device route
 * @ipv4_gateway      : ipv4 gateway
 * @ipv6_gateway_auto : whether the ipv6 gateway is to be automatically gathered
 *                      from the associated @link
 * @ipv6_gateway_dev  : whether the ipv6 gateway is to be set as a device route
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
	bool l2proxy;
	char name[IFNAMSIZ];
	char created_name[IFNAMSIZ];
	char transient_name[IFNAMSIZ];
	char *hwaddr;
	char *mtu;
	union netdev_p priv;
	struct list_head ipv4_addresses;
	struct list_head ipv6_addresses;
	bool ipv4_gateway_auto;
	bool ipv4_gateway_dev;
	struct in_addr *ipv4_gateway;
	bool ipv6_gateway_auto;
	bool ipv6_gateway_dev;
	struct in6_addr *ipv6_gateway;
	char *upscript;
	char *downscript;
	struct list_head head;
};

/* Convert a string mac address to a socket structure. */
__hidden extern int lxc_convert_mac(char *macaddr, struct sockaddr *sockaddr);

/* Move a device between namespaces. */
__hidden extern int lxc_netdev_move_by_index(int ifindex, pid_t pid, const char *ifname);
__hidden extern int lxc_netdev_move_by_name(const char *ifname, pid_t pid, const char *newname);

/* Delete a network device. */
__hidden extern int lxc_netdev_delete_by_name(const char *name);
__hidden extern int lxc_netdev_delete_by_index(int ifindex);

/* Change the device name. */
__hidden extern int lxc_netdev_rename_by_name(const char *oldname, const char *newname);
__hidden extern int lxc_netdev_rename_by_index(int ifindex, const char *newname);

__hidden extern int netdev_set_flag(const char *name, int flag);

/* Set the device network up or down. */
__hidden extern int lxc_netdev_isup(const char *name);
__hidden extern int lxc_netdev_up(const char *name);
__hidden extern int lxc_netdev_down(const char *name);

/* Change the mtu size for the specified device. */
__hidden extern int lxc_netdev_set_mtu(const char *name, int mtu);

/* Create a virtual network devices. */
__hidden extern int lxc_veth_create(const char *name1, const char *name2, pid_t pid,
				    unsigned int mtu, int n_rxqueues, int n_txqueues);
__hidden extern int lxc_macvlan_create(const char *parent, const char *name, int mode);
__hidden extern int lxc_vlan_create(const char *parent, const char *name, unsigned short vid);

/* Set ip address. */
__hidden extern int lxc_ipv6_addr_add(int ifindex, struct in6_addr *addr, struct in6_addr *mcast,
				      struct in6_addr *acast, int prefix);

__hidden extern int lxc_ipv4_addr_add(int ifindex, struct in_addr *addr, struct in_addr *bcast,
				      int prefix);

/* Get ip address. */
__hidden extern int lxc_ipv4_addr_get(int ifindex, struct in_addr **res);
__hidden extern int lxc_ipv6_addr_get(int ifindex, struct in6_addr **res);

/* Set default route. */
__hidden extern int lxc_ipv4_gateway_add(int ifindex, struct in_addr *gw);
__hidden extern int lxc_ipv6_gateway_add(int ifindex, struct in6_addr *gw);

/* Attach an interface to the bridge. */
__hidden extern int lxc_bridge_attach(const char *bridge, const char *ifname);
__hidden extern int lxc_ovs_delete_port(const char *bridge, const char *nic);

__hidden extern bool is_ovs_bridge(const char *bridge);

/* Create default gateway. */
__hidden extern int lxc_route_create_default(const char *addr, const char *ifname, int gateway);

/* Delete default gateway. */
__hidden extern int lxc_route_delete_default(const char *addr, const char *ifname, int gateway);

/* Activate neighbor proxying. */
__hidden extern int lxc_neigh_proxy_on(const char *name, int family);

/* Disable neighbor proxying. */
__hidden extern int lxc_neigh_proxy_off(const char *name, int family);

/* Activate IP forwarding. */
__hidden extern int lxc_ip_forwarding_on(const char *name, int family);

/* Disable IP forwarding. */
__hidden extern int lxc_ip_forwarding_off(const char *name, int family);

/*
 * Generate a new unique network interface name.
 *
 * Allows for 62^n unique combinations.
 */
__hidden extern char *lxc_ifname_alnum_case_sensitive(char *template);

__hidden extern const char *lxc_net_type_to_str(int type);
__hidden extern int setup_private_host_hw_addr(char *veth1);
__hidden extern int netdev_get_mtu(int ifindex);
__hidden extern int lxc_network_move_created_netdev_priv(struct lxc_handler *handler);
__hidden extern void lxc_delete_network(struct lxc_handler *handler);
__hidden extern int lxc_find_gateway_addresses(struct lxc_handler *handler);
__hidden extern int lxc_requests_empty_network(struct lxc_handler *handler);
__hidden extern int lxc_restore_phys_nics_to_netns(struct lxc_handler *handler);
__hidden extern int lxc_setup_network_in_child_namespaces(const struct lxc_conf *conf);
__hidden extern int lxc_network_send_to_child(struct lxc_handler *handler);
__hidden extern int lxc_network_recv_from_parent(struct lxc_handler *handler);
__hidden extern int lxc_network_send_name_and_ifindex_to_parent(struct lxc_handler *handler);
__hidden extern int lxc_network_recv_name_and_ifindex_from_child(struct lxc_handler *handler);
__hidden extern int lxc_netns_set_nsid(int netns_fd);
__hidden extern int lxc_netns_get_nsid(__s32 fd);
__hidden extern int lxc_create_network(struct lxc_handler *handler);

__hidden extern char *is_wlan(const char *ifname);
__hidden extern int lxc_netdev_move_wlan(char *physname, const char *ifname, pid_t pid,
					 const char *newname);

#endif /* __LXC_NETWORK_H */

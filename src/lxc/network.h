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

/*
 * Convert a string mac address to a socket structure
 */
extern int lxc_convert_mac(char *macaddr, struct sockaddr *sockaddr);

/*
 * Move a device between namespaces
 */
extern int lxc_netdev_move_by_index(int ifindex, pid_t pid, const char* ifname);
extern int lxc_netdev_move_by_name(const char *ifname, pid_t pid, const char* newname);

/*
 * Delete a network device
 */
extern int lxc_netdev_delete_by_name(const char *name);
extern int lxc_netdev_delete_by_index(int ifindex);

/*
 * Change the device name
 */
extern int lxc_netdev_rename_by_name(const char *oldname, const char *newname);
extern int lxc_netdev_rename_by_index(int ifindex, const char *newname);

extern int netdev_set_flag(const char *name, int flag);

/*
 * Set the device network up or down
 */

extern int lxc_netdev_isup(const char *name);
extern int lxc_netdev_up(const char *name);
extern int lxc_netdev_down(const char *name);

/*
 * Change the mtu size for the specified device
 */
extern int lxc_netdev_set_mtu(const char *name, int mtu);

/*
 * Create a virtual network devices
 */
extern int lxc_veth_create(const char *name1, const char *name2);
extern int lxc_macvlan_create(const char *master, const char *name, int mode);
extern int lxc_vlan_create(const char *master, const char *name, unsigned short vid);

/*
 * Activate forwarding
 */
extern int lxc_ip_forward_on(const char *name, int family);

/*
 * Disable forwarding
 */
extern int lxc_ip_forward_off(const char *name, int family);

/*
 * Set ip address
 */
extern int lxc_ipv6_addr_add(int ifindex, struct in6_addr *addr,
			     struct in6_addr *mcast,
			     struct in6_addr *acast, int prefix);

extern int lxc_ipv4_addr_add(int ifindex, struct in_addr *addr,
			     struct in_addr *bcast, int prefix);

/*
 * Get ip address
 */
extern int lxc_ipv4_addr_get(int ifindex, struct in_addr **res);
extern int lxc_ipv6_addr_get(int ifindex, struct in6_addr **res);

/*
 * Set a destination route to an interface
 */
extern int lxc_ipv4_dest_add(int ifindex, struct in_addr *dest);
extern int lxc_ipv6_dest_add(int ifindex, struct in6_addr *dest);

/*
 * Set default route.
 */
extern int lxc_ipv4_gateway_add(int ifindex, struct in_addr *gw);
extern int lxc_ipv6_gateway_add(int ifindex, struct in6_addr *gw);

/*
 * Attach an interface to the bridge
 */
extern int lxc_bridge_attach(const char *lxcpath, const char *name, const char *bridge, const char *ifname);

/*
 * Create default gateway
 */
extern int lxc_route_create_default(const char *addr, const char *ifname,
				    int gateway);

/*
 * Delete default gateway
 */
extern int lxc_route_delete_default(const char *addr, const char *ifname,
				    int gateway);

/*
 * Activate neighbor proxying
 */
extern int lxc_neigh_proxy_on(const char *name, int family);

/*
 * Disable neighbor proxying
 */
extern int lxc_neigh_proxy_off(const char *name, int family);

/*
 * Generate a new unique network interface name
 */
extern char *lxc_mkifname(char *template);

extern const char *lxc_net_type_to_str(int type);
extern int setup_private_host_hw_addr(char *veth1);
extern int netdev_get_mtu(int ifindex);
#endif

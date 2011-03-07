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
#ifndef _network_h
#define _network_h

/*
 * Convert a string mac address to a socket structure
 */
extern int lxc_convert_mac(char *macaddr, struct sockaddr *sockaddr);

/*
 * Move a device between namespaces
 */
extern int lxc_netdev_move_by_index(int ifindex, pid_t pid);

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

/*
 * Set the device network up or down
 */
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
extern int lxc_vlan_create(const char *master, const char *name, ushort vid);

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
 * Attach an interface to the bridge
 */
extern int lxc_bridge_attach(const char *bridge, const char *ifname);

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

#endif

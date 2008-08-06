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
#ifndef _conf_h
#define _conf_h

enum { 
	VETH,
	MACVLAN,
	PHYS,
	MAXCONFTYPE,
};

/*
 * Defines the structure to configure an ipv4 address
 * @address   : ipv4 address
 * @broadcast : ipv4 broadcast address
 * @mask      : network mask
 */
struct inetdev {
	struct in_addr addr;
	struct in_addr bcast;
	int prefix;
};

struct route {
	struct in_addr addr;
};

/*
 * Defines the structure to configure an ipv6 address
 * @flags     : set the address up
 * @address   : ipv6 address
 * @broadcast : ipv6 broadcast address
 * @mask      : network mask
 */
struct inet6dev {
	struct in6_addr addr;
	struct in6_addr bcast;
	struct in6_addr acast;
	int prefix;
};

struct route6 {
	struct in6_addr addr;
};
/*
 * Defines a structure to configure a network device
 * @ifname : network device name
 * @flags  : flag of the network device (IFF_UP, ... )
 * @ipv4   : a list of ipv4 addresses to be set on the network device
 * @ipv6   : a list of ipv6 addresses to be set on the network device
 */
struct netdev {
	int flags;
	char *ifname;
	char *newname;
	char *hwaddr;
	struct list ipv4;
	struct list ipv6;
	struct list route4;
	struct list route6;
};

/*
 * Defines the kind of the network to use
 * @type : the type of the network virtualization
 * @phys : phys configuration type
 * @veth : veth configuration type
 * @macvlan : macvlan configuration type
 */
struct network {
	int type;
	struct list netdev;
};

/*
 * Defines a structure to configure the control data and path
 */
struct cgroup {
	;
};

/*
 * Defines the global container configuration
 * @chroot  : the root directory to run the container
 * @mount   : the list of mount points
 * @network : the network configuration
 * @utsname : the container utsname
 */
struct lxc_conf {
	char *chroot;
	char *fstab;
	struct utsname *utsname;
	struct cgroup *cgroup;
	struct list networks;
};

/*
 * Configure the external resources for the container
 */
extern int lxc_configure(const char *name, struct lxc_conf *conf);

/*
 * Remove the resources created by the configuration
 */
extern int lxc_unconfigure(const char *name);

extern int conf_create_network(const char *name, pid_t pid);

extern int conf_destroy_network(const char *name);

/*
 * Configure the container from inside
 */
extern int lxc_setup(const char *name);

extern int conf_has(const char *name, const char *info);

#define conf_has_fstab(__name)   conf_has(__name, "fstab")
#define conf_has_utsname(__name) conf_has(__name, "utsname")
#define conf_has_network(__name) conf_has(__name, "network")


#endif

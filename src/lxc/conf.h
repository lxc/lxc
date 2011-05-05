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

#include <netinet/in.h>
#include <sys/param.h>

#include <lxc/list.h>

#include <lxc/start.h> /* for lxc_handler */

enum {
	LXC_NET_EMPTY,
	LXC_NET_VETH,
	LXC_NET_MACVLAN,
	LXC_NET_PHYS,
	LXC_NET_VLAN,
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
	int prefix;
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
	int prefix;
};

struct lxc_route6 {
	struct in6_addr addr;
};

struct ifla_veth {
	char *pair; /* pair name */
};

struct ifla_vlan {
	uint   flags;
	uint   fmask;
	ushort   vid;
	ushort   pad;
};

struct ifla_macvlan {
	int mode; /* private, vepa, bridge */
};

union netdev_p {
	struct ifla_veth veth_attr;
	struct ifla_vlan vlan_attr;
	struct ifla_macvlan macvlan_attr;
};

/*
 * Defines a structure to configure a network device
 * @link       : lxc.network.link, name of bridge or host iface to attach if any
 * @name       : lxc.network.name, name of iface on the container side
 * @flags      : flag of the network device (IFF_UP, ... )
 * @ipv4       : a list of ipv4 addresses to be set on the network device
 * @ipv6       : a list of ipv6 addresses to be set on the network device
 * @upscript   : a script filename to be executed during interface configuration
 */
struct lxc_netdev {
	int type;
	int flags;
	int ifindex;
	char *link;
	char *name;
	char *hwaddr;
	char *mtu;
	union netdev_p priv;
	struct lxc_list ipv4;
	struct lxc_list ipv6;
	char *upscript;
};

/*
 * Defines a generic struct to configure the control group.
 * It is up to the programmer to specify the right subsystem.
 * @subsystem : the targetted subsystem
 * @value     : the value to set
 */
struct lxc_cgroup {
	char *subsystem;
	char *value;
};

/*
 * Defines a structure containing a pty information for
 * virtualizing a tty
 * @name   : the path name of the slave pty side
 * @master : the file descriptor of the master
 * @slave  : the file descriptor of the slave
 */
struct lxc_pty_info {
	char name[MAXPATHLEN];
	int master;
	int slave;
	int busy;
};

/*
 * Defines the number of tty configured and contains the
 * instanciated ptys
 * @nbtty = number of configured ttys
 */
struct lxc_tty_info {
	int nbtty;
	struct lxc_pty_info *pty_info;
};

/*
 * Defines the structure to store the console information
 * @peer   : the file descriptor put/get console traffic
 * @name   : the file name of the slave pty
 */
struct lxc_console {
	int slave;
	int master;
	int peer;
	char *path;
	char name[MAXPATHLEN];
	struct termios *tios;
};

/*
 * Defines a structure to store the rootfs location, the
 * optionals pivot_root, rootfs mount paths
 * @rootfs     : a path to the rootfs
 * @pivot_root : a path to a pivot_root location to be used
 */
struct lxc_rootfs {
	char *path;
	char *mount;
	char *pivot;
};

/*
 * Defines the global container configuration
 * @rootfs     : root directory to run the container
 * @pivotdir   : pivotdir path, if not set default will be used
 * @mount      : list of mount points
 * @tty        : numbers of tty
 * @pts        : new pts instance
 * @mount_list : list of mount point (alternative to fstab file)
 * @network    : network configuration
 * @utsname    : container utsname
 * @fstab      : path to a fstab file format
 * @caps       : list of the capabilities
 * @tty_info   : tty data
 * @console    : console data
 */
struct lxc_conf {
	char *fstab;
	int tty;
	int pts;
	int reboot;
	int personality;
	struct utsname *utsname;
	struct lxc_list cgroup;
	struct lxc_list network;
	struct lxc_list mount_list;
	struct lxc_list caps;
	struct lxc_tty_info tty_info;
	struct lxc_console console;
	struct lxc_rootfs rootfs;
};

/*
 * Initialize the lxc configuration structure
 */
extern struct lxc_conf *lxc_conf_init(void);

extern int lxc_create_network(struct lxc_handler *handler);
extern void lxc_delete_network(struct lxc_list *networks);
extern int lxc_assign_network(struct lxc_list *networks, pid_t pid);

extern int lxc_create_tty(const char *name, struct lxc_conf *conf);
extern void lxc_delete_tty(struct lxc_tty_info *tty_info);

/*
 * Configure the container from inside
 */

extern int lxc_setup(const char *name, struct lxc_conf *lxc_conf);
#endif

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

enum {
	EMPTY,
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
	struct in6_addr bcast;
	struct in6_addr acast;
	int prefix;
};

struct lxc_route6 {
	struct in6_addr addr;
};
/*
 * Defines a structure to configure a network device
 * @link   : lxc.network.link, name of bridge or host iface to attach if any
 * @name   : lxc.network.name, name of iface on the container side
 * @flags  : flag of the network device (IFF_UP, ... )
 * @ipv4   : a list of ipv4 addresses to be set on the network device
 * @ipv6   : a list of ipv6 addresses to be set on the network device
 */
struct lxc_netdev {
	int type;
	int flags;
	int ifindex;
	char *link;
	char *name;
	char *hwaddr;
	char *mtu;
	struct lxc_list ipv4;
	struct lxc_list ipv6;
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
 * Defines the global container configuration
 * @rootfs  : the root directory to run the container
 * @mount   : the list of mount points
 * @network : the network configuration
 * @utsname : the container utsname
 */
struct lxc_conf {
	char *rootfs;
	char *fstab;
	int tty;
	int pts;
	struct utsname *utsname;
	struct lxc_list cgroup;
	struct lxc_list network;
	struct lxc_list mount_list;
	struct lxc_tty_info tty_info;
	char console[MAXPATHLEN];
};

/*
 * Initialize the lxc configuration structure
 */
extern int lxc_conf_init(struct lxc_conf *conf);

extern int lxc_create_network(struct lxc_list *networks);
extern int lxc_assign_network(struct lxc_list *networks, pid_t pid);

extern int lxc_create_tty(const char *name, struct lxc_conf *conf);
extern void lxc_delete_tty(struct lxc_tty_info *tty_info);

/*
 * Configure the container from inside
 */

struct lxc_handler;

extern int lxc_setup(const char *name, struct lxc_conf *lxc_conf);

extern int conf_has(const char *name, const char *info);

#define conf_has_fstab(__name)   conf_has(__name, "fstab")
#define conf_has_rootfs(__name)  conf_has(__name, "rootfs")
#define conf_has_utsname(__name) conf_has(__name, "utsname")
#define conf_has_network(__name) conf_has(__name, "network")
#define conf_has_console(__name) conf_has(__name, "console")
#define conf_has_cgroup(__name)  conf_has(__name, "cgroup")
#define conf_has_tty(__name)     conf_has(__name, "tty")
#define conf_has_pts(__name)     conf_has(__name, "pts")
#endif

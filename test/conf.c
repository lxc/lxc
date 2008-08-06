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
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <netinet/in.h>
#include <net/if.h>

#include <list.h>
#include <conf.h>

/*
 * I want to setup a container with a veth attached on a bridge, 
 * and have them up
 */

int main(int argc, char *argv[])
{
/* 	struct network network = { */
/* 		.net = init_list(&network.net), */
/* 		.netdev = init_list(&network.netdev), */
/* 	}; */

/* 	struct veth veth = { */
/* 		.link = "veth1", */
/* 		.peer = "veth2", */
/* 		.bridge = "br0", */
/* 	}; */

/* 	struct net net = { */
/* 		.type = VETH, */
/* 	}; */

/* 	net.veth = veth; */

/* 	struct netdev lo = { */
/* 		.ifname = "lo", */
/* 		.flags = IFF_UP, */
/* 		.ipv4 = init_list(&lo.ipv4), */
/* 		.ipv6 = init_list(&lo.ipv6), */
/* 	}; */

/* 	struct netdev veth1 = { */
/* 		.ifname = "veth1", */
/* 		.flags = IFF_UP, */
/* 		.ipv4 = init_list(&veth1.ipv4), */
/* 		.ipv6 = init_list(&veth1.ipv6), */
/* 	}; */

/* 	struct netdev veth2 = { */
/* 		.ifname = "veth2", */
/* 		.flags = IFF_UP, */
/* 		.netns = 1, */
/* 		.ipv4 = init_list(&veth2.ipv4), */
/* 		.ipv6 = init_list(&veth2.ipv6), */
/* 	}; */
	
/* 	struct netdev br0 = { */
/* 		.ifname = "br0", */
/* 		.ipv4 = init_list(&br0.ipv4), */
/* 		.ipv6 = init_list(&br0.ipv6), */
/* 	}; */

/* 	list_add(&network.netdev, &lo.list); */
/* 	list_add(&network.netdev, &veth1.list); */
/* 	list_add(&network.netdev, &veth2.list); */
/* 	list_add(&network.netdev, &br0.list); */
/* 	list_add(&network.net, &net.list); */
	
/* 	struct lxc_conf lxc_conf = { */
/* 		.network = &network, */
/* 		.mounts = init_list(&lxc_conf.mounts), */
/* 	}; */

/* 	if (lxc_configure("foo", &lxc_conf)) { */
/* 		fprintf(stderr, "failed to configure\n"); */
/* 		return 1; */
/* 	} */

	return 0;
}

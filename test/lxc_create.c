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
#include <unistd.h>
#include <sys/param.h>
#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>

#include <lxc.h>
#include <state.h>
#include <list.h>
#include <conf.h>

static void usage(const char *cmd)
{
	fprintf(stderr, "%s -n <name>\n", cmd);
	_exit(1);
}

int main(int argc, char *argv[])
{
	const char *name = NULL;
	int opt;
	
/* 	struct list mclist; */
/* 	struct list mclist2; */
/* 	struct list vethlist; */
/* 	struct list vethlist2; */
	struct list phylist;

/* 	struct inetdev idev; */
/* 	struct list l1 = init_list(&l1); */
/* 	l1.elem = &idev; */

/* 	struct inetdev idev_2; */
/* 	struct list l2 = init_list(&l2); */
/* 	l2.elem = &idev_2; */

/* 	struct inet6dev idev6; */
/* 	struct list l3 = init_list(&l3); */
/* 	l3.elem = &idev6; */

/* 	struct inet6dev idev6_2; */
/* 	struct list l4 = init_list(&l4); */
/* 	l4.elem = idev6_2; */


/* 	inet_pton(AF_INET, "1.2.3.4", &idev.addr); */
/* 	inet_pton(AF_INET, "1.2.3.255", &idev.bcast); */
/* 	idev.prefix = 24; */

/* 	inet_pton(AF_INET, "4.3.2.1", &idev_2.addr); */
/* 	inet_pton(AF_INET, "4.3.2.255", &idev_2.bcast); */

/* 	inet_pton(AF_INET6, "2003:db8:1:0:214:5eff:fe0b:3596", &idev6.addr); */
/* 	inet_pton(AF_INET6, "2003:db8:1:0:214:1234:fe0b:3596", &idev6_2.addr); */

/* 	struct network veth = { */
/* 		.type = VETH, */
/* 		.netdev = { */
/* 			.flags = IFF_UP, */
/* 			.ifname = "br0", */
/* 			.newname = "eth0", */
/* 			.ipv4 = init_list(&veth.netdev.ipv4), */
/* 			.ipv6 = init_list(&veth.netdev.ipv6), */
/* 		}, */
/* 	}; */
/* 	vethlist.elem = &veth; */

/* 	list_add(&veth.netdev.ipv4, &l1); */
/* 	list_add(&veth.netdev.ipv4, &l2); */
/* 	list_add(&veth.netdev.ipv6, &l4); */

/* 	struct network veth2 = { */
/* 		.type = VETH, */
/* 		.netdev = { */
/* 			.flags = IFF_UP, */
/* 			.ifname = "br0", */
/* 			.newname = "eth1", */
/* 			.ipv4 = init_list(&veth2.netdev.ipv4), */
/* 			.ipv6 = init_list(&veth2.netdev.ipv6), */
/* 		}, */
/* 	}; */
/* 	list_add(&veth2.netdev.ipv6, &l3); */
/* 	vethlist2.elem = &veth2; */

/* 	struct network macvlan = { */
/* 		.type = MACVLAN, */
/* 		.netdev = { */
/* 			.flags = IFF_UP, */
/* 			.ifname = "eth0", */
/* 			.ipv4 = init_list(&macvlan.netdev.ipv4), */
/* 			.ipv6 = init_list(&macvlan.netdev.ipv6), */
/* 		}, */
/* 	}; */
/* 	mclist.elem = &macvlan; */

/* 	struct network macvlan2 = { */
/* 		.type = MACVLAN, */
/* 		.netdev = { */
/* 			.ifname = "eth0", */
/* 			.ipv4 = init_list(&macvlan2.netdev.ipv4), */
/* 			.ipv6 = init_list(&macvlan2.netdev.ipv6), */
/* 		}, */
/* 	}; */
/* 	mclist2.elem = &macvlan2; */

	struct netdev nd = {
			.ifname = "dummy0",
			.ipv4 = init_list(&nd.ipv4),
			.ipv6 = init_list(&nd.ipv6),
	};
	struct list ndlist = init_list(&ndlist);
	ndlist.elem = &nd;

	struct network phys = {
		.type = PHYS,
		.netdev = init_list(&phys.netdev),
	};
 	phylist.elem = &phys;

	struct lxc_conf lxc_conf = {
		.networks = init_list(&lxc_conf.networks),
		.chroot = "/mnt/iso",
	};

	list_add(&phys.netdev, &ndlist);

/* 	list_add(&lxc_conf.networks, &vethlist); */
/* 	list_add(&lxc_conf.networks, &mclist); */
	list_add(&lxc_conf.networks, &phylist);
/* 	list_add(&lxc_conf.networks, &mclist); */
/* 	list_add(&lxc_conf.networks, &vethlist2); */

	while ((opt = getopt(argc, argv, "n:")) != -1) {
		switch (opt) {
		case 'n':
			name = optarg;
			break;
		}
	}

	if (!name)
		usage(argv[0]);

	if (lxc_create(name, &lxc_conf)) {
		fprintf(stderr, "failed to create the container %s\n", name);
		return 1;
	}

	return 0;
}

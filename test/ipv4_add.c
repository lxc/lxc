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
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <network.h>

void usage(char *cmd)
{
	fprintf(stderr, "%s -i <ifname> -a <ip>\n", cmd);
}

int main(int argc, char *argv[])
{
	char *ifname = NULL, *addr = NULL;
	int opt, ret = -EINVAL;

	while ((opt = getopt(argc, argv, "i:a:")) != -1) {
		switch (opt) {
		case 'a':
			addr = optarg;
			break;
		case 'i':
			ifname = optarg;
			break;
		}
	}
	
	if (!addr || !ifname) {
		usage(argv[0]);
		return 1;
	}
	
	ret = ip_addr_add(ifname, addr, 24, NULL);
	if (ret) {
		fprintf(stderr, "failed to set %s: %s\n", 
			ifname, strerror(-ret));
		return 1;
	}

	return 0;
}

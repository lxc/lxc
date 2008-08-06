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
#include <libgen.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <network.h>

void usage(char *cmd)
{
	fprintf(stderr, "%s -i <ifname> -d -f <up|down>\n", cmd);
}

int main(int argc, char *argv[])
{
	char *ifname = NULL, *flag = NULL;
	int opt, destroy = 0, ret = -EINVAL;

	while ((opt = getopt(argc, argv, "i:f:d")) != -1) {
		switch (opt) {
		case 'i':
			ifname = optarg;
			break;
		case 'f':
			flag = optarg;
			break;
		case 'd':
			destroy = 1;
			break;
		}
	}

	if (!ifname || (!flag && !destroy)) {
		usage(argv[0]);
		return 1;
	}

	if (destroy)
		ret = device_delete(ifname);
	else if (!strcmp(flag, "up"))
		ret = device_up(ifname);
	else if (!strcmp(flag, "down"))
		ret = device_down(ifname);

	if (ret) {
		fprintf(stderr, "failed to set %s: %s\n", 
			ifname, strerror(-ret));
		return 1;
	}

	return 0;
}

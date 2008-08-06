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

#include "../src/lxc/config.h"

static void usage(const char *cmd)
{
	fprintf(stderr, "%s -n <name>\n", cmd);
	_exit(1);
}

int main(int argc, char *argv[])
{
	char *file = NULL, *name = NULL;
	struct lxc_conf lxc_conf;
	int opt;

	while ((opt = getopt(argc, argv, "n:f:")) != -1) {
		switch (opt) {
		case 'f':
			file = optarg;
			break;
		case 'n':
			name = optarg;
			break;
		}
	}

	if (!file || !name)
		usage(argv[0]);

	if (config_init(&lxc_conf)) {
		fprintf(stderr, "failed to initialize configuration structure\n");
		return 1;
	}

	if (config_read(file, &lxc_conf)) {
		fprintf(stderr, "failed to read configuration\n");
		return 1;
	}

	if (lxc_create(name, &lxc_conf)) {
		fprintf(stderr, "failed to create <%s>\n", name);
		return 1;
	}

	return 0;
}

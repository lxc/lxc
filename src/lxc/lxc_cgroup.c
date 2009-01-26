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
#include <libgen.h>
#include <sys/types.h>

#include <lxc/lxc.h>

void usage(char *cmd)
{
	fprintf(stderr, "%s <subsystem> [value]\n", basename(cmd));
	fprintf(stderr, "\t -n <name>   : name of the container\n");
	_exit(1);
}

int main(int argc, char *argv[])
{
	int opt;
	char *name = NULL, *subsystem = NULL, *value = NULL;
	int nbargs = 0;

	while ((opt = getopt(argc, argv, "n:")) != -1) {
		switch (opt) {
		case 'n':
			name = optarg;
			break;
		}

		nbargs++;
	}

	if (!name || argc < 4)
		usage(argv[0]);

	if (argc >= 5)
		value = argv[4];

	subsystem = argv[3];

	if (value) {
		if (lxc_cgroup_set(name, subsystem, value)) {
			fprintf(stderr, "failed to assign '%s' value to '%s' for '%s'\n",
				value, subsystem, name);
			return 1;
		}
	} else {
		const unsigned long len = 4096;
		char buffer[len];
		if (lxc_cgroup_get(name, subsystem, buffer, len)) {
			fprintf(stderr, "failed to retrieve value of '%s' for '%s'\n",
				subsystem, name);
			return 1;
		}

		printf("%s", buffer);
	}

	return 0;
}

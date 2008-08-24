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

#include <lxc.h>

void usage(char *cmd)
{
	fprintf(stderr, "%s\n", basename(cmd));
	fprintf(stderr, "\t -n <name>       : name of the container\n");
	fprintf(stderr, "\t [-p <priority>] : priority of the container\n");
	_exit(1);
}

int main(int argc, char *argv[])
{
	char opt;
	char *name = NULL, *priority = NULL;
	int prio, nbargs = 0;

	while ((opt = getopt(argc, argv, "p:n:")) != -1) {
		switch (opt) {
		case 'n':
			name = optarg;
			break;
		case 'p':
			priority = optarg;
			break;
		}

		nbargs++;
	}

	if (!name)
		usage(argv[0]);

	if (!priority) {
		if (lxc_get_priority(name, &prio)) {
			fprintf(stderr, "failed to retrieve the priority of '%s'\n", name);
			return 1;
		}
		
		printf("'%s' has priority %d\n", name, prio);
		return 0;
	}

	prio = atoi(priority);
	if (lxc_set_priority(name, prio)) {
		fprintf(stderr, "failed to assign priority  %d to of '%s'", 
			prio, name);
		return 1;
	}

	return 0;
}

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
#include <libgen.h>
#include <unistd.h>
#include <sys/types.h>

#include <lxc.h>

void usage(char *cmd)
{
	fprintf(stderr, "%s <statefile>\n", basename(cmd));
	fprintf(stderr, "\t -n <name>   : name of the container\n");
	_exit(1);
}

int main(int argc, char *argv[])
{
	int opt;
	char *name = NULL;
	int stop = 0;
	int nbargs = 0;
	int ret = 1;

	while ((opt = getopt(argc, argv, "sn:")) != -1) {
		switch (opt) {
		case 'n':
			name = optarg;
			break;
		case 's':
			stop = 1;
			break;
		}

		nbargs++;
	}

	if (!name)
		usage(argv[0]);

	if (!argv[1])
		usage(argv[0]);

	if (lxc_freeze(name)) {
		fprintf(stderr, "failed to freeze '%s'\n", name);
		return -1;
	}

	if (lxc_checkpoint(name, argv[1], 0)) {
		fprintf(stderr, "failed to checkpoint %s\n", name);
		goto out;
	}

	if (stop) {
		if (lxc_stop(name)) {
			fprintf(stderr, "failed to stop '%s'\n", name);
			goto out;
		}
	}

	ret = 0;

out:
	if (lxc_unfreeze(name)) {
		fprintf(stderr, "failed to unfreeze '%s'\n", name);
		return 1;
	}

	return ret;
}

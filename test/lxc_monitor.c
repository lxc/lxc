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
#include <string.h>
#include <libgen.h>

#include <lxc.h>
#include <state.h>

void usage(char *cmd)
{
	fprintf(stderr, "%s <command>\n", basename(cmd));
	fprintf(stderr, "\t -n <name>   : name of the container\n");
	_exit(1);
}

int main(int argc, char *argv[])
{
	char opt;
	char *name = NULL;
	int fds[2];
	pid_t pid;

	while ((opt = getopt(argc, argv, "n:")) != -1) {
		switch (opt) {
		case 'n':
			name = optarg;
			break;
		}
	}

	if (!name)
		usage(argv[0]);

	if (pipe(fds)) {
		perror("pipe");
		return 1;
	}



	pid = fork();
	if (pid < 0) {
		perror("fork");
		return 1;
	}

	if (!pid) {
		close(fds[0]);
		if (lxc_monitor(name, fds[1])) {
			fprintf(stderr, "failed to monitor %s\n", name);
			return 1;
		}

		return 0;
	}

	close(fds[1]);

	for (;;) {
		int err, state;

		err = read(fds[0], &state, sizeof(state));
		if (err < 0) {
			perror("read");
			return 1;
		}

		if (!err) {
			printf("container has been destroyed\n");
			return 0;
		}

		printf("container has changed the state to %d - %s\n", 
		       state, state2str(state));
	}

	return 0;
}

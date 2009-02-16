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
#include <stdlib.h>
#include <unistd.h>
#include <libgen.h>
#include <getopt.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "lxc_namespace.h"

void usage(char *cmd)
{
	fprintf(stderr, "%s <options> [command]\n", basename(cmd));
	fprintf(stderr, "Options are:\n");
	fprintf(stderr, "\t -f      : fork and unshare (automatic when unsharing the pids)\n");
	fprintf(stderr, "\t -m      : unshare the mount points\n");
	fprintf(stderr, "\t -p      : unshare the pids\n");
	fprintf(stderr, "\t -h      : unshare the utsname\n");
	fprintf(stderr, "\t -i      : unshare the sysv ipc\n");
	fprintf(stderr, "\t -n      : unshare the network\n");
	fprintf(stderr, "\t -u <id> : unshare the users and set a new id\n");
	fprintf(stderr, "\t if -f or -p is specified, <command> is mandatory)\n");
	_exit(1);
}

int main(int argc, char *argv[])
{
	int opt, nbargs = 0, status = 1, hastofork = 0;
	char **args;
	long flags = 0;
	uid_t uid = 0;
	pid_t pid;

	while ((opt = getopt(argc, argv, "fmphiu:n")) != -1) {
		switch (opt) {
		case 'm':
			flags |= CLONE_NEWNS;
			break;
		case 'p':
			flags |= CLONE_NEWPID;
			break;
		case 'h':
			flags |= CLONE_NEWUTS;
			break;
		case 'i':
			flags |= CLONE_NEWIPC;
			break;
		case 'u':
			flags |= CLONE_NEWUSER;
			uid = atoi(optarg);
			break;
		case 'n':
			flags |= CLONE_NEWNET;
			break;
		case 'f':
			hastofork = 1;
			break;
		}

		nbargs++;
	}

	args = &argv[optind];
	argc -= nbargs;

	if (!flags)
		usage(argv[0]);

	if ((flags & CLONE_NEWPID) || hastofork) {

		if (!argv[optind] || !strlen(argv[optind]))
			usage(argv[0]);

		pid = fork_ns(flags);

		if (pid < 0) {
			fprintf(stderr, "failed to fork into a new namespace: %s\n",
				strerror(errno));
			return 1;
		}

		if (!pid) {
			if (flags & CLONE_NEWUSER && setuid(uid)) {
				fprintf(stderr, "failed to set uid %d: %s\n",
					uid, strerror(errno));
				exit(1);
			}

			execvp(args[0], args);
			fprintf(stderr, "failed to exec: '%s': %s\n",
				argv[0], strerror(errno));
			exit(1);
		}
		
		if (waitpid(pid, &status, 0) < 0)
			fprintf(stderr, "failed to wait for '%d'\n", pid);
		
		return status;
	}

	if (unshare_ns(flags)) {
		fprintf(stderr, "failed to unshare the current process: %s\n",
			strerror(errno));
		return 1;
	}

	if (flags & CLONE_NEWUSER && setuid(uid)) {
		fprintf(stderr, "failed to set uid %d: %s\n",
			uid, strerror(errno));
		return 1;
	}

	if (argv[optind] && strlen(argv[optind])) {
		execvp(args[0], args);
		fprintf(stderr, "failed to exec: '%s': %s\n",
			argv[0], strerror(errno));
		return 1;
	}

	return 0;
}


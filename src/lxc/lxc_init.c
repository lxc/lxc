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
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mount.h>
#define _GNU_SOURCE
#include <getopt.h>

static int mount_sysfs;
static int mount_procfs;

static struct option options[] = {
	{ "mount-sysfs", no_argument, &mount_sysfs, 1 },
	{ "mount-procfs", no_argument, &mount_procfs, 1 },
};

int main(int argc, char *argv[])
{
	pid_t pid;
	int nbargs = 0;
	char **aargv;

	while (1) {
		int ret = getopt_long_only(argc, argv, "", options, NULL);
		if (ret == -1)
			break;
		if (ret == '?')
			exit(1);
		nbargs++;
	}

	if (!argv[optind]) {
		fprintf(stderr, "missing command to launch\n");
		exit(1);
	}

	aargv = &argv[optind];
	argc -= nbargs;

	pid = fork();
	
	if (pid < 0)
		exit(1);

	if (!pid) {
		
		if (mount_sysfs && mount("sysfs", "/sys", "sysfs", 0, NULL)) {
			fprintf(stderr, "failed to mount '/sys'\n");
			exit(1);
		}
		
		if (mount_procfs && mount("proc", "/proc", "proc", 0, NULL)) {
			fprintf(stderr, "failed to mount '/proc'\n");
			exit(1);
		}

		execvp(aargv[0], aargv);
		fprintf(stderr, "failed to exec: %s\n", aargv[0]);
		exit(1);
	}

	

	for (;;) {
		int status;
		if (wait(&status) < 0) {
			if (errno == ECHILD)
				exit(0);
			if (errno == EINTR)
				continue;
			fprintf(stderr, "failed to wait child\n");
			return 1;
		}
	}

	return 0;
}

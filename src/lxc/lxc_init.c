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
#include <libgen.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mount.h>
#define _GNU_SOURCE
#include <getopt.h>
#include "log.h"
#include "error.h"

lxc_log_define(lxc_init, lxc);

static int mount_sysfs;
static int mount_procfs;
static char const *log_file;
static char const *log_priority;
static int quiet;

static struct option options[] = {
	{ "mount-sysfs", no_argument, &mount_sysfs, 1 },
	{ "mount-procfs", no_argument, &mount_procfs, 1 },
	{ "logfile", required_argument, 0, 'o' },
	{ "logpriority", required_argument, 0, 'l' },
	{ "quiet", no_argument, &quiet, 1 },
	{ 0, 0, 0, 0 },
};

int main(int argc, char *argv[])
{
	pid_t pid;
	int nbargs = 0;
	int err = -1;
	char **aargv;

	while (1) {
		int ret = getopt_long_only(argc, argv, "", options, NULL);
		if (ret == -1) {
			break;
		}
		switch (ret) {
		case 'o':	log_file = optarg; break;
		case 'l':	log_priority = optarg; break;
		case '?':
			exit(err);
		}
		nbargs++;
	}

	if (lxc_log_init(log_file, log_priority, basename(argv[0]), quiet))
		exit(err);

	if (!argv[optind]) {
		ERROR("missing command to launch");
		exit(err);
	}

	aargv = &argv[optind];
	argc -= nbargs;

	pid = fork();
	
	if (pid < 0)
		exit(err);

	if (!pid) {
		
		if (mount_sysfs && mount("sysfs", "/sys", "sysfs", 0, NULL)) {
			ERROR("failed to mount '/sys' : %s", strerror(errno));
			exit(err);
		}
		
		if (mount_procfs && mount("proc", "/proc", "proc", 0, NULL)) {
			ERROR("failed to mount '/proc' : %s", strerror(errno));
			exit(err);
		}

		execvp(aargv[0], aargv);
		ERROR("failed to exec: '%s' : %s", aargv[0], strerror(errno));
		exit(err);
	}

	for (;;) {
		int status;
		pid_t waited_pid;

		waited_pid = wait(&status);
		if (waited_pid < 0) {
			if (errno == ECHILD)
				goto out;
			if (errno == EINTR)
				continue;
			ERROR("failed to wait child : %s", strerror(errno));
			goto out;
		} else {
			err = lxc_error_set_and_log(waited_pid, status);
		}
	}
out:
	return err;
}

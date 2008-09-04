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
#define _GNU_SOURCE
#include <stdio.h>
#undef _GNU_SOURCE
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/param.h>

#include <lxc.h>

int lxc_kill(const char *name, int signum)
{
	char freezer[MAXPATHLEN], *signal = NULL;
	int fd = -1, ret = -1;
	
	if (signum < SIGHUP || signum > SIGRTMAX) {
		lxc_log_error("bad signal value %d", signum);
		return -1;
	}

	snprintf(freezer, MAXPATHLEN, LXCPATH "/%s/nsgroup/freezer.kill", name);

	if (!asprintf(&signal, "%d", signum)) {
		lxc_log_syserror("not enough memory");
		return -1;
	}

	fd = open(freezer, O_WRONLY);
	if (fd < 0) {
		lxc_log_syserror("failed to open %s for %s", freezer, name);
		goto out;
	}

	if (write(fd, &signal, strlen(signal)) < 0) {
		lxc_log_syserror("failed to write to %s", freezer);
		goto out;
	}

	ret = 0;
out:
	close(fd);
	free(signal);
	return ret;
}

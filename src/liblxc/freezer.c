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
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/inotify.h>
#include <netinet/in.h>
#include <net/if.h>

#include <lxc.h>
#include <state.h>
#include <log.h>

static int freeze_unfreeze(const char *name, int freeze)
{
	char *freezer, *f = freeze?"FROZEN":"RUNNING";
	int fd, ret = -1;
	
	asprintf(&freezer, LXCPATH "/%s/nsgroup/freezer.state", name);

	fd = open(freezer, O_WRONLY);
	if (fd < 0) {
		lxc_log_syserror("failed to open freezer for '%s'", name);
		goto out;
	}

	ret = write(fd, f, strlen(f) + 1) < 0;
	close(fd);
	if (ret) 
		lxc_log_syserror("failed to write to '%s'", freezer);
out:
	free(freezer);
	return ret;
}

int lxc_freeze(const char *name)
{
	return freeze_unfreeze(name, 1);
}

int lxc_unfreeze(const char *name)
{
	return freeze_unfreeze(name, 0);
}


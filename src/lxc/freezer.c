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
#include <sys/param.h>

#include "error.h"
#include <lxc/lxc.h>
#include <lxc/log.h>

lxc_log_define(lxc_freezer, lxc);

static int freeze_unfreeze(const char *name, int freeze)
{
	char freezer[MAXPATHLEN], *f;
	int fd, ret = -1;
	
	snprintf(freezer, MAXPATHLEN, 
		 LXCPATH "/%s/nsgroup/freezer.state", name);

	fd = open(freezer, O_WRONLY);
	if (fd < 0) {
		SYSERROR("failed to open freezer for '%s'", name);
		return -1;
	}

	if (freeze) {
		f = "FROZEN";
		ret = write(fd, f, strlen(f) + 1) < 0;
	} else {
		f = "THAWED";
		ret = write(fd, f, strlen(f) + 1) < 0;

		/* compatibility code with old freezer interface */
		if (ret) {
			f = "RUNNING";
			ret = write(fd, f, strlen(f) + 1) < 0;
		}
	}

	close(fd);
	if (ret) 
		SYSERROR("failed to write to '%s'", freezer);

	return 0;
}

int lxc_freeze(const char *name)
{
	if (freeze_unfreeze(name, 1))
		return -LXC_ERROR_INTERNAL;

	if (lxc_setstate(name, FROZEN))
		return -LXC_ERROR_INTERNAL;

	return 0;
}

int lxc_unfreeze(const char *name)
{
	if (freeze_unfreeze(name, 0))
		return -LXC_ERROR_INTERNAL;

	if (lxc_setstate(name, RUNNING))
		return -LXC_ERROR_INTERNAL;

	return 0;
}


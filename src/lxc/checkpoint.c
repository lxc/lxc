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
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/file.h>
#include <netinet/in.h>
#include <net/if.h>

#include "error.h"
#include "lxc_plugin.h"
#include <lxc.h>

#include <lxc/log.h>

lxc_log_define(lxc_checkpoint, lxc);

#define MAXPIDLEN 20

int lxc_checkpoint(const char *name, const char *statefile, 
		unsigned long flags)
{
	char init[MAXPATHLEN];
	char val[MAXPIDLEN];
	int fd, lock, ret = -1;
	size_t pid;

	lock = lxc_get_lock(name);
	if (lock >= 0) {
		lxc_put_lock(lock);
		return -LXC_ERROR_ESRCH;
	}

	if (lock < 0 && lock != -LXC_ERROR_EBUSY)
		return lock;

	snprintf(init, MAXPATHLEN, LXCPATH "/%s/init", name);
	fd = open(init, O_RDONLY);
	if (fd < 0) {
		SYSERROR("failed to open init file for %s", name);
		goto out_close;
	}
	
	if (read(fd, val, sizeof(val)) < 0) {
		SYSERROR("failed to read %s", init);
		goto out_close;
	}

	pid = atoi(val);

	if (lxc_plugin_checkpoint(pid, statefile, flags) < 0) {
		SYSERROR("failed to checkpoint %zd", pid);
		goto out_close;
	}

	ret = 0;

out_close:
	close(fd);
	return ret;
}

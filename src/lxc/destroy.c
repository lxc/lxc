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
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <sys/param.h>

#include "error.h"
#include <lxc/lxc.h>
#include <lxc/log.h>

lxc_log_define(lxc_destroy, lxc);

static int remove_lxc_directory(const char *dirname)
{
	char path[MAXPATHLEN];

	snprintf(path, MAXPATHLEN, LXCPATH "/%s", dirname);

	if (rmdir(path)) {
		SYSERROR("failed to remove %s directory", path);
		return -1;
	}

	return 0;
}

int lxc_destroy(const char *name)
{
	int lock, ret = -1;
	char path[MAXPATHLEN];

	lock = lxc_get_lock(name);
	if (lock < 0)
		return ret;

	if (lxc_rmstate(name)) {
		ERROR("failed to remove state file for %s", name);
		goto out_lock;
	}
	
	snprintf(path, MAXPATHLEN, LXCPATH "/%s/init", name);
	unlink(path);
	lxc_unlink_nsgroup(name);

	if (lxc_unconfigure(name)) {
		ERROR("failed to cleanup %s", name);
		goto out_lock;
	}

	if (remove_lxc_directory(name)) {
		SYSERROR("failed to remove '%s'", name);
		goto out_lock;
	}

	ret = 0;
	
out_lock:
	lxc_put_lock(lock);
	return ret;
}

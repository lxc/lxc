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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <sys/param.h>
#include <sys/inotify.h>
#include <sys/file.h>
#include <netinet/in.h>
#include <net/if.h>

#include <lxc.h>
#include <state.h>
#include <list.h>
#include <conf.h>
#include <log.h>
#include <lock.h>

static int dir_filter(const struct dirent *dirent)
{
	if (!strcmp(dirent->d_name, ".") ||
            !strcmp(dirent->d_name, ".."))
                return 0;
        return 1;
}

static int is_empty_directory(const char *dirname)
{
	struct dirent **namelist;
	int n;

	n = scandir(dirname, &namelist, dir_filter, alphasort);
	if (n < 0)
		lxc_log_syserror("failed to scan %s directory", dirname);
	return n == 0;
}

static int remove_lxc_directory(const char *dirname)
{
	char path[MAXPATHLEN];

	sprintf(path, LXCPATH "/%s", dirname);

	if (rmdir(path)) {
		lxc_log_syserror("failed to remove %s directory", path);
		return -1;
	}

	if (is_empty_directory(LXCPATH)) {
		if (rmdir(LXCPATH)) {
			lxc_log_syserror("failed to remove %s directory", LXCPATH);
			return -1;
		}
	}

	return 0;
}

int lxc_destroy(const char *name)
{
	int ret = -1, lock;

	lock = lxc_get_lock(name);
	if (!lock) {
		lxc_log_error("'%s' is busy", name);
		goto out;
	}

	if (lock < 0) {
		lxc_log_error("failed to acquire the lock for '%s':%s", 
			      name, strerror(-lock));
		goto out;
	}

	if (rmstate(name)) {
		lxc_log_error("failed to remove state file for %s", name);
		goto out_lock;
	}

	if (lxc_unconfigure(name)) {
		lxc_log_error("failed to cleanup %s", name);
		goto out_lock;
	}

	if (remove_lxc_directory(name)) {
		lxc_log_syserror("failed to remove '%s'", name);
		goto out_lock;
	}

	ret = 0;
	
out_lock:
	lxc_put_lock(lock);
out:
	return ret;
}

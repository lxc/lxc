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
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <lxc/lxc.h>

int lxc_stop(const char *name)
{
	char init[MAXPATHLEN];
	char val[MAXPIDLEN];
	int fd, lock, ret = -1;
	size_t pid;

	lock = lxc_get_lock(name);
	if (lock > 0) {
		lxc_log_error("'%s' is not running", name);
		lxc_put_lock(lock);
		return -1;
	}

	if (lock < 0) {
		lxc_log_error("failed to acquire the lock on '%s':%s", 
			      name, strerror(-lock));
		return -1;
	}

	snprintf(init, MAXPATHLEN, LXCPATH "/%s/init", name);
	fd = open(init, O_RDONLY);
	if (fd < 0) {
		lxc_log_syserror("failed to open init file for %s", name);
		goto out_unlock;
	}
	
	if (read(fd, val, sizeof(val)) < 0) {
		lxc_log_syserror("failed to read %s", init);
		goto out_close;
	}

	pid = atoi(val);

	if (kill(pid, SIGKILL)) {
		lxc_log_syserror("failed to kill %zd", pid);
		goto out_close;
	}

	if (unlink(init)) {
		lxc_log_syserror("failed to unlink %s", init);
		goto out_close;
	}

	ret = 0;

out_close:
	close(fd);
out_unlock:
	lxc_put_lock(lock);
	return ret;
}

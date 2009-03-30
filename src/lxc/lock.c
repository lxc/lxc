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
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/param.h>

#include "error.h"
#include <lxc/lxc.h>

int lxc_get_lock(const char *name)
{
	char lock[MAXPATHLEN];
	int fd, ret;

	snprintf(lock, MAXPATHLEN, LXCPATH "/%s", name);

	/* need to check access because of cap_dac_override */
	if (access(lock, R_OK |W_OK | X_OK)) {
		ret = errno;
		goto out_err;
	}

	fd = open(lock, O_RDONLY|O_DIRECTORY, S_IRUSR|S_IWUSR);
	if (fd < 0) {
		ret = errno;
		goto out_err;
	}

        fcntl(fd, F_SETFD, FD_CLOEXEC);

	if (flock(fd, LOCK_EX|LOCK_NB)) {
		ret = errno;
		close(fd);
		goto out_err;
	}

	ret = fd;
out:
	return ret;

out_err:
	switch (ret) {
	case EWOULDBLOCK:
		ret = -LXC_ERROR_EBUSY;
		goto out;
	case ENOENT:
		ret = -LXC_ERROR_ENOENT;
		goto out;
	case EACCES:
		ret = -LXC_ERROR_EACCES;
		goto out;
	default:
		ret = -LXC_ERROR_LOCK;
		goto out;
	}
}

void lxc_put_lock(int lock)
{
	flock(lock, LOCK_UN);
	close(lock);
}

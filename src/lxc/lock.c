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

lxc_log_define(lxc_lock, lxc);

static int __lxc_get_lock(const char *name)
{
	char lock[MAXPATHLEN];
	int fd, ret;

	snprintf(lock, MAXPATHLEN, LXCPATH "/%s", name);

	/* need to check access because of cap_dac_override */
	if (access(lock, R_OK |W_OK | X_OK))
		return -errno;

	fd = open(lock, O_RDONLY|O_DIRECTORY, S_IRUSR|S_IWUSR);
	if (fd < 0)
		return -errno;

        fcntl(fd, F_SETFD, FD_CLOEXEC);

	if (flock(fd, LOCK_EX|LOCK_NB)) {
		ret = -errno;
		close(fd);
		goto out;
	}

	ret = fd;
out:
	return ret;
}

int lxc_get_lock(const char *name)
{
	int ret;

	ret = __lxc_get_lock(name);
	if (ret < 0)
		goto out_err;

	return ret;
out_err:
	switch (-ret) {
	case EWOULDBLOCK:
		ERROR("container '%s' is busy", name);
		break;
	case ENOENT:
		ERROR("container '%s' is not found", name);
		break;
	case EACCES:
		ERROR("not enough privilege to use container '%s'", name);
		break;
	default:
		ERROR("container '%s' failed to lock : %s",
		      name, strerror(-ret));
	}
	return -1;
}

int lxc_check_lock(const char *name)
{
	int ret;

	ret = __lxc_get_lock(name);
	if (ret >= 0) {
		ERROR("container '%s' is not active", name);
		lxc_put_lock(ret);
		return -1;
	}
	if (ret != -EWOULDBLOCK) {
		ERROR("container '%s' : %s", name, strerror(-ret));
		return -1;
	}
	return 0;
}

void lxc_put_lock(int lock)
{
	flock(lock, LOCK_UN);
	close(lock);
}

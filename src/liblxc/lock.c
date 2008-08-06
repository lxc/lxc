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
#include <lxc.h>

int lxc_get_lock(const char *name)
{
	char *lock;
	int fd, ret;

	asprintf(&lock, LXCPATH "/%s", name);
	fd = open(lock, O_RDONLY|O_DIRECTORY, S_IRUSR|S_IWUSR);
	if (fd < 0) {
		ret = -errno;
		goto out;
	}

	if (flock(fd, LOCK_EX|LOCK_NB)) {
		ret = errno == EWOULDBLOCK ? 0 : -errno;
		close(fd);
		goto out;
	}

	ret = fd;
out:
	free(lock);
	return ret;
}

void lxc_put_lock(int lock)
{
	flock(lock, LOCK_UN);
	close(lock);
}

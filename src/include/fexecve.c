/* liblxcapi
 *
 * Copyright © 2019 Christian Brauner <christian.brauner@ubuntu.com>.
 * Copyright © 2019 Canonical Ltd.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.

 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "config.h"

static inline int lxc_raw_execveat(int dirfd, const char *pathname,
				   char *const argv[], char *const envp[],
				   int flags)
{
#ifdef __NR_execveat
	syscall(__NR_execveat, dirfd, pathname, argv, envp, flags);
#else
	errno = ENOSYS;
#endif
	return -1;
}

int fexecve(int fd, char *const argv[], char *const envp[])
{
	char procfd[256];
	int ret;

	if (fd < 0 || !argv || !envp) {
		errno = EINVAL;
		return -1;
	}

	lxc_raw_execveat(fd, "", argv, envp, AT_EMPTY_PATH);
	if (errno != ENOSYS)
		return -1;

	ret = snprintf(procfd, sizeof(procfd), "/proc/self/fd/%d", fd);
	if (ret < 0 || (size_t)ret >= sizeof(procfd)) {
		errno = ENAMETOOLONG;
		return -1;
	}

	execve(procfd, argv, envp);
	return -1;
}

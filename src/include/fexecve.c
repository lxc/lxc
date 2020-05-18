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
#include <stdio.h>
#include <unistd.h>

#include <fcntl.h>
#include "config.h"
#include "macro.h"
#include "process_utils.h"

int fexecve(int fd, char *const argv[], char *const envp[])
{
	char procfd[LXC_PROC_PID_FD_LEN];
	int ret;

	if (fd < 0 || !argv || !envp) {
		errno = EINVAL;
		return -1;
	}

	execveat(fd, "", argv, envp, AT_EMPTY_PATH);
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

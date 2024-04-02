/* liblxcapi
 *
 * SPDX-License-Identifier: LGPL-2.1+
 *
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

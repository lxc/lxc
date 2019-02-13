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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "file_utils.h"
#include "raw_syscalls.h"
#include "string_utils.h"
#include "syscall_wrappers.h"

#if IS_BIONIC
#include "../include/fexecve.h"
#endif

#define LXC_MEMFD_REXEC_SEALS \
	(F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE)

static int is_memfd(void)
{
	int fd, saved_errno, seals;

	fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -ENOTRECOVERABLE;

	seals = fcntl(fd, F_GET_SEALS);
	saved_errno = errno;
	close(fd);
	errno = saved_errno;
	if (seals < 0)
		return -EINVAL;

	return seals == LXC_MEMFD_REXEC_SEALS;
}

static void lxc_rexec_as_memfd(char **argv, char **envp, const char *memfd_name)
{
	int saved_errno;
	ssize_t bytes_sent;
	int fd = -1, memfd = -1;

	memfd = memfd_create(memfd_name, MFD_ALLOW_SEALING | MFD_CLOEXEC);
	if (memfd < 0)
		return;

	fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		goto on_error;

	/* sendfile() handles up to 2GB. */
	bytes_sent = lxc_sendfile_nointr(memfd, fd, NULL, LXC_SENDFILE_MAX);
	saved_errno = errno;
	close(fd);
	errno = saved_errno;
	if (bytes_sent < 0)
		goto on_error;

	if (fcntl(memfd, F_ADD_SEALS, LXC_MEMFD_REXEC_SEALS))
		goto on_error;

	fexecve(memfd, argv, envp);

on_error:
	saved_errno = errno;
	close(memfd);
	errno = saved_errno;
}

int lxc_rexec(char *argv[], const char *memfd_name)
{
	int ret;

	ret = is_memfd();
	if (ret < 0 && ret == -ENOTRECOVERABLE) {
		fprintf(stderr,
			"%s - Failed to determine whether this is a memfd\n",
			strerror(errno));
		return -1;
	} else if (ret > 0) {
		return 0;
	}

	lxc_rexec_as_memfd(argv, environ, memfd_name);
	fprintf(stderr, "%s - Failed to rexec as memfd\n", strerror(errno));
	return -1;
}

/**
 * This function will copy any binary that calls liblxc into a memory file and
 * will use the memfd to rexecute the binary. This is done to prevent attacks
 * through the /proc/self/exe symlink to corrupt the host binary when host and
 * container are in the same user namespace or have set up an identity id
 * mapping: CVE-2019-5736.
 */
__attribute__((constructor)) static void liblxc_rexec(int argc, char *argv[])
{
	if (getenv("LXC_MEMFD_REXEC") && lxc_rexec(argv, "liblxc")) {
		fprintf(stderr, "Failed to re-execute liblxc via memory file descriptor\n");
		_exit(EXIT_FAILURE);
	}
}

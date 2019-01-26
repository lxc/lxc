/* liblxcapi
 *
 * Copyright © 2019 Christian Brauner <christian.brauner@ubuntu.com>.
 * Copyright © 2019 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "file_utils.h"
#include "raw_syscalls.h"
#include "string_utils.h"
#include "syscall_wrappers.h"

#define LXC_MEMFD_REXEC_SEALS \
	(F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE)

static int push_vargs(char *data, int data_length, char ***output)
{
	int num = 0;
	char *cur = data;

	if (!data || *output)
		return -1;

	*output = must_realloc(NULL, sizeof(**output));

	while (cur < data + data_length) {
		num++;
		*output = must_realloc(*output, (num + 1) * sizeof(**output));

		(*output)[num - 1] = cur;
		cur += strlen(cur) + 1;
	}
	(*output)[num] = NULL;
	return num;
}

static int parse_exec_params(char ***argv, char ***envp)
{
	int ret;
	char *cmdline = NULL, *env = NULL;
	size_t cmdline_size, env_size;

	cmdline = file_to_buf("/proc/self/cmdline", &cmdline_size);
	if (!cmdline)
		goto on_error;

	env = file_to_buf("/proc/self/environ", &env_size);
	if (!env)
		goto on_error;

	ret = push_vargs(cmdline, cmdline_size, argv);
	if (ret <= 0)
		goto on_error;

	ret = push_vargs(env, env_size, envp);
	if (ret <= 0)
		goto on_error;

	return 0;

on_error:
	free(env);
	free(cmdline);

	return -1;
}

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

static int lxc_rexec(const char *memfd_name)
{
	int ret;
	char **argv = NULL, **envp = NULL;

	ret = is_memfd();
	if (ret < 0 && ret == -ENOTRECOVERABLE) {
		fprintf(stderr,
			"%s - Failed to determine whether this is a memfd\n",
			strerror(errno));
		return -1;
	} else if (ret > 0) {
		return 0;
	}

	ret = parse_exec_params(&argv, &envp);
	if (ret < 0) {
		fprintf(stderr,
			"%s - Failed to parse command line parameters\n",
			strerror(errno));
		return -1;
	}

	lxc_rexec_as_memfd(argv, envp, memfd_name);
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
__attribute__((constructor)) static void liblxc_rexec(void)
{
	if (lxc_rexec("liblxc")) {
		fprintf(stderr, "Failed to re-execute liblxc via memory file descriptor\n");
		_exit(EXIT_FAILURE);
	}
}

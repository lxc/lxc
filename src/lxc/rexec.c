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
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"
#include "macro.h"
#include "memory_utils.h"
#include "utils.h"

#if IS_BIONIC
#include "../include/fexecve.h"
#endif

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

static char *file_to_buf(char *path, size_t *length)
{
	int fd;
	char buf[PATH_MAX];
	char *copy = NULL;

	if (!length)
		return NULL;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return NULL;

	*length = 0;
	for (;;) {
		int n;
		char *old = copy;

		n = lxc_read_nointr(fd, buf, sizeof(buf));
		if (n < 0)
			goto on_error;
		if (!n)
			break;

		copy = must_realloc(old, (*length + n) * sizeof(*old));
		memcpy(copy + *length, buf, n);
		*length += n;
	}

	close(fd);
	return copy;

on_error:
	close(fd);
	free(copy);

	return NULL;
}

static int parse_argv(char ***argv)
{
	__do_free char *cmdline = NULL;
	int ret;
	size_t cmdline_size;

	cmdline = file_to_buf("/proc/self/cmdline", &cmdline_size);
	if (!cmdline)
		return -1;

	ret = push_vargs(cmdline, cmdline_size, argv);
	if (ret <= 0)
		return -1;

	move_ptr(cmdline);
	return 0;
}

static int is_memfd(void)
{
	__do_close_prot_errno int fd = -EBADF;
	int seals;

	fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -ENOTRECOVERABLE;

	seals = fcntl(fd, F_GET_SEALS);
	if (seals < 0) {
		struct stat s = {0};

		if (fstat(fd, &s) == 0)
			return (s.st_nlink == 0);

		return -EINVAL;
	}

	return seals == LXC_MEMFD_REXEC_SEALS;
}

/* Maximum number of bytes sendfile() is able to send in one go. */
#define LXC_SENDFILE_MAX 0x7ffff000
static ssize_t lxc_sendfile_nointr(int out_fd, int in_fd, off_t *offset, size_t count)
{
	ssize_t ret;

again:
	ret = sendfile(out_fd, in_fd, offset, count);
	if (ret < 0) {
		if (errno == EINTR)
			goto again;

		return -1;
	}

	return ret;
}

static int fd_to_fd(int from, int to)
{
	for (;;) {
		uint8_t buf[PATH_MAX];
		uint8_t *p = buf;
		ssize_t bytes_to_write;
		ssize_t bytes_read;

		bytes_read = lxc_read_nointr(from, buf, sizeof buf);
		if (bytes_read < 0)
			return -1;
		if (bytes_read == 0)
			break;

		bytes_to_write = (size_t)bytes_read;
		do {
			ssize_t bytes_written;

			bytes_written = lxc_write_nointr(to, p, bytes_to_write);
			if (bytes_written < 0)
				return -1;

			bytes_to_write -= bytes_written;
			p += bytes_written;
		} while (bytes_to_write > 0);
	}

	return 0;
}

static void lxc_rexec_as_memfd(char **argv, char **envp, const char *memfd_name)
{
	__do_close_prot_errno int execfd = -EBADF, fd = -EBADF, memfd = -EBADF,
				  tmpfd = -EBADF;
	int ret;
	ssize_t bytes_sent = 0;
	struct stat st = {0};

	memfd = memfd_create(memfd_name, MFD_ALLOW_SEALING | MFD_CLOEXEC);
	if (memfd < 0) {
		char template[PATH_MAX];

		ret = snprintf(template, sizeof(template),
			       P_tmpdir "/.%s_XXXXXX", memfd_name);
		if (ret < 0 || (size_t)ret >= sizeof(template))
			return;

		tmpfd = lxc_make_tmpfile(template, true);
		if (tmpfd < 0)
			return;

		ret = fchmod(tmpfd, 0700);
		if (ret)
			return;
	}

	fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return;

	/* sendfile() handles up to 2GB. */
	ret = fstat(fd, &st);
	if (ret)
		return;

	while (bytes_sent < st.st_size) {
		ssize_t sent;

		sent = lxc_sendfile_nointr(memfd >= 0 ? memfd : tmpfd, fd, NULL,
					   st.st_size - bytes_sent);
		if (sent < 0) {
			/* Fallback to shoveling data between kernel- and
			 * userspace.
			 */
			lseek(fd, 0, SEEK_SET);
			if (fd_to_fd(fd, memfd >= 0 ? memfd : tmpfd))
				break;

			return;
		}
		bytes_sent += sent;
	}
	close_prot_errno_disarm(fd);

	if (memfd >= 0) {
		if (fcntl(memfd, F_ADD_SEALS, LXC_MEMFD_REXEC_SEALS))
			return;

		execfd = memfd;
	} else {
		char procfd[LXC_PROC_PID_FD_LEN];

		ret = snprintf(procfd, sizeof(procfd), "/proc/self/fd/%d", tmpfd);
		if (ret < 0 || (size_t)ret >= sizeof(procfd))
			return;

		execfd = open(procfd, O_PATH | O_CLOEXEC);
		close_prot_errno_disarm(tmpfd);

	}
	if (execfd < 0)
		return;

	fexecve(execfd, argv, envp);
}

/*
 * Get cheap access to the environment. This must be declared by the user as
 * mandated by POSIX. The definition is located in unistd.h.
 */
extern char **environ;

int lxc_rexec(const char *memfd_name)
{
	int ret;
	char **argv = NULL;

	ret = is_memfd();
	if (ret < 0 && ret == -ENOTRECOVERABLE) {
		fprintf(stderr,
			"%s - Failed to determine whether this is a memfd\n",
			strerror(errno));
		return -1;
	} else if (ret > 0) {
		return 0;
	}

	ret = parse_argv(&argv);
	if (ret < 0) {
		fprintf(stderr,
			"%s - Failed to parse command line parameters\n",
			strerror(errno));
		return -1;
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
__attribute__((constructor)) static void liblxc_rexec(void)
{
	if (getenv("LXC_MEMFD_REXEC") && lxc_rexec("liblxc")) {
		fprintf(stderr, "Failed to re-execute liblxc via memory file descriptor\n");
		_exit(EXIT_FAILURE);
	}
}

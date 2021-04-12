/* SPDX-License-Identifier: LGPL-2.1+ */

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
#include "macro.h"
#include "memory_utils.h"
#include "process_utils.h"
#include "rexec.h"
#include "string_utils.h"
#include "syscall_wrappers.h"

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
	__do_close int fd = -EBADF;
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

static void lxc_rexec_as_memfd(char **argv, char **envp, const char *memfd_name)
{
	__do_close int execfd = -EBADF, fd = -EBADF, memfd = -EBADF,
		       tmpfd = -EBADF;
	int ret;
	ssize_t bytes_sent = 0;
	struct stat st = {0};

	memfd = memfd_create(memfd_name, MFD_ALLOW_SEALING | MFD_CLOEXEC);
	if (memfd < 0) {
		char template[PATH_MAX];

		ret = strnprintf(template, sizeof(template),
				 P_tmpdir "/.%s_XXXXXX", memfd_name);
		if (ret < 0)
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
			/*
			 * Fallback to shoveling data between kernel- and
			 * userspace.
			 */
			if (lseek(fd, 0, SEEK_SET) == (off_t) -1)
				fprintf(stderr, "Failed to seek to beginning of file");

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

		execfd = move_fd(memfd);
	} else {
		char procfd[LXC_PROC_PID_FD_LEN];

		ret = strnprintf(procfd, sizeof(procfd), "/proc/self/fd/%d", tmpfd);
		if (ret < 0)
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
	__do_free_string_list char **argv = NULL;
	int ret;

	ret = is_memfd();
	if (ret < 0 && ret == -ENOTRECOVERABLE) {
		fprintf(stderr, "%s - Failed to determine whether this is a memfd\n",
			strerror(errno));
		return -1;
	} else if (ret > 0) {
		return 0;
	}

	ret = parse_argv(&argv);
	if (ret < 0) {
		fprintf(stderr, "%s - Failed to parse command line parameters\n",
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

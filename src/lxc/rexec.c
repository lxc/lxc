/* SPDX-License-Identifier: LGPL-2.1+ */

#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "file_utils.h"
#include "macro.h"
#include "memory_utils.h"
#include "process_utils.h"
#include "rexec.h"
#include "string_utils.h"
#include "syscall_wrappers.h"

#define LXC_MEMFD_REXEC_SEALS \
	(F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE)

/**
 * Transforms null separated string elements into an array of pointers to these
 * elements.
 * @param[in] data - null separated string elements
 * @param[in] data_length - length of data
 * @param[out] output - NULL terminated array of pointers to a copy of elements
 *                      passed in data. Data are copied behind the array and the
 *                      whole output resides in one chunk of memory and should
 *                      be freed with free(*output).
 * @return Number of elements returned or -EINVAL if data or output is NULL or
 *         if *output is not NULL.
 */
static int push_vargs(const char *data, int data_length, char ***output)
{
	int i, j, nmemb;
	char *end;

	if (!data || !output || *output)
		return -EINVAL;

	for (nmemb = i = 0; i < data_length; i++)
		if (!data[i]) nmemb++;

	*output = must_realloc(NULL, (nmemb + 1) * sizeof(char*) + data_length);
	end = (char *)&(*output)[nmemb + 1];
	memcpy(end, data, data_length);

	(*output)[0] = end;
	for (i = j = 0; i < data_length; i++)
		if (!end[i]) (*output)[++j] = &end[i + 1];
	(*output)[j] = NULL;

	return nmemb;
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
	return ret <= 0 ? -1 : 0;
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
	__do_free char **argv = NULL;
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

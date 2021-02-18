/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sendfile.h>

#include "config.h"
#include "file_utils.h"
#include "log.h"
#include "macro.h"
#include "parse.h"
#include "syscall_wrappers.h"
#include "utils.h"

lxc_log_define(parse, lxc);

void *lxc_strmmap(void *addr, size_t length, int prot, int flags, int fd,
		  off_t offset)
{
	void *tmp = NULL, *overlap = NULL;

	/* We establish an anonymous mapping that is one byte larger than the
	 * underlying file. The pages handed to us are zero filled. */
	tmp = mmap(addr, length + 1, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (tmp == MAP_FAILED)
		return tmp;

	/* Now we establish a fixed-address mapping starting at the address we
	 * received from our anonymous mapping and replace all bytes excluding
	 * the additional \0-byte with the file. This allows us to use normal
	 * string-handling functions. */
	overlap = mmap(tmp, length, prot, MAP_FIXED | flags, fd, offset);
	if (overlap == MAP_FAILED)
		munmap(tmp, length + 1);

	return overlap;
}

int lxc_strmunmap(void *addr, size_t length)
{
	return munmap(addr, length + 1);
}

int lxc_file_for_each_line_mmap(const char *file, lxc_file_cb callback, void *data)
{
	__do_close int fd = -EBADF, memfd = -EBADF;
	ssize_t ret = -1;
	char *buf = NULL;
	struct stat st = {};
	ssize_t bytes;
	char *line;

	memfd = memfd_create(".lxc_config_file", MFD_CLOEXEC);
	if (memfd < 0) {
		char template[] = P_tmpdir "/.lxc_config_file_XXXXXX";

		if (errno != ENOSYS) {
			SYSERROR("Failed to create memory file");
			goto on_error;
		}

		TRACE("Failed to create in-memory file. Falling back to temporary file");
		memfd = lxc_make_tmpfile(template, true);
		if (memfd < 0) {
			SYSERROR("Failed to create temporary file \"%s\"", template);
			goto on_error;
		}
	}

	fd = open(file, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		SYSERROR("Failed to open file \"%s\"", file);
		goto on_error;
	}

	ret = fstat(fd, &st);
	if (ret) {
		SYSERROR("Failed to stat file \"%s\"", file);
		goto on_error;
	}

	if (st.st_size > INT_MAX) {
		SYSERROR("Excessively large config file \"%s\"", file);
		goto on_error;
	}


	bytes = __fd_to_fd(fd, memfd);
	if (bytes < 0) {
		SYSERROR("Failed to copy config file \"%s\"", file);
		goto on_error;
	}

	ret = lxc_write_nointr(memfd, "\0", 1);
	if (ret < 0) {
		SYSERROR("Failed to append zero byte");
		goto on_error;
	}
	bytes++;

	ret = lseek(memfd, 0, SEEK_SET);
	if (ret < 0) {
		SYSERROR("Failed to lseek");
		goto on_error;
	}

	ret = -1;
	buf = mmap(NULL, bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_POPULATE, memfd, 0);
	if (buf == MAP_FAILED) {
		buf = NULL;
		SYSERROR("Failed to mmap");
		goto on_error;
	}

	ret = 0;
	lxc_iterate_parts(line, buf, "\r\n\0") {
		ret = callback(line, data);
		if (ret) {
			/* Callback rv > 0 means stop here callback rv < 0 means
			 * error.
			 */
			if (ret < 0)
				ERROR("Failed to parse config file \"%s\" at line \"%s\"",
				      file, line);
			break;
		}
	}

on_error:
	if (buf && munmap(buf, bytes)) {
		SYSERROR("Failed to unmap");
		if (ret == 0)
			ret = -1;
	}

	return ret;
}

int lxc_file_for_each_line(const char *file, lxc_file_cb callback, void *data)
{
	__do_fclose FILE *f = NULL;
	__do_free char *line = NULL;
	int err = 0;
	size_t len = 0;

	f = fopen(file, "re");
	if (!f) {
		SYSERROR("Failed to open \"%s\"", file);
		return -1;
	}

	while (getline(&line, &len, f) != -1) {
		err = callback(line, data);
		if (err) {
			/* Callback rv > 0 means stop here callback rv < 0 means
			 * error.
			 */
			if (err < 0)
				ERROR("Failed to parse config: \"%s\"", line);
			break;
		}
	}

	return err;
}

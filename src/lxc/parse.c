/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2008
 *
 * Authors:
 * Daniel Lezcano <daniel.lezcano at free.fr>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "config.h"
#include "log.h"
#include "parse.h"
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
	int fd, saved_errno;
	char *buf, *line;
	struct stat st;
	int ret = 0;

	fd = open(file, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		SYSERROR("Failed to open config file \"%s\"", file);
		return -1;
	}

	ret = fstat(fd, &st);
	if (ret < 0) {
		SYSERROR("Failed to stat config file \"%s\"", file);
		goto on_error;
	}

	ret = 0;
	if (st.st_size == 0)
		goto on_error;

	ret = -1;
	buf = lxc_strmmap(NULL, st.st_size, PROT_READ | PROT_WRITE,
			  MAP_PRIVATE | MAP_POPULATE, fd, 0);
	if (buf == MAP_FAILED) {
		SYSERROR("Failed to map config file \"%s\"", file);
		goto on_error;
	}

	lxc_iterate_parts(line, buf, "\n\0") {
		ret = callback(line, data);
		if (ret) {
			/* Callback rv > 0 means stop here callback rv < 0 means
			 * error.
			 */
			if (ret < 0)
				ERROR("Failed to parse config file \"%s\" at "
				      "line \"%s\"",
				      file, line);
			break;
		}
	}

on_error:
	ret = lxc_strmunmap(buf, st.st_size);
	if (ret < 0)
		SYSERROR("Failed to unmap config file \"%s\"", file);

	saved_errno = errno;
	close(fd);
	errno = saved_errno;

	return ret;
}

int lxc_file_for_each_line(const char *file, lxc_file_cb callback, void *data)
{
	FILE *f;
	int err = 0;
	char *line = NULL;
	size_t len = 0;

	f = fopen(file, "r");
	if (!f) {
		SYSERROR("failed to open %s", file);
		return -1;
	}

	while (getline(&line, &len, f) != -1) {
		err = callback(line, data);
		if (err) {
			/* Callback rv > 0 means stop here callback rv < 0 means
			 * error.
			 */
			if (err < 0)
				ERROR("Failed to parse config: %s", line);
			break;
		}
	}

	free(line);
	fclose(f);
	return err;
}

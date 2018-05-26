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

#define _GNU_SOURCE
#include <stdio.h>
#undef _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "parse.h"
#include "config.h"
#include "utils.h"
#include "log.h"

lxc_log_define(lxc_parse, lxc);

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

int lxc_file_for_each_line_mmap(const char *file, lxc_file_cb callback,
				void *data)
{
	int fd;
	char *buf, *line;
	struct stat st;
	int ret = 0;
	char *saveptr = NULL;

	fd = open(file, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;

	ret = fstat(fd, &st);
	if (ret < 0) {
		close(fd);
		return -1;
	}

	if (st.st_size == 0) {
		close(fd);
		return 0;
	}

	buf = lxc_strmmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (buf == MAP_FAILED) {
		close(fd);
		return -1;
	}

	for (; (line = strtok_r(buf, "\n\0", &saveptr)); buf = NULL) {
		ret = callback(line, data);
		if (ret) {
			/* Callback rv > 0 means stop here callback rv < 0 means
			 * error.
			 */
			if (ret < 0)
				ERROR("Failed to parse config: %s", line);
			break;
		}
	}

	lxc_strmunmap(buf, st.st_size);
	close(fd);
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

int lxc_char_left_gc(const char *buffer, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		if (buffer[i] == ' ' ||
		    buffer[i] == '\t')
			continue;

		return i;
	}

	return 0;
}

int lxc_char_right_gc(const char *buffer, size_t len)
{
	int i;

	for (i = len - 1; i >= 0; i--) {
		if (buffer[i] == ' '  ||
		    buffer[i] == '\t' ||
		    buffer[i] == '\n' ||
		    buffer[i] == '\0')
			continue;

		return i + 1;
	}

	return 0;
}

char *lxc_trim_whitespace_in_place(char *buffer)
{
	buffer += lxc_char_left_gc(buffer, strlen(buffer));
	buffer[lxc_char_right_gc(buffer, strlen(buffer))] = '\0';
	return buffer;
}

int lxc_is_line_empty(const char *line)
{
	int i;
	size_t len = strlen(line);

	for (i = 0; i < len; i++)
		if (line[i] != ' ' && line[i] != '\t' &&
		    line[i] != '\n' && line[i] != '\r' &&
		    line[i] != '\f' && line[i] != '\0')
			return 0;
	return 1;
}

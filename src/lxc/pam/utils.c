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


#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/vfs.h>
#include <stdarg.h>

#include "utils.h"

#ifndef HAVE_STRLCAT
#include "include/strlcat.h"
#endif

bool file_exists(const char *f)
{
	struct stat statbuf;

	return stat(f, &statbuf) == 0;
}

void *must_realloc(void *orig, size_t sz)
{
	void *ret;

	do {
		ret = realloc(orig, sz);
	} while (!ret);

	return ret;
}

char *must_copy_string(const char *entry)
{
	char *ret;

	if (!entry)
		return NULL;
	do {
		ret = strdup(entry);
	} while (!ret);

	return ret;
}

char *must_make_path(const char *first, ...)
{
	va_list args;
	char *cur, *dest;
	size_t full_len = strlen(first);
	size_t buf_len;

	dest = must_copy_string(first);

	va_start(args, first);
	while ((cur = va_arg(args, char *)) != NULL) {
		full_len += strlen(cur);
		if (cur[0] != '/')
			full_len++;

		buf_len = full_len + 1;
		dest = must_realloc(dest, buf_len);

		if (cur[0] != '/')
			(void)strlcat(dest, "/", buf_len);
		(void)strlcat(dest, cur, buf_len);
	}
	va_end(args);

	return dest;
}

bool is_fs_type(const struct statfs *fs, fs_type_magic magic_val)
{
	return (fs->f_type == (fs_type_magic)magic_val);
}

bool has_fs_type(const char *path, fs_type_magic magic_val)
{
	bool has_type;
	int ret;
	struct statfs sb;

	ret = statfs(path, &sb);
	if (ret < 0)
		return false;

	has_type = is_fs_type(&sb, magic_val);

	return has_type;
}

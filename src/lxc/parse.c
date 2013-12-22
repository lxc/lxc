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
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <dirent.h>

#include "parse.h"
#include "config.h"
#include "utils.h"
#include <lxc/log.h>

/* Workaround for the broken signature of alphasort() in bionic.
   This was fixed upstream in 40e467ec668b59be25491bd44bf348a884d6a68d so the
   workaround can probably be dropped with the next version of the Android NDK.
 */
#ifdef IS_BIONIC
int bionic_alphasort(const struct dirent** a, const struct dirent** b) {
       return strcoll((*a)->d_name, (*b)->d_name);
}
#endif


lxc_log_define(lxc_parse, lxc);

static int dir_filter(const struct dirent *dirent)
{
	if (!strcmp(dirent->d_name, ".") ||
            !strcmp(dirent->d_name, ".."))
                return 0;
        return 1;
}

int lxc_dir_for_each(const char *name, const char *directory,
		     lxc_dir_cb callback, void *data)
{
	struct dirent **namelist;
	int n, ret = 0;

#ifdef IS_BIONIC
	n = scandir(directory, &namelist, dir_filter, bionic_alphasort);
#else
	n = scandir(directory, &namelist, dir_filter, alphasort);
#endif
	if (n < 0) {
		SYSERROR("failed to scan %s directory", directory);
		return -1;
	}

	while (n--) {
		if (!ret &&
		    callback(name, directory, namelist[n]->d_name, data)) {
			ERROR("callback failed");
			ret = -1;
		}
		free(namelist[n]);
	}
	free(namelist);

	return ret;
}

int lxc_file_for_each_line(const char *file, lxc_file_cb callback, void *data)
{
	FILE *f;
	int err = 0;
	char *line = NULL;
	size_t len = 0;

	f = lxc_fopen(file, "r");
	if (!f) {
		SYSERROR("failed to open %s", file);
		return -1;
	}

	while (getline(&line, &len, f) != -1) {
		err = callback(line, data);
		if (err) {
			// callback rv > 0 means stop here
			// callback rv < 0 means error
			if (err < 0)
				ERROR("Failed to parse config: %s", line);
			break;
		}
	}

	if (line)
		free(line);
	lxc_fclose(f);
	return err;
}

int lxc_char_left_gc(char *buffer, size_t len)
{
	int i;
	for (i = 0; i < len; i++) {
		if (buffer[i] == ' ' ||
		    buffer[i] == '\t')
			continue;
		return i;
	}
	return 0;
}

int lxc_char_right_gc(char *buffer, size_t len)
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

int lxc_is_line_empty(char *line)
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

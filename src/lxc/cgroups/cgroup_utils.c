/*
 * lxc: linux Container library
 *
 * Copyright © 2017 Canonical Ltd.
 *
 * Authors:
 * Serge Hallyn <serge.hallyn@ubuntu.com>
 * Christian Brauner <christian.brauner@ubuntu.com>
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
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cgroup_utils.h"
#include "config.h"
#include "macro.h"
#include "memory_utils.h"
#include "utils.h"

int get_cgroup_version(char *line)
{
	if (is_cgroupfs_v1(line))
		return CGROUP_SUPER_MAGIC;

	if (is_cgroupfs_v2(line))
		return CGROUP2_SUPER_MAGIC;

	return 0;
}

bool is_cgroupfs_v1(char *line)
{
	char *p = strstr(line, " - ");
	if (!p)
		return false;
	return strncmp(p, " - cgroup ", 10) == 0;
}

bool is_cgroupfs_v2(char *line)
{
	char *p = strstr(line, " - ");
	if (!p)
		return false;

	return strncmp(p, " - cgroup2 ", 11) == 0;
}

bool test_writeable_v1(char *mountpoint, char *path)
{
	__do_free char *fullpath = must_make_path(mountpoint, path, NULL);
	return (access(fullpath, W_OK) == 0);
}

bool test_writeable_v2(char *mountpoint, char *path)
{
	/* In order to move ourselves into an appropriate sub-cgroup we need to
	 * have write access to the parent cgroup's "cgroup.procs" file, i.e. we
	 * need to have write access to the our current cgroups's "cgroup.procs"
	 * file.
	 */
	int ret;
	__do_free char *cgroup_path = NULL, *cgroup_procs_file = NULL,
		       *cgroup_threads_file = NULL;

	cgroup_path = must_make_path(mountpoint, path, NULL);
	cgroup_procs_file = must_make_path(cgroup_path, "cgroup.procs", NULL);

	ret = access(cgroup_path, W_OK);
	if (ret < 0)
		return false;

	ret = access(cgroup_procs_file, W_OK);
	if (ret < 0)
		return false;

	/* Newer versions of cgroup2 now also require write access to the
	 * "cgroup.threads" file.
	 */
	cgroup_threads_file = must_make_path(cgroup_path, "cgroup.threads", NULL);
	if (!file_exists(cgroup_threads_file))
		return true;

	return (access(cgroup_threads_file, W_OK) == 0);
}

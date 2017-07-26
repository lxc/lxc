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

#ifndef __LXC_CGROUP_UTILS_H
#define __LXC_CGROUP_UTILS_H

#include <stdbool.h>
#include <stdio.h>

/* Check if given entry from /proc/<pid>/mountinfo is a cgroupfs v1 mount. */
extern bool is_cgroupfs_v1(char *line);

/* Check if given entry from /proc/<pid>/mountinfo is a cgroupfs v2 mount. */
extern bool is_cgroupfs_v2(char *line);

/* Given a v1 hierarchy @mountpoint and base @path, verify that we can create
 * directories underneath it.
 */
extern bool test_writeable_v1(char *mountpoint, char *path);

/* Given a v2 hierarchy @mountpoint and base @path, verify that we can create
 * directories underneath it and that we have write access to the cgroup's
 * "cgroup.procs" file.
 */
extern bool test_writeable_v2(char *mountpoint, char *path);

#endif /* __LXC_CGROUP_UTILS_H */

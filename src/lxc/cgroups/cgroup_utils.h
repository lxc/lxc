/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_CGROUP_UTILS_H
#define __LXC_CGROUP_UTILS_H

#include <stdbool.h>
#include <stdio.h>

/* Retrieve the cgroup version of a given entry from /proc/<pid>/mountinfo. */
extern int get_cgroup_version(char *line);

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

extern int unified_cgroup_hierarchy(void);

#endif /* __LXC_CGROUP_UTILS_H */

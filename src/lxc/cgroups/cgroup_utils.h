/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_CGROUP_UTILS_H
#define __LXC_CGROUP_UTILS_H

#include <stdbool.h>
#include <stdio.h>

#include "compiler.h"
#include "file_utils.h"

/* Retrieve the cgroup version of a given entry from /proc/<pid>/mountinfo. */
__hidden extern int get_cgroup_version(char *line);

/* Check if given entry from /proc/<pid>/mountinfo is a cgroupfs v1 mount. */
__hidden extern bool is_cgroupfs_v1(char *line);

/* Check if given entry from /proc/<pid>/mountinfo is a cgroupfs v2 mount. */
__hidden extern bool is_cgroupfs_v2(char *line);

/* Given a v1 hierarchy @mountpoint and base @path, verify that we can create
 * directories underneath it.
 */
__hidden extern bool test_writeable_v1(char *mountpoint, char *path);

/* Given a v2 hierarchy @mountpoint and base @path, verify that we can create
 * directories underneath it and that we have write access to the cgroup's
 * "cgroup.procs" file.
 */
__hidden extern bool test_writeable_v2(char *mountpoint, char *path);

__hidden extern int unified_cgroup_fd(int fd);

static inline bool cgns_supported(void)
{
	static int supported = -1;

	if (supported == -1)
		supported = file_exists("/proc/self/ns/cgroup");

	return supported == 1;
}

__hidden extern int cgroup_tree_prune(int dfd, const char *path);

/*
 * This function can only be called on information parsed from
 * /proc/<pid>/cgroup or on absolute paths and it will verify the latter and
 * return NULL if a relative path is passed.
 */
__hidden extern char *prune_init_scope(char *path);

#endif /* __LXC_CGROUP_UTILS_H */

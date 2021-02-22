/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_CGROUP_UTILS_H
#define __LXC_CGROUP_UTILS_H

#include <stdbool.h>
#include <stdio.h>

#include "compiler.h"
#include "file_utils.h"

__hidden extern bool unified_cgroup_fd(int fd);

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

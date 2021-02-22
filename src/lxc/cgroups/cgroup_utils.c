/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/vfs.h>
#include <unistd.h>

#include "cgroup.h"
#include "cgroup_utils.h"
#include "config.h"
#include "file_utils.h"
#include "log.h"
#include "macro.h"
#include "memory_utils.h"
#include "utils.h"

lxc_log_define(cgroup_utils, lxc);

bool unified_cgroup_fd(int fd)
{

	int ret;
	struct statfs fs;

	ret = fstatfs(fd, &fs);
	if (!ret && is_fs_type(&fs, CGROUP2_SUPER_MAGIC))
		return true;

	return false;
}

int cgroup_tree_prune(int dfd, const char *path)
{
	__do_close int dfd_disown = -EBADF, dfd_dup = -EBADF;
	__do_closedir DIR *dir = NULL;
	int ret;
	struct dirent *direntp;

	/*
	 * The unlinkat() syscall doesn't work with empty paths, i.e. it isn't
	 * possible to remove the fd itself.
	 */
	if (is_empty_string(path) || strequal(path, "."))
		return ret_errno(EINVAL);

	/*
	 * Note that O_PATH file descriptors can't be used with getdents() and
	 * therefore with readdir().
	 */
	dfd_disown = open_at(dfd, path, PROTECT_OPEN,
			     PROTECT_LOOKUP_BENEATH_WITH_SYMLINKS, 0);
	if (dfd_disown < 0)
		return -errno;

	dfd_dup = dup_cloexec(dfd_disown);
	if (dfd_dup < 0)
		return -errno;

	dir = fdopendir(dfd_disown);
	if (!dir)
		return -errno;

	/* Transfer ownership to fdopendir(). */
	move_fd(dfd_disown);

	while ((direntp = readdir(dir))) {
		struct stat st;

		if (strequal(direntp->d_name, ".") ||
		    strequal(direntp->d_name, ".."))
			continue;

		ret = fstatat(dfd_dup, direntp->d_name, &st,
			      AT_NO_AUTOMOUNT | AT_SYMLINK_NOFOLLOW);
		if (ret < 0)
			continue;

		if (!S_ISDIR(st.st_mode))
			continue;

		ret = cgroup_tree_prune(dfd_dup, direntp->d_name);
		if (ret < 0)
			return -errno;
	}

	ret = unlinkat(dfd, path, AT_REMOVEDIR);
	if (ret < 0)
		return -errno;

	return 0;
}

#define INIT_SCOPE "/init.scope"
char *prune_init_scope(char *path)
{
	char *slash = path;
	size_t len;

	/*
	 * This function can only be called on information parsed from
	 * /proc/<pid>/cgroup. The file displays the current cgroup of the
	 * process as absolute paths. So if we are passed a non-absolute path
	 * things are way wrong.
	 */
	if (!abspath(path))
		return ret_set_errno(NULL, EINVAL);

	len = strlen(path);
	if (len < STRLITERALLEN(INIT_SCOPE))
		return path;

	slash += (len - STRLITERALLEN(INIT_SCOPE));
	if (strequal(slash, INIT_SCOPE)) {
		if (slash == path)
			slash++;
		*slash = '\0';
	}

	return path;
}

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
	return strnequal(p, " - cgroup ", 10);
}

bool is_cgroupfs_v2(char *line)
{
	char *p = strstr(line, " - ");
	if (!p)
		return false;

	return strnequal(p, " - cgroup2 ", 11);
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

int unified_cgroup_fd(int fd)
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

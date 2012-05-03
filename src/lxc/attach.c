/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2008
 *
 * Authors:
 * Daniel Lezcano <dlezcano at fr.ibm.com>
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/param.h>
#include <sys/prctl.h>
#include <linux/unistd.h>

#if !HAVE_DECL_PR_CAPBSET_DROP
#define PR_CAPBSET_DROP 24
#endif

#include "namespace.h"
#include "log.h"
#include "attach.h"
#include "caps.h"
#include "cgroup.h"
#include "config.h"

lxc_log_define(lxc_attach, lxc);

int setns(int fd, int nstype)
{
#ifndef __NR_setns
	errno = ENOSYS;
	return -1;
#else
	return syscall(__NR_setns, fd, nstype);
#endif
}

struct lxc_proc_context_info *lxc_proc_get_context_info(pid_t pid)
{
	struct lxc_proc_context_info *info = calloc(1, sizeof(*info));
	FILE *proc_file;
	char proc_fn[MAXPATHLEN];
	char *line = NULL;
	size_t line_bufsz = 0;
	int ret, found;

	if (!info) {
		SYSERROR("Could not allocate memory.");
		return NULL;
	}

	/* read capabilities */
	snprintf(proc_fn, MAXPATHLEN, "/proc/%d/status", pid);

	proc_file = fopen(proc_fn, "r");
	if (!proc_file) {
		SYSERROR("Could not open %s", proc_fn);
		goto out_error;
	}

	found = 0;
	while (getline(&line, &line_bufsz, proc_file) != -1) {
		ret = sscanf(line, "CapBnd: %llx", &info->capability_mask);
		if (ret != EOF && ret > 0) {
			found = 1;
			break;
		}
	}

	fclose(proc_file);

	if (!found) {
		SYSERROR("Could not read capability bounding set from %s", proc_fn);
		errno = ENOENT;
		goto out_error;
	}

	/* read personality */
	snprintf(proc_fn, MAXPATHLEN, "/proc/%d/personality", pid);

	proc_file = fopen(proc_fn, "r");
	if (!proc_file) {
		SYSERROR("Could not open %s", proc_fn);
		goto out_error;
	}

	ret = fscanf(proc_file, "%lx", &info->personality);
	fclose(proc_file);

	if (ret == EOF || ret == 0) {
		SYSERROR("Could not read personality from %s", proc_fn);
		errno = ENOENT;
		goto out_error;
	}

	return info;

out_error:
	free(info);
	free(line);
	return NULL;
}

int lxc_attach_to_ns(pid_t pid)
{
	char path[MAXPATHLEN];
	char *ns[] = { "pid", "mnt", "net", "ipc", "uts" };
	const int size = sizeof(ns) / sizeof(char *);
	int fd[size];
	int i;

	snprintf(path, MAXPATHLEN, "/proc/%d/ns", pid);
	if (access(path, X_OK)) {
		ERROR("Does this kernel version support 'attach' ?");
		return -1;
	}

	for (i = 0; i < size; i++) {
		snprintf(path, MAXPATHLEN, "/proc/%d/ns/%s", pid, ns[i]);
		fd[i] = open(path, O_RDONLY);
		if (fd[i] < 0) {
			SYSERROR("failed to open '%s'", path);
			return -1;
		}
	}

	for (i = 0; i < size; i++) {
		if (setns(fd[i], 0)) {
			SYSERROR("failed to set namespace '%s'", ns[i]);
			return -1;
		}

		close(fd[i]);
	}

	return 0;
}

int lxc_attach_drop_privs(struct lxc_proc_context_info *ctx)
{
	int last_cap = lxc_caps_last_cap();
	int cap;

	for (cap = 0; cap <= last_cap; cap++) {
		if (ctx->capability_mask & (1LL << cap))
			continue;

		if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0)) {
			SYSERROR("failed to remove capability id %d", cap);
			return -1;
		}
	}

	return 0;
}

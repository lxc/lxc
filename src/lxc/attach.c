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

#if !HAVE_DECL_PR_CAPBSET_DROP
#define PR_CAPBSET_DROP 24
#endif

#include "namespace.h"
#include "log.h"
#include "attach.h"
#include "caps.h"
#include "cgroup.h"
#include "config.h"

#include "setns.h"

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
	char *line = NULL, *ptr, *ptr2;
	size_t line_bufsz = 0;
	int ret, found, l;
	int i;

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

	/* read cgroups */
	snprintf(proc_fn, MAXPATHLEN, "/proc/%d/cgroup", pid);

	proc_file = fopen(proc_fn, "r");
	if (!proc_file) {
		SYSERROR("Could not open %s", proc_fn);
		goto out_error;
	}

	/* we don't really know how many cgroup subsystems there are
	 * mounted, so we go through the whole file twice */
	i = 0;
	while (getline(&line, &line_bufsz, proc_file) != -1) {
		/* we assume that all lines containing at least two colons
		 * are valid */
		ptr = strchr(line, ':');
		if (ptr && strchr(ptr + 1, ':'))
			i++;
	}

	rewind(proc_file);

	info->cgroups = calloc(i, sizeof(*(info->cgroups)));
	info->cgroups_count = i;

	i = 0;
	while (getline(&line, &line_bufsz, proc_file) != -1 && i < info->cgroups_count) {
		/* format of the lines is:
		 * id:subsystems:path, where subsystems are separated by
		 * commas and each subsystem may also be of the form
		 * name=xxx if it describes a private named hierarchy
		 * we will ignore the id in the following */
		ptr = strchr(line, ':');
		ptr2 = ptr ? strchr(ptr + 1, ':') : NULL;

		/* ignore invalid lines */
		if (!ptr || !ptr2) continue;

		l = strlen(ptr2) - 1;
		if (ptr2[l] == '\n')
			ptr2[l] = '\0';

		info->cgroups[i].subsystems = strndup(ptr + 1, ptr2 - (ptr + 1));
		info->cgroups[i].cgroup = strdup(ptr2 + 1);

		i++;
	}

	free(line);
	fclose(proc_file);

	return info;

out_error:
	lxc_proc_free_context_info(info);
	free(line);
	return NULL;
}

void lxc_proc_free_context_info(struct lxc_proc_context_info *info)
{
	if (!info)
		return;

	if (info->cgroups) {
		int i;
		for (i = 0; i < info->cgroups_count; i++) {
			free(info->cgroups[i].subsystems);
			free(info->cgroups[i].cgroup);
		}
	}
	free(info->cgroups);
	free(info);
}

int lxc_attach_proc_to_cgroups(pid_t pid, struct lxc_proc_context_info *ctx)
{
	int i, ret;

	if (!ctx) {
		ERROR("No valid context supplied when asked to attach "
		      "process to cgroups.");
		return -1;
	}

	for (i = 0; i < ctx->cgroups_count; i++) {
		char *path;

		/* the kernel should return paths that start with '/' */
		if (ctx->cgroups[i].cgroup[0] != '/') {
			ERROR("For cgroup subsystem(s) %s the path '%s' does "
			      "not start with a '/'",
			      ctx->cgroups[i].subsystems,
			      ctx->cgroups[i].cgroup);
			return -1;
		}

		/* lxc_cgroup_path_get can process multiple subsystems */
		ret = lxc_cgroup_path_get(&path, ctx->cgroups[i].subsystems,
		                          &ctx->cgroups[i].cgroup[1]);
		if (ret)
			return -1;

		ret = lxc_cgroup_attach(path, pid);
		if (ret)
			return -1;
	}

	return 0;
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

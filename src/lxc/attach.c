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
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <linux/unistd.h>
#include <pwd.h>

#if !HAVE_DECL_PR_CAPBSET_DROP
#define PR_CAPBSET_DROP 24
#endif

#include "namespace.h"
#include "log.h"
#include "attach.h"
#include "caps.h"
#include "config.h"
#include "apparmor.h"

lxc_log_define(lxc_attach, lxc);

/* Define setns() if missing from the C library */
#ifndef HAVE_SETNS
static int setns(int fd, int nstype)
{
#ifdef __NR_setns
return syscall(__NR_setns, fd, nstype);
#else
errno = ENOSYS;
return -1;
#endif
}
#endif

/* Define unshare() if missing from the C library */
#ifndef HAVE_UNSHARE
static int unshare(int flags)
{
#ifdef __NR_unshare
return syscall(__NR_unshare, flags);
#else
errno = ENOSYS;
return -1;
#endif
}
#endif

/* Define getline() if missing from the C library */
#ifndef HAVE_GETLINE
#ifdef HAVE_FGETLN
#include <../include/getline.h>
#endif
#endif

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
	info->aa_profile = aa_get_profile(pid);

	return info;

out_error:
	free(info);
	free(line);
	return NULL;
}

int lxc_attach_to_ns(pid_t pid, int which)
{
	char path[MAXPATHLEN];
	/* according to <http://article.gmane.org/gmane.linux.kernel.containers.lxc.devel/1429>,
	 * the file for user namepsaces in /proc/$pid/ns will be called
	 * 'user' once the kernel supports it
	 */
	static char *ns[] = { "mnt", "pid", "uts", "ipc", "user", "net" };
	static int flags[] = {
		CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWUTS, CLONE_NEWIPC,
		CLONE_NEWUSER, CLONE_NEWNET
	};
	static const int size = sizeof(ns) / sizeof(char *);
	int fd[size];
	int i, j, saved_errno;


	snprintf(path, MAXPATHLEN, "/proc/%d/ns", pid);
	if (access(path, X_OK)) {
		ERROR("Does this kernel version support 'attach' ?");
		return -1;
	}

	for (i = 0; i < size; i++) {
		/* ignore if we are not supposed to attach to that
		 * namespace
		 */
		if (which != -1 && !(which & flags[i])) {
			fd[i] = -1;
			continue;
		}

		snprintf(path, MAXPATHLEN, "/proc/%d/ns/%s", pid, ns[i]);
		fd[i] = open(path, O_RDONLY);
		if (fd[i] < 0) {
			saved_errno = errno;

			/* close all already opened file descriptors before
			 * we return an error, so we don't leak them
			 */
			for (j = 0; j < i; j++)
				close(fd[j]);

			errno = saved_errno;
			SYSERROR("failed to open '%s'", path);
			return -1;
		}
	}

	for (i = 0; i < size; i++) {
		if (fd[i] >= 0 && setns(fd[i], 0) != 0) {
			saved_errno = errno;

			for (j = i; j < size; j++)
				close(fd[j]);

			errno = saved_errno;
			SYSERROR("failed to set namespace '%s'", ns[i]);
			return -1;
		}

		close(fd[i]);
	}

	return 0;
}

int lxc_attach_remount_sys_proc()
{
	int ret;

	ret = unshare(CLONE_NEWNS);
	if (ret < 0) {
		SYSERROR("failed to unshare mount namespace");
		return -1;
	}

	/* assume /proc is always mounted, so remount it */
	ret = umount2("/proc", MNT_DETACH);
	if (ret < 0) {
		SYSERROR("failed to unmount /proc");
		return -1;
	}

	ret = mount("none", "/proc", "proc", 0, NULL);
	if (ret < 0) {
		SYSERROR("failed to remount /proc");
		return -1;
	}

	/* try to umount /sys - if it's not a mount point,
	 * we'll get EINVAL, then we ignore it because it
	 * may not have been mounted in the first place
	 */
	ret = umount2("/sys", MNT_DETACH);
	if (ret < 0 && errno != EINVAL) {
		SYSERROR("failed to unmount /sys");
		return -1;
	} else if (ret == 0) {
		/* remount it */
		ret = mount("none", "/sys", "sysfs", 0, NULL);
		if (ret < 0) {
			SYSERROR("failed to remount /sys");
			return -1;
		}
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

int lxc_attach_set_environment(enum lxc_attach_env_policy_t policy, char** extra_env, char** extra_keep)
{
	/* TODO: implement extra_env, extra_keep
	 * Rationale:
	 *  - extra_env is an array of strings of the form
	 *    "VAR=VALUE", which are to be set (after clearing or not,
	 *    depending on the value of the policy variable)
	 *  - extra_keep is an array of strings of the form
	 *    "VAR", which are extra environment variables to be kept
	 *    around after clearing (if that is done, otherwise, the
	 *    remain anyway)
	 */
	(void) extra_env;
	(void) extra_keep;

	if (policy == LXC_ATTACH_CLEAR_ENV) {
		if (clearenv()) {
			SYSERROR("failed to clear environment");
			/* don't error out though */
		}
	}

	if (putenv("container=lxc")) {
		SYSERROR("failed to set environment variable");
		return -1;
	}

	return 0;
}

char *lxc_attach_getpwshell(uid_t uid)
{
	/* local variables */
	pid_t pid;
	int pipes[2];
	int ret;
	int fd;
	char *result = NULL;

	/* we need to fork off a process that runs the
	 * getent program, and we need to capture its
	 * output, so we use a pipe for that purpose
	 */
	ret = pipe(pipes);
	if (ret < 0)
		return NULL;

	pid = fork();
	if (pid < 0) {
		close(pipes[0]);
		close(pipes[1]);
		return NULL;
	}

	if (pid) {
		/* parent process */
		FILE *pipe_f;
		char *line = NULL;
		size_t line_bufsz = 0;
		int found = 0;
		int status;

		close(pipes[1]);

		pipe_f = fdopen(pipes[0], "r");
		while (getline(&line, &line_bufsz, pipe_f) != -1) {
			char *token;
			char *saveptr = NULL;
			long value;
			char *endptr = NULL;
			int i;

			/* if we already found something, just continue
			 * to read until the pipe doesn't deliver any more
			 * data, but don't modify the existing data
			 * structure
			 */
			if (found)
				continue;

			/* trim line on the right hand side */
			for (i = strlen(line); line && i > 0 && (line[i - 1] == '\n' || line[i - 1] == '\r'); --i)
				line[i - 1] = '\0';

			/* split into tokens: first user name */
			token = strtok_r(line, ":", &saveptr);
			if (!token)
				continue;
			/* next: dummy password field */
			token = strtok_r(NULL, ":", &saveptr);
			if (!token)
				continue;
			/* next: user id */
			token = strtok_r(NULL, ":", &saveptr);
			value = token ? strtol(token, &endptr, 10) : 0;
			if (!token || !endptr || *endptr || value == LONG_MIN || value == LONG_MAX)
				continue;
			/* dummy sanity check: user id matches */
			if ((uid_t) value != uid)
				continue;
			/* skip fields: gid, gecos, dir, go to next field 'shell' */
			for (i = 0; i < 4; i++) {
				token = strtok_r(NULL, ":", &saveptr);
				if (!token)
					break;
			}
			if (!token)
				continue;
			if (result)
				free(result);
			result = strdup(token);

			/* sanity check that there are no fields after that */
			token = strtok_r(NULL, ":", &saveptr);
			if (token)
				continue;

			found = 1;
		}

		free(line);
		fclose(pipe_f);
	again:
		if (waitpid(pid, &status, 0) < 0) {
			if (errno == EINTR)
				goto again;
			return NULL;
		}

		/* some sanity checks: if anything even hinted at going
		 * wrong: we can't be sure we have a valid result, so
		 * we assume we don't
		 */

		if (!WIFEXITED(status))
			return NULL;

		if (WEXITSTATUS(status) != 0)
			return NULL;

		if (!found)
			return NULL;

		return result;
	} else {
		/* child process */
		char uid_buf[32];
		char *arguments[] = {
			"getent",
			"passwd",
			uid_buf,
			NULL
		};

		close(pipes[0]);

		/* we want to capture stdout */
		dup2(pipes[1], 1);
		close(pipes[1]);

		/* get rid of stdin/stderr, so we try to associate it
		 * with /dev/null
		 */
		fd = open("/dev/null", O_RDWR);
		if (fd < 0) {
			close(0);
			close(2);
		} else {
			dup2(fd, 0);
			dup2(fd, 2);
			close(fd);
		}

		/* finish argument list */
		ret = snprintf(uid_buf, sizeof(uid_buf), "%ld", (long) uid);
		if (ret <= 0)
			exit(-1);

		/* try to run getent program */
		(void) execvp("getent", arguments);
		exit(-1);
	}
}

void lxc_attach_get_init_uidgid(uid_t* init_uid, gid_t* init_gid)
{
	FILE *proc_file;
	char proc_fn[MAXPATHLEN];
	char *line = NULL;
	size_t line_bufsz = 0;
	int ret;
	long value = -1;
	uid_t uid = (uid_t)-1;
	gid_t gid = (gid_t)-1;

	/* read capabilities */
	snprintf(proc_fn, MAXPATHLEN, "/proc/%d/status", 1);

	proc_file = fopen(proc_fn, "r");
	if (!proc_file)
		return;

	while (getline(&line, &line_bufsz, proc_file) != -1) {
		/* format is: real, effective, saved set user, fs
		 * we only care about real uid
		 */
		ret = sscanf(line, "Uid: %ld", &value);
		if (ret != EOF && ret > 0) {
			uid = (uid_t) value;
		} else {
			ret = sscanf(line, "Gid: %ld", &value);
			if (ret != EOF && ret > 0)
				gid = (gid_t) value;
		}
		if (uid != (uid_t)-1 && gid != (gid_t)-1)
			break;
	}

	fclose(proc_file);
	free(line);

	/* only override arguments if we found something */
	if (uid != (uid_t)-1)
		*init_uid = uid;
	if (gid != (gid_t)-1)
		*init_gid = gid;

	/* TODO: we should also parse supplementary groups and use
	 * setgroups() to set them */
}

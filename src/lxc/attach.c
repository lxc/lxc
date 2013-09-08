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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
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
#include <sys/socket.h>
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
#include "utils.h"
#include "commands.h"
#include "cgroup.h"

#if HAVE_SYS_PERSONALITY_H
#include <sys/personality.h>
#endif

#ifndef SOCK_CLOEXEC
#  define SOCK_CLOEXEC                02000000
#endif

lxc_log_define(lxc_attach, lxc);

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

	if (line)
		free(line);
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
		fd[i] = open(path, O_RDONLY | O_CLOEXEC);
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
	if (policy == LXC_ATTACH_CLEAR_ENV) {
		char **extra_keep_store = NULL;
		int path_kept = 0;

		if (extra_keep) {
			size_t count, i;

			for (count = 0; extra_keep[count]; count++);

			extra_keep_store = calloc(count, sizeof(char *));
			if (!extra_keep_store) {
				SYSERROR("failed to allocate memory for storing current "
				         "environment variable values that will be kept");
				return -1;
			}
			for (i = 0; i < count; i++) {
				char *v = getenv(extra_keep[i]);
				if (v) {
					extra_keep_store[i] = strdup(v);
					if (!extra_keep_store[i]) {
						SYSERROR("failed to allocate memory for storing current "
						         "environment variable values that will be kept");
						while (i > 0)
							free(extra_keep_store[--i]);
						free(extra_keep_store);
						return -1;
					}
					if (strcmp(extra_keep[i], "PATH") == 0)
						path_kept = 1;
				}
				/* calloc sets entire array to zero, so we don't
				 * need an else */
			}
		}

		if (clearenv()) {
			char **p;
			SYSERROR("failed to clear environment");
			if (extra_keep_store) {
				for (p = extra_keep_store; *p; p++)
					free(*p);
				free(extra_keep_store);
			}
			return -1;
		}

		if (extra_keep_store) {
			size_t i;
			for (i = 0; extra_keep[i]; i++) {
				if (extra_keep_store[i])
					setenv(extra_keep[i], extra_keep_store[i], 1);
				free(extra_keep_store[i]);
			}
			free(extra_keep_store);
		}

		/* always set a default path; shells and execlp tend
		 * to be fine without it, but there is a disturbing
		 * number of C programs out there that just assume
		 * that getenv("PATH") is never NULL and then die a
		 * painful segfault death. */
		if (!path_kept) {
#ifdef HAVE_CONFSTR
			size_t n;
			char *path_env;

			n = confstr(_CS_PATH, NULL, 0);
			path_env = malloc(n);
			if (path_env) {
				confstr(_CS_PATH, path_env, n);
				setenv("PATH", path_env, 1);
				free(path_env);
			}
			/* don't error out, this is just an extra service */
#else
			setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1);
#endif
		}
	}

	if (putenv("container=lxc")) {
		SYSERROR("failed to set environment variable");
		return -1;
	}

	/* set extra environment variables */
	if (extra_env) {
		for (; *extra_env; extra_env++) {
			/* duplicate the string, just to be on
			 * the safe side, because putenv does not
			 * do it for us */
			char *p = strdup(*extra_env);
			/* we just assume the user knows what they
			 * are doing, so we don't do any checks */
			if (!p) {
				SYSERROR("failed to allocate memory for additional environment "
				         "variables");
				return -1;
			}
			putenv(p);
		}
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
			for (i = strlen(line); i > 0 && (line[i - 1] == '\n' || line[i - 1] == '\r'); --i)
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

struct attach_clone_payload {
	int ipc_socket;
	lxc_attach_options_t* options;
	struct lxc_proc_context_info* init_ctx;
	lxc_attach_exec_t exec_function;
	void* exec_payload;
};

static int attach_child_main(void* data);

/* help the optimizer along if it doesn't know that exit always exits */
#define rexit(c)  do { int __c = (c); exit(__c); return __c; } while(0)

/* define default options if no options are supplied by the user */
static lxc_attach_options_t attach_static_default_options = LXC_ATTACH_OPTIONS_DEFAULT;

int lxc_attach(const char* name, const char* lxcpath, lxc_attach_exec_t exec_function, void* exec_payload, lxc_attach_options_t* options, pid_t* attached_process)
{
	int ret, status;
	pid_t init_pid, pid, attached_pid;
	struct lxc_proc_context_info *init_ctx;
	char* cwd;
	char* new_cwd;
	int ipc_sockets[2];

	if (!options)
		options = &attach_static_default_options;

	init_pid = lxc_cmd_get_init_pid(name, lxcpath);
	if (init_pid < 0) {
		ERROR("failed to get the init pid");
		return -1;
	}

	init_ctx = lxc_proc_get_context_info(init_pid);
	if (!init_ctx) {
		ERROR("failed to get context of the init process, pid = %ld", (long)init_pid);
		return -1;
	}

	cwd = getcwd(NULL, 0);

	/* determine which namespaces the container was created with
	 * by asking lxc-start, if necessary
	 */
	if (options->namespaces == -1) {
		options->namespaces = lxc_cmd_get_clone_flags(name, lxcpath);
		/* call failed */
		if (options->namespaces == -1) {
			ERROR("failed to automatically determine the "
			      "namespaces which the container unshared");
			free(cwd);
			free(init_ctx->aa_profile);
			free(init_ctx);
			return -1;
		}
	}

	/* create a socket pair for IPC communication; set SOCK_CLOEXEC in order
	 * to make sure we don't irritate other threads that want to fork+exec away
	 *
	 * IMPORTANT: if the initial process is multithreaded and another call
	 * just fork()s away without exec'ing directly after, the socket fd will
	 * exist in the forked process from the other thread and any close() in
	 * our own child process will not really cause the socket to close properly,
	 * potentiall causing the parent to hang.
	 *
	 * For this reason, while IPC is still active, we have to use shutdown()
	 * if the child exits prematurely in order to signal that the socket
	 * is closed and cannot assume that the child exiting will automatically
	 * do that.
	 *
	 * IPC mechanism: (X is receiver)
	 *   initial process        intermediate          attached
	 *        X           <---  send pid of
	 *                          attached proc,
	 *                          then exit
	 *    send 0 ------------------------------------>    X
	 *                                              [do initialization]
	 *        X  <------------------------------------  send 1
	 *   [add to cgroup, ...]
	 *    send 2 ------------------------------------>    X
	 *   close socket                                 close socket
	 *                                                run program
	 */
	ret = socketpair(PF_LOCAL, SOCK_STREAM | SOCK_CLOEXEC, 0, ipc_sockets);
	if (ret < 0) {
		SYSERROR("could not set up required IPC mechanism for attaching");
		free(cwd);
		free(init_ctx->aa_profile);
		free(init_ctx);
		return -1;
	}

	/* create intermediate subprocess, three reasons:
	 *       1. runs all pthread_atfork handlers and the
	 *          child will no longer be threaded
	 *          (we can't properly setns() in a threaded process)
	 *       2. we can't setns() in the child itself, since
	 *          we want to make sure we are properly attached to
	 *          the pidns
	 *       3. also, the initial thread has to put the attached
	 *          process into the cgroup, which we can only do if
	 *          we didn't already setns() (otherwise, user
	 *          namespaces will hate us)
	 */
	pid = fork();

	if (pid < 0) {
		SYSERROR("failed to create first subprocess");
		free(cwd);
		free(init_ctx->aa_profile);
		free(init_ctx);
		return -1;
	}

	if (pid) {
		pid_t to_cleanup_pid = pid;
		int expected = 0;

		/* inital thread, we close the socket that is for the
		 * subprocesses
		 */
		close(ipc_sockets[1]);
		free(cwd);

		/* get pid from intermediate process */
		ret = lxc_read_nointr_expect(ipc_sockets[0], &attached_pid, sizeof(attached_pid), NULL);
		if (ret <= 0) {
			if (ret != 0)
				ERROR("error using IPC to receive pid of attached process");
			goto cleanup_error;
		}

		/* reap intermediate process */
		ret = wait_for_pid(pid);
		if (ret < 0)
			goto cleanup_error;

		/* we will always have to reap the grandchild now */
		to_cleanup_pid = attached_pid;

		/* tell attached process it may start initializing */
		status = 0;
		ret = lxc_write_nointr(ipc_sockets[0], &status, sizeof(status));
		if (ret <= 0) {
			ERROR("error using IPC to notify attached process for initialization (0)");
			goto cleanup_error;
		}

		/* wait for the attached process to finish initializing */
		expected = 1;
		ret = lxc_read_nointr_expect(ipc_sockets[0], &status, sizeof(status), &expected);
		if (ret <= 0) {
			if (ret != 0)
				ERROR("error using IPC to receive notification from attached process (1)");
			goto cleanup_error;
		}

		/* attach to cgroup, if requested */
		if (options->attach_flags & LXC_ATTACH_MOVE_TO_CGROUP) {
			struct cgroup_meta_data *meta_data;
			struct cgroup_process_info *container_info;

			meta_data = lxc_cgroup_load_meta();
			if (!meta_data) {
				ERROR("could not move attached process %ld to cgroup of container", (long)attached_pid);
				goto cleanup_error;
			}

			container_info = lxc_cgroup_get_container_info(name, lxcpath, meta_data);
			lxc_cgroup_put_meta(meta_data);
			if (!container_info) {
				ERROR("could not move attached process %ld to cgroup of container", (long)attached_pid);
				goto cleanup_error;
			}

			ret = lxc_cgroup_enter(container_info, attached_pid, false);
			lxc_cgroup_process_info_free(container_info);
			if (ret < 0) {
				ERROR("could not move attached process %ld to cgroup of container", (long)attached_pid);
				goto cleanup_error;
			}
		}

		/* tell attached process we're done */
		status = 2;
		ret = lxc_write_nointr(ipc_sockets[0], &status, sizeof(status));
		if (ret <= 0) {
			ERROR("error using IPC to notify attached process for initialization (2)");
			goto cleanup_error;
		}

		/* now shut down communication with child, we're done */
		shutdown(ipc_sockets[0], SHUT_RDWR);
		close(ipc_sockets[0]);
		free(init_ctx->aa_profile);
		free(init_ctx);

		/* we're done, the child process should now execute whatever
		 * it is that the user requested. The parent can now track it
		 * with waitpid() or similar.
		 */

		*attached_process = attached_pid;
		return 0;

	cleanup_error:
		/* first shut down the socket, then wait for the pid,
		 * otherwise the pid we're waiting for may never exit
		 */
		shutdown(ipc_sockets[0], SHUT_RDWR);
		close(ipc_sockets[0]);
		if (to_cleanup_pid)
			(void) wait_for_pid(to_cleanup_pid);
		free(init_ctx->aa_profile);
		free(init_ctx);
		return -1;
	}

	/* first subprocess begins here, we close the socket that is for the
	 * initial thread
	 */
	close(ipc_sockets[0]);

	/* attach now, create another subprocess later, since pid namespaces
	 * only really affect the children of the current process
	 */
	ret = lxc_attach_to_ns(init_pid, options->namespaces);
	if (ret < 0) {
		ERROR("failed to enter the namespace");
		shutdown(ipc_sockets[1], SHUT_RDWR);
		rexit(-1);
	}

	/* attach succeeded, try to cwd */
	if (options->initial_cwd)
		new_cwd = options->initial_cwd;
	else
		new_cwd = cwd;
	ret = chdir(new_cwd);
	if (ret < 0)
		WARN("could not change directory to '%s'", new_cwd);
	free(cwd);

	/* now create the real child process */
	{
		struct attach_clone_payload payload = {
			.ipc_socket = ipc_sockets[1],
			.options = options,
			.init_ctx = init_ctx,
			.exec_function = exec_function,
			.exec_payload = exec_payload
		};
		/* We use clone_parent here to make this subprocess a direct child of
		 * the initial process. Then this intermediate process can exit and
		 * the parent can directly track the attached process.
		 */
		pid = lxc_clone(attach_child_main, &payload, CLONE_PARENT);
	}

	/* shouldn't happen, clone() should always return positive pid */
	if (pid <= 0) {
		SYSERROR("failed to create subprocess");
		shutdown(ipc_sockets[1], SHUT_RDWR);
		rexit(-1);
	}

	/* tell grandparent the pid of the pid of the newly created child */
	ret = lxc_write_nointr(ipc_sockets[1], &pid, sizeof(pid));
	if (ret != sizeof(pid)) {
		/* if this really happens here, this is very unfortunate, since the
		 * parent will not know the pid of the attached process and will
		 * not be able to wait for it (and we won't either due to CLONE_PARENT)
		 * so the parent won't be able to reap it and the attached process
		 * will remain a zombie
		 */
		ERROR("error using IPC to notify main process of pid of the attached process");
		shutdown(ipc_sockets[1], SHUT_RDWR);
		rexit(-1);
	}

	/* the rest is in the hands of the initial and the attached process */
	rexit(0);
}

int attach_child_main(void* data)
{
	struct attach_clone_payload* payload = (struct attach_clone_payload*)data;
	int ipc_socket = payload->ipc_socket;
	lxc_attach_options_t* options = payload->options;
	struct lxc_proc_context_info* init_ctx = payload->init_ctx;
#if HAVE_SYS_PERSONALITY_H
	long new_personality;
#endif
	int ret;
	int status;
	int expected;
	long flags;
	int fd;
	uid_t new_uid;
	gid_t new_gid;

	/* wait for the initial thread to signal us that it's ready
	 * for us to start initializing
	 */
	expected = 0;
	status = -1;
	ret = lxc_read_nointr_expect(ipc_socket, &status, sizeof(status), &expected);
	if (ret <= 0) {
		ERROR("error using IPC to receive notification from initial process (0)");
		shutdown(ipc_socket, SHUT_RDWR);
		rexit(-1);
	}

	/* load apparmor profile */
	if ((options->namespaces & CLONE_NEWNS) && (options->attach_flags & LXC_ATTACH_APPARMOR)) {
		ret = attach_apparmor(init_ctx->aa_profile);
		if (ret < 0) {
			shutdown(ipc_socket, SHUT_RDWR);
			rexit(-1);
		}
	}

	/* A description of the purpose of this functionality is
	 * provided in the lxc-attach(1) manual page. We have to
	 * remount here and not in the parent process, otherwise
	 * /proc may not properly reflect the new pid namespace.
	 */
	if (!(options->namespaces & CLONE_NEWNS) && (options->attach_flags & LXC_ATTACH_REMOUNT_PROC_SYS)) {
		ret = lxc_attach_remount_sys_proc();
		if (ret < 0) {
			shutdown(ipc_socket, SHUT_RDWR);
			rexit(-1);
		}
	}

	/* now perform additional attachments*/
#if HAVE_SYS_PERSONALITY_H
	if (options->personality < 0)
		new_personality = init_ctx->personality;
	else
		new_personality = options->personality;

	if (options->attach_flags & LXC_ATTACH_SET_PERSONALITY) {
		ret = personality(new_personality);
		if (ret < 0) {
			SYSERROR("could not ensure correct architecture");
			shutdown(ipc_socket, SHUT_RDWR);
			rexit(-1);
		}
	}
#endif

	if (options->attach_flags & LXC_ATTACH_DROP_CAPABILITIES) {
		ret = lxc_attach_drop_privs(init_ctx);
		if (ret < 0) {
			ERROR("could not drop privileges");
			shutdown(ipc_socket, SHUT_RDWR);
			rexit(-1);
		}
	}

	/* always set the environment (specify (LXC_ATTACH_KEEP_ENV, NULL, NULL) if you want this to be a no-op) */
	ret = lxc_attach_set_environment(options->env_policy, options->extra_env_vars, options->extra_keep_env);
	if (ret < 0) {
		ERROR("could not set initial environment for attached process");
		shutdown(ipc_socket, SHUT_RDWR);
		rexit(-1);
	}

	/* set user / group id */
	new_uid = 0;
	new_gid = 0;
	/* ignore errors, we will fall back to root in that case
	 * (/proc was not mounted etc.)
	 */
	if (options->namespaces & CLONE_NEWUSER)
		lxc_attach_get_init_uidgid(&new_uid, &new_gid);

	if (options->uid != (uid_t)-1)
		new_uid = options->uid;
	if (options->gid != (gid_t)-1)
		new_gid = options->gid;

	/* try to set the uid/gid combination */
	if ((new_gid != 0 || options->namespaces & CLONE_NEWUSER) && setgid(new_gid)) {
		SYSERROR("switching to container gid");
		shutdown(ipc_socket, SHUT_RDWR);
		rexit(-1);
	}
	if ((new_uid != 0 || options->namespaces & CLONE_NEWUSER) && setuid(new_uid)) {
		SYSERROR("switching to container uid");
		shutdown(ipc_socket, SHUT_RDWR);
		rexit(-1);
	}

	/* tell initial process it may now put us into the cgroups */
	status = 1;
	ret = lxc_write_nointr(ipc_socket, &status, sizeof(status));
	if (ret != sizeof(status)) {
		ERROR("error using IPC to notify initial process for initialization (1)");
		shutdown(ipc_socket, SHUT_RDWR);
		rexit(-1);
	}

	/* wait for the initial thread to signal us that it has done
	 * everything for us when it comes to cgroups etc.
	 */
	expected = 2;
	status = -1;
	ret = lxc_read_nointr_expect(ipc_socket, &status, sizeof(status), &expected);
	if (ret <= 0) {
		ERROR("error using IPC to receive final notification from initial process (2)");
		shutdown(ipc_socket, SHUT_RDWR);
		rexit(-1);
	}

	shutdown(ipc_socket, SHUT_RDWR);
	close(ipc_socket);
	free(init_ctx->aa_profile);
	free(init_ctx);

	/* The following is done after the communication socket is
	 * shut down. That way, all errors that might (though
	 * unlikely) occur up until this point will have their messages
	 * printed to the original stderr (if logging is so configured)
	 * and not the fd the user supplied, if any.
	 */

	/* fd handling for stdin, stdout and stderr;
	 * ignore errors here, user may want to make sure
	 * the fds are closed, for example */
	if (options->stdin_fd >= 0 && options->stdin_fd != 0)
		dup2(options->stdin_fd, 0);
	if (options->stdout_fd >= 0 && options->stdout_fd != 1)
		dup2(options->stdout_fd, 1);
	if (options->stderr_fd >= 0 && options->stderr_fd != 2)
		dup2(options->stderr_fd, 2);

	/* close the old fds */
	if (options->stdin_fd > 2)
		close(options->stdin_fd);
	if (options->stdout_fd > 2)
		close(options->stdout_fd);
	if (options->stderr_fd > 2)
		close(options->stderr_fd);

	/* try to remove CLOEXEC flag from stdin/stdout/stderr,
	 * but also here, ignore errors */
	for (fd = 0; fd <= 2; fd++) {
		flags = fcntl(fd, F_GETFL);
		if (flags < 0)
			continue;
		if (flags & FD_CLOEXEC)
			fcntl(fd, F_SETFL, flags & ~FD_CLOEXEC);
	}

	/* we're done, so we can now do whatever the user intended us to do */
	rexit(payload->exec_function(payload->exec_payload));
}

int lxc_attach_run_command(void* payload)
{
	lxc_attach_command_t* cmd = (lxc_attach_command_t*)payload;

	execvp(cmd->program, cmd->argv);
	SYSERROR("failed to exec '%s'", cmd->program);
	return -1;
}

int lxc_attach_run_shell(void* payload)
{
	uid_t uid;
	struct passwd *passwd;
	char *user_shell;

	/* ignore payload parameter */
	(void)payload;

	uid = getuid();
	passwd = getpwuid(uid);

	/* this probably happens because of incompatible nss
	 * implementations in host and container (remember, this
	 * code is still using the host's glibc but our mount
	 * namespace is in the container)
	 * we may try to get the information by spawning a
	 * [getent passwd uid] process and parsing the result
	 */
	if (!passwd)
		user_shell = lxc_attach_getpwshell(uid);
	else
		user_shell = passwd->pw_shell;

	if (user_shell)
		execlp(user_shell, user_shell, NULL);

	/* executed if either no passwd entry or execvp fails,
	 * we will fall back on /bin/sh as a default shell
	 */
	execlp("/bin/sh", "/bin/sh", NULL);
	SYSERROR("failed to exec shell");
	return -1;
}

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
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/unistd.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#include <lxc/lxccontainer.h>

#ifndef HAVE_DECL_PR_CAPBSET_DROP
#define PR_CAPBSET_DROP 24
#endif

#ifndef HAVE_DECL_PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif

#ifndef HAVE_DECL_PR_GET_NO_NEW_PRIVS
#define PR_GET_NO_NEW_PRIVS 39
#endif

#include "af_unix.h"
#include "attach.h"
#include "caps.h"
#include "cgroup.h"
#include "commands.h"
#include "conf.h"
#include "config.h"
#include "confile.h"
#include "log.h"
#include "lsm/lsm.h"
#include "lxclock.h"
#include "lxcseccomp.h"
#include "mainloop.h"
#include "namespace.h"
#include "terminal.h"
#include "utils.h"

#if HAVE_SYS_PERSONALITY_H
#include <sys/personality.h>
#endif

#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 02000000
#endif

#ifndef MS_REC
#define MS_REC 16384
#endif

#ifndef MS_SLAVE
#define MS_SLAVE (1 << 19)
#endif

lxc_log_define(lxc_attach, lxc);

/* /proc/pid-to-str/status\0 = (5 + 21 + 7 + 1) */
#define __PROC_STATUS_LEN (5 + (LXC_NUMSTRLEN64) + 7 + 1)
static struct lxc_proc_context_info *lxc_proc_get_context_info(pid_t pid)
{
	int ret;
	bool found;
	FILE *proc_file;
	char proc_fn[__PROC_STATUS_LEN];
	size_t line_bufsz = 0;
	char *line = NULL;
	struct lxc_proc_context_info *info = NULL;

	/* Read capabilities. */
	ret = snprintf(proc_fn, __PROC_STATUS_LEN, "/proc/%d/status", pid);
	if (ret < 0 || ret >= __PROC_STATUS_LEN)
		goto on_error;

	proc_file = fopen(proc_fn, "r");
	if (!proc_file) {
		SYSERROR("Could not open %s.", proc_fn);
		goto on_error;
	}

	info = calloc(1, sizeof(*info));
	if (!info) {
		SYSERROR("Could not allocate memory.");
		fclose(proc_file);
		return NULL;
	}

	found = false;
	while (getline(&line, &line_bufsz, proc_file) != -1) {
		ret = sscanf(line, "CapBnd: %llx", &info->capability_mask);
		if (ret != EOF && ret == 1) {
			found = true;
			break;
		}
	}

	free(line);
	fclose(proc_file);

	if (!found) {
		SYSERROR("Could not read capability bounding set from %s.",
			 proc_fn);
		errno = ENOENT;
		goto on_error;
	}

	info->lsm_label = lsm_process_label_get(pid);
	info->ns_inherited = 0;
	memset(info->ns_fd, -1, sizeof(int) * LXC_NS_MAX);

	return info;

on_error:
	free(info);
	return NULL;
}

static inline void lxc_proc_close_ns_fd(struct lxc_proc_context_info *ctx)
{
	int i;

	for (i = 0; i < LXC_NS_MAX; i++) {
		if (ctx->ns_fd[i] < 0)
			continue;
		close(ctx->ns_fd[i]);
		ctx->ns_fd[i] = -EBADF;
	}
}

static void lxc_proc_put_context_info(struct lxc_proc_context_info *ctx)
{
	free(ctx->lsm_label);
	ctx->lsm_label = NULL;

	if (ctx->container) {
		lxc_container_put(ctx->container);
		ctx->container = NULL;
	}

	lxc_proc_close_ns_fd(ctx);
	free(ctx);
	ctx = NULL;
}

/**
 * in_same_namespace - Check whether two processes are in the same namespace.
 * @pid1 - PID of the first process.
 * @pid2 - PID of the second process.
 * @ns   - Name of the namespace to check. Must correspond to one of the names
 *         for the namespaces as shown in /proc/<pid/ns/
 *
 * If the two processes are not in the same namespace returns an fd to the
 * namespace of the second process identified by @pid2. If the two processes are
 * in the same namespace returns -EINVAL, -1 if an error occurred.
 */
static int in_same_namespace(pid_t pid1, pid_t pid2, const char *ns)
{
	int ns_fd1 = -1, ns_fd2 = -1, ret = -1;
	struct stat ns_st1, ns_st2;

	ns_fd1 = lxc_preserve_ns(pid1, ns);
	if (ns_fd1 < 0) {
		/* The kernel does not support this namespace. This is not an
		 * error.
		 */
		if (errno == ENOENT)
			return -EINVAL;

		goto out;
	}

	ns_fd2 = lxc_preserve_ns(pid2, ns);
	if (ns_fd2 < 0)
		goto out;

	ret = fstat(ns_fd1, &ns_st1);
	if (ret < 0)
		goto out;

	ret = fstat(ns_fd2, &ns_st2);
	if (ret < 0)
		goto out;

	/* processes are in the same namespace */
	ret = -EINVAL;
	if ((ns_st1.st_dev == ns_st2.st_dev ) && (ns_st1.st_ino == ns_st2.st_ino))
		goto out;

	/* processes are in different namespaces */
	ret = ns_fd2;
	ns_fd2 = -1;

out:

	if (ns_fd1 >= 0)
		close(ns_fd1);
	if (ns_fd2 >= 0)
		close(ns_fd2);

	return ret;
}

static int lxc_attach_to_ns(pid_t pid, struct lxc_proc_context_info *ctx)
{
	int i, ret;

	for (i = 0; i < LXC_NS_MAX; i++) {
		if (ctx->ns_fd[i] < 0)
			continue;

		ret = setns(ctx->ns_fd[i], ns_info[i].clone_flag);
		if (ret < 0) {
			SYSERROR("Failed to attach to %s namespace of %d",
				 ns_info[i].proc_name, pid);
			return -1;
		}

		DEBUG("Attached to %s namespace of %d", ns_info[i].proc_name, pid);
	}

	return 0;
}

static int lxc_attach_remount_sys_proc(void)
{
	int ret;

	ret = unshare(CLONE_NEWNS);
	if (ret < 0) {
		SYSERROR("Failed to unshare mount namespace.");
		return -1;
	}

	if (detect_shared_rootfs()) {
		if (mount(NULL, "/", NULL, MS_SLAVE | MS_REC, NULL)) {
			SYSERROR("Failed to make / rslave.");
			ERROR("Continuing...");
		}
	}

	/* Assume /proc is always mounted, so remount it. */
	ret = umount2("/proc", MNT_DETACH);
	if (ret < 0) {
		SYSERROR("Failed to unmount /proc.");
		return -1;
	}

	ret = mount("none", "/proc", "proc", 0, NULL);
	if (ret < 0) {
		SYSERROR("Failed to remount /proc.");
		return -1;
	}

	/* Try to umount /sys. If it's not a mount point, we'll get EINVAL, then
	 * we ignore it because it may not have been mounted in the first place.
	 */
	ret = umount2("/sys", MNT_DETACH);
	if (ret < 0 && errno != EINVAL) {
		SYSERROR("Failed to unmount /sys.");
		return -1;
	} else if (ret == 0) {
		/* Remount it. */
		ret = mount("none", "/sys", "sysfs", 0, NULL);
		if (ret < 0) {
			SYSERROR("Failed to remount /sys.");
			return -1;
		}
	}

	return 0;
}

static int lxc_attach_drop_privs(struct lxc_proc_context_info *ctx)
{
	int cap, last_cap;

	last_cap = lxc_caps_last_cap();
	for (cap = 0; cap <= last_cap; cap++) {
		if (ctx->capability_mask & (1LL << cap))
			continue;

		if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0)) {
			SYSERROR("Failed to drop capability %d", cap);
			return -1;
		}
		TRACE("Dropped capability %d", cap);
	}

	return 0;
}

static int lxc_attach_set_environment(struct lxc_proc_context_info *init_ctx,
				      enum lxc_attach_env_policy_t policy,
				      char **extra_env, char **extra_keep)
{
	int ret;
	struct lxc_list *iterator;

	if (policy == LXC_ATTACH_CLEAR_ENV) {
		int path_kept = 0;
		char **extra_keep_store = NULL;

		if (extra_keep) {
			size_t count, i;

			for (count = 0; extra_keep[count]; count++)
				;

			extra_keep_store = calloc(count, sizeof(char *));
			if (!extra_keep_store)
				return -1;

			for (i = 0; i < count; i++) {
				char *v = getenv(extra_keep[i]);
				if (v) {
					extra_keep_store[i] = strdup(v);
					if (!extra_keep_store[i]) {
						while (i > 0)
							free(extra_keep_store[--i]);
						free(extra_keep_store);
						return -1;
					}

					if (strcmp(extra_keep[i], "PATH") == 0)
						path_kept = 1;
				}
			}
		}

		if (clearenv()) {
			if (extra_keep_store) {
				char **p;

				for (p = extra_keep_store; *p; p++)
					free(*p);

				free(extra_keep_store);
			}

			SYSERROR("Failed to clear environment");
			return -1;
		}

		if (extra_keep_store) {
			size_t i;

			for (i = 0; extra_keep[i]; i++) {
				if (extra_keep_store[i]) {
					ret = setenv(extra_keep[i], extra_keep_store[i], 1);
					if (ret < 0)
						WARN("%s - Failed to set environment variable", strerror(errno));
				}
				free(extra_keep_store[i]);
			}
			free(extra_keep_store);
		}

		/* Always set a default path; shells and execlp tend to be fine
		 * without it, but there is a disturbing number of C programs
		 * out there that just assume that getenv("PATH") is never NULL
		 * and then die a painful segfault death.
		 */
		if (!path_kept) {
			ret = setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1);
			if (ret < 0)
				WARN("%s - Failed to set environment variable", strerror(errno));
		}
	}

	ret = putenv("container=lxc");
	if (ret < 0) {
		WARN("%s - Failed to set environment variable", strerror(errno));
		return -1;
	}

	/* Set container environment variables.*/
	if (init_ctx && init_ctx->container && init_ctx->container->lxc_conf) {
		lxc_list_for_each(iterator, &init_ctx->container->lxc_conf->environment) {
			char *env_tmp;

			env_tmp = strdup((char *)iterator->elem);
			if (!env_tmp)
				return -1;

			ret = putenv(env_tmp);
			if (ret < 0) {
				SYSERROR("Failed to set environment variable: %s", (char *)iterator->elem);
				return -1;
			}
		}
	}

	/* Set extra environment variables. */
	if (extra_env) {
		for (; *extra_env; extra_env++) {
			char *p;
			/* We just assume the user knows what they are doing, so
			 * we don't do any checks.
			 */
			p = strdup(*extra_env);
			if (!p)
				return -1;

			ret = putenv(p);
			if (ret < 0)
				WARN("%s - Failed to set environment variable", strerror(errno));
		}
	}

	return 0;
}

static char *lxc_attach_getpwshell(uid_t uid)
{
	int fd, ret;
	pid_t pid;
	int pipes[2];
	char *result = NULL;

	/* We need to fork off a process that runs the getent program, and we
	 * need to capture its output, so we use a pipe for that purpose.
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
		int status;
		FILE *pipe_f;
		int found = 0;
		size_t line_bufsz = 0;
		char *line = NULL;

		close(pipes[1]);

		pipe_f = fdopen(pipes[0], "r");
		while (getline(&line, &line_bufsz, pipe_f) != -1) {
			int i;
			long value;
			char *token;
			char *endptr = NULL, *saveptr = NULL;

			/* If we already found something, just continue to read
			 * until the pipe doesn't deliver any more data, but
			 * don't modify the existing data structure.
			 */
			if (found)
				continue;

			/* Trim line on the right hand side. */
			for (i = strlen(line); i > 0 && (line[i - 1] == '\n' || line[i - 1] == '\r'); --i)
				line[i - 1] = '\0';

			/* Split into tokens: first: user name. */
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
			free(result);
			result = strdup(token);

			/* Sanity check that there are no fields after that. */
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
			free(result);
			return NULL;
		}

		/* Some sanity checks. If anything even hinted at going wrong,
		 * we can't be sure we have a valid result, so we assume we
		 * don't.
		 */

		if (!WIFEXITED(status)) {
			free(result);
			return NULL;
		}

		if (WEXITSTATUS(status) != 0) {
			free(result);
			return NULL;
		}

		if (!found) {
			free(result);
			return NULL;
		}

		return result;
	} else {
		char uid_buf[32];
		char *arguments[] = {
			"getent",
			"passwd",
			uid_buf,
			NULL
		};

		close(pipes[0]);

		/* We want to capture stdout. */
		dup2(pipes[1], 1);
		close(pipes[1]);

		/* Get rid of stdin/stderr, so we try to associate it with
		 * /dev/null.
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

		/* Finish argument list. */
		ret = snprintf(uid_buf, sizeof(uid_buf), "%ld", (long) uid);
		if (ret <= 0)
			exit(-1);

		/* Try to run getent program. */
		(void) execvp("getent", arguments);
		exit(-1);
	}
}

static void lxc_attach_get_init_uidgid(uid_t *init_uid, gid_t *init_gid)
{
	FILE *proc_file;
	char proc_fn[__PROC_STATUS_LEN];
	int ret;
	char *line = NULL;
	size_t line_bufsz = 0;
	long value = -1;
	uid_t uid = (uid_t)-1;
	gid_t gid = (gid_t)-1;

	/* Read capabilities. */
	snprintf(proc_fn, __PROC_STATUS_LEN, "/proc/%d/status", 1);

	proc_file = fopen(proc_fn, "r");
	if (!proc_file)
		return;

	while (getline(&line, &line_bufsz, proc_file) != -1) {
		/* Format is: real, effective, saved set user, fs we only care
		 * about real uid.
		 */
		ret = sscanf(line, "Uid: %ld", &value);
		if (ret != EOF && ret == 1) {
			uid = (uid_t)value;
		} else {
			ret = sscanf(line, "Gid: %ld", &value);
			if (ret != EOF && ret == 1)
				gid = (gid_t)value;
		}
		if (uid != (uid_t)-1 && gid != (gid_t)-1)
			break;
	}

	fclose(proc_file);
	free(line);

	/* Only override arguments if we found something. */
	if (uid != (uid_t)-1)
		*init_uid = uid;
	if (gid != (gid_t)-1)
		*init_gid = gid;

	/* TODO: we should also parse supplementary groups and use
	 * setgroups() to set them.
	 */
}

/* Help the optimizer along if it doesn't know that exit always exits. */
#define rexit(c)                                                               \
	do {                                                                   \
		int __c = (c);                                                 \
		_exit(__c);                                                    \
		return __c;                                                    \
	} while (0)

/* Define default options if no options are supplied by the user. */
static lxc_attach_options_t attach_static_default_options = LXC_ATTACH_OPTIONS_DEFAULT;

static bool fetch_seccomp(struct lxc_container *c,
			  lxc_attach_options_t *options)
{
	char *path;

	if (!(options->namespaces & CLONE_NEWNS) ||
	    !(options->attach_flags & LXC_ATTACH_LSM)) {
		free(c->lxc_conf->seccomp);
		c->lxc_conf->seccomp = NULL;
		return true;
	}

	/* Remove current setting. */
	if (!c->set_config_item(c, "lxc.seccomp", "") &&
	    !c->set_config_item(c, "lxc.seccomp.profile", "")) {
		return false;
	}

	/* Fetch the current profile path over the cmd interface. */
	path = c->get_running_config_item(c, "lxc.seccomp.profile");
	if (!path) {
		INFO("Failed to get running config item for lxc.seccomp.profile");
		path = c->get_running_config_item(c, "lxc.seccomp");
	}
	if (!path) {
		INFO("Failed to get running config item for lxc.seccomp");
		return true;
	}

	/* Copy the value into the new lxc_conf. */
	if (!c->set_config_item(c, "lxc.seccomp.profile", path)) {
		free(path);
		return false;
	}
	free(path);

	/* Attempt to parse the resulting config. */
	if (lxc_read_seccomp_config(c->lxc_conf) < 0) {
		ERROR("Error reading seccomp policy.");
		return false;
	}

	INFO("Retrieved seccomp policy.");
	return true;
}

static bool no_new_privs(struct lxc_container *c, lxc_attach_options_t *options)
{
	char *val;

	/* Remove current setting. */
	if (!c->set_config_item(c, "lxc.no_new_privs", ""))
		return false;

	/* Retrieve currently active setting. */
	val = c->get_running_config_item(c, "lxc.no_new_privs");
	if (!val) {
		INFO("Failed to get running config item for lxc.no_new_privs.");
		return false;
	}

	/* Set currently active setting. */
	if (!c->set_config_item(c, "lxc.no_new_privs", val)) {
		free(val);
		return false;
	}
	free(val);

	return true;
}

static signed long get_personality(const char *name, const char *lxcpath)
{
	char *p;
	signed long ret;

	p = lxc_cmd_get_config_item(name, "lxc.arch", lxcpath);
	if (!p)
		return -1;

	ret = lxc_config_parse_arch(p);
	free(p);

	return ret;
}

struct attach_clone_payload {
	int ipc_socket;
	int terminal_slave_fd;
	lxc_attach_options_t *options;
	struct lxc_proc_context_info *init_ctx;
	lxc_attach_exec_t exec_function;
	void *exec_payload;
};

static void lxc_put_attach_clone_payload(struct attach_clone_payload *p)
{
	if (p->ipc_socket >= 0) {
		shutdown(p->ipc_socket, SHUT_RDWR);
		close(p->ipc_socket);
		p->ipc_socket = -EBADF;
	}

	if (p->terminal_slave_fd >= 0) {
		close(p->terminal_slave_fd);
		p->terminal_slave_fd = -EBADF;
	}

	if (p->init_ctx) {
		lxc_proc_put_context_info(p->init_ctx);
		p->init_ctx = NULL;
	}
}

static int attach_child_main(struct attach_clone_payload *payload)
{
	int fd, lsm_fd, ret;
	uid_t new_uid;
	gid_t new_gid;
	lxc_attach_options_t* options = payload->options;
	struct lxc_proc_context_info* init_ctx = payload->init_ctx;
	bool needs_lsm = (options->namespaces & CLONE_NEWNS) &&
			 (options->attach_flags & LXC_ATTACH_LSM) &&
			 init_ctx->lsm_label;

	/* A description of the purpose of this functionality is provided in the
	 * lxc-attach(1) manual page. We have to remount here and not in the
	 * parent process, otherwise /proc may not properly reflect the new pid
	 * namespace.
	 */
	if (!(options->namespaces & CLONE_NEWNS) &&
	    (options->attach_flags & LXC_ATTACH_REMOUNT_PROC_SYS)) {
		ret = lxc_attach_remount_sys_proc();
		if (ret < 0)
			goto on_error;
		TRACE("Remounted \"/proc\" and \"/sys\"");
	}

/* Now perform additional attachments. */
#if HAVE_SYS_PERSONALITY_H
	if (options->attach_flags & LXC_ATTACH_SET_PERSONALITY) {
		long new_personality;

		if (options->personality < 0)
			new_personality = init_ctx->personality;
		else
			new_personality = options->personality;
		ret = personality(new_personality);
		if (ret < 0)
			goto on_error;
		TRACE("Set new personality");
	}
#endif

	if (options->attach_flags & LXC_ATTACH_DROP_CAPABILITIES) {
		ret = lxc_attach_drop_privs(init_ctx);
		if (ret < 0)
			goto on_error;
		TRACE("Dropped capabilities");
	}

	/* Always set the environment (specify (LXC_ATTACH_KEEP_ENV, NULL, NULL)
	 * if you want this to be a no-op).
	 */
	ret = lxc_attach_set_environment(init_ctx,
					 options->env_policy,
					 options->extra_env_vars,
					 options->extra_keep_env);
	if (ret < 0)
		goto on_error;
	TRACE("Set up environment");

	/* This remark only affects fully unprivileged containers:
	 * Receive fd for LSM security module before we set{g,u}id(). The reason
	 * is that on set{g,u}id() the kernel will a) make us undumpable and b)
	 * we will change our effective uid. This means our effective uid will
	 * be different from the effective uid of the process that created us
	 * which means that this processs no longer has capabilities in our
	 * namespace including CAP_SYS_PTRACE. This means we will not be able to
	 * read and /proc/<pid> files for the process anymore when /proc is
	 * mounted with hidepid={1,2}. So let's get the lsm label fd before the
	 * set{g,u}id().
	 */
	if (needs_lsm) {
		ret = lxc_abstract_unix_recv_fds(payload->ipc_socket, &lsm_fd, 1, NULL, 0);
		if (ret <= 0)
			goto on_error;
		TRACE("Received LSM label file descriptor %d from parent", lsm_fd);
	}

	if (options->stdin_fd > 0 && isatty(options->stdin_fd)) {
		ret = lxc_make_controlling_terminal(options->stdin_fd);
		if (ret < 0)
			goto on_error;
	}

	/* Set {u,g}id. */
	new_uid = 0;
	new_gid = 0;
	/* Ignore errors, we will fall back to root in that case (/proc was not
	 * mounted etc.).
	 */
	if (options->namespaces & CLONE_NEWUSER)
		lxc_attach_get_init_uidgid(&new_uid, &new_gid);

	if (options->uid != (uid_t)-1)
		new_uid = options->uid;
	if (options->gid != (gid_t)-1)
		new_gid = options->gid;

	/* Try to set the {u,g}id combination. */
	if (new_uid != 0 || new_gid != 0 || options->namespaces & CLONE_NEWUSER) {
		ret = lxc_switch_uid_gid(new_uid, new_gid);
		if (ret < 0)
			goto on_error;
	}

	ret = lxc_setgroups(0, NULL);
	if (ret < 0 && errno != EPERM)
		goto on_error;

	if ((init_ctx->container && init_ctx->container->lxc_conf &&
	     init_ctx->container->lxc_conf->no_new_privs) ||
	    (options->attach_flags & LXC_ATTACH_NO_NEW_PRIVS)) {
		ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
		if (ret < 0)
			goto on_error;
		TRACE("Set PR_SET_NO_NEW_PRIVS");
	}

	if (needs_lsm) {
		bool on_exec;

		/* Change into our new LSM profile. */
		on_exec = options->attach_flags & LXC_ATTACH_LSM_EXEC ? true : false;
		ret = lsm_process_label_set_at(lsm_fd, init_ctx->lsm_label, on_exec);
		close(lsm_fd);
		if (ret < 0)
			goto on_error;
		TRACE("Set %s LSM label to \"%s\"", lsm_name(), init_ctx->lsm_label);
	}

	if (init_ctx->container && init_ctx->container->lxc_conf &&
	    init_ctx->container->lxc_conf->seccomp) {
		ret = lxc_seccomp_load(init_ctx->container->lxc_conf);
		if (ret < 0)
			goto on_error;
		TRACE("Loaded seccomp profile");
	}
	shutdown(payload->ipc_socket, SHUT_RDWR);
	close(payload->ipc_socket);
	payload->ipc_socket = -EBADF;
	lxc_proc_put_context_info(init_ctx);

	/* The following is done after the communication socket is shut down.
	 * That way, all errors that might (though unlikely) occur up until this
	 * point will have their messages printed to the original stderr (if
	 * logging is so configured) and not the fd the user supplied, if any.
	 */

	/* Fd handling for stdin, stdout and stderr; ignore errors here, user
	 * may want to make sure the fds are closed, for example.
	 */
	if (options->stdin_fd >= 0 && options->stdin_fd != STDIN_FILENO)
		dup2(options->stdin_fd, STDIN_FILENO);

	if (options->stdout_fd >= 0 && options->stdout_fd != STDOUT_FILENO)
		dup2(options->stdout_fd, STDOUT_FILENO);

	if (options->stderr_fd >= 0 && options->stderr_fd != STDERR_FILENO)
		dup2(options->stderr_fd, STDERR_FILENO);

	/* close the old fds */
	if (options->stdin_fd > STDERR_FILENO)
		close(options->stdin_fd);

	if (options->stdout_fd > STDERR_FILENO)
		close(options->stdout_fd);

	if (options->stderr_fd > STDERR_FILENO)
		close(options->stderr_fd);

	/* Try to remove FD_CLOEXEC flag from stdin/stdout/stderr, but also
	 * here, ignore errors.
	 */
	for (fd = STDIN_FILENO; fd <= STDERR_FILENO; fd++) {
		int flags;

		flags = fcntl(fd, F_GETFL);
		if (flags < 0)
			continue;

		if ((flags & FD_CLOEXEC) == 0)
			continue;

		ret = fcntl(fd, F_SETFL, flags & ~FD_CLOEXEC);
		if (ret < 0) {
			SYSERROR("Failed to clear FD_CLOEXEC from file descriptor %d", fd);
			goto on_error;
		}
	}

	if (options->attach_flags & LXC_ATTACH_TERMINAL) {
		ret = lxc_terminal_prepare_login(payload->terminal_slave_fd);
		if (ret < 0) {
			SYSERROR("Failed to prepare terminal file descriptor %d", payload->terminal_slave_fd);
			goto on_error;
		}
		TRACE("Prepared terminal file descriptor %d", payload->terminal_slave_fd);
	}

	/* We're done, so we can now do whatever the user intended us to do. */
	rexit(payload->exec_function(payload->exec_payload));

on_error:
	lxc_put_attach_clone_payload(payload);
	rexit(EXIT_FAILURE);
}

static int lxc_attach_terminal(struct lxc_conf *conf,
			       struct lxc_terminal *terminal)
{
	int ret;

	lxc_terminal_init(terminal);

	ret = lxc_terminal_create(terminal);
	if (ret < 0) {
		SYSERROR("Failed to create terminal");
		return -1;
	}

	/* Shift ttys to container. */
	ret = lxc_terminal_map_ids(conf, terminal);
	if (ret < 0) {
		ERROR("Failed to chown terminal");
		goto on_error;
	}

	return 0;

on_error:
	lxc_terminal_delete(terminal);
	lxc_terminal_conf_free(terminal);
	return -1;
}

static int lxc_attach_terminal_mainloop_init(struct lxc_terminal *terminal,
					     struct lxc_epoll_descr *descr)
{
	int ret;

	ret = lxc_mainloop_open(descr);
	if (ret < 0) {
		ERROR("Failed to create mainloop");
		return -1;
	}

	ret = lxc_terminal_mainloop_add(descr, terminal);
	if (ret < 0) {
		ERROR("Failed to add handlers to mainloop");
		lxc_mainloop_close(descr);
		return -1;
	}

	return 0;
}

static inline void lxc_attach_terminal_close_master(struct lxc_terminal *terminal)
{
	if (terminal->master < 0)
		return;

	close(terminal->master);
	terminal->master = -EBADF;
}

static inline void lxc_attach_terminal_close_slave(struct lxc_terminal *terminal)
{
	if (terminal->slave < 0)
		return;

	close(terminal->slave);
	terminal->slave = -EBADF;
}

static inline void lxc_attach_terminal_close_peer(struct lxc_terminal *terminal)
{
	if (terminal->peer < 0)
		return;

	close(terminal->peer);
	terminal->peer = -EBADF;
}

static inline void lxc_attach_terminal_close_log(struct lxc_terminal *terminal)
{
	if (terminal->log_fd < 0)
		return;

	close(terminal->log_fd);
	terminal->log_fd = -EBADF;
}

int lxc_attach(const char *name, const char *lxcpath,
	       lxc_attach_exec_t exec_function, void *exec_payload,
	       lxc_attach_options_t *options, pid_t *attached_process)
{
	int i, ret, status;
	int ipc_sockets[2];
	char *cwd, *new_cwd;
	signed long personality;
	pid_t attached_pid, init_pid, pid;
	struct lxc_proc_context_info *init_ctx;
	struct lxc_terminal terminal;
	struct lxc_conf *conf;
	struct attach_clone_payload payload = {0};

	ret = access("/proc/self/ns", X_OK);
	if (ret) {
		ERROR("Does this kernel version support namespaces?");
		return -1;
	}

	if (!options)
		options = &attach_static_default_options;

	init_pid = lxc_cmd_get_init_pid(name, lxcpath);
	if (init_pid < 0) {
		ERROR("Failed to get init pid.");
		return -1;
	}

	init_ctx = lxc_proc_get_context_info(init_pid);
	if (!init_ctx) {
		ERROR("Failed to get context of init process: %ld", (long)init_pid);
		return -1;
	}

	personality = get_personality(name, lxcpath);
	if (init_ctx->personality < 0) {
		ERROR("Failed to get personality of the container");
		lxc_proc_put_context_info(init_ctx);
		return -1;
	}
	init_ctx->personality = personality;

	init_ctx->container = lxc_container_new(name, lxcpath);
	if (!init_ctx->container) {
		lxc_proc_put_context_info(init_ctx);
		return -1;
	}

	if (!init_ctx->container->lxc_conf) {
		init_ctx->container->lxc_conf = lxc_conf_init();
		if (!init_ctx->container->lxc_conf) {
			lxc_proc_put_context_info(init_ctx);
			return -ENOMEM;
		}
	}
	conf = init_ctx->container->lxc_conf;

	if (!fetch_seccomp(init_ctx->container, options))
		WARN("Failed to get seccomp policy.");

	if (!no_new_privs(init_ctx->container, options))
		WARN("Could not determine whether PR_SET_NO_NEW_PRIVS is set.");

	cwd = getcwd(NULL, 0);

	/* Determine which namespaces the container was created with
	 * by asking lxc-start, if necessary.
	 */
	if (options->namespaces == -1) {
		options->namespaces = lxc_cmd_get_clone_flags(name, lxcpath);
		/* call failed */
		if (options->namespaces == -1) {
			ERROR("Failed to automatically determine the "
			      "namespaces which the container uses");
			free(cwd);
			lxc_proc_put_context_info(init_ctx);
			return -1;
		}

		for (i = 0; i < LXC_NS_MAX; i++) {
			if (ns_info[i].clone_flag & CLONE_NEWCGROUP)
				if (!(options->attach_flags & LXC_ATTACH_MOVE_TO_CGROUP) ||
				    !cgns_supported())
					continue;

			if (ns_info[i].clone_flag & options->namespaces)
				continue;

			init_ctx->ns_inherited |= ns_info[i].clone_flag;
		}
	}

	pid = lxc_raw_getpid();
	for (i = 0; i < LXC_NS_MAX; i++) {
		int j, saved_errno;

		if (options->namespaces & ns_info[i].clone_flag)
			init_ctx->ns_fd[i] = lxc_preserve_ns(init_pid, ns_info[i].proc_name);
		else if (init_ctx->ns_inherited & ns_info[i].clone_flag)
			init_ctx->ns_fd[i] = in_same_namespace(pid, init_pid, ns_info[i].proc_name);
		else
			continue;
		if (init_ctx->ns_fd[i] >= 0)
			continue;

		if (init_ctx->ns_fd[i] == -EINVAL) {
			DEBUG("Inheriting %s namespace from %d",
			      ns_info[i].proc_name, pid);
			init_ctx->ns_inherited &= ~ns_info[i].clone_flag;
			continue;
		}

		/* We failed to preserve the namespace. */
		saved_errno = errno;
		/* Close all already opened file descriptors before we return an
		 * error, so we don't leak them.
		 */
		for (j = 0; j < i; j++)
			close(init_ctx->ns_fd[j]);

		errno = saved_errno;
		SYSERROR("Failed to attach to %s namespace of %d",
			 ns_info[i].proc_name, pid);
		free(cwd);
		lxc_proc_put_context_info(init_ctx);
		return -1;
	}

	if (options->attach_flags & LXC_ATTACH_TERMINAL) {
		ret = lxc_attach_terminal(conf, &terminal);
		if (ret < 0) {
			ERROR("Failed to setup new terminal");
			free(cwd);
			lxc_proc_put_context_info(init_ctx);
			return -1;
		}

		terminal.log_fd = options->log_fd;
	} else {
		lxc_terminal_init(&terminal);
	}

	/* Create a socket pair for IPC communication; set SOCK_CLOEXEC in order
	 * to make sure we don't irritate other threads that want to fork+exec
	 * away
	 *
	 * IMPORTANT: if the initial process is multithreaded and another call
	 * just fork()s away without exec'ing directly after, the socket fd will
	 * exist in the forked process from the other thread and any close() in
	 * our own child process will not really cause the socket to close
	 * properly, potentiall causing the parent to hang.
	 *
	 * For this reason, while IPC is still active, we have to use shutdown()
	 * if the child exits prematurely in order to signal that the socket is
	 * closed and cannot assume that the child exiting will automatically do
	 * that.
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
	 *						[set LXC_ATTACH_NO_NEW_PRIVS]
	 *        X  <------------------------------------  send 3
	 *   [open LSM label fd]
	 *    send 4 ------------------------------------>    X
	 *   						[set LSM label]
	 *   close socket                                 close socket
	 *                                                run program
	 */
	ret = socketpair(PF_LOCAL, SOCK_STREAM | SOCK_CLOEXEC, 0, ipc_sockets);
	if (ret < 0) {
		SYSERROR("Could not set up required IPC mechanism for attaching.");
		free(cwd);
		lxc_proc_put_context_info(init_ctx);
		return -1;
	}

	/* Create intermediate subprocess, two reasons:
	 *       1. We can't setns() in the child itself, since we want to make
	 *          sure we are properly attached to the pidns.
	 *       2. Also, the initial thread has to put the attached process
	 *          into the cgroup, which we can only do if we didn't already
	 *          setns() (otherwise, user namespaces will hate us).
	 */
	pid = fork();
	if (pid < 0) {
		SYSERROR("Failed to create first subprocess.");
		free(cwd);
		lxc_proc_put_context_info(init_ctx);
		return -1;
	}

	if (pid) {
		int ret_parent = -1;
		pid_t to_cleanup_pid = pid;
		struct lxc_epoll_descr descr = {0};

		/* close unneeded file descriptors */
		close(ipc_sockets[1]);
		free(cwd);
		lxc_proc_close_ns_fd(init_ctx);
		if (options->attach_flags & LXC_ATTACH_TERMINAL)
			lxc_attach_terminal_close_slave(&terminal);

		/* Attach to cgroup, if requested. */
		if (options->attach_flags & LXC_ATTACH_MOVE_TO_CGROUP) {
			struct cgroup_ops *cgroup_ops;

			cgroup_ops = cgroup_init(NULL);
			if (!cgroup_ops)
				goto on_error;

			if (!cgroup_ops->attach(cgroup_ops, name, lxcpath, pid))
				goto on_error;

			cgroup_exit(cgroup_ops);
			TRACE("Moved intermediate process %d into container's cgroups", pid);
		}

		/* Setup /proc limits */
		if (!lxc_list_empty(&conf->procs)) {
			ret = setup_proc_filesystem(&conf->procs, pid);
			if (ret < 0)
				goto on_error;
		}

		/* Setup resource limits */
		if (!lxc_list_empty(&conf->limits)) {
			ret = setup_resource_limits(&conf->limits, pid);
			if (ret < 0)
				goto on_error;
		}

		if (options->attach_flags & LXC_ATTACH_TERMINAL) {
			ret = lxc_attach_terminal_mainloop_init(&terminal, &descr);
			if (ret < 0)
				goto on_error;
			TRACE("Initialized terminal mainloop");
		}

		/* Let the child process know to go ahead. */
		status = 0;
		ret = lxc_write_nointr(ipc_sockets[0], &status, sizeof(status));
		if (ret != sizeof(status))
			goto close_mainloop;
		TRACE("Told intermediate process to start initializing");

		/* Get pid of attached process from intermediate process. */
		ret = lxc_read_nointr(ipc_sockets[0], &attached_pid, sizeof(attached_pid));
		if (ret != sizeof(attached_pid))
			goto close_mainloop;
		TRACE("Received pid %d of attached process in parent pid namespace", attached_pid);

		/* Ignore SIGKILL (CTRL-C) and SIGQUIT (CTRL-\) - issue #313. */
		if (options->stdin_fd == 0) {
			signal(SIGINT, SIG_IGN);
			signal(SIGQUIT, SIG_IGN);
		}

		/* Reap intermediate process. */
		ret = wait_for_pid(pid);
		if (ret < 0)
			goto close_mainloop;
		TRACE("Intermediate process %d exited", pid);

		/* We will always have to reap the attached process now. */
		to_cleanup_pid = attached_pid;

		/* Open LSM fd and send it to child. */
		if ((options->namespaces & CLONE_NEWNS) &&
		    (options->attach_flags & LXC_ATTACH_LSM) &&
		    init_ctx->lsm_label) {
			int ret = -1;
			int labelfd;
			bool on_exec;

			on_exec = options->attach_flags & LXC_ATTACH_LSM_EXEC ? true : false;
			labelfd = lsm_process_label_fd_get(attached_pid, on_exec);
			if (labelfd < 0)
				goto close_mainloop;
			TRACE("Opened LSM label file descriptor %d", labelfd);

			/* Send child fd of the LSM security module to write to. */
			ret = lxc_abstract_unix_send_fds(ipc_sockets[0], &labelfd, 1, NULL, 0);
			close(labelfd);
			if (ret <= 0) {
				SYSERROR("%d", (int)ret);
				goto close_mainloop;
			}
			TRACE("Sent LSM label file descriptor %d to child", labelfd);
		}

		/* We're done, the child process should now execute whatever it
		 * is that the user requested. The parent can now track it with
		 * waitpid() or similar.
		 */

		*attached_process = attached_pid;

		/* Now shut down communication with child, we're done. */
		shutdown(ipc_sockets[0], SHUT_RDWR);
		close(ipc_sockets[0]);
		ipc_sockets[0] = -1;

		ret_parent = 0;
		to_cleanup_pid = -1;
		if (options->attach_flags & LXC_ATTACH_TERMINAL) {
			ret = lxc_mainloop(&descr, -1);
			if (ret < 0) {
				ret_parent = -1;
				to_cleanup_pid = attached_pid;
			}
		}

	close_mainloop:
		if (options->attach_flags & LXC_ATTACH_TERMINAL)
			lxc_mainloop_close(&descr);

	on_error:
		if (ipc_sockets[0] >= 0) {
			shutdown(ipc_sockets[0], SHUT_RDWR);
			close(ipc_sockets[0]);
		}

		if (to_cleanup_pid > 0)
			(void)wait_for_pid(to_cleanup_pid);

		if (options->attach_flags & LXC_ATTACH_TERMINAL) {
			lxc_terminal_delete(&terminal);
			lxc_terminal_conf_free(&terminal);
		}
		lxc_proc_put_context_info(init_ctx);
		return ret_parent;
	}

	/* close unneeded file descriptors */
	close(ipc_sockets[0]);
	ipc_sockets[0] = -EBADF;
	if (options->attach_flags & LXC_ATTACH_TERMINAL) {
		lxc_attach_terminal_close_master(&terminal);
		lxc_attach_terminal_close_peer(&terminal);
		lxc_attach_terminal_close_log(&terminal);
	}

	/* Wait for the parent to have setup cgroups. */
	ret = lxc_read_nointr(ipc_sockets[1], &status, sizeof(status));
	if (ret != sizeof(status)) {
		shutdown(ipc_sockets[1], SHUT_RDWR);
		lxc_proc_put_context_info(init_ctx);
		rexit(-1);
	}
	TRACE("Intermediate process starting to initialize");

	/* Attach now, create another subprocess later, since pid namespaces
	 * only really affect the children of the current process.
	 */
	ret = lxc_attach_to_ns(init_pid, init_ctx);
	if (ret < 0) {
		ERROR("Failed to enter namespaces");
		shutdown(ipc_sockets[1], SHUT_RDWR);
		lxc_proc_put_context_info(init_ctx);
		rexit(-1);
	}
	/* close namespace file descriptors */
	lxc_proc_close_ns_fd(init_ctx);

	/* Attach succeeded, try to cwd. */
	if (options->initial_cwd)
		new_cwd = options->initial_cwd;
	else
		new_cwd = cwd;
	if (new_cwd) {
		ret = chdir(new_cwd);
		if (ret < 0)
			WARN("Could not change directory to \"%s\"", new_cwd);
	}
	free(cwd);

	/* Create attached process. */
	payload.ipc_socket = ipc_sockets[1];
	payload.options = options;
	payload.init_ctx = init_ctx;
	payload.terminal_slave_fd = terminal.slave;
	payload.exec_function = exec_function;
	payload.exec_payload = exec_payload;

	pid = lxc_raw_clone(CLONE_PARENT);
	if (pid < 0) {
		SYSERROR("Failed to clone attached process");
		shutdown(ipc_sockets[1], SHUT_RDWR);
		lxc_proc_put_context_info(init_ctx);
		rexit(-1);
	}

	if (pid == 0) {
		ret = attach_child_main(&payload);
		if (ret < 0)
			ERROR("Failed to exec");
		_exit(EXIT_FAILURE);
	}
	if (options->attach_flags & LXC_ATTACH_TERMINAL)
		lxc_attach_terminal_close_slave(&terminal);

	/* Tell grandparent the pid of the pid of the newly created child. */
	ret = lxc_write_nointr(ipc_sockets[1], &pid, sizeof(pid));
	if (ret != sizeof(pid)) {
		/* If this really happens here, this is very unfortunate, since
		 * the parent will not know the pid of the attached process and
		 * will not be able to wait for it (and we won't either due to
		 * CLONE_PARENT) so the parent won't be able to reap it and the
		 * attached process will remain a zombie.
		 */
		shutdown(ipc_sockets[1], SHUT_RDWR);
		lxc_proc_put_context_info(init_ctx);
		rexit(-1);
	}
	TRACE("Sending pid %d of attached process", pid);

	/* The rest is in the hands of the initial and the attached process. */
	lxc_proc_put_context_info(init_ctx);
	rexit(0);
}

int lxc_attach_run_command(void* payload)
{
	lxc_attach_command_t* cmd = (lxc_attach_command_t*)payload;

	execvp(cmd->program, cmd->argv);
	SYSERROR("Failed to exec \"%s\".", cmd->program);
	return -1;
}

int lxc_attach_run_shell(void* payload)
{
	uid_t uid;
	struct passwd *passwd;
	char *user_shell;

	/* Ignore payload parameter. */
	(void)payload;

	uid = getuid();
	passwd = getpwuid(uid);

	/* This probably happens because of incompatible nss implementations in
	 * host and container (remember, this code is still using the host's
	 * glibc but our mount namespace is in the container) we may try to get
	 * the information by spawning a [getent passwd uid] process and parsing
	 * the result.
	 */
	if (!passwd)
		user_shell = lxc_attach_getpwshell(uid);
	else
		user_shell = passwd->pw_shell;
	if (user_shell)
		execlp(user_shell, user_shell, (char *)NULL);

	/* Executed if either no passwd entry or execvp fails, we will fall back
	 * on /bin/sh as a default shell.
	 */
	execlp("/bin/sh", "/bin/sh", (char *)NULL);
	SYSERROR("Failed to execute shell");
	if (!passwd)
		free(user_shell);
	return -1;
}

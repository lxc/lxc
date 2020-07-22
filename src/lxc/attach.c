/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/unistd.h>
#include <pwd.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include <lxc/lxccontainer.h>

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
#include "macro.h"
#include "mainloop.h"
#include "memory_utils.h"
#include "mount_utils.h"
#include "namespace.h"
#include "process_utils.h"
#include "syscall_wrappers.h"
#include "terminal.h"
#include "utils.h"

#if HAVE_SYS_PERSONALITY_H
#include <sys/personality.h>
#endif

lxc_log_define(attach, lxc);

/* Define default options if no options are supplied by the user. */
static lxc_attach_options_t attach_static_default_options = LXC_ATTACH_OPTIONS_DEFAULT;

static struct lxc_proc_context_info *lxc_proc_get_context_info(pid_t pid)
{
	__do_free char *line = NULL;
	__do_fclose FILE *proc_file = NULL;
	__do_free struct lxc_proc_context_info *info = NULL;
	int ret;
	bool found;
	char proc_fn[LXC_PROC_STATUS_LEN];
	size_t line_bufsz = 0;

	/* Read capabilities. */
	ret = snprintf(proc_fn, LXC_PROC_STATUS_LEN, "/proc/%d/status", pid);
	if (ret < 0 || ret >= LXC_PROC_STATUS_LEN)
		return NULL;

	proc_file = fopen(proc_fn, "re");
	if (!proc_file)
		return log_error_errno(NULL, errno, "Failed to open %s", proc_fn);

	info = calloc(1, sizeof(*info));
	if (!info)
		return NULL;

	found = false;

	while (getline(&line, &line_bufsz, proc_file) != -1) {
		ret = sscanf(line, "CapBnd: %llx", &info->capability_mask);
		if (ret != EOF && ret == 1) {
			found = true;
			break;
		}
	}

	if (!found)
		return log_error_errno(NULL, ENOENT, "Failed to read capability bounding set from %s", proc_fn);

	info->lsm_label = lsm_process_label_get(pid);
	info->ns_inherited = 0;
	for (int i = 0; i < LXC_NS_MAX; i++)
		info->ns_fd[i] = -EBADF;

	return move_ptr(info);
}

static inline void lxc_proc_close_ns_fd(struct lxc_proc_context_info *ctx)
{
	for (int i = 0; i < LXC_NS_MAX; i++)
		close_prot_errno_disarm(ctx->ns_fd[i]);
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
	__do_close int ns_fd1 = -EBADF, ns_fd2 = -EBADF;
	int ret = -1;
	struct stat ns_st1, ns_st2;

	ns_fd1 = lxc_preserve_ns(pid1, ns);
	if (ns_fd1 < 0) {
		/* The kernel does not support this namespace. This is not an
		 * error.
		 */
		if (errno == ENOENT)
			return -EINVAL;

		return -1;
	}

	ns_fd2 = lxc_preserve_ns(pid2, ns);
	if (ns_fd2 < 0)
		return -1;

	ret = fstat(ns_fd1, &ns_st1);
	if (ret < 0)
		return -1;

	ret = fstat(ns_fd2, &ns_st2);
	if (ret < 0)
		return -1;

	/* processes are in the same namespace */
	if ((ns_st1.st_dev == ns_st2.st_dev) && (ns_st1.st_ino == ns_st2.st_ino))
		return -EINVAL;

	/* processes are in different namespaces */
	return move_fd(ns_fd2);
}

static int lxc_attach_to_ns(pid_t pid, struct lxc_proc_context_info *ctx)
{
	for (int i = 0; i < LXC_NS_MAX; i++) {
		int ret;

		if (ctx->ns_fd[i] < 0)
			continue;

		ret = setns(ctx->ns_fd[i], ns_info[i].clone_flag);
		if (ret < 0)
			return log_error_errno(-1,
					       errno, "Failed to attach to %s namespace of %d",
					       ns_info[i].proc_name, pid);

		DEBUG("Attached to %s namespace of %d", ns_info[i].proc_name, pid);
	}

	return 0;
}

int lxc_attach_remount_sys_proc(void)
{
	int ret;

	ret = unshare(CLONE_NEWNS);
	if (ret < 0)
		return log_error_errno(-1, errno, "Failed to unshare mount namespace");

	if (detect_shared_rootfs() && mount(NULL, "/", NULL, MS_SLAVE | MS_REC, NULL))
		SYSERROR("Failed to recursively turn root mount tree into dependent mount. Continuing...");

	/* Assume /proc is always mounted, so remount it. */
	ret = umount2("/proc", MNT_DETACH);
	if (ret < 0)
		return log_error_errno(-1, errno, "Failed to unmount /proc");

	ret = mount_filesystem("proc", "/proc", 0);
	if (ret < 0)
		return log_error_errno(-1, errno, "Failed to remount /proc");

	/*
	 * Try to umount /sys. If it's not a mount point, we'll get EINVAL, then
	 * we ignore it because it may not have been mounted in the first place.
	 */
	ret = umount2("/sys", MNT_DETACH);
	if (ret < 0 && errno != EINVAL)
		return log_error_errno(-1, errno, "Failed to unmount /sys");

	/* Remount it. */
	if (ret == 0 && mount_filesystem("sysfs", "/sys", 0))
		return log_error_errno(-1, errno, "Failed to remount /sys");

	return 0;
}

static int lxc_attach_drop_privs(struct lxc_proc_context_info *ctx)
{
	int last_cap;

	last_cap = lxc_caps_last_cap();
	for (int cap = 0; cap <= last_cap; cap++) {
		if (ctx->capability_mask & (1LL << cap))
			continue;

		if (prctl(PR_CAPBSET_DROP, prctl_arg(cap), prctl_arg(0),
			  prctl_arg(0), prctl_arg(0)))
			return log_error_errno(-1, errno, "Failed to drop capability %d", cap);

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

			return log_error(-1, "Failed to clear environment");
		}

		if (extra_keep_store) {
			size_t i;

			for (i = 0; extra_keep[i]; i++) {
				if (extra_keep_store[i]) {
					ret = setenv(extra_keep[i], extra_keep_store[i], 1);
					if (ret < 0)
						SYSWARN("Failed to set environment variable");
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
				SYSWARN("Failed to set environment variable");
		}
	}

	ret = putenv("container=lxc");
	if (ret < 0)
		return log_warn(-1, "Failed to set environment variable");

	/* Set container environment variables.*/
	if (init_ctx && init_ctx->container && init_ctx->container->lxc_conf) {
		lxc_list_for_each(iterator, &init_ctx->container->lxc_conf->environment) {
			char *env_tmp;

			env_tmp = strdup((char *)iterator->elem);
			if (!env_tmp)
				return -1;

			ret = putenv(env_tmp);
			if (ret < 0)
				return log_error_errno(-1, errno, "Failed to set environment variable: %s", (char *)iterator->elem);
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
				SYSWARN("Failed to set environment variable");
		}
	}

	return 0;
}

static char *lxc_attach_getpwshell(uid_t uid)
{
	__do_free char *line = NULL, *result = NULL;
	__do_fclose FILE *pipe_f = NULL;
	int fd, ret;
	pid_t pid;
	int pipes[2];
	bool found = false;
	size_t line_bufsz = 0;

	/* We need to fork off a process that runs the getent program, and we
	 * need to capture its output, so we use a pipe for that purpose.
	 */
	ret = pipe2(pipes, O_CLOEXEC);
	if (ret < 0)
		return NULL;

	pid = fork();
	if (pid < 0) {
		close(pipes[0]);
		close(pipes[1]);
		return NULL;
	}

	if (!pid) {
		char uid_buf[32];
		char *arguments[] = {
			"getent",
			"passwd",
			uid_buf,
			NULL
		};

		close(pipes[0]);

		/* We want to capture stdout. */
		ret = dup2(pipes[1], STDOUT_FILENO);
		close(pipes[1]);
		if (ret < 0)
			_exit(EXIT_FAILURE);

		/* Get rid of stdin/stderr, so we try to associate it with
		 * /dev/null.
		 */
		fd = open_devnull();
		if (fd < 0) {
			close(STDIN_FILENO);
			close(STDERR_FILENO);
		} else {
			(void)dup3(fd, STDIN_FILENO, O_CLOEXEC);
			(void)dup3(fd, STDERR_FILENO, O_CLOEXEC);
			close(fd);
		}

		/* Finish argument list. */
		ret = snprintf(uid_buf, sizeof(uid_buf), "%ld", (long)uid);
		if (ret <= 0 || ret >= sizeof(uid_buf))
			_exit(EXIT_FAILURE);

		/* Try to run getent program. */
		(void)execvp("getent", arguments);
		_exit(EXIT_FAILURE);
	}

	close(pipes[1]);

	pipe_f = fdopen(pipes[0], "re");
	if (!pipe_f) {
		close(pipes[0]);
		goto reap_child;
	}
	/* Transfer ownership of pipes[0] to pipe_f. */
	move_fd(pipes[0]);

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

		if (!line)
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
		if (!token || !endptr || *endptr || value == LONG_MIN ||
		    value == LONG_MAX)
			continue;

		/* dummy sanity check: user id matches */
		if ((uid_t)value != uid)
			continue;

		/* skip fields: gid, gecos, dir, go to next field 'shell' */
		for (i = 0; i < 4; i++) {
			token = strtok_r(NULL, ":", &saveptr);
			if (!token)
				continue;
		}

		if (!token)
			continue;

		free_disarm(result);
		result = strdup(token);

		/* Sanity check that there are no fields after that. */
		token = strtok_r(NULL, ":", &saveptr);
		if (token)
			continue;

		found = true;
	}

reap_child:
	ret = wait_for_pid(pid);
	if (ret < 0)
		return NULL;

	if (!found)
		return NULL;

	return move_ptr(result);
}

static void lxc_attach_get_init_uidgid(uid_t *init_uid, gid_t *init_gid)
{
	__do_free char *line = NULL;
	__do_fclose FILE *proc_file = NULL;
	char proc_fn[LXC_PROC_STATUS_LEN];
	int ret;
	size_t line_bufsz = 0;
	long value = -1;
	uid_t uid = LXC_INVALID_UID;
	gid_t gid = LXC_INVALID_GID;

	ret = snprintf(proc_fn, LXC_PROC_STATUS_LEN, "/proc/%d/status", 1);
	if (ret < 0 || ret >= LXC_PROC_STATUS_LEN)
		return;

	proc_file = fopen(proc_fn, "re");
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

		if (uid != LXC_INVALID_UID && gid != LXC_INVALID_GID)
			break;
	}

	/* Only override arguments if we found something. */
	if (uid != LXC_INVALID_UID)
		*init_uid = uid;

	if (gid != LXC_INVALID_GID)
		*init_gid = gid;

	/* TODO: we should also parse supplementary groups and use
	 * setgroups() to set them.
	 */
}

static bool fetch_seccomp(struct lxc_container *c, lxc_attach_options_t *options)
{
	__do_free char *path = NULL;
	int ret;
	bool bret;

	if (!(options->namespaces & CLONE_NEWNS) ||
	    !(options->attach_flags & LXC_ATTACH_LSM)) {
		free_disarm(c->lxc_conf->seccomp.seccomp);
		return true;
	}

	/* Remove current setting. */
	if (!c->set_config_item(c, "lxc.seccomp.profile", "") &&
	    !c->set_config_item(c, "lxc.seccomp", ""))
		return false;

	/* Fetch the current profile path over the cmd interface. */
	path = c->get_running_config_item(c, "lxc.seccomp.profile");
	if (!path) {
		INFO("Failed to retrieve lxc.seccomp.profile");

		path = c->get_running_config_item(c, "lxc.seccomp");
		if (!path)
			return log_info(true, "Failed to retrieve lxc.seccomp");
	}

	/* Copy the value into the new lxc_conf. */
	bret = c->set_config_item(c, "lxc.seccomp.profile", path);
	if (!bret)
		return false;

	/* Attempt to parse the resulting config. */
	ret = lxc_read_seccomp_config(c->lxc_conf);
	if (ret < 0)
		return log_error(false, "Failed to retrieve seccomp policy");

	return log_info(true, "Retrieved seccomp policy");
}

static bool no_new_privs(struct lxc_container *c, lxc_attach_options_t *options)
{
	__do_free char *val = NULL;

	/* Remove current setting. */
	if (!c->set_config_item(c, "lxc.no_new_privs", ""))
		return log_info(false, "Failed to unset lxc.no_new_privs");

	/* Retrieve currently active setting. */
	val = c->get_running_config_item(c, "lxc.no_new_privs");
	if (!val)
		return log_info(false, "Failed to retrieve lxc.no_new_privs");

	/* Set currently active setting. */
	return c->set_config_item(c, "lxc.no_new_privs", val);
}

static signed long get_personality(const char *name, const char *lxcpath)
{
	__do_free char *p = NULL;

	p = lxc_cmd_get_config_item(name, "lxc.arch", lxcpath);
	if (!p)
		return -1;

	return lxc_config_parse_arch(p);
}

struct attach_clone_payload {
	int ipc_socket;
	int terminal_pts_fd;
	lxc_attach_options_t *options;
	struct lxc_proc_context_info *init_ctx;
	lxc_attach_exec_t exec_function;
	void *exec_payload;
};

static void lxc_put_attach_clone_payload(struct attach_clone_payload *p)
{
	close_prot_errno_disarm(p->ipc_socket);
	close_prot_errno_disarm(p->terminal_pts_fd);
	if (p->init_ctx) {
		lxc_proc_put_context_info(p->init_ctx);
		p->init_ctx = NULL;
	}
}

static int attach_child_main(struct attach_clone_payload *payload)
{
	int lsm_fd, ret;
	uid_t new_uid;
	gid_t new_gid;
	uid_t ns_root_uid = 0;
	gid_t ns_root_gid = 0;
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
		if (ret <= 0) {
			if (ret < 0)
				SYSERROR("Failed to receive lsm label fd");

			goto on_error;
		}

		TRACE("Received LSM label file descriptor %d from parent", lsm_fd);
	}

	if (options->stdin_fd > 0 && isatty(options->stdin_fd)) {
		ret = lxc_make_controlling_terminal(options->stdin_fd);
		if (ret < 0)
			goto on_error;
	}

	if (!lxc_setgroups(0, NULL) && errno != EPERM)
		goto on_error;

	if (options->namespaces & CLONE_NEWUSER) {
		/* Check whether nsuid 0 has a mapping. */
		ns_root_uid = get_ns_uid(0);

		/* Check whether nsgid 0 has a mapping. */
		ns_root_gid = get_ns_gid(0);

		/* If there's no mapping for nsuid 0 try to retrieve the nsuid
		 * init was started with.
		 */
		if (ns_root_uid == LXC_INVALID_UID)
			lxc_attach_get_init_uidgid(&ns_root_uid, &ns_root_gid);

		if (ns_root_uid == LXC_INVALID_UID)
			goto on_error;

		if (!lxc_switch_uid_gid(ns_root_uid, ns_root_gid))
			goto on_error;
	}

	/* Set {u,g}id. */
	if (options->uid != LXC_INVALID_UID)
		new_uid = options->uid;
	else
		new_uid = ns_root_uid;

	if (options->gid != LXC_INVALID_GID)
		new_gid = options->gid;
	else
		new_gid = ns_root_gid;

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

	if ((init_ctx->container && init_ctx->container->lxc_conf &&
	     init_ctx->container->lxc_conf->no_new_privs) ||
	    (options->attach_flags & LXC_ATTACH_NO_NEW_PRIVS)) {
		ret = prctl(PR_SET_NO_NEW_PRIVS, prctl_arg(1), prctl_arg(0),
			    prctl_arg(0), prctl_arg(0));
		if (ret < 0)
			goto on_error;

		TRACE("Set PR_SET_NO_NEW_PRIVS");
	}

	if (init_ctx->container && init_ctx->container->lxc_conf &&
	    init_ctx->container->lxc_conf->seccomp.seccomp) {
		struct lxc_conf *conf = init_ctx->container->lxc_conf;

		ret = lxc_seccomp_load(conf);
		if (ret < 0)
			goto on_error;

		TRACE("Loaded seccomp profile");

		ret = lxc_seccomp_send_notifier_fd(&conf->seccomp, payload->ipc_socket);
		if (ret < 0)
			goto on_error;
	}

	close(payload->ipc_socket);
	payload->ipc_socket = -EBADF;
	lxc_proc_put_context_info(init_ctx);
	payload->init_ctx = NULL;

	/* The following is done after the communication socket is shut down.
	 * That way, all errors that might (though unlikely) occur up until this
	 * point will have their messages printed to the original stderr (if
	 * logging is so configured) and not the fd the user supplied, if any.
	 */

	/* Fd handling for stdin, stdout and stderr; ignore errors here, user
	 * may want to make sure the fds are closed, for example.
	 */
	if (options->stdin_fd >= 0 && options->stdin_fd != STDIN_FILENO)
		(void)dup2(options->stdin_fd, STDIN_FILENO);

	if (options->stdout_fd >= 0 && options->stdout_fd != STDOUT_FILENO)
		(void)dup2(options->stdout_fd, STDOUT_FILENO);

	if (options->stderr_fd >= 0 && options->stderr_fd != STDERR_FILENO)
		(void)dup2(options->stderr_fd, STDERR_FILENO);

	/* close the old fds */
	if (options->stdin_fd > STDERR_FILENO)
		close(options->stdin_fd);

	if (options->stdout_fd > STDERR_FILENO)
		close(options->stdout_fd);

	if (options->stderr_fd > STDERR_FILENO)
		close(options->stderr_fd);

	/*
	 * Try to remove FD_CLOEXEC flag from stdin/stdout/stderr, but also
	 * here, ignore errors.
	 */
	for (int fd = STDIN_FILENO; fd <= STDERR_FILENO; fd++) {
		ret = fd_cloexec(fd, false);
		if (ret < 0) {
			SYSERROR("Failed to clear FD_CLOEXEC from file descriptor %d", fd);
			goto on_error;
		}
	}

	if (options->attach_flags & LXC_ATTACH_TERMINAL) {
		ret = lxc_terminal_prepare_login(payload->terminal_pts_fd);
		if (ret < 0) {
			SYSERROR("Failed to prepare terminal file descriptor %d", payload->terminal_pts_fd);
			goto on_error;
		}

		TRACE("Prepared terminal file descriptor %d", payload->terminal_pts_fd);
	}

	/* Avoid unnecessary syscalls. */
	if (new_uid == ns_root_uid)
		new_uid = LXC_INVALID_UID;

	if (new_gid == ns_root_gid)
		new_gid = LXC_INVALID_GID;

	/* Make sure that the processes STDIO is correctly owned by the user that we are switching to */
	ret = fix_stdio_permissions(new_uid);
	if (ret)
		WARN("Failed to ajust stdio permissions");

	if (!lxc_switch_uid_gid(new_uid, new_gid))
		goto on_error;

	/* We're done, so we can now do whatever the user intended us to do. */
	_exit(payload->exec_function(payload->exec_payload));

on_error:
	lxc_put_attach_clone_payload(payload);
	_exit(EXIT_FAILURE);
}

static int lxc_attach_terminal(struct lxc_conf *conf,
			       struct lxc_terminal *terminal)
{
	int ret;

	lxc_terminal_init(terminal);

	ret = lxc_terminal_create(terminal);
	if (ret < 0)
		return log_error(-1, "Failed to create terminal");

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
	if (ret < 0)
		return log_error(-1, "Failed to create mainloop");

	ret = lxc_terminal_mainloop_add(descr, terminal);
	if (ret < 0) {
		lxc_mainloop_close(descr);
		return log_error(-1, "Failed to add handlers to mainloop");
	}

	return 0;
}

static inline void lxc_attach_terminal_close_ptx(struct lxc_terminal *terminal)
{
	close_prot_errno_disarm(terminal->ptx);
}

static inline void lxc_attach_terminal_close_pts(struct lxc_terminal *terminal)
{
	close_prot_errno_disarm(terminal->pty);
}

static inline void lxc_attach_terminal_close_peer(struct lxc_terminal *terminal)
{
	close_prot_errno_disarm(terminal->peer);
}

static inline void lxc_attach_terminal_close_log(struct lxc_terminal *terminal)
{
	close_prot_errno_disarm(terminal->log_fd);
}

int lxc_attach(struct lxc_container *container, lxc_attach_exec_t exec_function,
	       void *exec_payload, lxc_attach_options_t *options,
	       pid_t *attached_process)
{
	int i, ret, status;
	int ipc_sockets[2];
	char *cwd, *new_cwd;
	signed long personality;
	pid_t attached_pid, init_pid, pid;
	struct lxc_proc_context_info *init_ctx;
	struct lxc_terminal terminal;
	struct lxc_conf *conf;
	char *name, *lxcpath;
	struct attach_clone_payload payload = {0};

	ret = access("/proc/self/ns", X_OK);
	if (ret)
		return log_error_errno(-1, errno, "Does this kernel version support namespaces?");

	if (!container)
		return ret_set_errno(-1, EINVAL);

	if (!lxc_container_get(container))
		return ret_set_errno(-1, EINVAL);

	name = container->name;
	lxcpath = container->config_path;

	if (!options)
		options = &attach_static_default_options;

	init_pid = lxc_cmd_get_init_pid(name, lxcpath);
	if (init_pid < 0) {
		lxc_container_put(container);
		return log_error(-1, "Failed to get init pid");
	}

	init_ctx = lxc_proc_get_context_info(init_pid);
	if (!init_ctx) {
		ERROR("Failed to get context of init process: %ld", (long)init_pid);
		lxc_container_put(container);
		return -1;
	}

	init_ctx->container = container;

	personality = get_personality(name, lxcpath);
	if (init_ctx->personality < 0) {
		ERROR("Failed to get personality of the container");
		lxc_proc_put_context_info(init_ctx);
		return -1;
	}
	init_ctx->personality = personality;

	if (!init_ctx->container->lxc_conf) {
		init_ctx->container->lxc_conf = lxc_conf_init();
		if (!init_ctx->container->lxc_conf) {
			lxc_proc_put_context_info(init_ctx);
			return -1;
		}
	}
	conf = init_ctx->container->lxc_conf;
	if (!conf)
		return log_error_errno(-EINVAL, EINVAL, "Missing container confifg");

	if (!fetch_seccomp(init_ctx->container, options))
		WARN("Failed to get seccomp policy");

	if (!no_new_privs(init_ctx->container, options))
		WARN("Could not determine whether PR_SET_NO_NEW_PRIVS is set");

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
		int j;

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
		SYSERROR("Failed to attach to %s namespace of %d",
		         ns_info[i].proc_name, pid);

		/* Close all already opened file descriptors before we return an
		 * error, so we don't leak them.
		 */
		for (j = 0; j < i; j++)
			close(init_ctx->ns_fd[j]);

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
	 * properly, potentially causing the parent to hang.
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
		SYSERROR("Could not set up required IPC mechanism for attaching");
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
		SYSERROR("Failed to create first subprocess");
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
			lxc_attach_terminal_close_pts(&terminal);

		/* Attach to cgroup, if requested. */
		if (options->attach_flags & LXC_ATTACH_MOVE_TO_CGROUP) {
			/*
			 * If this is the unified hierarchy cgroup_attach() is
			 * enough.
			 */
			ret = cgroup_attach(conf, name, lxcpath, pid);
			if (ret) {
				call_cleaner(cgroup_exit) struct cgroup_ops *cgroup_ops = NULL;

				cgroup_ops = cgroup_init(conf);
				if (!cgroup_ops)
					goto on_error;

				if (!cgroup_ops->attach(cgroup_ops, conf, name, lxcpath, pid))
					goto on_error;
			}
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
			int labelfd;
			bool on_exec;

			ret = -1;
			on_exec = options->attach_flags & LXC_ATTACH_LSM_EXEC ? true : false;
			labelfd = lsm_process_label_fd_get(attached_pid, on_exec);
			if (labelfd < 0)
				goto close_mainloop;

			TRACE("Opened LSM label file descriptor %d", labelfd);

			/* Send child fd of the LSM security module to write to. */
			ret = lxc_abstract_unix_send_fds(ipc_sockets[0], &labelfd, 1, NULL, 0);
			if (ret <= 0) {
				if (ret < 0)
					SYSERROR("Failed to send lsm label fd");

				close(labelfd);
				goto close_mainloop;
			}

			close(labelfd);
			TRACE("Sent LSM label file descriptor %d to child", labelfd);
		}

		if (conf->seccomp.seccomp) {
			ret = lxc_seccomp_recv_notifier_fd(&conf->seccomp, ipc_sockets[0]);
			if (ret < 0)
				goto close_mainloop;

			ret = lxc_seccomp_add_notifier(name, lxcpath, &conf->seccomp);
			if (ret < 0)
				goto close_mainloop;
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
	close_prot_errno_disarm(ipc_sockets[0]);

	if (options->attach_flags & LXC_ATTACH_TERMINAL) {
		lxc_attach_terminal_close_ptx(&terminal);
		lxc_attach_terminal_close_peer(&terminal);
		lxc_attach_terminal_close_log(&terminal);
	}

	/* Wait for the parent to have setup cgroups. */
	ret = lxc_read_nointr(ipc_sockets[1], &status, sizeof(status));
	if (ret != sizeof(status)) {
		shutdown(ipc_sockets[1], SHUT_RDWR);
		lxc_proc_put_context_info(init_ctx);
		_exit(EXIT_FAILURE);
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
		_exit(EXIT_FAILURE);
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
	payload.terminal_pts_fd = terminal.pty;
	payload.exec_function = exec_function;
	payload.exec_payload = exec_payload;

	pid = lxc_raw_clone(CLONE_PARENT, NULL);
	if (pid < 0) {
		SYSERROR("Failed to clone attached process");
		shutdown(ipc_sockets[1], SHUT_RDWR);
		lxc_proc_put_context_info(init_ctx);
		_exit(EXIT_FAILURE);
	}

	if (pid == 0) {
		if (options->attach_flags & LXC_ATTACH_TERMINAL) {
			ret = pthread_sigmask(SIG_SETMASK,
					      &terminal.tty_state->oldmask, NULL);
			if (ret < 0) {
				SYSERROR("Failed to reset signal mask");
				_exit(EXIT_FAILURE);
			}
		}

		ret = attach_child_main(&payload);
		if (ret < 0)
			ERROR("Failed to exec");

		_exit(EXIT_FAILURE);
	}

	if (options->attach_flags & LXC_ATTACH_TERMINAL)
		lxc_attach_terminal_close_pts(&terminal);

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
		_exit(EXIT_FAILURE);
	}

	TRACE("Sending pid %d of attached process", pid);

	/* The rest is in the hands of the initial and the attached process. */
	lxc_proc_put_context_info(init_ctx);
	_exit(EXIT_SUCCESS);
}

int lxc_attach_run_command(void *payload)
{
	int ret = -1;
	lxc_attach_command_t *cmd = payload;

	ret = execvp(cmd->program, cmd->argv);
	if (ret < 0) {
		switch (errno) {
		case ENOEXEC:
			ret = 126;
			break;
		case ENOENT:
			ret = 127;
			break;
		}
	}

	return log_error_errno(ret, errno, "Failed to exec \"%s\"", cmd->program);
}

int lxc_attach_run_shell(void* payload)
{
	__do_free char *buf = NULL;
	uid_t uid;
	struct passwd pwent;
	struct passwd *pwentp = NULL;
	char *user_shell;
	size_t bufsize;
	int ret;

	/* Ignore payload parameter. */
	(void)payload;

	uid = getuid();

	bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (bufsize == -1)
		bufsize = 1024;

	buf = malloc(bufsize);
	if (buf) {
		ret = getpwuid_r(uid, &pwent, buf, bufsize, &pwentp);
		if (!pwentp) {
			if (ret == 0)
				WARN("Could not find matched password record");

			WARN("Failed to get password record - %u", uid);
		}
	}

	/* This probably happens because of incompatible nss implementations in
	 * host and container (remember, this code is still using the host's
	 * glibc but our mount namespace is in the container) we may try to get
	 * the information by spawning a [getent passwd uid] process and parsing
	 * the result.
	 */
	if (!pwentp)
		user_shell = lxc_attach_getpwshell(uid);
	else
		user_shell = pwent.pw_shell;

	if (user_shell)
		execlp(user_shell, user_shell, (char *)NULL);

	/* Executed if either no passwd entry or execvp fails, we will fall back
	 * on /bin/sh as a default shell.
	 */
	execlp("/bin/sh", "/bin/sh", (char *)NULL);

	SYSERROR("Failed to execute shell");
	if (!pwentp)
		free(user_shell);

	return -1;
}

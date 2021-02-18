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
#include "sync.h"
#include "syscall_wrappers.h"
#include "terminal.h"
#include "utils.h"

#if HAVE_SYS_PERSONALITY_H
#include <sys/personality.h>
#endif

lxc_log_define(attach, lxc);

/* Define default options if no options are supplied by the user. */
static lxc_attach_options_t attach_static_default_options = LXC_ATTACH_OPTIONS_DEFAULT;

/*
 * The context used to attach to the container.
 * @attach_flags    : the attach flags specified in lxc_attach_options_t
 * @init_pid        : the PID of the container's init process
 * @dfd_init_pid    : file descriptor to /proc/@init_pid
 *                    __Must be closed in attach_context_security_barrier()__!
 * @dfd_self_pid    : file descriptor to /proc/self
 *                    __Must be closed in attach_context_security_barrier()__!
 * @setup_ns_uid    : if CLONE_NEWUSER is specified will contain the uid used
 *                    during attach setup.
 * @setup_ns_gid    : if CLONE_NEWUSER is specified will contain the gid used
 *                    during attach setup.
 * @target_ns_uid   : if CLONE_NEWUSER is specified the uid that the final
 *                    program will be run with.
 * @target_ns_gid   : if CLONE_NEWUSER is specified the gid that the final
 *                    program will be run with.
 * @target_host_uid : if CLONE_NEWUSER is specified the uid that the final
 *                    program will be run with on the host.
 * @target_host_gid : if CLONE_NEWUSER is specified the gid that the final
 *                    program will be run with on the host.
 * @lsm_label       : LSM label to be used for the attaching process
 * @container       : the container we're attaching o
 * @personality     : the personality to use for the final program
 * @capability      : the capability mask of the @init_pid
 * @ns_inherited    : flags of namespaces that the final program will inherit
 *                    from @init_pid
 * @ns_fd           : file descriptors to @init_pid's namespaces
 */
struct attach_context {
	unsigned int attach_flags;
	int init_pid;
	int dfd_init_pid;
	int dfd_self_pid;
	uid_t setup_ns_uid;
	gid_t setup_ns_gid;
	uid_t target_ns_uid;
	gid_t target_ns_gid;
	uid_t target_host_uid;
	uid_t target_host_gid;
	char *lsm_label;
	struct lxc_container *container;
	signed long personality;
	unsigned long long capability_mask;
	int ns_inherited;
	int ns_fd[LXC_NS_MAX];
	struct lsm_ops *lsm_ops;
};

static pid_t pidfd_get_pid(int pidfd)
{
	__do_free char *line = NULL;
	__do_fclose FILE *f = NULL;
	size_t len = 0;
	char path[STRLITERALLEN("/proc/self/fdinfo/") +
		  INTTYPE_TO_STRLEN(int) + 1 ] = "/proc/self/fdinfo/";
	int ret;

	if (pidfd < 0)
		return -EBADF;

	ret = snprintf(path + STRLITERALLEN("/proc/self/fdinfo/"),
			INTTYPE_TO_STRLEN(int), "%d", pidfd);
	if (ret < 0 || ret > (size_t)INTTYPE_TO_STRLEN(int))
		return ret_errno(EIO);

	f = fopen_cloexec(path, "re");
	if (!f)
		return -errno;

	while (getline(&line, &len, f) != -1) {
		const char *prefix = "Pid:\t";
		const size_t prefix_len = STRLITERALLEN("Pid:\t");
		int pid = -ESRCH;
		char *slider = line;

		if (strncmp(slider, prefix, prefix_len))
			continue;

		slider += prefix_len;
		slider = lxc_trim_whitespace_in_place(slider);

		ret = lxc_safe_int(slider, &pid);
		if (ret)
			return -ret;

		return pid;
	}

	return ret_errno(ENOENT);
}

static inline bool sync_wake_pid(int fd, pid_t pid)
{
	return lxc_write_nointr(fd, &pid, sizeof(pid_t)) == sizeof(pid_t);
}

static inline bool sync_wait_pid(int fd, pid_t *pid)
{
	return lxc_read_nointr(fd, pid, sizeof(pid_t)) == sizeof(pid_t);
}

static inline bool sync_wake_fd(int fd, int fd_send)
{
	return lxc_abstract_unix_send_fds(fd, &fd_send, 1, NULL, 0) > 0;
}

static inline bool sync_wait_fd(int fd, int *fd_recv)
{
	return lxc_abstract_unix_recv_fds(fd, fd_recv, 1, NULL, 0) > 0;
}

static bool attach_lsm(lxc_attach_options_t *options)
{
	return (options->namespaces & CLONE_NEWNS) &&
	       (options->attach_flags & (LXC_ATTACH_LSM | LXC_ATTACH_LSM_LABEL));
}

static struct attach_context *alloc_attach_context(void)
{
	struct attach_context *ctx;

	ctx = zalloc(sizeof(struct attach_context));
	if (!ctx)
		return ret_set_errno(NULL, ENOMEM);

	ctx->dfd_self_pid = -EBADF;
	ctx->dfd_init_pid = -EBADF;
	ctx->init_pid = -ESRCH;
	ctx->setup_ns_uid = LXC_INVALID_UID;
	ctx->setup_ns_gid = LXC_INVALID_GID;
	ctx->target_ns_uid = LXC_INVALID_UID;
	ctx->target_ns_gid = LXC_INVALID_GID;
	ctx->target_host_uid = LXC_INVALID_UID;
	ctx->target_host_gid = LXC_INVALID_GID;

	for (int i = 0; i < LXC_NS_MAX; i++)
		ctx->ns_fd[i] = -EBADF;

	return ctx;
}

static int get_personality(const char *name, const char *lxcpath,
			   signed long *personality)
{
	__do_free char *p = NULL;
	signed long per;

	p = lxc_cmd_get_config_item(name, "lxc.arch", lxcpath);
	if (!p) {
		*personality = LXC_ARCH_UNCHANGED;
		return 0;
	}

	per = lxc_config_parse_arch(p);
	if (per == LXC_ARCH_UNCHANGED)
		return ret_errno(EINVAL);

	*personality = per;
	return 0;
}

static int userns_setup_ids(struct attach_context *ctx,
			    lxc_attach_options_t *options)
{
	__do_free char *line = NULL;
	__do_fclose FILE *f_gidmap = NULL, *f_uidmap = NULL;
	size_t len = 0;
	uid_t init_ns_uid = LXC_INVALID_UID;
	gid_t init_ns_gid = LXC_INVALID_GID;
	uid_t nsuid, hostuid, range_uid;
	gid_t nsgid, hostgid, range_gid;

	if (!(options->namespaces & CLONE_NEWUSER))
		return 0;

	f_uidmap = fdopen_at(ctx->dfd_init_pid, "uid_map", "re", PROTECT_OPEN, PROTECT_LOOKUP_ABSOLUTE);
	if (!f_uidmap)
		return log_error_errno(-errno, errno, "Failed to open uid_map");

	while (getline(&line, &len, f_uidmap) != -1) {
		if (sscanf(line, "%u %u %u", &nsuid, &hostuid, &range_uid) != 3)
			continue;

		if (0 >= nsuid && 0 < nsuid + range_uid) {
			ctx->setup_ns_uid = 0;
			TRACE("Container has mapping for uid 0");
			break;
		}

		if (ctx->target_host_uid >= hostuid && ctx->target_host_uid < hostuid + range_uid) {
			init_ns_uid = (ctx->target_host_uid - hostuid) + nsuid;
			TRACE("Container runs with uid %d", init_ns_uid);
		}
	}

	f_gidmap = fdopen_at(ctx->dfd_init_pid, "gid_map", "re", PROTECT_OPEN, PROTECT_LOOKUP_ABSOLUTE);
	if (!f_gidmap)
		return log_error_errno(-errno, errno, "Failed to open gid_map");

	while (getline(&line, &len, f_gidmap) != -1) {
		if (sscanf(line, "%u %u %u", &nsgid, &hostgid, &range_gid) != 3)
			continue;

		if (0 >= nsgid && 0 < nsgid + range_gid) {
			ctx->setup_ns_gid = 0;
			TRACE("Container has mapping for gid 0");
			break;
		}

		if (ctx->target_host_gid >= hostgid && ctx->target_host_gid < hostgid + range_gid) {
			init_ns_gid = (ctx->target_host_gid - hostgid) + nsgid;
			TRACE("Container runs with gid %d", init_ns_gid);
		}
	}

	if (ctx->setup_ns_uid == LXC_INVALID_UID)
		ctx->setup_ns_uid = init_ns_uid;

	if (ctx->setup_ns_gid == LXC_INVALID_UID)
		ctx->setup_ns_gid = init_ns_gid;

	/*
	 * TODO: we should also parse supplementary groups and use
	 * setgroups() to set them.
	 */

	return 0;
}

static void userns_target_ids(struct attach_context *ctx, lxc_attach_options_t *options)
{
	if (options->uid != LXC_INVALID_UID)
		ctx->target_ns_uid = options->uid;
	else if (options->namespaces & CLONE_NEWUSER)
		ctx->target_ns_uid = ctx->setup_ns_uid;
	else
		ctx->target_ns_uid = 0;

	if (ctx->target_ns_uid == LXC_INVALID_UID)
		WARN("Invalid uid specified");

	if (options->gid != LXC_INVALID_GID)
		ctx->target_ns_gid = options->gid;
	else if (options->namespaces & CLONE_NEWUSER)
		ctx->target_ns_gid = ctx->setup_ns_gid;
	else
		ctx->target_ns_gid = 0;

	if (ctx->target_ns_gid == LXC_INVALID_GID)
		WARN("Invalid gid specified");
}

static int parse_init_status(struct attach_context *ctx, lxc_attach_options_t *options)
{
	__do_free char *line = NULL;
	__do_fclose FILE *f = NULL;
	size_t len = 0;
	bool caps_found = false;
	int ret;

	f = fdopen_at(ctx->dfd_init_pid, "status", "re", PROTECT_OPEN, PROTECT_LOOKUP_ABSOLUTE);
	if (!f)
		return log_error_errno(-errno, errno, "Failed to open status file");

	while (getline(&line, &len, f) != -1) {
		signed long value = -1;

		/*
		 * Format is: real, effective, saved set user, fs we only care
		 * about real uid.
		 */
		ret = sscanf(line, "Uid: %ld", &value);
		if (ret != EOF && ret == 1) {
			ctx->target_host_uid = (uid_t)value;
			TRACE("Container's init process runs with hostuid %d", ctx->target_host_uid);
			goto next;
		}

		ret = sscanf(line, "Gid: %ld", &value);
		if (ret != EOF && ret == 1) {
			ctx->target_host_gid = (gid_t)value;
			TRACE("Container's init process runs with hostgid %d", ctx->target_host_gid);
			goto next;
		}

		ret = sscanf(line, "CapBnd: %llx", &ctx->capability_mask);
		if (ret != EOF && ret == 1) {
			caps_found = true;
			goto next;
		}

        next:
		if (ctx->target_host_uid != LXC_INVALID_UID &&
		    ctx->target_host_gid != LXC_INVALID_GID &&
		    caps_found)
			break;

	}

	ret = userns_setup_ids(ctx, options);
	if (ret)
		return log_error_errno(ret, errno, "Failed to get setup ids");
	userns_target_ids(ctx, options);

	/*
	 * TODO: we should also parse supplementary groups and use
	 * setgroups() to set them.
	 */

	return 0;
}

static int get_attach_context(struct attach_context *ctx,
			      struct lxc_container *container,
			      lxc_attach_options_t *options)
{
	__do_close int init_pidfd = -EBADF;
	__do_free char *lsm_label = NULL;
	int ret;
	char path[LXC_PROC_PID_LEN];

	ctx->container = container;
	ctx->attach_flags = options->attach_flags;

	init_pidfd = lxc_cmd_get_init_pidfd(container->name, container->config_path);
	if (init_pidfd >= 0)
		ctx->init_pid = pidfd_get_pid(init_pidfd);
	else
		ctx->init_pid = lxc_cmd_get_init_pid(container->name, container->config_path);

	if (ctx->init_pid < 0)
		return log_error(-1, "Failed to get init pid");

	ctx->dfd_self_pid = open_at(-EBADF, "/proc/self",
				    PROTECT_OPATH_FILE & ~O_NOFOLLOW,
				    (PROTECT_LOOKUP_ABSOLUTE_WITH_SYMLINKS & ~RESOLVE_NO_XDEV), 0);
	if (ctx->dfd_self_pid < 0)
		return log_error_errno(-errno, errno, "Failed to open /proc/self");

	ret = snprintf(path, sizeof(path), "/proc/%d", ctx->init_pid);
	if (ret < 0 || ret >= sizeof(path))
		return ret_errno(EIO);

	ctx->dfd_init_pid = open_at(-EBADF, path,
				    PROTECT_OPATH_DIRECTORY,
				    (PROTECT_LOOKUP_ABSOLUTE & ~RESOLVE_NO_XDEV), 0);
	if (ctx->dfd_init_pid < 0)
		return log_error_errno(-errno, errno, "Failed to open /proc/%d", ctx->init_pid);

	if (init_pidfd >= 0) {
		ret = lxc_raw_pidfd_send_signal(init_pidfd, 0, NULL, 0);
		if (ret)
			return log_error_errno(-errno, errno, "Container process exited or PID has been recycled");
		else
			TRACE("Container process still running and PID was not recycled");
	}

	/* Determine which namespaces the container was created with. */
	if (options->namespaces == -1) {
		options->namespaces = lxc_cmd_get_clone_flags(container->name, container->config_path);
		if (options->namespaces == -1)
			return log_error_errno(-EINVAL, EINVAL, "Failed to automatically determine the namespaces which the container uses");

		for (int i = 0; i < LXC_NS_MAX; i++) {
			if (ns_info[i].clone_flag & CLONE_NEWCGROUP)
				if (!(options->attach_flags & LXC_ATTACH_MOVE_TO_CGROUP) ||
				    !cgns_supported())
					continue;

			if (ns_info[i].clone_flag & options->namespaces)
				continue;

			ctx->ns_inherited |= ns_info[i].clone_flag;
		}
	}

	ret = parse_init_status(ctx, options);
	if (ret)
		return log_error_errno(-errno, errno, "Failed to open parse file");

	ctx->lsm_ops = lsm_init_static();

	if (attach_lsm(options)) {
		if (ctx->attach_flags & LXC_ATTACH_LSM_LABEL)
			lsm_label = options->lsm_label;
		else
			lsm_label = ctx->lsm_ops->process_label_get_at(ctx->lsm_ops, ctx->dfd_init_pid);
		if (!lsm_label)
			WARN("No security context received");
		else
			INFO("Retrieved security context %s", lsm_label);
	}
	ctx->ns_inherited = 0;

	ret = get_personality(container->name, container->config_path, &ctx->personality);
	if (ret)
		return log_error_errno(ret, errno, "Failed to get personality of the container");

	if (!ctx->container->lxc_conf) {
		ctx->container->lxc_conf = lxc_conf_init();
		if (!ctx->container->lxc_conf)
			return log_error_errno(-ENOMEM, ENOMEM, "Failed to allocate new lxc config");
	}

	ctx->lsm_label = move_ptr(lsm_label);
	return 0;
}

static int same_ns(int ns_fd_pid1, int ns_fd_pid2, const char *ns_path)
{
	__do_close int ns_fd1 = -EBADF, ns_fd2 = -EBADF;
	int ret = -1;
	struct stat ns_st1, ns_st2;

	ns_fd1 = open_at(ns_fd_pid1, ns_path,
			 PROTECT_OPEN_WITH_TRAILING_SYMLINKS,
			 (PROTECT_LOOKUP_BENEATH_WITH_MAGICLINKS & ~(RESOLVE_NO_XDEV | RESOLVE_BENEATH)),
			 0);
	if (ns_fd1 < 0) {
		/* The kernel does not support this namespace. This is not an error. */
		if (errno == ENOENT)
			return -EINVAL;

		return log_error_errno(-errno, errno, "Failed to open %d(%s)", ns_fd_pid1, ns_path);
	}

	ns_fd2 = open_at(ns_fd_pid2, ns_path,
			 PROTECT_OPEN_WITH_TRAILING_SYMLINKS,
			 (PROTECT_LOOKUP_BENEATH_WITH_MAGICLINKS & ~(RESOLVE_NO_XDEV | RESOLVE_BENEATH)),
			 0);
	if (ns_fd2 < 0)
		return log_error_errno(-errno, errno, "Failed to open %d(%s)", ns_fd_pid2, ns_path);

	ret = fstat(ns_fd1, &ns_st1);
	if (ret < 0)
		return -1;

	ret = fstat(ns_fd2, &ns_st2);
	if (ret < 0)
		return -1;

	/* processes are in the same namespace */
        if ((ns_st1.st_dev == ns_st2.st_dev) &&
            (ns_st1.st_ino == ns_st2.st_ino))
		return -EINVAL;

	/* processes are in different namespaces */
	return move_fd(ns_fd2);
}

static int get_attach_context_nsfds(struct attach_context *ctx,
				    lxc_attach_options_t *options)
{
	for (int i = 0; i < LXC_NS_MAX; i++) {
		int j;

		if (options->namespaces & ns_info[i].clone_flag)
			ctx->ns_fd[i] = open_at(ctx->dfd_init_pid,
						ns_info[i].proc_path,
						PROTECT_OPEN_WITH_TRAILING_SYMLINKS,
						(PROTECT_LOOKUP_BENEATH_WITH_MAGICLINKS & ~(RESOLVE_NO_XDEV | RESOLVE_BENEATH)),
						0);
		else if (ctx->ns_inherited & ns_info[i].clone_flag)
			ctx->ns_fd[i] = same_ns(ctx->dfd_self_pid,
						ctx->dfd_init_pid,
						ns_info[i].proc_path);
		else
			continue;

		if (ctx->ns_fd[i] >= 0)
			continue;

		if (ctx->ns_fd[i] == -EINVAL) {
			DEBUG("Inheriting %s namespace", ns_info[i].proc_name);
			ctx->ns_inherited &= ~ns_info[i].clone_flag;
			continue;
		}

		/* We failed to preserve the namespace. */
		SYSERROR("Failed to preserve %s namespace of %d", ns_info[i].proc_name, ctx->init_pid);

		/* Close all already opened file descriptors before we return an
		 * error, so we don't leak them.
		 */
		for (j = 0; j < i; j++)
			close_prot_errno_disarm(ctx->ns_fd[j]);

		return -1;
	}

	return 0;
}

static inline void close_nsfds(struct attach_context *ctx)
{
	for (int i = 0; i < LXC_NS_MAX; i++)
		close_prot_errno_disarm(ctx->ns_fd[i]);
}

static void put_attach_context(struct attach_context *ctx)
{
	if (ctx) {
		if (!(ctx->attach_flags & LXC_ATTACH_LSM_LABEL))
			free_disarm(ctx->lsm_label);
		close_prot_errno_disarm(ctx->dfd_init_pid);

		if (ctx->container) {
			lxc_container_put(ctx->container);
			ctx->container = NULL;
		}

		close_nsfds(ctx);
		free(ctx);
	}
}

static int attach_context_container(struct attach_context *ctx)
{
	for (int i = 0; i < LXC_NS_MAX; i++) {
		int ret;

		if (ctx->ns_fd[i] < 0)
			continue;

		ret = setns(ctx->ns_fd[i], ns_info[i].clone_flag);
		if (ret < 0)
			return log_error_errno(-1, errno,
					       "Failed to attach to %s namespace of %d",
					       ns_info[i].proc_name, ctx->init_pid);

		DEBUG("Attached to %s namespace of %d",
		ns_info[i].proc_name, ctx->init_pid);
	}

	return 0;
}

/*
 * Place anything in here that needs to be get rid of before we move into the
 * container's context and fail hard if we can't.
 */
static bool attach_context_security_barrier(struct attach_context *ctx)
{
	if (ctx) {
		if (close(ctx->dfd_self_pid))
			return false;
		ctx->dfd_self_pid = -EBADF;

		if (close(ctx->dfd_init_pid))
			return false;
		ctx->dfd_init_pid = -EBADF;
	}

	return true;
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

static int drop_capabilities(struct attach_context *ctx)
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

static int lxc_attach_set_environment(struct attach_context *ctx,
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

			extra_keep_store = zalloc(count * sizeof(char *));
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
	if (ctx->container->lxc_conf) {
		lxc_list_for_each(iterator, &ctx->container->lxc_conf->environment) {
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

static bool fetch_seccomp(struct lxc_container *c, lxc_attach_options_t *options)
{
	__do_free char *path = NULL;
	int ret;
	bool bret;

	if (!attach_lsm(options)) {
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

struct attach_payload {
	int ipc_socket;
	int terminal_pts_fd;
	lxc_attach_options_t *options;
	struct attach_context *ctx;
	lxc_attach_exec_t exec_function;
	void *exec_payload;
};

static void put_attach_payload(struct attach_payload *p)
{
	if (p) {
		close_prot_errno_disarm(p->ipc_socket);
		close_prot_errno_disarm(p->terminal_pts_fd);
		put_attach_context(p->ctx);
		p->ctx = NULL;
	}
}

__noreturn static void do_attach(struct attach_payload *ap)
{
	lxc_attach_exec_t attach_function = move_ptr(ap->exec_function);
	void *attach_function_args = move_ptr(ap->exec_payload);
	int lsm_fd, ret;
	lxc_attach_options_t* options = ap->options;
        struct attach_context *ctx = ap->ctx;
        struct lxc_conf *conf = ctx->container->lxc_conf;

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
			new_personality = ctx->personality;
		else
			new_personality = options->personality;

		if (new_personality != LXC_ARCH_UNCHANGED) {
			ret = personality(new_personality);
			if (ret < 0)
				goto on_error;

			TRACE("Set new personality");
		}
	}
#endif

	if (options->attach_flags & LXC_ATTACH_DROP_CAPABILITIES) {
		ret = drop_capabilities(ctx);
		if (ret < 0)
			goto on_error;

		TRACE("Dropped capabilities");
	}

	/* Always set the environment (specify (LXC_ATTACH_KEEP_ENV, NULL, NULL)
	 * if you want this to be a no-op).
	 */
	ret = lxc_attach_set_environment(ctx,
					 options->env_policy,
					 options->extra_env_vars,
					 options->extra_keep_env);
	if (ret < 0)
		goto on_error;

	TRACE("Set up environment");

	/*
	 * This remark only affects fully unprivileged containers:
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
	if (attach_lsm(options) && ctx->lsm_label) {
		if (!sync_wait_fd(ap->ipc_socket, ATTACH_SYNC_LSM(&lsm_fd))) {
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

	if (options->namespaces & CLONE_NEWUSER)
		if (!lxc_switch_uid_gid(ctx->setup_ns_uid, ctx->setup_ns_gid))
			goto on_error;

	if (attach_lsm(options) && ctx->lsm_label) {
		bool on_exec;

		/* Change into our new LSM profile. */
		on_exec = options->attach_flags & LXC_ATTACH_LSM_EXEC ? true : false;
		ret = ctx->lsm_ops->process_label_set_at(ctx->lsm_ops, lsm_fd, ctx->lsm_label, on_exec);
		close_prot_errno_disarm(lsm_fd);
		if (ret < 0)
			goto on_error;

		TRACE("Set %s LSM label to \"%s\"", ctx->lsm_ops->name, ctx->lsm_label);
	}

	if (conf->no_new_privs || (options->attach_flags & LXC_ATTACH_NO_NEW_PRIVS)) {
		ret = prctl(PR_SET_NO_NEW_PRIVS, prctl_arg(1), prctl_arg(0),
			    prctl_arg(0), prctl_arg(0));
		if (ret < 0)
			goto on_error;

		TRACE("Set PR_SET_NO_NEW_PRIVS");
	}

	if (conf->seccomp.seccomp) {
		ret = lxc_seccomp_load(conf);
		if (ret < 0)
			goto on_error;

		TRACE("Loaded seccomp profile");

		ret = lxc_seccomp_send_notifier_fd(&conf->seccomp, ap->ipc_socket);
		if (ret < 0)
			goto on_error;
	}

	/* The following is done after the communication socket is shut down.
	 * That way, all errors that might (though unlikely) occur up until this
	 * point will have their messages printed to the original stderr (if
	 * logging is so configured) and not the fd the user supplied, if any.
	 */

	/* Fd handling for stdin, stdout and stderr; ignore errors here, user
	 * may want to make sure the fds are closed, for example.
	 */
	if (options->stdin_fd >= 0 && options->stdin_fd != STDIN_FILENO)
		if (dup2(options->stdin_fd, STDIN_FILENO) < 0)
			SYSDEBUG("Failed to replace stdin with %d", options->stdin_fd);

	if (options->stdout_fd >= 0 && options->stdout_fd != STDOUT_FILENO)
		if (dup2(options->stdout_fd, STDOUT_FILENO) < 0)
			SYSDEBUG("Failed to replace stdout with %d", options->stdout_fd);

	if (options->stderr_fd >= 0 && options->stderr_fd != STDERR_FILENO)
		if (dup2(options->stderr_fd, STDERR_FILENO) < 0)
			SYSDEBUG("Failed to replace stderr with %d", options->stderr_fd);

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
		ret = lxc_terminal_prepare_login(ap->terminal_pts_fd);
		if (ret < 0) {
			SYSERROR("Failed to prepare terminal file descriptor %d", ap->terminal_pts_fd);
			goto on_error;
		}

		TRACE("Prepared terminal file descriptor %d", ap->terminal_pts_fd);
	}

	put_attach_payload(ap);

	/* Avoid unnecessary syscalls. */
	if (ctx->setup_ns_uid == ctx->target_ns_uid)
		ctx->target_ns_uid = LXC_INVALID_UID;

	if (ctx->setup_ns_gid == ctx->target_ns_gid)
		ctx->target_ns_gid = LXC_INVALID_GID;

	/*
	 * Make sure that the processes STDIO is correctly owned by the user
	 * that we are switching to.
	 */
	ret = fix_stdio_permissions(ctx->target_ns_uid);
	if (ret)
		INFO("Failed to adjust stdio permissions");

	if (!lxc_switch_uid_gid(ctx->target_ns_uid, ctx->target_ns_gid))
		goto on_error;

	/* We're done, so we can now do whatever the user intended us to do. */
	_exit(attach_function(attach_function_args));

on_error:
	ERROR("Failed to attach to container");
	_exit(EXIT_FAILURE);
}

static int lxc_attach_terminal(const char *name, const char *lxcpath, struct lxc_conf *conf,
			       struct lxc_terminal *terminal)
{
	int ret;

	lxc_terminal_init(terminal);

	ret = lxc_terminal_create(name, lxcpath, conf, terminal);
	if (ret < 0)
		return log_error(-1, "Failed to create terminal");

	return 0;
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
	int ret_parent = -1;
	struct lxc_epoll_descr descr = {};
	int ret;
	char *name, *lxcpath;
	int ipc_sockets[2];
	pid_t attached_pid, pid, to_cleanup_pid;
	struct attach_context *ctx;
	struct lxc_terminal terminal;
	struct lxc_conf *conf;

	if (!container)
		return ret_set_errno(-1, EINVAL);

	if (!lxc_container_get(container))
		return ret_set_errno(-1, EINVAL);

	name = container->name;
	lxcpath = container->config_path;

	if (!options) {
		options = &attach_static_default_options;
		options->lsm_label = NULL;
	}

	ctx = alloc_attach_context();
	if (!ctx) {
		lxc_container_put(container);
		return log_error_errno(-ENOMEM, ENOMEM, "Failed to allocate attach context");
	}

	ret = get_attach_context(ctx, container, options);
	if (ret) {
		put_attach_context(ctx);
		return log_error(-1, "Failed to get attach context");
	}

	conf = ctx->container->lxc_conf;

	if (!fetch_seccomp(ctx->container, options))
		WARN("Failed to get seccomp policy");

	if (!no_new_privs(ctx->container, options))
		WARN("Could not determine whether PR_SET_NO_NEW_PRIVS is set");

	ret = get_attach_context_nsfds(ctx, options);
	if (ret) {
		lxc_container_put(container);
		return log_error(-1, "Failed to get namespace file descriptors");
	}

	if (options->attach_flags & LXC_ATTACH_TERMINAL) {
		ret = lxc_attach_terminal(name, lxcpath, conf, &terminal);
		if (ret < 0) {
			put_attach_context(ctx);
			return log_error(-1, "Failed to setup new terminal");
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
		put_attach_context(ctx);
		return log_error_errno(-1, errno, "Could not set up required IPC mechanism for attaching");
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
		put_attach_context(ctx);
		return log_error_errno(-1, errno, "Failed to create first subprocess");
	}

	if (pid == 0) {
		char *cwd, *new_cwd;

		/* close unneeded file descriptors */
		close_prot_errno_disarm(ipc_sockets[0]);

		if (options->attach_flags & LXC_ATTACH_TERMINAL) {
			lxc_attach_terminal_close_ptx(&terminal);
			lxc_attach_terminal_close_peer(&terminal);
			lxc_attach_terminal_close_log(&terminal);
		}

		/* Wait for the parent to have setup cgroups. */
		if (!sync_wait(ipc_sockets[1], ATTACH_SYNC_CGROUP)) {
			shutdown(ipc_sockets[1], SHUT_RDWR);
			put_attach_context(ctx);
			_exit(EXIT_FAILURE);
		}

		if (!attach_context_security_barrier(ctx)) {
			shutdown(ipc_sockets[1], SHUT_RDWR);
			put_attach_context(ctx);
			_exit(EXIT_FAILURE);
		}

		TRACE("Intermediate process starting to initialize");

		cwd = getcwd(NULL, 0);

		/*
		 * Attach now, create another subprocess later, since pid
		 * namespaces only really affect the children of the current
		 * process.
		 *
		 * Note that this is a crucial barrier. We're no moving into
		 * the container's context so we need to make sure to not leak
		 * anything sensitive. That especially means things such as
		 * open file descriptors!
		 */
		ret = attach_context_container(ctx);
		if (ret < 0) {
			ERROR("Failed to enter namespaces");
			shutdown(ipc_sockets[1], SHUT_RDWR);
			put_attach_context(ctx);
			_exit(EXIT_FAILURE);
		}

		/* close namespace file descriptors */
		close_nsfds(ctx);

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
		free_disarm(cwd);

		/* Create attached process. */
		pid = lxc_raw_clone(CLONE_PARENT, NULL);
		if (pid < 0) {
			SYSERROR("Failed to clone attached process");
			shutdown(ipc_sockets[1], SHUT_RDWR);
			put_attach_context(ctx);
			_exit(EXIT_FAILURE);
		}

		if (pid == 0) {
			struct attach_payload ap = {
				.ipc_socket		= ipc_sockets[1],
				.options		= options,
				.ctx			= ctx,
				.terminal_pts_fd	= terminal.pty,
				.exec_function		= exec_function,
				.exec_payload		= exec_payload,
			};

			if (options->attach_flags & LXC_ATTACH_TERMINAL) {
				ret = lxc_terminal_signal_sigmask_safe_blocked(&terminal);
				if (ret < 0) {
					SYSERROR("Failed to reset signal mask");
					_exit(EXIT_FAILURE);
				}
			}

			/* Does not return. */
			do_attach(&ap);
		}

		if (options->attach_flags & LXC_ATTACH_TERMINAL)
			lxc_attach_terminal_close_pts(&terminal);

		/* Tell grandparent the pid of the pid of the newly created child. */
		if (!sync_wake_pid(ipc_sockets[1], ATTACH_SYNC_PID(pid))) {
			/* If this really happens here, this is very unfortunate, since
			 * the parent will not know the pid of the attached process and
			 * will not be able to wait for it (and we won't either due to
			 * CLONE_PARENT) so the parent won't be able to reap it and the
			 * attached process will remain a zombie.
			 */
			shutdown(ipc_sockets[1], SHUT_RDWR);
			put_attach_context(ctx);
			_exit(EXIT_FAILURE);
		}

		TRACE("Sending pid %d of attached process", pid);

		/* The rest is in the hands of the initial and the attached process. */
		put_attach_context(ctx);
		_exit(EXIT_SUCCESS);
	}

	to_cleanup_pid = pid;

	/* close unneeded file descriptors */
	close_prot_errno_disarm(ipc_sockets[1]);
	close_nsfds(ctx);
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

		TRACE("Setup /proc/%d settings", pid);
	}

	/* Setup resource limits */
	if (!lxc_list_empty(&conf->limits)) {
		ret = setup_resource_limits(&conf->limits, pid);
		if (ret < 0)
			goto on_error;

		TRACE("Setup resource limits");
	}

	if (options->attach_flags & LXC_ATTACH_TERMINAL) {
		ret = lxc_attach_terminal_mainloop_init(&terminal, &descr);
		if (ret < 0)
			goto on_error;

		TRACE("Initialized terminal mainloop");
	}

	/* Let the child process know to go ahead. */
	if (!sync_wake(ipc_sockets[0], ATTACH_SYNC_CGROUP))
		goto close_mainloop;

	TRACE("Told intermediate process to start initializing");

	/* Get pid of attached process from intermediate process. */
	if (!sync_wait_pid(ipc_sockets[0], ATTACH_SYNC_PID(&attached_pid)))
		goto close_mainloop;

	TRACE("Received pid %d of attached process in parent pid namespace", attached_pid);

	/* Ignore SIGKILL (CTRL-C) and SIGQUIT (CTRL-\) - issue #313. */
	if (options->stdin_fd == STDIN_FILENO) {
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
	if (attach_lsm(options) && ctx->lsm_label) {
		__do_close int labelfd = -EBADF;
		bool on_exec;

		on_exec = options->attach_flags & LXC_ATTACH_LSM_EXEC ? true : false;
		labelfd = ctx->lsm_ops->process_label_fd_get(ctx->lsm_ops, attached_pid, on_exec);
		if (labelfd < 0)
			goto close_mainloop;

		TRACE("Opened LSM label file descriptor %d", labelfd);

		/* Send child fd of the LSM security module to write to. */
		if (!sync_wake_fd(ipc_sockets[0], ATTACH_SYNC_LSM(labelfd))) {
			SYSERROR("Failed to send lsm label fd");
			goto close_mainloop;
		}

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
	close_prot_errno_disarm(ipc_sockets[0]);

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
		close_prot_errno_disarm(ipc_sockets[0]);
	}

	if (to_cleanup_pid > 0)
		(void)wait_for_pid(to_cleanup_pid);

	if (options->attach_flags & LXC_ATTACH_TERMINAL) {
		lxc_terminal_delete(&terminal);
		lxc_terminal_conf_free(&terminal);
	}

	put_attach_context(ctx);
	return ret_parent;
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

/* SPDX-License-Identifier: LGPL-2.1+ */

#include "config.h"

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

#include "attach.h"

#include "af_unix.h"
#include "attach.h"
#include "caps.h"
#include "cgroups/cgroup.h"
#include "cgroups/cgroup_utils.h"
#include "commands.h"
#include "conf.h"
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
#include "open_utils.h"
#include "process_utils.h"
#include "sync.h"
#include "syscall_wrappers.h"
#include "terminal.h"
#include "utils.h"

lxc_log_define(attach, lxc);

/* Define default options if no options are supplied by the user. */
static lxc_attach_options_t attach_static_default_options = LXC_ATTACH_OPTIONS_DEFAULT;

/*
 * The context used to attach to the container.
 * @attach_flags	: the attach flags specified in lxc_attach_options_t
 * @init_pid        	: the PID of the container's init process
 * @dfd_init_pid    	: file descriptor to /proc/@init_pid
 *                  	  __Must be closed in attach_context_security_barrier()__!
 * @dfd_self_pid    	: file descriptor to /proc/self
 *                  	  __Must be closed in attach_context_security_barrier()__!
 * @setup_ns_uid    	: if CLONE_NEWUSER is specified will contain the uid used
 *                  	  during attach setup.
 * @setup_ns_gid    	: if CLONE_NEWUSER is specified will contain the gid used
 *                  	  during attach setup.
 * @target_ns_uid   	: if CLONE_NEWUSER is specified the uid that the final
 *                  	  program will be run with.
 * @target_ns_gid   	: if CLONE_NEWUSER is specified the gid that the final
 *                  	  program will be run with.
 * @target_host_uid 	: if CLONE_NEWUSER is specified the uid that the final
 *                  	  program will be run with on the host.
 * @target_host_gid 	: if CLONE_NEWUSER is specified the gid that the final
 *                  	  program will be run with on the host.
 * @lsm_label       	: LSM label to be used for the attaching process
 * @container       	: the container we're attaching o
 * @personality     	: the personality to use for the final program
 * @capability      	: the capability mask of the @init_pid
 * @ns_inherited    	: flags of namespaces that the final program will inherit
 *                  	  from @init_pid
 * @ns_fd           	: file descriptors to @init_pid's namespaces
 * @core_sched_cookie	: core scheduling cookie
 */
struct attach_context {
	unsigned int ns_clone_flags;
	unsigned int attach_flags;
	int init_pid;
	int init_pidfd;
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
	personality_t personality;
	unsigned long long capability_mask;
	int ns_inherited;
	int ns_fd[LXC_NS_MAX];
	struct lsm_ops *lsm_ops;
	__u64 core_sched_cookie;
};

static pid_t pidfd_get_pid(int dfd_init_pid, int pidfd)
{
	__do_free char *line = NULL;
	__do_fclose FILE *f = NULL;
	size_t len = 0;
	char path[STRLITERALLEN("fdinfo/") + INTTYPE_TO_STRLEN(int) + 1 ] = "fdinfo/";
	int ret;

	if (dfd_init_pid < 0 || pidfd < 0)
		return ret_errno(EBADF);

	ret = strnprintf(path + STRLITERALLEN("fdinfo/"), INTTYPE_TO_STRLEN(int), "%d", pidfd);
	if (ret < 0)
		return ret_errno(EIO);

	f = fdopen_at(dfd_init_pid, path, "re", PROTECT_OPEN, PROTECT_LOOKUP_BENEATH);
	if (!f)
		return -errno;

	while (getline(&line, &len, f) != -1) {
		const char *prefix = "Pid:\t";
		const size_t prefix_len = STRLITERALLEN("Pid:\t");
		int pid = -ESRCH;
		char *slider = line;

		if (!strnequal(slider, prefix, prefix_len))
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
	return lxc_abstract_unix_recv_one_fd(fd, fd_recv, NULL, 0) > 0;
}

static inline bool attach_lsm(lxc_attach_options_t *options)
{
	return (options->attach_flags & (LXC_ATTACH_LSM | LXC_ATTACH_LSM_LABEL));
}

static struct attach_context *alloc_attach_context(void)
{
	struct attach_context *ctx;

	ctx = zalloc(sizeof(struct attach_context));
	if (!ctx)
		return ret_set_errno(NULL, ENOMEM);

	ctx->init_pid		= -ESRCH;

	ctx->dfd_self_pid	= -EBADF;
	ctx->dfd_init_pid	= -EBADF;
	ctx->init_pidfd		= -EBADF;

	ctx->setup_ns_uid	= LXC_INVALID_UID;
	ctx->setup_ns_gid	= LXC_INVALID_GID;
	ctx->target_ns_uid	= LXC_INVALID_UID;
	ctx->target_ns_gid	= LXC_INVALID_GID;
	ctx->target_host_uid	= LXC_INVALID_UID;
	ctx->target_host_gid	= LXC_INVALID_GID;

	ctx->core_sched_cookie	= INVALID_SCHED_CORE_COOKIE;

	for (lxc_namespace_t i = 0; i < LXC_NS_MAX; i++)
		ctx->ns_fd[i] = -EBADF;

	return ctx;
}

static int get_personality(const char *name, const char *lxcpath,
			   personality_t *personality)
{
	__do_free char *p = NULL;
	int ret;
	signed long per;

	p = lxc_cmd_get_config_item(name, "lxc.arch", lxcpath);
	if (!p) {
		*personality = LXC_ARCH_UNCHANGED;
		return 0;
	}

	ret = lxc_config_parse_arch(p, &per);
	if (ret < 0)
		return syserror("Failed to parse personality");

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

	f_uidmap = fdopen_at(ctx->dfd_init_pid, "uid_map", "re", PROTECT_OPEN, PROTECT_LOOKUP_BENEATH);
	if (!f_uidmap)
		return syserror("Failed to open uid_map");

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

	f_gidmap = fdopen_at(ctx->dfd_init_pid, "gid_map", "re", PROTECT_OPEN, PROTECT_LOOKUP_BENEATH);
	if (!f_gidmap)
		return syserror("Failed to open gid_map");

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

	f = fdopen_at(ctx->dfd_init_pid, "status", "re", PROTECT_OPEN, PROTECT_LOOKUP_BENEATH);
	if (!f)
		return syserror("Failed to open status file");

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
		return syserror_ret(ret, "Failed to get setup ids");
	userns_target_ids(ctx, options);

	return 0;
}

static bool pidfd_setns_supported(struct attach_context *ctx)
{
	int ret;

	/*
	 * The ability to attach to time namespaces came after the introduction
	 * of of using pidfds for attaching to namespaces. To avoid having to
	 * special-case both CLONE_NEWUSER and CLONE_NEWTIME handling, let's
	 * use CLONE_NEWTIME as gatekeeper.
	 */
	if (ctx->init_pidfd >= 0)
		ret = setns(ctx->init_pidfd, CLONE_NEWTIME);
	else
		ret = -EOPNOTSUPP;
	TRACE("Attaching to namespaces via pidfds %s",
	      ret ? "unsupported" : "supported");
	return ret == 0;
}

static int get_attach_context(struct attach_context *ctx,
			      struct lxc_container *container,
			      lxc_attach_options_t *options)
{
	__do_free char *lsm_label = NULL;
	int ret;
	char path[LXC_PROC_PID_LEN];

	ctx->container = container;
	ctx->attach_flags = options->attach_flags;

	ctx->dfd_self_pid = open_at(-EBADF, "/proc/self",
				    PROTECT_OPATH_FILE & ~O_NOFOLLOW,
				    (PROTECT_LOOKUP_ABSOLUTE_WITH_SYMLINKS & ~RESOLVE_NO_XDEV), 0);
	if (ctx->dfd_self_pid < 0)
		return syserror("Failed to open /proc/self");

	ctx->init_pidfd = lxc_cmd_get_init_pidfd(container->name, container->config_path);
	if (ctx->init_pidfd >= 0)
		ctx->init_pid = pidfd_get_pid(ctx->dfd_self_pid, ctx->init_pidfd);
	else
		ctx->init_pid = lxc_cmd_get_init_pid(container->name, container->config_path);
	if (ctx->init_pid < 0)
		return syserror_ret(-1, "Failed to get init pid");

	ret = lxc_cmd_get_clone_flags(container->name, container->config_path);
	if (ret < 0)
		SYSERROR("Failed to retrieve namespace flags");
	ctx->ns_clone_flags = ret;

	ret = core_scheduling_cookie_get(ctx->init_pid, &ctx->core_sched_cookie);
	if (ret || !core_scheduling_cookie_valid(ctx->core_sched_cookie))
		INFO("Container does not run in a separate core scheduling domain");
	else
		INFO("Container runs in separate core scheduling domain %llu",
		     (llu)ctx->core_sched_cookie);

	ret = strnprintf(path, sizeof(path), "/proc/%d", ctx->init_pid);
	if (ret < 0)
		return ret_errno(EIO);

	ctx->dfd_init_pid = open_at(-EBADF, path,
				    PROTECT_OPATH_DIRECTORY,
				    (PROTECT_LOOKUP_ABSOLUTE & ~RESOLVE_NO_XDEV), 0);
	if (ctx->dfd_init_pid < 0)
		return syserror("Failed to open /proc/%d", ctx->init_pid);

	if (ctx->init_pidfd >= 0) {
		ret = lxc_raw_pidfd_send_signal(ctx->init_pidfd, 0, NULL, 0);
		if (ret)
			return syserror("Container process exited or PID has been recycled");
		else
			TRACE("Container process still running and PID was not recycled");

		if (!pidfd_setns_supported(ctx)) {
			/* We can't risk leaking file descriptors during attach. */
			if (close(ctx->init_pidfd))
				return syserror("Failed to close pidfd");

			ctx->init_pidfd = -EBADF;
			TRACE("Attaching to namespaces via pidfds not supported");
		}
	}

	/* Determine which namespaces the container was created with. */
	if (options->namespaces == -1) {
		options->namespaces = ctx->ns_clone_flags;
		if (options->namespaces == -1)
			return syserror_set(-EINVAL, "Failed to automatically determine the namespaces which the container uses");

		for (lxc_namespace_t i = 0; i < LXC_NS_MAX; i++) {
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
		return syserror("Failed to open parse file");

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

	ret = get_personality(container->name, container->config_path, &ctx->personality);
	if (ret)
		return syserror_ret(ret, "Failed to get personality of the container");

	if (!ctx->container->lxc_conf) {
		ctx->container->lxc_conf = lxc_conf_init();
		if (!ctx->container->lxc_conf)
			return syserror_set(-ENOMEM, "Failed to allocate new lxc config");
	}

	ctx->lsm_label = move_ptr(lsm_label);
	return 0;
}

static int same_nsfd(int dfd_pid1, int dfd_pid2, const char *ns_path)
{
	int ret;
	struct stat ns_st1, ns_st2;

	ret = fstatat(dfd_pid1, ns_path, &ns_st1, 0);
	if (ret)
		return -errno;

	ret = fstatat(dfd_pid2, ns_path, &ns_st2, 0);
	if (ret)
		return -errno;

	/* processes are in the same namespace */
	if ((ns_st1.st_dev == ns_st2.st_dev) &&
	    (ns_st1.st_ino == ns_st2.st_ino))
		return 1;

	return 0;
}

static int same_ns(int dfd_pid1, int dfd_pid2, const char *ns_path)
{
	__do_close int ns_fd2 = -EBADF;
	int ret = -1;

	ns_fd2 = open_at(dfd_pid2, ns_path, PROTECT_OPEN_WITH_TRAILING_SYMLINKS,
			 (PROTECT_LOOKUP_BENEATH_WITH_MAGICLINKS &
			  ~(RESOLVE_NO_XDEV | RESOLVE_BENEATH)), 0);
	if (ns_fd2 < 0) {
		if (errno == ENOENT)
			return -ENOENT;
		return syserror("Failed to open %d(%s)", dfd_pid2, ns_path);
	}

	ret = same_nsfd(dfd_pid1, dfd_pid2, ns_path);
	switch (ret) {
	case -ENOENT:
		__fallthrough;
	case 1:
		return ret_errno(ENOENT);
	case 0:
		/* processes are in different namespaces */
		return move_fd(ns_fd2);
	}

	return ret;
}

static int __prepare_namespaces_pidfd(struct attach_context *ctx)
{
	for (lxc_namespace_t i = 0; i < LXC_NS_MAX; i++) {
		int ret;

		ret = same_nsfd(ctx->dfd_self_pid,
				ctx->dfd_init_pid,
				ns_info[i].proc_path);
		switch (ret) {
		case -ENOENT:
			__fallthrough;
		case 1:
			ctx->ns_inherited &= ~ns_info[i].clone_flag;
			TRACE("Shared %s namespace doesn't need attach", ns_info[i].proc_name);
			continue;
		case 0:
			TRACE("Different %s namespace needs attach", ns_info[i].proc_name);
			continue;
		}

		return syserror("Failed to determine whether %s namespace is shared",
				ns_info[i].proc_name);
	}

	return 0;
}

static int __prepare_namespaces_nsfd(struct attach_context *ctx,
				     lxc_attach_options_t *options)
{
	for (lxc_namespace_t i = 0; i < LXC_NS_MAX; i++) {
		lxc_namespace_t j;

		if (options->namespaces & ns_info[i].clone_flag)
			ctx->ns_fd[i] = open_at(ctx->dfd_init_pid,
						ns_info[i].proc_path,
						PROTECT_OPEN_WITH_TRAILING_SYMLINKS,
						(PROTECT_LOOKUP_BENEATH_WITH_MAGICLINKS &
						 ~(RESOLVE_NO_XDEV | RESOLVE_BENEATH)),
						0);
		else if (ctx->ns_inherited & ns_info[i].clone_flag)
			ctx->ns_fd[i] = same_ns(ctx->dfd_self_pid,
						ctx->dfd_init_pid,
						ns_info[i].proc_path);
		else
			continue;

		if (ctx->ns_fd[i] >= 0)
			continue;

		if (ctx->ns_fd[i] == -ENOENT) {
			ctx->ns_inherited &= ~ns_info[i].clone_flag;
			continue;
		}

		/* We failed to preserve the namespace. */
		SYSERROR("Failed to preserve %s namespace of %d",
			 ns_info[i].proc_name, ctx->init_pid);

		/* Close all already opened file descriptors before we return an
		 * error, so we don't leak them.
		 */
		for (j = 0; j < i; j++)
			close_prot_errno_disarm(ctx->ns_fd[j]);

		return ret_errno(EINVAL);
	}

	return 0;
}

static int prepare_namespaces(struct attach_context *ctx,
			      lxc_attach_options_t *options)
{
	if (ctx->init_pidfd < 0)
		return __prepare_namespaces_nsfd(ctx, options);

	return __prepare_namespaces_pidfd(ctx);
}

static inline void put_namespaces(struct attach_context *ctx)
{
	if (ctx->init_pidfd < 0) {
		for (int i = 0; i < LXC_NS_MAX; i++)
			close_prot_errno_disarm(ctx->ns_fd[i]);
	}
}

static int __attach_namespaces_pidfd(struct attach_context *ctx,
				     lxc_attach_options_t *options)
{
	unsigned int ns_flags = options->namespaces | ctx->ns_inherited;
	int ret;

	/* The common case is to attach to all namespaces. */
	ret = setns(ctx->init_pidfd, ns_flags);
	if (ret)
		return syserror("Failed to attach to namespaces via pidfd");

	/* We can't risk leaking file descriptors into the container. */
	if (close(ctx->init_pidfd))
		return syserror("Failed to close pidfd");
	ctx->init_pidfd = -EBADF;

	return log_trace(0, "Attached to container namespaces via pidfd");
}

static int __attach_namespaces_nsfd(struct attach_context *ctx,
				    lxc_attach_options_t *options)
{
	int fret = 0;

	for (lxc_namespace_t i = 0; i < LXC_NS_MAX; i++) {
		int ret;

		if (ctx->ns_fd[i] < 0)
			continue;

		ret = setns(ctx->ns_fd[i], ns_info[i].clone_flag);
		if (ret)
			return syserror("Failed to attach to %s namespace of %d",
					ns_info[i].proc_name, ctx->init_pid);

		if (close(ctx->ns_fd[i])) {
			fret = -errno;
			SYSERROR("Failed to close file descriptor for %s namespace",
				 ns_info[i].proc_name);
		}
		ctx->ns_fd[i] = -EBADF;
	}

	return fret;
}

static int attach_namespaces(struct attach_context *ctx,
			     lxc_attach_options_t *options)
{
	if (lxc_log_trace()) {
		for (lxc_namespace_t i = 0; i < LXC_NS_MAX; i++) {
			if (ns_info[i].clone_flag & options->namespaces) {
				TRACE("Attaching to %s namespace", ns_info[i].proc_name);
				continue;
			}
			if (ns_info[i].clone_flag & ctx->ns_inherited) {
				TRACE("Sharing %s namespace", ns_info[i].proc_name);
				continue;
			}
			TRACE("Inheriting %s namespace", ns_info[i].proc_name);
		}
	}

	if (ctx->init_pidfd < 0)
		return __attach_namespaces_nsfd(ctx, options);

	return __attach_namespaces_pidfd(ctx, options);
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

		put_namespaces(ctx);
		free(ctx);
	}
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
		return syserror("Failed to unshare mount namespace");

	if (detect_shared_rootfs() && mount(NULL, "/", NULL, MS_SLAVE | MS_REC, NULL))
		SYSERROR("Failed to recursively turn root mount tree into dependent mount. Continuing...");

	/* Assume /proc is always mounted, so remount it. */
	ret = umount2("/proc", MNT_DETACH);
	if (ret < 0)
		return syserror("Failed to unmount /proc");

	ret = mount("none", "/proc", "proc", 0, NULL);
	if (ret < 0)
		return syserror("Failed to remount /proc");

	/*
	 * Try to umount /sys. If it's not a mount point, we'll get EINVAL, then
	 * we ignore it because it may not have been mounted in the first place.
	 */
	ret = umount2("/sys", MNT_DETACH);
	if (ret < 0 && errno != EINVAL)
		return syserror("Failed to unmount /sys");

	/* Remount it. */
	if (ret == 0 && mount("none", "/sys", "sysfs", 0, NULL))
		return syserror("Failed to remount /sys");

	return 0;
}

static int drop_capabilities(struct attach_context *ctx)
{
	int ret;
	__u32 last_cap;

	ret = lxc_caps_last_cap(&last_cap);
	if (ret)
		return syserror_ret(ret, "%d - Failed to drop capabilities", ret);

	for (__u32 cap = 0; cap <= last_cap; cap++) {
		if (ctx->capability_mask & (1LL << cap))
			continue;

		if (prctl(PR_CAPBSET_DROP, prctl_arg(cap), prctl_arg(0),
			  prctl_arg(0), prctl_arg(0)))
			return syserror("Failed to drop capability %d", cap);

		TRACE("Dropped capability %d", cap);
	}

	return 0;
}

static int lxc_attach_set_environment(struct attach_context *ctx,
				      enum lxc_attach_env_policy_t policy,
				      char **extra_env, char **extra_keep)
{
	int ret;

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

					if (strequal(extra_keep[i], "PATH"))
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

			return syserror("Failed to clear environment");
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
		ret = lxc_set_environment(ctx->container->lxc_conf);
		if (ret < 0)
			return -1;
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
		ret = strnprintf(uid_buf, sizeof(uid_buf), "%ld", (long)uid);
		if (ret <= 0)
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

		/* next: placeholder password field */
		token = strtok_r(NULL, ":", &saveptr);
		if (!token)
			continue;

		/* next: user id */
		token = strtok_r(NULL, ":", &saveptr);
		value = token ? strtol(token, &endptr, 10) : 0;
		if (!token || !endptr || *endptr || value == LONG_MIN ||
		    value == LONG_MAX)
			continue;

		/* placeholder conherence check: user id matches */
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
	int fd_lsm, ret;
	lxc_attach_options_t* options = ap->options;
        struct attach_context *ctx = ap->ctx;
        struct lxc_conf *conf = ctx->container->lxc_conf;

	/*
	 * We currently artificially restrict core scheduling to be a pid
	 * namespace concept since this makes the code easier. We can revisit
	 * this no problem and make this work with shared pid namespaces as
	 * well. This check here makes sure that the container was created with
	 * a separate pid namespace (ctx->ns_clone_flags) and whether we are
	 * actually attaching to this pid namespace (options->namespaces).
	 */
	if (core_scheduling_cookie_valid(ctx->core_sched_cookie) &&
	    (ctx->ns_clone_flags & CLONE_NEWPID) &&
	    (options->namespaces & CLONE_NEWPID)) {
		__u64 core_sched_cookie;

		ret = core_scheduling_cookie_share_with(1);
		if (ret < 0) {
			SYSERROR("Failed to join core scheduling domain of %d",
				 ctx->init_pid);
			goto on_error;
		}

		ret = core_scheduling_cookie_get(getpid(), &core_sched_cookie);
		if (ret || !core_scheduling_cookie_valid(core_sched_cookie) ||
		    (ctx->core_sched_cookie != core_sched_cookie)) {
			SYSERROR("Invalid core scheduling domain cookie %llu != %llu",
				 (llu)core_sched_cookie,
				 (llu)ctx->core_sched_cookie);
			goto on_error;
		}

		INFO("Joined core scheduling domain of %d with cookie %lld",
		     ctx->init_pid, (llu)core_sched_cookie);
	}

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
	if (options->attach_flags & LXC_ATTACH_SET_PERSONALITY) {
		long new_personality;

		if (options->personality == LXC_ATTACH_DETECT_PERSONALITY)
			new_personality = ctx->personality;
		else
			new_personality = options->personality;

		if (new_personality != LXC_ARCH_UNCHANGED) {
			ret = lxc_personality(new_personality);
			if (ret < 0)
				goto on_error;

			TRACE("Set new personality");
		}
	}

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
		if (!sync_wait_fd(ap->ipc_socket, &fd_lsm)) {
			SYSERROR("Failed to receive lsm label fd");
			goto on_error;
		}

		TRACE("Received LSM label file descriptor %d from parent", fd_lsm);
	}

	if (options->stdin_fd > 0 && isatty(options->stdin_fd)) {
		ret = lxc_make_controlling_terminal(options->stdin_fd);
		if (ret < 0)
			goto on_error;
	}

	if ((options->attach_flags & LXC_ATTACH_SETGROUPS) &&
	    options->groups.size > 0) {
		if (!lxc_setgroups(options->groups.list, options->groups.size))
			goto on_error;
	} else {
		if (!lxc_drop_groups() && errno != EPERM)
			goto on_error;
	}

	if (options->namespaces & CLONE_NEWUSER)
		if (!lxc_switch_uid_gid(ctx->setup_ns_uid, ctx->setup_ns_gid))
			goto on_error;

	if (attach_lsm(options) && ctx->lsm_label) {
		bool on_exec;

		/* Change into our new LSM profile. */
		on_exec = options->attach_flags & LXC_ATTACH_LSM_EXEC ? true : false;
		ret = ctx->lsm_ops->process_label_set_at(ctx->lsm_ops, fd_lsm, ctx->lsm_label, on_exec);
		close_prot_errno_disarm(fd_lsm);
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
		ret = lxc_fd_cloexec(fd, false);
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

	if (conf->seccomp.seccomp) {
		ret = lxc_seccomp_load(conf);
		if (ret < 0)
			goto on_error;

		TRACE("Loaded seccomp profile");

		ret = lxc_seccomp_send_notifier_fd(&conf->seccomp, ap->ipc_socket);
		if (ret < 0)
			goto on_error;
		lxc_seccomp_close_notifier_fd(&conf->seccomp);
	}

	if (!lxc_switch_uid_gid(ctx->target_ns_uid, ctx->target_ns_gid))
		goto on_error;

	put_attach_payload(ap);

	/* We're done, so we can now do whatever the user intended us to do. */
	_exit(attach_function(attach_function_args));

on_error:
	ERROR("Failed to attach to container");
	put_attach_payload(ap);
	_exit(EXIT_FAILURE);
}

static int lxc_attach_terminal(const char *name, const char *lxcpath, struct lxc_conf *conf,
			       struct lxc_terminal *terminal)
{
	int ret;

	lxc_terminal_init(terminal);

	ret = lxc_terminal_create(name, lxcpath, conf, terminal);
	if (ret < 0)
		return syserror("Failed to create terminal");

	return 0;
}

static int lxc_attach_terminal_mainloop_init(struct lxc_terminal *terminal,
					     struct lxc_async_descr *descr)
{
	int ret;

	ret = lxc_mainloop_open(descr);
	if (ret < 0)
		return syserror("Failed to create mainloop");

	ret = lxc_terminal_mainloop_add(descr, terminal);
	if (ret < 0) {
		lxc_mainloop_close(descr);
		return syserror("Failed to add handlers to mainloop");
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

void SIGCHLD_handler(int signum) {
	signal(SIGTERM, SIG_IGN); /* not terminating directly but: */
	raise(SIGTERM);           /* leads to LXC_MAINLOOP_CLOSE and a clean exit */
}

int lxc_attach(struct lxc_container *container, lxc_attach_exec_t exec_function,
	       void *exec_payload, lxc_attach_options_t *options,
	       pid_t *attached_process)
{
	int ret_parent = -1;
	struct lxc_async_descr descr = {};
	int ret;
	char *name, *lxcpath;
	int ipc_sockets[2];
	pid_t attached_pid, pid, to_cleanup_pid;
	struct attach_context *ctx;
	struct lxc_terminal terminal;
	struct lxc_conf *conf;

	if (!container)
		return ret_errno(EINVAL);

	if (!lxc_container_get(container))
		return ret_errno(EINVAL);

	name = container->name;
	lxcpath = container->config_path;

	if (!options) {
		options = &attach_static_default_options;
		options->lsm_label = NULL;
	}

	ctx = alloc_attach_context();
	if (!ctx) {
		lxc_container_put(container);
		return syserror_set(-ENOMEM, "Failed to allocate attach context");
	}

	ret = get_attach_context(ctx, container, options);
	if (ret) {
		put_attach_context(ctx);
		return syserror("Failed to get attach context");
	}

	conf = ctx->container->lxc_conf;

	if (!fetch_seccomp(ctx->container, options))
		WARN("Failed to get seccomp policy");

	if (!no_new_privs(ctx->container, options))
		WARN("Could not determine whether PR_SET_NO_NEW_PRIVS is set");

	ret = prepare_namespaces(ctx, options);
	if (ret) {
		put_attach_context(ctx);
		return syserror("Failed to get namespace file descriptors");
	}

	if (options->attach_flags & LXC_ATTACH_TERMINAL) {
		ret = lxc_attach_terminal(name, lxcpath, conf, &terminal);
		if (ret < 0) {
			put_attach_context(ctx);
			return syserror("Failed to setup new terminal");
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
	 * properly, potentially causing the parent to get stuck.
	 *
	 * For this reason, while IPC is still active, we have to use shutdown()
	 * if the child exits prematurely in order to signal that the socket is
	 * closed and cannot assume that the child exiting will automatically do
	 * that.
	 *
	 * IPC mechanism: (X is receiver)
	 *   initial process        transient process   attached process
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
		return syserror("Could not set up required IPC mechanism for attaching");
	}

	/* Create transient process, two reasons:
	 *       1. We can't setns() in the child itself, since we want to make
	 *          sure we are properly attached to the pidns.
	 *       2. Also, the initial thread has to put the attached process
	 *          into the cgroup, which we can only do if we didn't already
	 *          setns() (otherwise, user namespaces will hate us).
	 */
	pid = fork();
	if (pid < 0) {
		put_attach_context(ctx);
		return syserror("Failed to create first subprocess");
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
		ret = attach_namespaces(ctx, options);
		if (ret < 0) {
			ERROR("Failed to enter namespaces");
			shutdown(ipc_sockets[1], SHUT_RDWR);
			put_attach_context(ctx);
			_exit(EXIT_FAILURE);
		}

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
		TRACE("Attached process %d started initializing", pid);

		if (options->attach_flags & LXC_ATTACH_TERMINAL)
			lxc_attach_terminal_close_pts(&terminal);

		/* Tell grandparent the pid of the pid of the newly created child. */
		if (!sync_wake_pid(ipc_sockets[1], pid)) {
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

		/* The rest is in the hands of the initial and the attached process. */
		put_attach_context(ctx);
		_exit(EXIT_SUCCESS);
	}
	TRACE("Transient process %d started initializing", pid);

	to_cleanup_pid = pid;

	/* close unneeded file descriptors */
	close_prot_errno_disarm(ipc_sockets[1]);
	put_namespaces(ctx);
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
			if (!ERRNO_IS_NOT_SUPPORTED(ret)) {
				SYSERROR("Failed to attach cgroup");
				goto on_error;
			}

			cgroup_ops = cgroup_init(conf);
			if (!cgroup_ops)
				goto on_error;

			if (!cgroup_ops->attach(cgroup_ops, conf, name, lxcpath, pid))
				goto on_error;
		}

		TRACE("Moved transient process %d into container cgroup", pid);
	}

	/*
	 * Close sensitive file descriptors we don't need anymore. Even if
	 * we're the parent.
	 */
	if (!attach_context_security_barrier(ctx))
		goto on_error;

	/* Setup /proc limits */
	ret = setup_proc_filesystem(conf, pid);
	if (ret < 0)
		goto on_error;

	/* Setup resource limits */
	ret = setup_resource_limits(conf, pid);
	if (ret < 0)
		goto on_error;

	if (options->attach_flags & LXC_ATTACH_TERMINAL) {
		ret = lxc_attach_terminal_mainloop_init(&terminal, &descr);
		if (ret < 0)
			goto on_error;

		TRACE("Initialized terminal mainloop");
	}

	/* Let the child process know to go ahead. */
	if (!sync_wake(ipc_sockets[0], ATTACH_SYNC_CGROUP))
		goto close_mainloop;

	TRACE("Told transient process to start initializing");

	/* Get pid of attached process from transient process. */
	if (!sync_wait_pid(ipc_sockets[0], &attached_pid))
		goto close_mainloop;

	TRACE("Received pid %d of attached process in parent pid namespace", attached_pid);

	/* Ignore SIGKILL (CTRL-C) and SIGQUIT (CTRL-\) - issue #313. */
	if (options->stdin_fd == STDIN_FILENO) {
		signal(SIGINT, SIG_IGN);
		signal(SIGQUIT, SIG_IGN);
	}

	/* Reap transient process. */
	ret = wait_for_pid(pid);
	if (ret < 0)
		goto close_mainloop;

	TRACE("Transient process %d exited", pid);

	if (options->attach_flags & LXC_ATTACH_TERMINAL)
		signal(SIGCHLD, SIGCHLD_handler); /* after transient process end */

	/* We will always have to reap the attached process now. */
	to_cleanup_pid = attached_pid;

	/* Open LSM fd and send it to child. */
	if (attach_lsm(options) && ctx->lsm_label) {
		__do_close int fd_lsm = -EBADF;
		bool on_exec;

		on_exec = options->attach_flags & LXC_ATTACH_LSM_EXEC ? true : false;
		fd_lsm = ctx->lsm_ops->process_label_fd_get(ctx->lsm_ops, attached_pid, on_exec);
		if (fd_lsm < 0)
			goto close_mainloop;

		TRACE("Opened LSM label file descriptor %d", fd_lsm);

		/* Send child fd of the LSM security module to write to. */
		if (!sync_wake_fd(ipc_sockets[0], fd_lsm)) {
			SYSERROR("Failed to send lsm label fd");
			goto close_mainloop;
		}

		TRACE("Sent LSM label file descriptor %d to child", fd_lsm);
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
		case EACCES:
		case ENOEXEC:
			ret = 126;
			break;
		case ENOENT:
			ret = 127;
			break;
		}
	}

	return syserror_ret(ret, "Failed to exec \"%s\"", cmd->program);
}

int lxc_attach_run_shell(void* payload)
{
	__do_free char *buf = NULL;
	uid_t uid;
	struct passwd pwent;
	struct passwd *pwentp = NULL;
	char *user_shell;
	ssize_t bufsize;
	int ret;

	/* Ignore payload parameter. */
	(void)payload;

	uid = getuid();

	bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (bufsize < 0)
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

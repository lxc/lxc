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

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <sys/param.h>
#include <sys/file.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <sys/syscall.h>

#if HAVE_SYS_CAPABILITY_H
#include <sys/capability.h>
#endif

#if !HAVE_DECL_PR_CAPBSET_DROP
#define PR_CAPBSET_DROP 24
#endif

#include "start.h"
#include "conf.h"
#include "log.h"
#include "cgroup.h"
#include "error.h"
#include "af_unix.h"
#include "mainloop.h"
#include "utils.h"
#include "lxcutmp.h"
#include "monitor.h"
#include "commands.h"
#include "console.h"
#include "sync.h"
#include "namespace.h"
#include "lxcseccomp.h"
#include "caps.h"
#include "bdev.h"
#include "lsm/lsm.h"

lxc_log_define(lxc_start, lxc);

const struct ns_info ns_info[LXC_NS_MAX] = {
	[LXC_NS_MNT] = {"mnt", CLONE_NEWNS},
	[LXC_NS_PID] = {"pid", CLONE_NEWPID},
	[LXC_NS_UTS] = {"uts", CLONE_NEWUTS},
	[LXC_NS_IPC] = {"ipc", CLONE_NEWIPC},
	[LXC_NS_USER] = {"user", CLONE_NEWUSER},
	[LXC_NS_NET] = {"net", CLONE_NEWNET}
};

static void print_top_failing_dir(const char *path)
{
	size_t len = strlen(path);
	char *copy = alloca(len+1), *p, *e, saved;
	strcpy(copy, path);

	p = copy;
	e = copy + len;
	while (p < e) {
		while (p < e && *p == '/') p++;
		while (p < e && *p != '/') p++;
		saved = *p;
		*p = '\0';
		if (access(copy, X_OK)) {
			SYSERROR("could not access %s.  Please grant it 'x' " \
			      "access, or add an ACL for the container root.",
			      copy);
			return;
		}
		*p = saved;
	}
}

static void close_ns(int ns_fd[LXC_NS_MAX]) {
	int i;

	for (i = 0; i < LXC_NS_MAX; i++) {
		if (ns_fd[i] > -1) {
			close(ns_fd[i]);
			ns_fd[i] = -1;
		}
	}
}

static int preserve_ns(int ns_fd[LXC_NS_MAX], int clone_flags) {
	int i, saved_errno;
	char path[MAXPATHLEN];

	for (i = 0; i < LXC_NS_MAX; i++)
		ns_fd[i] = -1;

	if (access("/proc/self/ns", X_OK)) {
		WARN("Kernel does not support attach; preserve_ns ignored");
		return 0;
	}

	for (i = 0; i < LXC_NS_MAX; i++) {
		if ((clone_flags & ns_info[i].clone_flag) == 0)
			continue;
		snprintf(path, MAXPATHLEN, "/proc/self/ns/%s", ns_info[i].proc_name);
		ns_fd[i] = open(path, O_RDONLY | O_CLOEXEC);
		if (ns_fd[i] < 0)
			goto error;
	}

	return 0;

error:
	saved_errno = errno;
	close_ns(ns_fd);
	errno = saved_errno;
	SYSERROR("failed to open '%s'", path);
	return -1;
}

static int attach_ns(const int ns_fd[LXC_NS_MAX]) {
	int i;

	for (i = 0; i < LXC_NS_MAX; i++) {
		if (ns_fd[i] < 0)
			continue;

		if (setns(ns_fd[i], 0) != 0)
			goto error;
	}
	return 0;

error:
	SYSERROR("failed to set namespace '%s'", ns_info[i].proc_name);
	return -1;
}

static int match_fd(int fd)
{
	return (fd == 0 || fd == 1 || fd == 2);
}

/*
 * Check for any fds we need to close
 * * if fd_to_ignore != -1, then if we find that fd open we will ignore it.
 * * By default we warn about open fds we find.
 * * If closeall is true, we will close open fds.
 * * If lxc-start was passed "-C", then conf->close_all_fds will be true,
 *     in which case we also close all open fds.
 * * A daemonized container will always pass closeall=true.
 */
int lxc_check_inherited(struct lxc_conf *conf, bool closeall, int fd_to_ignore)
{
	struct dirent dirent, *direntp;
	int fd, fddir;
	DIR *dir;

	if (conf && conf->close_all_fds)
		closeall = true;

restart:
	dir = opendir("/proc/self/fd");
	if (!dir) {
		WARN("failed to open directory: %m");
		return -1;
	}

	fddir = dirfd(dir);

	while (!readdir_r(dir, &dirent, &direntp)) {
		if (!direntp)
			break;

		if (!strcmp(direntp->d_name, "."))
			continue;

		if (!strcmp(direntp->d_name, ".."))
			continue;

		fd = atoi(direntp->d_name);

		if (fd == fddir || fd == lxc_log_fd || fd == fd_to_ignore)
			continue;

		if (match_fd(fd))
			continue;

		if (closeall) {
			close(fd);
			closedir(dir);
			INFO("closed inherited fd %d", fd);
			goto restart;
		}
		WARN("inherited fd %d", fd);
	}

	closedir(dir); /* cannot fail */
	return 0;
}

static int setup_signal_fd(sigset_t *oldmask)
{
	sigset_t mask;
	int fd;

	/* Block everything except serious error signals */
	if (sigfillset(&mask) ||
	    sigdelset(&mask, SIGILL) ||
	    sigdelset(&mask, SIGSEGV) ||
	    sigdelset(&mask, SIGBUS) ||
	    sigdelset(&mask, SIGWINCH) ||
	    sigprocmask(SIG_BLOCK, &mask, oldmask)) {
		SYSERROR("failed to set signal mask");
		return -1;
	}

	fd = signalfd(-1, &mask, 0);
	if (fd < 0) {
		SYSERROR("failed to create the signal fd");
		return -1;
	}

	if (fcntl(fd, F_SETFD, FD_CLOEXEC)) {
		SYSERROR("failed to set sigfd to close-on-exec");
		close(fd);
		return -1;
	}

	DEBUG("sigchild handler set");

	return fd;
}

static int signal_handler(int fd, uint32_t events, void *data,
			   struct lxc_epoll_descr *descr)
{
	struct signalfd_siginfo siginfo;
	siginfo_t info;
	int ret;
	pid_t *pid = data;
	bool init_died = false;

	ret = read(fd, &siginfo, sizeof(siginfo));
	if (ret < 0) {
		ERROR("failed to read signal info");
		return -1;
	}

	if (ret != sizeof(siginfo)) {
		ERROR("unexpected siginfo size");
		return -1;
	}

	// check whether init is running
	info.si_pid = 0;
	ret = waitid(P_PID, *pid, &info, WEXITED | WNOWAIT | WNOHANG);
	if (ret == 0 && info.si_pid == *pid) {
		init_died = true;
	}

	if (siginfo.ssi_signo != SIGCHLD) {
		kill(*pid, siginfo.ssi_signo);
		INFO("forwarded signal %d to pid %d", siginfo.ssi_signo, *pid);
		return init_died ? 1 : 0;
	}

	if (siginfo.ssi_code == CLD_STOPPED ||
	    siginfo.ssi_code == CLD_CONTINUED) {
		INFO("container init process was stopped/continued");
		return init_died ? 1 : 0;
	}

	/* more robustness, protect ourself from a SIGCHLD sent
	 * by a process different from the container init
	 */
	if (siginfo.ssi_pid != *pid) {
		WARN("invalid pid for SIGCHLD");
		return init_died ? 1 : 0;
	}

	DEBUG("container init process exited");
	return 1;
}

int lxc_set_state(const char *name, struct lxc_handler *handler, lxc_state_t state)
{
	handler->state = state;
	lxc_monitor_send_state(name, state, handler->lxcpath);
	return 0;
}

int lxc_poll(const char *name, struct lxc_handler *handler)
{
	int sigfd = handler->sigfd;
	int pid = handler->pid;
	struct lxc_epoll_descr descr;

	if (lxc_mainloop_open(&descr)) {
		ERROR("failed to create mainloop");
		goto out_sigfd;
	}

	if (lxc_mainloop_add_handler(&descr, sigfd, signal_handler, &pid)) {
		ERROR("failed to add handler for the signal");
		goto out_mainloop_open;
	}

	if (lxc_console_mainloop_add(&descr, handler)) {
		ERROR("failed to add console handler to mainloop");
		goto out_mainloop_open;
	}

	if (lxc_cmd_mainloop_add(name, &descr, handler)) {
		ERROR("failed to add command handler to mainloop");
		goto out_mainloop_open;
	}

	if (handler->conf->need_utmp_watch) {
		#if HAVE_SYS_CAPABILITY_H
		if (lxc_utmp_mainloop_add(&descr, handler)) {
			ERROR("failed to add utmp handler to mainloop");
			goto out_mainloop_open;
		}
		#else
			DEBUG("not starting utmp handler as cap_sys_boot cannot be dropped without capabilities support");
		#endif
	}

	return lxc_mainloop(&descr, -1);

out_mainloop_open:
	lxc_mainloop_close(&descr);
out_sigfd:
	close(sigfd);
	return -1;
}

struct lxc_handler *lxc_init(const char *name, struct lxc_conf *conf, const char *lxcpath)
{
	struct lxc_handler *handler;

	handler = malloc(sizeof(*handler));
	if (!handler)
		return NULL;

	memset(handler, 0, sizeof(*handler));

	handler->ttysock[0] = handler->ttysock[1] = -1;
	handler->conf = conf;
	handler->lxcpath = lxcpath;
	handler->pinfd = -1;

	lsm_init();

	handler->name = strdup(name);
	if (!handler->name) {
		ERROR("failed to allocate memory");
		goto out_free;
	}

	if (lxc_cmd_init(name, handler, lxcpath))
		goto out_free_name;

	if (lxc_read_seccomp_config(conf) != 0) {
		ERROR("failed loading seccomp policy");
		goto out_close_maincmd_fd;
	}

	/* Begin by setting the state to STARTING */
	if (lxc_set_state(name, handler, STARTING)) {
		ERROR("failed to set state '%s'", lxc_state2str(STARTING));
		goto out_close_maincmd_fd;
	}

	/* Start of environment variable setup for hooks */
	if (setenv("LXC_NAME", name, 1)) {
		SYSERROR("failed to set environment variable for container name");
	}
	if (setenv("LXC_CONFIG_FILE", conf->rcfile, 1)) {
		SYSERROR("failed to set environment variable for config path");
	}
	if (setenv("LXC_ROOTFS_MOUNT", conf->rootfs.mount, 1)) {
		SYSERROR("failed to set environment variable for rootfs mount");
	}
	if (setenv("LXC_ROOTFS_PATH", conf->rootfs.path, 1)) {
		SYSERROR("failed to set environment variable for rootfs mount");
	}
	if (conf->console.path && setenv("LXC_CONSOLE", conf->console.path, 1)) {
		SYSERROR("failed to set environment variable for console path");
	}
	if (conf->console.log_path && setenv("LXC_CONSOLE_LOGPATH", conf->console.log_path, 1)) {
		SYSERROR("failed to set environment variable for console log");
	}
	/* End of environment variable setup for hooks */

	if (run_lxc_hooks(name, "pre-start", conf, handler->lxcpath, NULL)) {
		ERROR("failed to run pre-start hooks for container '%s'.", name);
		goto out_aborting;
	}

	/* the signal fd has to be created before forking otherwise
	 * if the child process exits before we setup the signal fd,
	 * the event will be lost and the command will be stuck */
	handler->sigfd = setup_signal_fd(&handler->oldmask);
	if (handler->sigfd < 0) {
		ERROR("failed to set sigchild fd handler");
		goto out_delete_tty;
	}

	/* do this after setting up signals since it might unblock SIGWINCH */
	if (lxc_console_create(conf)) {
		ERROR("failed to create console");
		goto out_restore_sigmask;
	}

	if (ttys_shift_ids(conf) < 0) {
		ERROR("Failed to shift tty into container");
		goto out_restore_sigmask;
	}

	INFO("'%s' is initialized", name);
	return handler;

out_restore_sigmask:
	sigprocmask(SIG_SETMASK, &handler->oldmask, NULL);
out_delete_tty:
	lxc_delete_tty(&conf->tty_info);
out_aborting:
	lxc_set_state(name, handler, ABORTING);
out_close_maincmd_fd:
	close(conf->maincmd_fd);
	conf->maincmd_fd = -1;
out_free_name:
	free(handler->name);
	handler->name = NULL;
out_free:
	free(handler);
	return NULL;
}

void lxc_fini(const char *name, struct lxc_handler *handler)
{
	/* The STOPPING state is there for future cleanup code
	 * which can take awhile
	 */
	lxc_set_state(name, handler, STOPPING);
	lxc_set_state(name, handler, STOPPED);

	if (run_lxc_hooks(name, "post-stop", handler->conf, handler->lxcpath, NULL))
		ERROR("failed to run post-stop hooks for container '%s'.", name);

	/* reset mask set by setup_signal_fd */
	if (sigprocmask(SIG_SETMASK, &handler->oldmask, NULL))
		WARN("failed to restore sigprocmask");

	lxc_console_delete(&handler->conf->console);
	lxc_delete_tty(&handler->conf->tty_info);
	close(handler->conf->maincmd_fd);
	handler->conf->maincmd_fd = -1;
	free(handler->name);
	if (handler->ttysock[0] != -1) {
		close(handler->ttysock[0]);
		close(handler->ttysock[1]);
	}
	cgroup_destroy(handler);
	free(handler);
}

void lxc_abort(const char *name, struct lxc_handler *handler)
{
	int ret, status;

	lxc_set_state(name, handler, ABORTING);
	if (handler->pid > 0)
		kill(handler->pid, SIGKILL);
	while ((ret = waitpid(-1, &status, 0)) > 0) ;
}

#include <sys/reboot.h>
#include <linux/reboot.h>

/*
 * reboot(LINUX_REBOOT_CMD_CAD_ON) will return -EINVAL
 * in a child pid namespace if container reboot support exists.
 * Otherwise, it will either succeed or return -EPERM.
 */
static int container_reboot_supported(void *arg)
{
        int *cmd = arg;
	int ret;

        ret = reboot(*cmd);
	if (ret == -1 && errno == EINVAL)
		return 1;
	return 0;
}

static int must_drop_cap_sys_boot(struct lxc_conf *conf)
{
	FILE *f;
	int ret, cmd, v, flags;
        long stack_size = 4096;
        void *stack = alloca(stack_size);
        int status;
        pid_t pid;

	f = fopen("/proc/sys/kernel/ctrl-alt-del", "r");
	if (!f) {
		DEBUG("failed to open /proc/sys/kernel/ctrl-alt-del");
		return 1;
	}

	ret = fscanf(f, "%d", &v);
	fclose(f);
	if (ret != 1) {
		DEBUG("Failed to read /proc/sys/kernel/ctrl-alt-del");
		return 1;
	}
	cmd = v ? LINUX_REBOOT_CMD_CAD_ON : LINUX_REBOOT_CMD_CAD_OFF;

	flags = CLONE_NEWPID | SIGCHLD;
	if (!lxc_list_empty(&conf->id_map))
		flags |= CLONE_NEWUSER;

#ifdef __ia64__
	pid = __clone2(container_reboot_supported, stack, stack_size, flags,  &cmd);
#else
	stack += stack_size;
	pid = clone(container_reboot_supported, stack, flags, &cmd);
#endif
	if (pid < 0) {
		if (flags & CLONE_NEWUSER)
			ERROR("failed to clone (%#x): %s (includes CLONE_NEWUSER)", flags, strerror(errno));
		else
			ERROR("failed to clone (%#x): %s", flags, strerror(errno));
		return -1;
	}
	if (wait(&status) < 0) {
		SYSERROR("unexpected wait error: %m");
		return -1;
	}

	if (WEXITSTATUS(status) != 1)
		return 1;

	return 0;
}

/*
 * netpipe is used in the unprivileged case to transfer the ifindexes
 * from parent to child
 */
static int netpipe = -1;

static inline int count_veths(struct lxc_list *network)
{
	struct lxc_list *iterator;
	struct lxc_netdev *netdev;
	int count = 0;

	lxc_list_for_each(iterator, network) {
		netdev = iterator->elem;
		if (netdev->type != LXC_NET_VETH)
			continue;
		count++;
	}
	return count;
}

static int read_unpriv_netifindex(struct lxc_list *network)
{
	struct lxc_list *iterator;
	struct lxc_netdev *netdev;

	if (netpipe == -1)
		return 0;
	lxc_list_for_each(iterator, network) {
		netdev = iterator->elem;
		if (netdev->type != LXC_NET_VETH)
			continue;
		if (!(netdev->name = malloc(IFNAMSIZ))) {
			ERROR("Out of memory");
			close(netpipe);
			return -1;
		}
		if (read(netpipe, netdev->name, IFNAMSIZ) != IFNAMSIZ) {
			close(netpipe);
			return -1;
		}
	}
	close(netpipe);
	return 0;
}

static int do_start(void *data)
{
	struct lxc_list *iterator;
	struct lxc_handler *handler = data;

	if (sigprocmask(SIG_SETMASK, &handler->oldmask, NULL)) {
		SYSERROR("failed to set sigprocmask");
		return -1;
	}

        /* This prctl must be before the synchro, so if the parent
	 * dies before we set the parent death signal, we will detect
	 * its death with the synchro right after, otherwise we have
	 * a window where the parent can exit before we set the pdeath
	 * signal leading to a unsupervized container.
	 */
	if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0)) {
		SYSERROR("failed to set pdeath signal");
		return -1;
	}

	lxc_sync_fini_parent(handler);

	/* don't leak the pinfd to the container */
	if (handler->pinfd >= 0) {
		close(handler->pinfd);
	}

	/* Tell the parent task it can begin to configure the
	 * container and wait for it to finish
	 */
	if (lxc_sync_barrier_parent(handler, LXC_SYNC_CONFIGURE))
		return -1;

	if (read_unpriv_netifindex(&handler->conf->network) < 0)
		goto out_warn_father;

	/*
	 * if we are in a new user namespace, become root there to have
	 * privilege over our namespace
	 */
	if (!lxc_list_empty(&handler->conf->id_map)) {
		NOTICE("switching to gid/uid 0 in new user namespace");
		if (setgid(0)) {
			SYSERROR("setgid");
			goto out_warn_father;
		}
		if (setuid(0)) {
			SYSERROR("setuid");
			goto out_warn_father;
		}
		if (setgroups(0, NULL)) {
			SYSERROR("setgroups");
			goto out_warn_father;
		}
	}

	if (access(handler->lxcpath, X_OK)) {
		print_top_failing_dir(handler->lxcpath);
		goto out_warn_father;
	}

	#if HAVE_SYS_CAPABILITY_H
	if (handler->conf->need_utmp_watch) {
		if (prctl(PR_CAPBSET_DROP, CAP_SYS_BOOT, 0, 0, 0)) {
			SYSERROR("failed to remove CAP_SYS_BOOT capability");
			goto out_warn_father;
		}
		DEBUG("Dropped cap_sys_boot");
	}
	#endif

	/* Setup the container, ip, names, utsname, ... */
	if (lxc_setup(handler)) {
		ERROR("failed to setup the container");
		goto out_warn_father;
	}

	/* ask father to setup cgroups and wait for him to finish */
	if (lxc_sync_barrier_parent(handler, LXC_SYNC_CGROUP))
		return -1;

	/* Set the label to change to when we exec(2) the container's init */
	if (lsm_process_label_set(NULL, handler->conf, 1, 1) < 0)
		goto out_warn_father;

	/* Some init's such as busybox will set sane tty settings on stdin,
	 * stdout, stderr which it thinks is the console. We already set them
	 * the way we wanted on the real terminal, and we want init to do its
	 * setup on its console ie. the pty allocated in lxc_console_create()
	 * so make sure that that pty is stdin,stdout,stderr.
	 */
	if (lxc_console_set_stdfds(handler) < 0)
		goto out_warn_father;

	/* If we mounted a temporary proc, then unmount it now */
	tmp_proc_unmount(handler->conf);

	if (lxc_seccomp_load(handler->conf) != 0)
		goto out_warn_father;

	if (run_lxc_hooks(handler->name, "start", handler->conf, handler->lxcpath, NULL)) {
		ERROR("failed to run start hooks for container '%s'.", handler->name);
		goto out_warn_father;
	}

	/* The clearenv() and putenv() calls have been moved here
	 * to allow us to use environment variables passed to the various
	 * hooks, such as the start hook above.  Not all of the
	 * variables like CONFIG_PATH or ROOTFS are valid in this
	 * context but others are. */
	if (clearenv()) {
		SYSERROR("failed to clear environment");
		/* don't error out though */
	}

	lxc_list_for_each(iterator, &handler->conf->environment) {
		if (putenv((char *)iterator->elem)) {
			SYSERROR("failed to set environment variable '%s'", (char *)iterator->elem);
			goto out_warn_father;
		}
	}

	if (putenv("container=lxc")) {
		SYSERROR("failed to set environment variable 'container=lxc'");
		goto out_warn_father;
	}

	if (handler->conf->pty_names) {
		if (putenv(handler->conf->pty_names)) {
			SYSERROR("failed to set environment variable for container ptys");
			goto out_warn_father;
		}
	}

	close(handler->sigfd);

	/* after this call, we are in error because this
	 * ops should not return as it execs */
	handler->ops->start(handler, handler->data);

out_warn_father:
	/* we want the parent to know something went wrong, so any
	 * value other than what it expects is ok. */
	lxc_sync_wake_parent(handler, LXC_SYNC_POST_CONFIGURE);
	return -1;
}

static int save_phys_nics(struct lxc_conf *conf)
{
	struct lxc_list *iterator;

	lxc_list_for_each(iterator, &conf->network) {
		struct lxc_netdev *netdev = iterator->elem;

		if (netdev->type != LXC_NET_PHYS)
			continue;
		conf->saved_nics = realloc(conf->saved_nics,
				(conf->num_savednics+1)*sizeof(struct saved_nic));
		if (!conf->saved_nics) {
			SYSERROR("failed to allocate memory");
			return -1;
		}
		conf->saved_nics[conf->num_savednics].ifindex = netdev->ifindex;
		conf->saved_nics[conf->num_savednics].orig_name = strdup(netdev->link);
		if (!conf->saved_nics[conf->num_savednics].orig_name) {
			SYSERROR("failed to allocate memory");
			return -1;
		}
		INFO("stored saved_nic #%d idx %d name %s", conf->num_savednics,
			conf->saved_nics[conf->num_savednics].ifindex,
			conf->saved_nics[conf->num_savednics].orig_name);
		conf->num_savednics++;
	}

	return 0;
}

static int recv_fd(int sock, int *fd)
{
	if (lxc_abstract_unix_recv_fd(sock, fd, NULL, 0) < 0) {
		SYSERROR("Error receiving tty fd from child");
		return -1;
	}
	if (*fd == -1)
		return -1;
	return 0;
}

static int recv_ttys_from_child(struct lxc_handler *handler)
{
	struct lxc_conf *conf = handler->conf;
	int i, sock = handler->ttysock[1];
	struct lxc_tty_info *tty_info = &conf->tty_info;

	if (!conf->tty)
		return 0;

	tty_info->pty_info = malloc(sizeof(*tty_info->pty_info)*conf->tty);
	if (!tty_info->pty_info) {
		SYSERROR("failed to allocate pty_info");
		return -1;
	}

	for (i = 0; i < conf->tty; i++) {
		struct lxc_pty_info *pty_info = &tty_info->pty_info[i];
		pty_info->busy = 0;
		if (recv_fd(sock, &pty_info->slave) < 0 ||
				recv_fd(sock, &pty_info->master) < 0) {
			ERROR("Error receiving tty info from child");
			return -1;
		}
	}
	tty_info->nbtty = conf->tty;

	return 0;
}

static int lxc_spawn(struct lxc_handler *handler)
{
	int failed_before_rename = 0;
	const char *name = handler->name;
	bool cgroups_connected = false;
	int saved_ns_fd[LXC_NS_MAX];
	int preserve_mask = 0, i;
	int netpipepair[2], nveths;

	netpipe = -1;

	for (i = 0; i < LXC_NS_MAX; i++)
		if (handler->conf->inherit_ns_fd[i] != -1)
			preserve_mask |= ns_info[i].clone_flag;

	if (lxc_sync_init(handler))
		return -1;

	handler->clone_flags = CLONE_NEWPID|CLONE_NEWNS;
	if (!lxc_list_empty(&handler->conf->id_map)) {
		INFO("Cloning a new user namespace");
		handler->clone_flags |= CLONE_NEWUSER;
	}

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, handler->ttysock) < 0) {
		lxc_sync_fini(handler);
		return -1;
	}

	if (handler->conf->inherit_ns_fd[LXC_NS_NET] == -1) {
		if (!lxc_requests_empty_network(handler))
			handler->clone_flags |= CLONE_NEWNET;

		if (!lxc_list_empty(&handler->conf->network)) {

			/* Find gateway addresses from the link device, which is
			 * no longer accessible inside the container. Do this
			 * before creating network interfaces, since goto
			 * out_delete_net does not work before lxc_clone. */
			if (lxc_find_gateway_addresses(handler)) {
				ERROR("failed to find gateway addresses");
				lxc_sync_fini(handler);
				return -1;
			}

			/* that should be done before the clone because we will
			 * fill the netdev index and use them in the child
			 */
			if (lxc_create_network(handler)) {
				ERROR("failed to create the network");
				lxc_sync_fini(handler);
				return -1;
			}
		}

		if (save_phys_nics(handler->conf)) {
			ERROR("failed to save physical nic info");
			goto out_abort;
		}
	} else {
		INFO("Inheriting a net namespace");
	}

	if (handler->conf->inherit_ns_fd[LXC_NS_IPC] == -1) {
		handler->clone_flags |= CLONE_NEWIPC;
	} else {
		INFO("Inheriting an IPC namespace");
	}

	if (handler->conf->inherit_ns_fd[LXC_NS_UTS] == -1) {
		handler->clone_flags |= CLONE_NEWUTS;
	} else {
		INFO("Inheriting a UTS namespace");
	}


	if (!cgroup_init(handler)) {
		ERROR("failed initializing cgroup support");
		goto out_delete_net;
	}

	cgroups_connected = true;

	if (!cgroup_create(handler)) {
		ERROR("failed creating cgroups");
		goto out_delete_net;
	}

	/*
	 * if the rootfs is not a blockdev, prevent the container from
	 * marking it readonly.
	 *
	 * if the container is unprivileged then skip rootfs pinning
	 */
	if (lxc_list_empty(&handler->conf->id_map)) {
		handler->pinfd = pin_rootfs(handler->conf->rootfs.path);
		if (handler->pinfd == -1)
			INFO("failed to pin the container's rootfs");
	}

	if (preserve_ns(saved_ns_fd, preserve_mask) < 0)
		goto out_delete_net;
	if (attach_ns(handler->conf->inherit_ns_fd) < 0)
		goto out_delete_net;

	if (am_unpriv() && (nveths = count_veths(&handler->conf->network))) {
		if (pipe(netpipepair) < 0) {
			SYSERROR("Error creating pipe");
			goto out_delete_net;
		}
		/* store netpipe in the global var for do_start's use */
		netpipe = netpipepair[0];
	}

	/* Create a process in a new set of namespaces */
	handler->pid = lxc_clone(do_start, handler, handler->clone_flags);
	if (handler->pid < 0) {
		SYSERROR("failed to fork into a new namespace");
		goto out_delete_net;
	}

	if (attach_ns(saved_ns_fd))
		WARN("failed to restore saved namespaces");

	lxc_sync_fini_child(handler);

	if (lxc_sync_wait_child(handler, LXC_SYNC_CONFIGURE))
		failed_before_rename = 1;

	if (!cgroup_create_legacy(handler)) {
		ERROR("failed to setup the legacy cgroups for %s", name);
		goto out_delete_net;
	}
	if (!cgroup_setup_limits(handler, false)) {
		ERROR("failed to setup the cgroup limits for '%s'", name);
		goto out_delete_net;
	}

	if (!cgroup_enter(handler))
		goto out_delete_net;

	if (!cgroup_chown(handler))
		goto out_delete_net;

	if (failed_before_rename)
		goto out_delete_net;

	/* Create the network configuration */
	if (handler->clone_flags & CLONE_NEWNET) {
		if (lxc_assign_network(&handler->conf->network, handler->pid)) {
			ERROR("failed to create the configured network");
			goto out_delete_net;
		}
	}

	if (netpipe != -1) {
		struct lxc_list *iterator;
		struct lxc_netdev *netdev;

		close(netpipe);
		lxc_list_for_each(iterator, &handler->conf->network) {
			netdev = iterator->elem;
			if (netdev->type != LXC_NET_VETH)
				continue;
			if (write(netpipepair[1], netdev->name, IFNAMSIZ) != IFNAMSIZ) {
				ERROR("Error writing veth name to container");
				goto out_delete_net;
			}
		}
		close(netpipepair[1]);
	}

	/* map the container uids - the container became an invalid
	 * userid the moment it was cloned with CLONE_NEWUSER - this
	 * call doesn't change anything immediately, but allows the
	 * container to setuid(0) (0 being mapped to something else on
	 * the host) later to become a valid uid again */
	if (lxc_map_ids(&handler->conf->id_map, handler->pid)) {
		ERROR("failed to set up id mapping");
		goto out_delete_net;
	}

	/* Tell the child to continue its initialization.  we'll get
	 * LXC_SYNC_CGROUP when it is ready for us to setup cgroups
	 */
	if (lxc_sync_barrier_child(handler, LXC_SYNC_POST_CONFIGURE))
		goto out_delete_net;

	if (!cgroup_setup_limits(handler, true)) {
		ERROR("failed to setup the devices cgroup for '%s'", name);
		goto out_delete_net;
	}

	cgroup_disconnect();
	cgroups_connected = false;

	/* read tty fds allocated by child */
	if (recv_ttys_from_child(handler) < 0) {
		ERROR("failed to receive tty info from child");
		goto out_delete_net;
	}

	/* Tell the child to complete its initialization and wait for
	 * it to exec or return an error.  (the child will never
	 * return LXC_SYNC_POST_CGROUP+1.  It will either close the
	 * sync pipe, causing lxc_sync_barrier_child to return
	 * success, or return a different value, causing us to error
	 * out).
	 */
	if (lxc_sync_barrier_child(handler, LXC_SYNC_POST_CGROUP))
		return -1;

	if (detect_shared_rootfs())
		umount2(handler->conf->rootfs.mount, MNT_DETACH);

	if (handler->ops->post_start(handler, handler->data))
		goto out_abort;

	if (lxc_set_state(name, handler, RUNNING)) {
		ERROR("failed to set state to %s",
			      lxc_state2str(RUNNING));
		goto out_abort;
	}

	lxc_sync_fini(handler);

	return 0;

out_delete_net:
	if (cgroups_connected)
		cgroup_disconnect();
	if (handler->clone_flags & CLONE_NEWNET)
		lxc_delete_network(handler);
out_abort:
	lxc_abort(name, handler);
	lxc_sync_fini(handler);
	if (handler->pinfd >= 0) {
		close(handler->pinfd);
		handler->pinfd = -1;
	}

	return -1;
}

int get_netns_fd(int pid)
{
	char path[MAXPATHLEN];
	int ret, fd;

	ret = snprintf(path, MAXPATHLEN, "/proc/%d/ns/net", pid);
	if (ret < 0 || ret >= MAXPATHLEN) {
		WARN("Failed to pin netns file for pid %d", pid);
		return -1;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		WARN("Failed to pin netns file %s for pid %d: %s",
				path, pid, strerror(errno));
		return -1;
	}
	return fd;
}

int __lxc_start(const char *name, struct lxc_conf *conf,
		struct lxc_operations* ops, void *data, const char *lxcpath)
{
	struct lxc_handler *handler;
	int err = -1;
	int status;
	int netnsfd = -1;

	handler = lxc_init(name, conf, lxcpath);
	if (!handler) {
		ERROR("failed to initialize the container");
		return -1;
	}
	handler->ops = ops;
	handler->data = data;

	if (must_drop_cap_sys_boot(handler->conf)) {
		#if HAVE_SYS_CAPABILITY_H
		DEBUG("Dropping cap_sys_boot");
		#else
		DEBUG("Can't drop cap_sys_boot as capabilities aren't supported");
		#endif
	} else {
		DEBUG("Not dropping cap_sys_boot or watching utmp");
		handler->conf->need_utmp_watch = 0;
	}

	if (!attach_block_device(handler->conf)) {
		ERROR("Failure attaching block device");
		goto out_fini_nonet;
	}

	if (geteuid() == 0 && !lxc_list_empty(&conf->id_map)) {
		/* if the backing store is a device, mount it here and now */
		if (rootfs_is_blockdev(conf)) {
			if (unshare(CLONE_NEWNS) < 0) {
				ERROR("Error unsharing mounts");
				goto out_fini_nonet;
			}
			remount_all_slave();
			if (do_rootfs_setup(conf, name, lxcpath) < 0) {
				ERROR("Error setting up rootfs mount as root before spawn");
				goto out_fini_nonet;
			}
			INFO("Set up container rootfs as host root");
		}
	}

	err = lxc_spawn(handler);
	if (err) {
		ERROR("failed to spawn '%s'", name);
		goto out_detach_blockdev;
	}

	netnsfd = get_netns_fd(handler->pid);

	err = lxc_poll(name, handler);
	if (err) {
		ERROR("mainloop exited with an error");
		if (netnsfd >= 0)
			close(netnsfd);
		goto out_abort;
	}

	while (waitpid(handler->pid, &status, 0) < 0 && errno == EINTR)
		continue;

	/*
	 * If the child process exited but was not signaled,
	 * it didn't call reboot.  This should mean it was an
	 * lxc-execute which simply exited.  In any case, treat
	 * it as a 'halt'
	 */
        if (WIFSIGNALED(status)) {
		switch(WTERMSIG(status)) {
		case SIGINT: /* halt */
			DEBUG("Container halting");
			break;
		case SIGHUP: /* reboot */
			DEBUG("Container rebooting");
			handler->conf->reboot = 1;
			break;
		case SIGSYS: /* seccomp */
			DEBUG("Container violated its seccomp policy");
			break;
		default:
			DEBUG("unknown exit status for init: %d", WTERMSIG(status));
			break;
		}
        }

	lxc_rename_phys_nics_on_shutdown(netnsfd, handler->conf);
	if (netnsfd >= 0)
		close(netnsfd);

	if (handler->pinfd >= 0) {
		close(handler->pinfd);
		handler->pinfd = -1;
	}

	lxc_monitor_send_exit_code(name, status, handler->lxcpath);
	err =  lxc_error_set_and_log(handler->pid, status);
out_fini:
	lxc_delete_network(handler);

out_detach_blockdev:
	detach_block_device(handler->conf);

out_fini_nonet:
	lxc_fini(name, handler);
	return err;

out_abort:
	lxc_abort(name, handler);
	goto out_fini;
}

struct start_args {
	char *const *argv;
};

static int start(struct lxc_handler *handler, void* data)
{
	struct start_args *arg = data;

	NOTICE("exec'ing '%s'", arg->argv[0]);

	execvp(arg->argv[0], arg->argv);
	SYSERROR("failed to exec %s", arg->argv[0]);
	return 0;
}

static int post_start(struct lxc_handler *handler, void* data)
{
	struct start_args *arg = data;

	NOTICE("'%s' started with pid '%d'", arg->argv[0], handler->pid);
	return 0;
}

static struct lxc_operations start_ops = {
	.start = start,
	.post_start = post_start
};

int lxc_start(const char *name, char *const argv[], struct lxc_conf *conf,
	      const char *lxcpath)
{
	struct start_args start_arg = {
		.argv = argv,
	};

	conf->need_utmp_watch = 1;
	return __lxc_start(name, conf, &start_ops, &start_arg, lxcpath);
}

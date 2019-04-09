/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2008
 *
 * Authors:
 * Daniel Lezcano <daniel.lezcano at free.fr>
 * Serge Hallyn <serge@hallyn.com>
 * Christian Brauner <christian.brauner@ubuntu.com>
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
#include "config.h"

#include <alloca.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>

#if HAVE_LIBCAP
#include <sys/capability.h>
#endif

#if !HAVE_DECL_PR_CAPBSET_DROP
#define PR_CAPBSET_DROP 24
#endif

#include "af_unix.h"
#include "caps.h"
#include "cgroup.h"
#include "commands.h"
#include "commands_utils.h"
#include "conf.h"
#include "confile_utils.h"
#include "console.h"
#include "error.h"
#include "list.h"
#include "log.h"
#include "lxccontainer.h"
#include "lxclock.h"
#include "lxcseccomp.h"
#include "lxcutmp.h"
#include "mainloop.h"
#include "monitor.h"
#include "namespace.h"
#include "network.h"
#include "start.h"
#include "sync.h"
#include "utils.h"
#include "lsm/lsm.h"
#include "storage/storage.h"
#include "storage/storage_utils.h"

#ifndef HAVE_STRLCPY
#include "include/strlcpy.h"
#endif

lxc_log_define(lxc_start, lxc);

extern void mod_all_rdeps(struct lxc_container *c, bool inc);
static bool do_destroy_container(struct lxc_handler *handler);
static int lxc_rmdir_onedev_wrapper(void *data);
static void lxc_destroy_container_on_signal(struct lxc_handler *handler,
					    const char *name);

static void print_top_failing_dir(const char *path)
{
	int ret;
	size_t len;
	char *copy, *e, *p, saved;

	len = strlen(path);
	copy = alloca(len + 1);
	(void)strlcpy(copy, path, len + 1);

	p = copy;
	e = copy + len;

	while (p < e) {
		while (p < e && *p == '/')
			p++;

		while (p < e && *p != '/')
			p++;

		saved = *p;
		*p = '\0';

		ret = access(copy, X_OK);
		if (ret != 0) {
			SYSERROR("Could not access %s. Please grant it x "
				 "access, or add an ACL for the container "
				 "root", copy);
			return;
		}
		*p = saved;
	}
}

static void close_ns(int ns_fd[LXC_NS_MAX])
{
	int i;

	for (i = 0; i < LXC_NS_MAX; i++) {
		if (ns_fd[i] < 0)
			continue;

		close(ns_fd[i]);
		ns_fd[i] = -EBADF;
	}
}

/* preserve_ns: open /proc/@pid/ns/@ns for each namespace specified
 * in clone_flags.
 * Return true on success, false on failure.
 */
static bool preserve_ns(int ns_fd[LXC_NS_MAX], int clone_flags, pid_t pid)
{
	int i;

	for (i = 0; i < LXC_NS_MAX; i++)
		ns_fd[i] = -EBADF;

	for (i = 0; i < LXC_NS_MAX; i++) {
		if ((clone_flags & ns_info[i].clone_flag) == 0)
			continue;
		ns_fd[i] = lxc_preserve_ns(pid, ns_info[i].proc_name);
		if (ns_fd[i] < 0)
			goto error;
	}

	return true;

error:
	if (errno == ENOENT)
		SYSERROR("Kernel does not support attaching to %s namespaces",
			 ns_info[i].proc_name);
	else
		SYSERROR("Failed to open file descriptor for %s namespace",
			 ns_info[i].proc_name);
	close_ns(ns_fd);
	return false;
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
	SYSERROR("Failed to attach %s namespace.", ns_info[i].proc_name);
	return -1;
}

static int match_fd(int fd)
{
	return (fd == 0 || fd == 1 || fd == 2);
}

int lxc_check_inherited(struct lxc_conf *conf, bool closeall,
			int *fds_to_ignore, size_t len_fds)
{
	int fd, fddir;
	size_t i;
	DIR *dir;
	struct dirent *direntp;

	if (conf && conf->close_all_fds)
		closeall = true;

restart:
	dir = opendir("/proc/self/fd");
	if (!dir) {
		WARN("%s - Failed to open directory", strerror(errno));
		return -1;
	}

	fddir = dirfd(dir);

	while ((direntp = readdir(dir))) {
		int ret;

		if (strcmp(direntp->d_name, ".") == 0)
			continue;

		if (strcmp(direntp->d_name, "..") == 0)
			continue;

		ret = lxc_safe_int(direntp->d_name, &fd);
		if (ret < 0) {
			INFO("Could not parse file descriptor for \"%s\"", direntp->d_name);
			continue;
		}

		for (i = 0; i < len_fds; i++)
			if (fds_to_ignore[i] == fd)
				break;

		if (fd == fddir || fd == lxc_log_fd ||
		    (i < len_fds && fd == fds_to_ignore[i]))
			continue;

		if (conf) {
			for (i = 0; i < LXC_NS_MAX; i++)
				if (conf->inherit_ns_fd[i] == fd)
					break;

			if (i < LXC_NS_MAX)
				continue;
		}

		if (current_config && fd == current_config->logfd)
			continue;

		if (match_fd(fd))
			continue;

		if (closeall) {
			close(fd);
			closedir(dir);
			INFO("Closed inherited fd: %d.", fd);
			goto restart;
		}
		WARN("Inherited fd: %d.", fd);
	}

	closedir(dir); /* cannot fail */
	return 0;
}

static int setup_signal_fd(sigset_t *oldmask)
{
	int ret, sig;
	sigset_t mask;
	int signals[] = {SIGBUS, SIGILL, SIGSEGV, SIGWINCH};

	/* Block everything except serious error signals. */
	ret = sigfillset(&mask);
	if (ret < 0)
		return -EBADF;

	for (sig = 0; sig < (sizeof(signals) / sizeof(signals[0])); sig++) {
		ret = sigdelset(&mask, signals[sig]);
		if (ret < 0)
			return -EBADF;
	}

	ret = pthread_sigmask(SIG_BLOCK, &mask, oldmask);
	if (ret < 0) {
		SYSERROR("Failed to set signal mask");
		return -EBADF;
	}

	ret = signalfd(-1, &mask, SFD_CLOEXEC);
	if (ret < 0) {
		SYSERROR("Failed to create signal file descriptor");
		return -EBADF;
	}

	TRACE("Created signal file descriptor %d", ret);

	return ret;
}

static int signal_handler(int fd, uint32_t events, void *data,
			  struct lxc_epoll_descr *descr)
{
	int ret;
	siginfo_t info;
	struct signalfd_siginfo siginfo;
	struct lxc_handler *hdlr = data;

	ret = lxc_read_nointr(fd, &siginfo, sizeof(siginfo));
	if (ret < 0) {
		ERROR("Failed to read signal info from signal file descriptor %d", fd);
		return -1;
	}

	if (ret != sizeof(siginfo)) {
		ERROR("Unexpected size for struct signalfd_siginfo");
		return -EINVAL;
	}

	/* Check whether init is running. */
	info.si_pid = 0;
	ret = waitid(P_PID, hdlr->pid, &info, WEXITED | WNOWAIT | WNOHANG);
	if (ret == 0 && info.si_pid == hdlr->pid)
		hdlr->init_died = true;

	/* Try to figure out a reasonable exit status to report. */
	if (hdlr->init_died) {
		switch (info.si_code) {
		case CLD_EXITED:
			hdlr->exit_status = info.si_status << 8;
			break;
		case CLD_KILLED:
		case CLD_DUMPED:
		case CLD_STOPPED:
			hdlr->exit_status = info.si_status << 8 | 0x7f;
			break;
		case CLD_CONTINUED:
			/* Huh? The waitid() told us it's dead *and* continued? */
			WARN("Init %d dead and continued?", hdlr->pid);
			hdlr->exit_status = 1;
			break;
		default:
			ERROR("Unknown si_code: %d", info.si_code);
			hdlr->exit_status = 1;
		}
	}

	if (siginfo.ssi_signo == SIGHUP) {
		kill(hdlr->pid, SIGTERM);
		INFO("Killing %d since terminal hung up", hdlr->pid);
		return hdlr->init_died ? LXC_MAINLOOP_CLOSE : 0;
	}

	if (siginfo.ssi_signo != SIGCHLD) {
		kill(hdlr->pid, siginfo.ssi_signo);
		INFO("Forwarded signal %d to pid %d", siginfo.ssi_signo, hdlr->pid);
		return hdlr->init_died ? LXC_MAINLOOP_CLOSE : 0;
	}

	/* More robustness, protect ourself from a SIGCHLD sent
	 * by a process different from the container init.
	 */
	if (siginfo.ssi_pid != hdlr->pid) {
		NOTICE("Received %d from pid %d instead of container init %d",
		       siginfo.ssi_signo, siginfo.ssi_pid, hdlr->pid);
		return hdlr->init_died ? LXC_MAINLOOP_CLOSE : 0;
	}

	if (siginfo.ssi_code == CLD_STOPPED) {
		INFO("Container init process was stopped");
		return hdlr->init_died ? LXC_MAINLOOP_CLOSE : 0;
	} else if (siginfo.ssi_code == CLD_CONTINUED) {
		INFO("Container init process was continued");
		return hdlr->init_died ? LXC_MAINLOOP_CLOSE : 0;
	}

	DEBUG("Container init process %d exited", hdlr->pid);
	return LXC_MAINLOOP_CLOSE;
}

int lxc_serve_state_clients(const char *name, struct lxc_handler *handler,
			    lxc_state_t state)
{
	size_t retlen;
	ssize_t ret;
	struct lxc_list *cur, *next;
	struct state_client *client;
	struct lxc_msg msg = {.type = lxc_msg_state, .value = state};

	if (state == THAWED)
		handler->state = RUNNING;
	else
		handler->state = state;

	TRACE("Set container state to %s", lxc_state2str(state));

	if (lxc_list_empty(&handler->state_clients)) {
		TRACE("No state clients registered");
		return 0;
	}

	retlen = strlcpy(msg.name, name, sizeof(msg.name));
	if (retlen >= sizeof(msg.name))
		return -E2BIG;

	lxc_list_for_each_safe(cur, &handler->state_clients, next) {
		client = cur->elem;

		if (!client->states[state]) {
			TRACE("State %s not registered for state client %d",
			      lxc_state2str(state), client->clientfd);
			continue;
		}

		TRACE("Sending state %s to state client %d",
		      lxc_state2str(state), client->clientfd);

	again:
		ret = send(client->clientfd, &msg, sizeof(msg), 0);
		if (ret <= 0) {
			if (errno == EINTR) {
				TRACE("Caught EINTR; retrying");
				goto again;
			}

			ERROR("%s - Failed to send message to client",
			      strerror(errno));
		}

		/* kick client from list */
		lxc_list_del(cur);
		close(client->clientfd);
		free(cur->elem);
		free(cur);
	}

	return 0;
}

static int lxc_serve_state_socket_pair(const char *name,
				       struct lxc_handler *handler,
				       lxc_state_t state)
{
	ssize_t ret;

	if (!handler->backgrounded ||
            handler->state_socket_pair[1] < 0 ||
	    state == STARTING)
		return 0;

	/* Close read end of the socket pair. */
	close(handler->state_socket_pair[0]);
	handler->state_socket_pair[0] = -1;

again:
	ret = lxc_abstract_unix_send_credential(handler->state_socket_pair[1],
						&(int){state}, sizeof(int));
	if (ret != sizeof(int)) {
		if (errno == EINTR)
			goto again;
		SYSERROR("Failed to send state to %d",
			 handler->state_socket_pair[1]);
		return -1;
	}

	TRACE("Sent container state \"%s\" to %d", lxc_state2str(state),
	      handler->state_socket_pair[1]);

	/* Close write end of the socket pair. */
	close(handler->state_socket_pair[1]);
	handler->state_socket_pair[1] = -1;

	return 0;
}

int lxc_set_state(const char *name, struct lxc_handler *handler,
		  lxc_state_t state)
{
	int ret;

	ret = lxc_serve_state_socket_pair(name, handler, state);
	if (ret < 0) {
		ERROR("Failed to synchronize via anonymous pair of unix sockets");
		return -1;
	}

	ret = lxc_serve_state_clients(name, handler, state);
	if (ret < 0)
		return -1;

	/* This function will try to connect to the legacy lxc-monitord state
	 * server and only exists for backwards compatibility.
	 */
	lxc_monitor_send_state(name, state, handler->lxcpath);

	return 0;
}

int lxc_poll(const char *name, struct lxc_handler *handler)
{
	int ret;
	bool has_console = true;
	struct lxc_epoll_descr descr, descr_console;

	if (handler->conf->console.path &&
	    strcmp(handler->conf->console.path, "none") == 0)
		has_console = false;

	ret = lxc_mainloop_open(&descr);
	if (ret < 0) {
		ERROR("Failed to create mainloop");
		goto out_sigfd;
	}

	if (has_console) {
		ret = lxc_mainloop_open(&descr_console);
		if (ret < 0) {
			ERROR("Failed to create console mainloop");
			goto out_mainloop;
		}
	}

	ret = lxc_mainloop_add_handler(&descr, handler->sigfd, signal_handler, handler);
	if (ret < 0) {
		ERROR("Failed to add signal handler for %d to mainloop", handler->sigfd);
		goto out_mainloop_console;
	}

	if (handler->conf->need_utmp_watch) {
		#if HAVE_LIBCAP
		if (lxc_utmp_mainloop_add(&descr, handler)) {
			ERROR("Failed to add utmp handler to LXC mainloop.");
			goto out_mainloop_console;
		}
		#else
			DEBUG("Not starting utmp handler as CAP_SYS_BOOT cannot be dropped without capabilities support.");
		#endif
	}

	if (has_console) {
		struct lxc_console *console = &handler->conf->console;

		ret = lxc_console_mainloop_add(&descr, console);
		if (ret < 0) {
			ERROR("Failed to add console handlers to mainloop");
			goto out_mainloop_console;
		}

		ret = lxc_console_mainloop_add(&descr_console, console);
		if (ret < 0) {
			ERROR("Failed to add console handlers to console mainloop");
			goto out_mainloop_console;
		}

		handler->conf->console.descr = &descr;
	}

	ret = lxc_cmd_mainloop_add(name, &descr, handler);
	if (ret < 0) {
		ERROR("Failed to add command handler to mainloop");
		goto out_mainloop_console;
	}

	TRACE("Mainloop is ready");

	ret = lxc_mainloop(&descr, -1);
	close(descr.epfd);
	descr.epfd = -EBADF;
	if (ret < 0 || !handler->init_died)
		goto out_mainloop_console;

	if (has_console)
		ret = lxc_mainloop(&descr_console, 0);

out_mainloop_console:
	if (has_console) {
		lxc_mainloop_close(&descr_console);
		TRACE("Closed console mainloop");
	}

out_mainloop:
	lxc_mainloop_close(&descr);
	TRACE("Closed mainloop");

out_sigfd:
	close(handler->sigfd);
	TRACE("Closed signal file descriptor %d", handler->sigfd);
	handler->sigfd = -EBADF;

	return ret;
}

void lxc_zero_handler(struct lxc_handler *handler)
{
	int i;

	memset(handler, 0, sizeof(struct lxc_handler));

	handler->clone_flags = -1;

	handler->pinfd = -1;

	handler->sigfd = -1;

	for (i = 0; i < LXC_NS_MAX; i++)
		handler->nsfd[i] = -1;

	handler->data_sock[0] = -1;
	handler->data_sock[1] = -1;

	handler->state_socket_pair[0] = -1;
	handler->state_socket_pair[1] = -1;

	handler->sync_sock[0] = -1;
	handler->sync_sock[1] = -1;
}

static void lxc_put_nsfds(struct lxc_handler *handler)
{
	int i;

	for (i = 0; i < LXC_NS_MAX; i++) {
		if (handler->nsfd[i] < 0)
			continue;

		close(handler->nsfd[i]);
		handler->nsfd[i] = -EBADF;
	}
}

void lxc_free_handler(struct lxc_handler *handler)
{
	if (handler->pinfd >= 0)
		close(handler->pinfd);

	if (handler->sigfd >= 0)
		close(handler->sigfd);

	lxc_put_nsfds(handler);

	if (handler->conf && handler->conf->reboot == 0)
		if (handler->conf->maincmd_fd >= 0)
			close(handler->conf->maincmd_fd);

	if (handler->state_socket_pair[0] >= 0)
		close(handler->state_socket_pair[0]);

	if (handler->state_socket_pair[1] >= 0)
		close(handler->state_socket_pair[1]);

	handler->conf = NULL;
	free(handler);
	handler = NULL;
}

struct lxc_handler *lxc_init_handler(const char *name, struct lxc_conf *conf,
				     const char *lxcpath, bool daemonize)
{
	int i, ret;
	struct lxc_handler *handler;

	handler = malloc(sizeof(*handler));
	if (!handler)
		return NULL;
	memset(handler, 0, sizeof(*handler));

	/* Note that am_guest_unpriv() checks the effective uid. We
	 * probably don't care if we are real root only if we are running
	 * as root so this should be fine.
	 */
	handler->am_root = !am_guest_unpriv();
	handler->data_sock[0] = handler->data_sock[1] = -1;
	handler->conf = conf;
	handler->lxcpath = lxcpath;
	handler->pinfd = -1;
	handler->sigfd = -EBADF;
	handler->init_died = false;
	handler->state_socket_pair[0] = handler->state_socket_pair[1] = -1;
	lxc_list_init(&handler->state_clients);

	for (i = 0; i < LXC_NS_MAX; i++)
		handler->nsfd[i] = -1;

	handler->name = name;

	if (daemonize && !handler->conf->reboot) {
		/* Create socketpair() to synchronize on daemonized startup.
		 * When the container reboots we don't need to synchronize
		 * again currently so don't open another socketpair().
		 */
		ret = socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0,
				 handler->state_socket_pair);
		if (ret < 0) {
			ERROR("Failed to create anonymous pair of unix sockets");
			goto on_error;
		}
		TRACE("Created anonymous pair {%d,%d} of unix sockets",
		      handler->state_socket_pair[0],
		      handler->state_socket_pair[1]);
	}

	handler->conf->maincmd_fd = lxc_cmd_init(name, lxcpath, "command");
	if (handler->conf->maincmd_fd < 0) {
		ERROR("Failed to set up command socket");
		goto on_error;
	}
	TRACE("Unix domain socket %d for command server is ready",
	      handler->conf->maincmd_fd);

	return handler;

on_error:
	lxc_free_handler(handler);

	return NULL;
}

int lxc_init(const char *name, struct lxc_handler *handler)
{
	int ret;
	const char *loglevel;
	struct lxc_conf *conf = handler->conf;

	lsm_init();
	TRACE("Initialized LSM");

	ret = lxc_read_seccomp_config(conf);
	if (ret < 0) {
		ERROR("Failed loading seccomp policy");
		goto out_close_maincmd_fd;
	}
	TRACE("Read seccomp policy");

	/* Begin by setting the state to STARTING. */
	ret = lxc_set_state(name, handler, STARTING);
	if (ret < 0) {
		ERROR("Failed to set state to \"%s\"", lxc_state2str(STARTING));
		goto out_close_maincmd_fd;
	}
	TRACE("set container state to \"STARTING\"");

	/* Start of environment variable setup for hooks. */
	ret = setenv("LXC_NAME", name, 1);
	if (ret < 0)
		SYSERROR("Failed to set environment variable: LXC_NAME=%s", name);

	if (conf->rcfile) {
		ret = setenv("LXC_CONFIG_FILE", conf->rcfile, 1);
		if (ret < 0)
			SYSERROR("Failed to set environment variable: "
				 "LXC_CONFIG_FILE=%s", conf->rcfile);
	}

	if (conf->rootfs.mount) {
		ret = setenv("LXC_ROOTFS_MOUNT", conf->rootfs.mount, 1);
		if (ret < 0)
			SYSERROR("Failed to set environment variable: "
				 "LXC_ROOTFS_MOUNT=%s", conf->rootfs.mount);
	}

	if (conf->rootfs.path) {
		ret = setenv("LXC_ROOTFS_PATH", conf->rootfs.path, 1);
		if (ret < 0)
			SYSERROR("Failed to set environment variable: "
				 "LXC_ROOTFS_PATH=%s", conf->rootfs.path);
	}

	if (conf->console.path) {
		ret = setenv("LXC_CONSOLE", conf->console.path, 1);
		if (ret < 0)
			SYSERROR("Failed to set environment variable: "
				 "LXC_CONSOLE=%s", conf->console.path);
	}

	if (conf->console.log_path) {
		ret = setenv("LXC_CONSOLE_LOGPATH", conf->console.log_path, 1);
		if (ret < 0)
			SYSERROR("Failed to set environment variable: "
				 "LXC_CONSOLE_LOGPATH=%s", conf->console.log_path);
	}

	if (cgns_supported()) {
		ret = setenv("LXC_CGNS_AWARE", "1", 1);
		if (ret < 0)
			SYSERROR("Failed to set environment variable "
				 "LXC_CGNS_AWARE=1");
	}

	loglevel = lxc_log_priority_to_string(lxc_log_get_level());
	if (setenv("LXC_LOG_LEVEL", loglevel, 1))
		SYSERROR("Failed to set environment variable LXC_LOG_LEVEL=%s", loglevel);

	TRACE("Set environment variables");

	ret = run_lxc_hooks(name, "pre-start", conf, handler->lxcpath, NULL);
	if (ret < 0) {
		ERROR("Failed to run lxc.hook.pre-start for container \"%s\"", name);
		goto out_aborting;
	}
	TRACE("Ran pre-start hooks");

	/* The signal fd has to be created before forking otherwise if the child
	 * process exits before we setup the signal fd, the event will be lost
	 * and the command will be stuck.
	 */
	handler->sigfd = setup_signal_fd(&handler->oldmask);
	if (handler->sigfd < 0) {
		ERROR("Failed to setup SIGCHLD fd handler.");
		goto out_delete_tty;
	}
	TRACE("Set up signal fd");

	/* Do this after setting up signals since it might unblock SIGWINCH. */
	ret = lxc_console_create(conf);
	if (ret < 0) {
		ERROR("Failed to create console");
		goto out_restore_sigmask;
	}
	TRACE("Created console");

	ret = lxc_pty_map_ids(conf, &conf->console);
	if (ret < 0) {
		ERROR("Failed to chown console");
		goto out_restore_sigmask;
	}
	TRACE("Chowned console");

	INFO("Container \"%s\" is initialized", name);
	return 0;

out_restore_sigmask:
	(void)pthread_sigmask(SIG_SETMASK, &handler->oldmask, NULL);
out_delete_tty:
	lxc_delete_tty(&conf->tty_info);
out_aborting:
	(void)lxc_set_state(name, handler, ABORTING);
out_close_maincmd_fd:
	close(conf->maincmd_fd);
	conf->maincmd_fd = -1;
	return -1;
}

void lxc_fini(const char *name, struct lxc_handler *handler)
{
	int i, ret;
	struct lxc_list *cur, *next;
	pid_t self = lxc_raw_getpid();
	char *namespaces[LXC_NS_MAX + 1];
	size_t namespace_count = 0;

	/* The STOPPING state is there for future cleanup code which can take
	 * awhile.
	 */
	lxc_set_state(name, handler, STOPPING);

	for (i = 0; i < LXC_NS_MAX; i++) {
		if (handler->nsfd[i] != -1) {
			ret = asprintf(&namespaces[namespace_count], "%s:/proc/%d/fd/%d",
			              ns_info[i].proc_name, self, handler->nsfd[i]);
			if (ret == -1) {
				SYSERROR("Failed to allocate memory.");
				break;
			}
			++namespace_count;
		}
	}
	namespaces[namespace_count] = NULL;

	if (handler->conf->reboot && setenv("LXC_TARGET", "reboot", 1))
		SYSERROR("Failed to set environment variable: LXC_TARGET=reboot.");

	if (!handler->conf->reboot && setenv("LXC_TARGET", "stop", 1))
		SYSERROR("Failed to set environment variable: LXC_TARGET=stop.");

	if (run_lxc_hooks(name, "stop", handler->conf, handler->lxcpath, namespaces))
		ERROR("Failed to run lxc.hook.stop for container \"%s\".", name);

	while (namespace_count--)
		free(namespaces[namespace_count]);

	for (i = 0; i < LXC_NS_MAX; i++) {
		if (handler->nsfd[i] != -1) {
			close(handler->nsfd[i]);
			handler->nsfd[i] = -1;
		}
	}

	if (handler->netnsfd >= 0) {
		close(handler->netnsfd);
		handler->netnsfd = -1;
	}

	cgroup_destroy(handler);

	/* For all new state clients simply close the command socket.
	* This will inform all state clients that the container is
	* STOPPED and also prevents a race between a open()/close() on
	* the command socket causing a new process to get ECONNREFUSED
	* because we haven't yet closed the command socket.
	 */
	close(handler->conf->maincmd_fd);
	handler->conf->maincmd_fd = -1;
	TRACE("Closed command socket");

	/* This function will try to connect to the legacy lxc-monitord
	 * state server and only exists for backwards compatibility.
	 */
	lxc_monitor_send_state(name, STOPPED, handler->lxcpath);

	/* The command socket is closed so no one can acces the command
	 * socket anymore so there's no need to lock it.
	 */
	handler->state = STOPPED;
	TRACE("Set container state to \"STOPPED\"");

	if (run_lxc_hooks(name, "post-stop", handler->conf, handler->lxcpath, NULL)) {
		ERROR("Failed to run lxc.hook.post-stop for container \"%s\".", name);
		if (handler->conf->reboot) {
			WARN("Container will be stopped instead of rebooted.");
			handler->conf->reboot = 0;
			if (setenv("LXC_TARGET", "stop", 1))
				WARN("Failed to set environment variable: LXC_TARGET=stop.");
		}
	}

	/* Reset mask set by setup_signal_fd. */
	ret = pthread_sigmask(SIG_SETMASK, &handler->oldmask, NULL);
	if (ret < 0)
		WARN("%s - Failed to restore signal mask", strerror(errno));

	lxc_console_delete(&handler->conf->console);
	lxc_delete_tty(&handler->conf->tty_info);

	/* The command socket is now closed, no more state clients can register
	 * themselves from now on. So free the list of state clients.
	 */
	lxc_list_for_each_safe(cur, &handler->state_clients, next) {
		struct state_client *client = cur->elem;
		/* close state client socket */
		close(client->clientfd);
		lxc_list_del(cur);
		free(cur->elem);
		free(cur);
	}

	if (handler->conf->ephemeral == 1 && handler->conf->reboot != 1)
		lxc_destroy_container_on_signal(handler, name);

	lxc_free_handler(handler);
}

void lxc_abort(const char *name, struct lxc_handler *handler)
{
	int ret, status;

	lxc_set_state(name, handler, ABORTING);

	if (handler->pid > 0) {
		ret = kill(handler->pid, SIGKILL);
		if (ret < 0)
			SYSERROR("Failed to send SIGKILL to %d", handler->pid);
	}

	while ((ret = waitpid(-1, &status, 0)) > 0) {
		;
	}
}

#include <sys/reboot.h>
#include <linux/reboot.h>

/* reboot(LINUX_REBOOT_CMD_CAD_ON) will return -EINVAL in a child pid namespace
 * if container reboot support exists.  Otherwise, it will either succeed or
 * return -EPERM.
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
		DEBUG("Failed to read /proc/sys/kernel/ctrl-alt-del.");
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
			ERROR("Failed to clone (%#x): %s (includes CLONE_NEWUSER).", flags, strerror(errno));
		else
			ERROR("Failed to clone (%#x): %s.", flags, strerror(errno));
		return -1;
	}
	if (wait(&status) < 0) {
		SYSERROR("Unexpected wait error: %s.", strerror(errno));
		return -1;
	}

	if (WEXITSTATUS(status) != 1)
		return 1;

	return 0;
}

static int lxc_set_death_signal(int signal)
{
	int ret;
	pid_t ppid;

	ret = prctl(PR_SET_PDEATHSIG, signal, 0, 0, 0);

	/* Check whether we have been orphaned. */
	ppid = (pid_t)syscall(SYS_getppid);
	if (ppid == 1) {
		pid_t self;

		self = lxc_raw_getpid();
		ret = kill(self, SIGKILL);
		if (ret < 0)
			return -1;
	}

	if (ret < 0) {
		SYSERROR("Failed to set PR_SET_PDEATHSIG to %d", signal);
		return -1;
	}

	return 0;
}

static int do_start(void *data)
{
	int ret;
	struct lxc_list *iterator;
	char path[PATH_MAX];
	bool have_cap_setgid;
	uid_t new_uid;
	gid_t new_gid;
	int devnull_fd = -1;
	struct lxc_handler *handler = data;

	lxc_sync_fini_parent(handler);

	/* This prctl must be before the synchro, so if the parent dies before
	 * we set the parent death signal, we will detect its death with the
	 * synchro right after, otherwise we have a window where the parent can
	 * exit before we set the pdeath signal leading to a unsupervized
	 * container.
	 */
	ret = lxc_set_death_signal(SIGKILL);
	if (ret < 0) {
		SYSERROR("Failed to set PR_SET_PDEATHSIG to SIGKILL");
		goto out_warn_father;
	}

	ret = lxc_ambient_caps_up();
	if (ret < 0) {
		ERROR("Failed to raise ambient capabilities");
		goto out_warn_father;
	}

	ret = pthread_sigmask(SIG_SETMASK, &handler->oldmask, NULL);
	if (ret < 0) {
		SYSERROR("Failed to set signal mask");
		goto out_warn_father;
	}

	/* Don't leak the pinfd to the container. */
	if (handler->pinfd >= 0) {
		close(handler->pinfd);
	}

	ret = lxc_sync_wait_parent(handler, LXC_SYNC_STARTUP);
	if (ret < 0)
		goto out_warn_father;

	/* Unshare CLONE_NEWNET after CLONE_NEWUSER. See
	 * https://github.com/lxc/lxd/issues/1978.
	 */
	if ((handler->clone_flags & (CLONE_NEWNET | CLONE_NEWUSER)) ==
	    (CLONE_NEWNET | CLONE_NEWUSER)) {
		ret = unshare(CLONE_NEWNET);
		if (ret < 0) {
			SYSERROR("Failed to unshare CLONE_NEWNET.");
			goto out_warn_father;
		}
		INFO("Unshared CLONE_NEWNET.");
	}

	/* Tell the parent task it can begin to configure the container and wait
	 * for it to finish.
	 */
	ret = lxc_sync_barrier_parent(handler, LXC_SYNC_CONFIGURE);
	if (ret < 0)
		goto out_warn_father;

	if (lxc_network_recv_veth_names_from_parent(handler) < 0) {
		ERROR("Failed to receive veth names from parent");
		goto out_warn_father;
	}

	/* If we are in a new user namespace, become root there to have
	 * privilege over our namespace.
	 */
	if (!lxc_list_empty(&handler->conf->id_map)) {
		uid_t nsuid = (handler->conf->root_nsuid_map != NULL)
				  ? 0
				  : handler->conf->init_uid;
		gid_t nsgid = (handler->conf->root_nsgid_map != NULL)
				  ? 0
				  : handler->conf->init_gid;

		if (!lxc_switch_uid_gid(nsuid, nsgid))
			goto out_warn_father;

		/* Drop groups only after we switched to a valid gid in the new
		 * user namespace.
		 */
		if (!lxc_setgroups(0, NULL) && (handler->am_root || errno != EPERM))
			goto out_warn_father;

		ret = prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
		if (ret < 0)
			goto out_warn_father;

		/* set{g,u}id() clears deathsignal */
		ret = lxc_set_death_signal(SIGKILL);
		if (ret < 0) {
			SYSERROR("Failed to set PR_SET_PDEATHSIG to SIGKILL");
			goto out_warn_father;
		}
	}

	if (access(handler->lxcpath, X_OK)) {
		print_top_failing_dir(handler->lxcpath);
		goto out_warn_father;
	}

	#if HAVE_LIBCAP
	if (handler->conf->need_utmp_watch) {
		if (prctl(PR_CAPBSET_DROP, CAP_SYS_BOOT, 0, 0, 0)) {
			SYSERROR("Failed to remove the CAP_SYS_BOOT capability.");
			goto out_warn_father;
		}
		DEBUG("Dropped the CAP_SYS_BOOT capability.");
	}
	#endif

	ret = snprintf(path, sizeof(path), "%s/dev/null", handler->conf->rootfs.mount);
	if (ret < 0 || ret >= sizeof(path))
		goto out_warn_father;

	/* In order to checkpoint restore, we need to have everything in the
	 * same mount namespace. However, some containers may not have a
	 * reasonable /dev (in particular, they may not have /dev/null), so we
	 * can't set init's std fds to /dev/null by opening it from inside the
	 * container.
	 *
	 * If that's the case, fall back to using the host's /dev/null. This
	 * means that migration won't work, but at least we won't spew output
	 * where it isn't wanted.
	 */
	if (handler->backgrounded && !handler->conf->autodev && access(path, F_OK) < 0) {
		devnull_fd = open_devnull();

		if (devnull_fd < 0)
			goto out_warn_father;
		WARN("Using /dev/null from the host for container init's "
		     "standard file descriptors. Migration will not work.");
	}

	/* Ask father to setup cgroups and wait for him to finish. */
	if (lxc_sync_barrier_parent(handler, LXC_SYNC_CGROUP))
		goto out_error;

	/* Unshare cgroup namespace after we have setup our cgroups. If we do it
	 * earlier we end up with a wrong view of /proc/self/cgroup. For
	 * example, assume we unshare(CLONE_NEWCGROUP) first, and then create
	 * the cgroup for the container, say /sys/fs/cgroup/cpuset/lxc/c, then
	 * /proc/self/cgroup would show us:
	 *
	 *	8:cpuset:/lxc/c
	 *
	 * whereas it should actually show
	 *
	 *	8:cpuset:/
	 */
	if (handler->clone_flags & CLONE_NEWCGROUP) {
		if (unshare(CLONE_NEWCGROUP) < 0) {
			INFO("Failed to unshare CLONE_NEWCGROUP.");
			goto out_warn_father;
		}
		INFO("Unshared CLONE_NEWCGROUP.");
	}

	/* Add the requested environment variables to the current environment to
	 * allow them to be used by the various hooks, such as the start hook
	 * above.
	 */
	lxc_list_for_each(iterator, &handler->conf->environment) {
		if (putenv((char *)iterator->elem)) {
			SYSERROR("Failed to set environment variable: %s.", (char *)iterator->elem);
			goto out_warn_father;
		}
	}

	/* Setup the container, ip, names, utsname, ... */
	ret = lxc_setup(handler);
	close(handler->data_sock[1]);
	close(handler->data_sock[0]);
	if (ret < 0) {
		ERROR("Failed to setup container \"%s\".", handler->name);
		goto out_warn_father;
	}

	/* Set the label to change to when we exec(2) the container's init. */
	if (lsm_process_label_set(NULL, handler->conf, 1, 1) < 0)
		goto out_warn_father;

	/* Some init's such as busybox will set sane tty settings on stdin,
	 * stdout, stderr which it thinks is the console. We already set them
	 * the way we wanted on the real terminal, and we want init to do its
	 * setup on its console ie. the pty allocated in lxc_console_create() so
	 * make sure that that pty is stdin,stdout,stderr.
	 */
	 if (handler->conf->console.slave >= 0) {
		 if (handler->backgrounded || handler->conf->is_execute == 0)
			 ret = set_stdfds(handler->conf->console.slave);
		 else
			 ret = lxc_console_set_stdfds(handler->conf->console.slave);
		 if (ret < 0) {
			ERROR("Failed to redirect std{in,out,err} to pty file "
			      "descriptor %d",
			      handler->conf->console.slave);
			goto out_warn_father;
		 }
	 }

	/* If we mounted a temporary proc, then unmount it now. */
	tmp_proc_unmount(handler->conf);

	if (lxc_seccomp_load(handler->conf) != 0)
		goto out_warn_father;

	if (run_lxc_hooks(handler->name, "start", handler->conf, handler->lxcpath, NULL)) {
		ERROR("Failed to run lxc.hook.start for container \"%s\".", handler->name);
		goto out_warn_father;
	}

	close(handler->sigfd);

	if (handler->conf->console.slave < 0 && handler->backgrounded) {
		if (devnull_fd < 0) {
			devnull_fd = open_devnull();
			if (devnull_fd < 0)
				goto out_warn_father;
		}

		ret = set_stdfds(devnull_fd);
		if (ret < 0) {
			ERROR("Failed to redirect std{in,out,err} to \"/dev/null\"");
			goto out_warn_father;
		}
	}

	setsid();

	if (lxc_sync_barrier_parent(handler, LXC_SYNC_CGROUP_LIMITS))
		goto out_warn_father;

	/* Reset the environment variables the user requested in a clear
	 * environment.
	 */
	if (clearenv()) {
		SYSERROR("Failed to clear environment.");
		/* Don't error out though. */
	}

	lxc_list_for_each(iterator, &handler->conf->environment) {
		if (putenv((char *)iterator->elem)) {
			SYSERROR("Failed to set environment variable: %s.", (char *)iterator->elem);
			goto out_warn_father;
		}
	}

	if (putenv("container=lxc")) {
		SYSERROR("Failed to set environment variable: container=lxc.");
		goto out_warn_father;
	}

	if (handler->conf->pty_names) {
		if (putenv(handler->conf->pty_names)) {
			SYSERROR("Failed to set environment variable for container ptys.");
			goto out_warn_father;
		}
	}

	/* The container has been setup. We can now switch to an unprivileged
	 * uid/gid.
	 */
	new_uid = handler->conf->init_uid;
	new_gid = handler->conf->init_gid;

	/* If we are in a new user namespace we already dropped all
	 * groups when we switched to root in the new user namespace
	 * further above. Only drop groups if we can, so ensure that we
	 * have necessary privilege.
	 */
	#if HAVE_LIBCAP
	have_cap_setgid = lxc_proc_cap_is_set(CAP_SETGID, CAP_EFFECTIVE);
	#else
	have_cap_setgid = false;
	#endif
	if (lxc_list_empty(&handler->conf->id_map) && have_cap_setgid)
		if (!lxc_setgroups(0, NULL))
			goto out_warn_father;

	if (!lxc_switch_uid_gid(new_uid, new_gid))
		goto out_warn_father;

	ret = lxc_ambient_caps_down();
	if (ret < 0) {
		ERROR("Failed to clear ambient capabilities");
		goto out_warn_father;
	}

	/* After this call, we are in error because this ops should not return
	 * as it execs.
	 */
	handler->ops->start(handler, handler->data);

out_warn_father:
	/* We want the parent to know something went wrong, so we return a
	 * special error code.
	 */
	lxc_sync_wake_parent(handler, LXC_SYNC_ERROR);

out_error:
	if (devnull_fd >= 0)
		close(devnull_fd);

	return -1;
}

static int lxc_recv_ttys_from_child(struct lxc_handler *handler)
{
	int i;
	struct lxc_pty_info *pty_info;
	int ret = -1;
	int sock = handler->data_sock[1];
	struct lxc_conf *conf = handler->conf;
	struct lxc_tty_info *tty_info = &conf->tty_info;

	if (!conf->tty)
		return 0;

	tty_info->pty_info = malloc(sizeof(*tty_info->pty_info) * conf->tty);
	if (!tty_info->pty_info)
		return -1;

	for (i = 0; i < conf->tty; i++) {
		int ttyfds[2];

		ret = lxc_abstract_unix_recv_fds(sock, ttyfds, 2, NULL, 0);
		if (ret < 0)
			break;

		pty_info = &tty_info->pty_info[i];
		pty_info->busy = 0;
		pty_info->master = ttyfds[0];
		pty_info->slave = ttyfds[1];
		TRACE("Received pty with master fd %d and slave fd %d from "
		      "parent", pty_info->master, pty_info->slave);
	}
	if (ret < 0)
		ERROR("Failed to receive %d ttys from child: %s", conf->tty,
		      strerror(errno));
	else
		TRACE("Received %d ttys from child", conf->tty);

	tty_info->nbtty = conf->tty;

	return ret;
}

int resolve_clone_flags(struct lxc_handler *handler)
{
	handler->clone_flags = CLONE_NEWPID | CLONE_NEWNS;

	if (!lxc_list_empty(&handler->conf->id_map))
		handler->clone_flags |= CLONE_NEWUSER;

	if (handler->conf->inherit_ns_fd[LXC_NS_NET] == -1) {
		if (!lxc_requests_empty_network(handler))
			handler->clone_flags |= CLONE_NEWNET;
	} else {
		INFO("Inheriting a net namespace.");
	}

	if (handler->conf->inherit_ns_fd[LXC_NS_IPC] == -1)
		handler->clone_flags |= CLONE_NEWIPC;
	else
		INFO("Inheriting an ipc namespace.");

	if (handler->conf->inherit_ns_fd[LXC_NS_UTS] == -1)
		handler->clone_flags |= CLONE_NEWUTS;
	else
		INFO("Inheriting a uts namespace.");

	if (handler->conf->inherit_ns_fd[LXC_NS_PID] == -1)
		handler->clone_flags |= CLONE_NEWPID;
	else
		INFO("Inheriting pid namespace");

	if (cgns_supported()) {
		if (handler->conf->inherit_ns_fd[LXC_NS_CGROUP] == -1)
			handler->clone_flags |= CLONE_NEWCGROUP;
		else
			INFO("Inheriting cgroup namespace");
	} else if (handler->conf->inherit_ns_fd[LXC_NS_CGROUP] >= 0) {
			return -EINVAL;
	}

	return 0;
}

/* lxc_spawn() performs crucial setup tasks and clone()s the new process which
 * exec()s the requested container binary.
 * Note that lxc_spawn() runs in the parent namespaces. Any operations performed
 * right here should be double checked if they'd pose a security risk. (For
 * example, any {u}mount() operations performed here will be reflected on the
 * host!)
 */
static int lxc_spawn(struct lxc_handler *handler)
{
	int i, flags, ret;
	bool wants_to_map_ids;
	int saved_ns_fd[LXC_NS_MAX];
	struct lxc_list *id_map;
	int preserve_mask = 0;
	const char *name = handler->name;
	bool cgroups_connected = false;

	id_map = &handler->conf->id_map;
	wants_to_map_ids = !lxc_list_empty(id_map);
	memset(saved_ns_fd, -1, sizeof(int) * LXC_NS_MAX);

	for (i = 0; i < LXC_NS_MAX; i++)
		if (handler->conf->inherit_ns_fd[i] != -1)
			preserve_mask |= ns_info[i].clone_flag;

	if (lxc_sync_init(handler))
		return -1;

	ret = socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0,
			 handler->data_sock);
	if (ret < 0) {
		lxc_sync_fini(handler);
		return -1;
	}

	ret = resolve_clone_flags(handler);
	if (ret < 0) {
		lxc_sync_fini(handler);
		return -1;
	}

	if (handler->clone_flags & CLONE_NEWNET) {
		if (!lxc_list_empty(&handler->conf->network)) {

			/* Find gateway addresses from the link device, which is
			 * no longer accessible inside the container. Do this
			 * before creating network interfaces, since goto
			 * out_delete_net does not work before lxc_clone.
			 */
			if (lxc_find_gateway_addresses(handler)) {
				ERROR("Failed to find gateway addresses.");
				lxc_sync_fini(handler);
				return -1;
			}

			/* That should be done before the clone because we will
			 * fill the netdev index and use them in the child.
			 */
			if (lxc_create_network_priv(handler)) {
				ERROR("Failed to create the network.");
				lxc_sync_fini(handler);
				return -1;
			}
		}
	}

	if (!cgroup_init(handler)) {
		ERROR("Failed initializing cgroup support.");
		goto out_delete_net;
	}

	cgroups_connected = true;

	if (!cgroup_create(handler)) {
		ERROR("Failed creating cgroups.");
		goto out_delete_net;
	}

	/* If the rootfs is not a blockdev, prevent the container from marking
	 * it readonly.
	 * If the container is unprivileged then skip rootfs pinning.
	 */
	if (!wants_to_map_ids) {
		handler->pinfd = pin_rootfs(handler->conf->rootfs.path);
		if (handler->pinfd == -1)
			INFO("Failed to pin the rootfs for container \"%s\".", handler->name);
	}

	if (!preserve_ns(saved_ns_fd, preserve_mask, lxc_raw_getpid()))
		goto out_delete_net;

	if (attach_ns(handler->conf->inherit_ns_fd) < 0)
		goto out_delete_net;

	/* Create a process in a new set of namespaces. */
	flags = handler->clone_flags;
	if (handler->clone_flags & CLONE_NEWUSER) {
		/* If CLONE_NEWUSER and CLONE_NEWNET was requested, we need to
		 * clone a new user namespace first and only later unshare our
		 * network namespace to ensure that network devices ownership is
		 * set up correctly.
		 */
		flags &= ~CLONE_NEWNET;
	}

	handler->pid = lxc_raw_clone_cb(do_start, handler, flags);
	if (handler->pid < 0) {
		SYSERROR("Failed to clone a new set of namespaces.");
		goto out_delete_net;
	}
	TRACE("Cloned child process %d", handler->pid);

	for (i = 0; i < LXC_NS_MAX; i++)
		if (flags & ns_info[i].clone_flag)
			INFO("Cloned %s.", ns_info[i].flag_name);

	if (!preserve_ns(handler->nsfd, handler->clone_flags | preserve_mask, handler->pid))
		INFO("Failed to preserve namespace for lxc.hook.stop.");

	if (attach_ns(saved_ns_fd))
		WARN("Failed to restore saved namespaces.");

	lxc_sync_fini_child(handler);

	/* Map the container uids. The container became an invalid userid the
	 * moment it was cloned with CLONE_NEWUSER. This call doesn't change
	 * anything immediately, but allows the container to setuid(0) (0 being
	 * mapped to something else on the host.) later to become a valid uid
	 * again.
	 */
	if (wants_to_map_ids && lxc_map_ids(id_map, handler->pid)) {
		ERROR("Failed to set up id mapping.");
		goto out_delete_net;
	}

	if (lxc_sync_wake_child(handler, LXC_SYNC_STARTUP))
		goto out_delete_net;

	if (lxc_sync_wait_child(handler, LXC_SYNC_CONFIGURE))
		goto out_delete_net;

	if (!cgroup_create_legacy(handler)) {
		ERROR("Failed to setup legacy cgroups for container \"%s\".", name);
		goto out_delete_net;
	}
	if (!cgroup_setup_limits(handler, false)) {
		ERROR("Failed to setup cgroup limits for container \"%s\".", name);
		goto out_delete_net;
	}

	if (!cgroup_enter(handler))
		goto out_delete_net;

	if (!cgroup_chown(handler))
		goto out_delete_net;

	handler->netnsfd = lxc_preserve_ns(handler->pid, "net");
	if (handler->netnsfd < 0) {
		ERROR("Failed to preserve network namespace");
		goto out_delete_net;
	}

	/* Create the network configuration. */
	if (handler->clone_flags & CLONE_NEWNET) {
		if (lxc_network_move_created_netdev_priv(handler->lxcpath,
							 handler->name,
							 &handler->conf->network,
							 handler->pid)) {
			ERROR("Failed to create the configured network.");
			goto out_delete_net;
		}

		if (lxc_create_network_unpriv(handler->lxcpath, handler->name,
					      &handler->conf->network,
					      handler->pid)) {
			ERROR("Failed to create the configured network.");
			goto out_delete_net;
		}
	}

	if (lxc_network_send_veth_names_to_child(handler) < 0) {
		ERROR("Failed to send veth names to child");
		goto out_delete_net;
	}

	/* Tell the child to continue its initialization. We'll get
	 * LXC_SYNC_CGROUP when it is ready for us to setup cgroups.
	 */
	if (lxc_sync_barrier_child(handler, LXC_SYNC_POST_CONFIGURE))
		goto out_delete_net;

	if (lxc_sync_barrier_child(handler, LXC_SYNC_CGROUP_UNSHARE))
		goto out_delete_net;

	if (!cgroup_setup_limits(handler, true)) {
		ERROR("Failed to setup the devices cgroup for container \"%s\".", name);
		goto out_delete_net;
	}
	TRACE("Set up cgroup device limits");

	cgroup_disconnect();
	cgroups_connected = false;

	if (handler->clone_flags & CLONE_NEWCGROUP) {
		/* Now we're ready to preserve the cgroup namespace */
		ret = lxc_preserve_ns(handler->pid, "cgroup");
		if (ret < 0) {
			ERROR("%s - Failed to preserve cgroup namespace", strerror(errno));
			goto out_delete_net;
		}
		handler->nsfd[LXC_NS_CGROUP] = ret;
		DEBUG("Preserved cgroup namespace via fd %d", ret);
	}

	/* Tell the child to complete its initialization and wait for it to exec
	 * or return an error. (The child will never return
	 * LXC_SYNC_POST_CGROUP+1. It will either close the sync pipe, causing
	 * lxc_sync_barrier_child to return success, or return a different
	 * value, causing us to error out).
	 */
	if (lxc_sync_barrier_child(handler, LXC_SYNC_POST_CGROUP))
		return -1;

	if (lxc_network_recv_name_and_ifindex_from_child(handler) < 0) {
		ERROR("Failed to receive names and ifindices for network "
		      "devices from child");
		goto out_delete_net;
	}

	/* Now all networks are created, network devices are moved into place,
	 * and the correct names and ifindeces in the respective namespaces have
	 * been recorded. The corresponding structs have now all been filled. So
	 * log them for debugging purposes.
	 */
	lxc_log_configured_netdevs(handler->conf);

	/* Read tty fds allocated by child. */
	if (lxc_recv_ttys_from_child(handler) < 0) {
		ERROR("Failed to receive tty info from child process.");
		goto out_delete_net;
	}

	if (handler->ops->post_start(handler, handler->data))
		goto out_abort;

	if (lxc_set_state(name, handler, RUNNING)) {
		ERROR("Failed to set state for container \"%s\" to \"%s\".", name,
		      lxc_state2str(RUNNING));
		goto out_abort;
	}

	lxc_sync_fini(handler);

	for (i = 0; i < LXC_NS_MAX; i++)
		if (saved_ns_fd[i] != -1)
			close(saved_ns_fd[i]);

	return 0;

out_delete_net:
	for (i = 0; i < LXC_NS_MAX; i++)
		if (saved_ns_fd[i] != -1)
			close(saved_ns_fd[i]);

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

	if (handler->netnsfd >= 0) {
		close(handler->netnsfd);
		handler->netnsfd = -1;
	}

	return -1;
}

int __lxc_start(const char *name, struct lxc_handler *handler,
		struct lxc_operations* ops, void *data, const char *lxcpath,
		bool backgrounded, int *error_num)
{
	int status;
	int err = -1;
	struct lxc_conf *conf = handler->conf;

	if (lxc_init(name, handler) < 0) {
		ERROR("Failed to initialize container \"%s\".", name);
		return -1;
	}
	handler->ops = ops;
	handler->data = data;
	handler->backgrounded = backgrounded;
	handler->netnsfd = -1;

	if (must_drop_cap_sys_boot(handler->conf)) {
		#if HAVE_LIBCAP
		DEBUG("Dropping CAP_SYS_BOOT capability.");
		#else
		DEBUG("Not dropping CAP_SYS_BOOT capability as capabilities aren't supported.");
		#endif
	} else {
		DEBUG("Not dropping CAP_SYS_BOOT or watching utmp.");
		handler->conf->need_utmp_watch = 0;
	}

	if (!attach_block_device(handler->conf)) {
		ERROR("Failed to attach block device.");
		goto out_fini_nonet;
	}

	if (geteuid() == 0 && !lxc_list_empty(&conf->id_map)) {
		/* If the backing store is a device, mount it here and now. */
		if (rootfs_is_blockdev(conf)) {
			if (unshare(CLONE_NEWNS) < 0) {
				ERROR("Failed to unshare CLONE_NEWNS.");
				goto out_fini_nonet;
			}
			INFO("Unshared CLONE_NEWNS.");

			remount_all_slave();
			if (do_rootfs_setup(conf, name, lxcpath) < 0) {
				ERROR("Error setting up rootfs mount as root before spawn.");
				goto out_fini_nonet;
			}
			INFO("Set up container rootfs as host root.");
		}
	}

	err = lxc_spawn(handler);
	if (err) {
		ERROR("Failed to spawn container \"%s\".", name);
		goto out_detach_blockdev;
	}
	/* close parent side of data socket */
	close(handler->data_sock[0]);
	handler->data_sock[0] = -1;
	close(handler->data_sock[1]);
	handler->data_sock[1] = -1;

	handler->conf->reboot = 0;

	err = lxc_poll(name, handler);
	if (err) {
		ERROR("LXC mainloop exited with error: %d.", err);
		goto out_abort;
	}

	if (!handler->init_died && handler->pid > 0) {
		ERROR("Child process is not killed");
		goto out_abort;
	}

	status = lxc_wait_for_pid_status(handler->pid);
	if (status < 0)
		SYSERROR("Failed to retrieve status for %d", handler->pid);

	/* If the child process exited but was not signaled, it didn't call
	 * reboot. This should mean it was an lxc-execute which simply exited.
	 * In any case, treat it as a 'halt'.
	 */
	if (WIFSIGNALED(status)) {
		switch(WTERMSIG(status)) {
		case SIGINT: /* halt */
			DEBUG("Container \"%s\" is halting.", name);
			break;
		case SIGHUP: /* reboot */
			DEBUG("Container \"%s\" is rebooting.", name);
			handler->conf->reboot = 1;
			break;
		case SIGSYS: /* seccomp */
			DEBUG("Container \"%s\" violated its seccomp policy.", name);
			break;
		default:
			DEBUG("Unknown exit status for container \"%s\" init %d.", name, WTERMSIG(status));
			break;
		}
	}

	err = lxc_restore_phys_nics_to_netns(handler);
	if (err < 0)
		ERROR("Failed to move physical network devices back to parent "
		      "network namespace");

	if (handler->pinfd >= 0) {
		close(handler->pinfd);
		handler->pinfd = -1;
	}

	lxc_monitor_send_exit_code(name, status, handler->lxcpath);
	lxc_error_set_and_log(handler->pid, status);
	if (error_num)
		*error_num = handler->exit_status;

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

	NOTICE("Exec'ing \"%s\"", arg->argv[0]);

	execvp(arg->argv[0], arg->argv);
	SYSERROR("Failed to exec \"%s\"", arg->argv[0]);
	return 0;
}

static int post_start(struct lxc_handler *handler, void* data)
{
	struct start_args *arg = data;

	NOTICE("Started \"%s\" with pid \"%d\"", arg->argv[0], handler->pid);
	return 0;
}

static struct lxc_operations start_ops = {
	.start = start,
	.post_start = post_start
};

int lxc_start(const char *name, char *const argv[], struct lxc_handler *handler,
	      const char *lxcpath, bool backgrounded, int *error_num)
{
	struct start_args start_arg = {
		.argv = argv,
	};

	handler->conf->need_utmp_watch = 1;
	return __lxc_start(name, handler, &start_ops, &start_arg, lxcpath, backgrounded, error_num);
}

static void lxc_destroy_container_on_signal(struct lxc_handler *handler,
					    const char *name)
{
	char destroy[MAXPATHLEN];
	struct lxc_container *c;
	int ret = 0;
	bool bret = true;

	if (handler->conf->rootfs.path && handler->conf->rootfs.mount) {
		bret = do_destroy_container(handler);
		if (!bret) {
			ERROR("Error destroying rootfs for container \"%s\"", name);
			return;
		}
	}
	INFO("Destroyed rootfs for container \"%s\"", name);

	ret = snprintf(destroy, MAXPATHLEN, "%s/%s", handler->lxcpath, name);
	if (ret < 0 || ret >= MAXPATHLEN) {
		ERROR("Error destroying directory for container \"%s\"", name);
		return;
	}

	c = lxc_container_new(name, handler->lxcpath);
	if (c) {
		if (container_disk_lock(c)) {
			INFO("Could not update lxc_snapshots file");
			lxc_container_put(c);
		} else {
			mod_all_rdeps(c, false);
			container_disk_unlock(c);
			lxc_container_put(c);
		}
	}

	if (!handler->am_root)
		ret = userns_exec_full(handler->conf, lxc_rmdir_onedev_wrapper,
				       destroy, "lxc_rmdir_onedev_wrapper");
	else
		ret = lxc_rmdir_onedev(destroy, NULL);

	if (ret < 0) {
		ERROR("Error destroying directory for container \"%s\"", name);
		return;
	}
	INFO("Destroyed directory for container \"%s\"", name);
}

static int lxc_rmdir_onedev_wrapper(void *data)
{
	char *arg = (char *) data;
	return lxc_rmdir_onedev(arg, NULL);
}

static bool do_destroy_container(struct lxc_handler *handler)
{
	int ret;

	if (!handler->am_root) {
		ret = userns_exec_full(handler->conf, storage_destroy_wrapper,
				       handler->conf, "storage_destroy_wrapper");
		if (ret < 0)
			return false;

		return true;
	}

	return storage_destroy(handler->conf);
}

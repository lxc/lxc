/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
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
#include <unistd.h>

#include "af_unix.h"
#include "caps.h"
#include "cgroup.h"
#include "commands.h"
#include "commands_utils.h"
#include "conf.h"
#include "config.h"
#include "confile_utils.h"
#include "error.h"
#include "file_utils.h"
#include "list.h"
#include "log.h"
#include "lsm/lsm.h"
#include "lxccontainer.h"
#include "lxclock.h"
#include "lxcseccomp.h"
#include "macro.h"
#include "mainloop.h"
#include "memory_utils.h"
#include "monitor.h"
#include "namespace.h"
#include "network.h"
#include "raw_syscalls.h"
#include "start.h"
#include "storage/storage.h"
#include "storage/storage_utils.h"
#include "sync.h"
#include "syscall_wrappers.h"
#include "terminal.h"
#include "utils.h"

#if HAVE_LIBCAP
#include <sys/capability.h>
#endif

#ifndef HAVE_STRLCPY
#include "include/strlcpy.h"
#endif

lxc_log_define(start, lxc);

extern void mod_all_rdeps(struct lxc_container *c, bool inc);
static bool do_destroy_container(struct lxc_handler *handler);
static int lxc_rmdir_onedev_wrapper(void *data);
static void lxc_destroy_container_on_signal(struct lxc_handler *handler,
					    const char *name);

static void print_top_failing_dir(const char *path)
{
	__do_free char *copy = NULL;
	int ret;
	char *e, *p, saved;

	copy = must_copy_string(path);
	p = copy;
	e = copy + strlen(path);

	while (p < e) {
		while (p < e && *p == '/')
			p++;

		while (p < e && *p != '/')
			p++;

		saved = *p;
		*p = '\0';

		ret = access(copy, X_OK);
		if (ret != 0) {
			SYSERROR("Could not access %s. Please grant it x access, or add an ACL for the container " "root", copy);
			return;
		}
		*p = saved;
	}
}

static void lxc_put_nsfds(struct lxc_handler *handler)
{
	for (int i = 0; i < LXC_NS_MAX; i++) {
		if (handler->nsfd[i] < 0)
			continue;

		close_prot_errno_disarm(handler->nsfd[i]);
	}
}

static int lxc_try_preserve_ns(const int pid, const char *ns)
{
	int fd;

	fd = lxc_preserve_ns(pid, ns);
	if (fd < 0) {
		if (errno != ENOENT)
			return log_error_errno(-EINVAL,
					       errno, "Failed to preserve %s namespace",
					       ns);

		return log_warn_errno(-EOPNOTSUPP,
				      errno, "Kernel does not support preserving %s namespaces",
				      ns);
	}

	return fd;
}

/* lxc_try_preserve_namespaces: open /proc/@pid/ns/@ns for each namespace
 * specified in ns_clone_flags.
 * Return true on success, false on failure.
 */
static bool lxc_try_preserve_namespaces(struct lxc_handler *handler,
					int ns_clone_flags, pid_t pid)
{
	int i;

	for (i = 0; i < LXC_NS_MAX; i++)
		handler->nsfd[i] = -EBADF;

	for (i = 0; i < LXC_NS_MAX; i++) {
		int fd;

		if ((ns_clone_flags & ns_info[i].clone_flag) == 0)
			continue;

		fd = lxc_try_preserve_ns(pid, ns_info[i].proc_name);
		if (fd < 0) {
			/* Do not fail to start container on kernels that do
			 * not support interacting with namespaces through
			 * /proc.
			 */
			if (fd == -EOPNOTSUPP)
				continue;

			lxc_put_nsfds(handler);
			return false;
		}

		handler->nsfd[i] = fd;
		DEBUG("Preserved %s namespace via fd %d", ns_info[i].proc_name,
		      handler->nsfd[i]);
	}

	return true;
}

static inline bool match_stdfds(int fd)
{
	return (fd == STDIN_FILENO || fd == STDOUT_FILENO || fd == STDERR_FILENO);
}

#ifdef HAVE_DLOG
static bool match_dlog_fds(struct dirent *direntp)
{
	char path[PATH_MAX] = {0};
	char link[PATH_MAX] = {0};
	ssize_t linklen;
	int ret;

	ret = snprintf(path, PATH_MAX, "/proc/self/fd/%s", direntp->d_name);
	if (ret < 0 || ret >= PATH_MAX)
		return log_error(false, "Failed to create file descriptor name");

	linklen = readlink(path, link, PATH_MAX);
	if (linklen < 0)
		return log_error(false, "Failed to read link path - \"%s\"", path);
	else if (linklen >= PATH_MAX)
		return log_error(false, "The name of link path is too long - \"%s\"", path);

	if (strcmp(link, "/dev/log_main")	== 0 ||
	    strcmp(link, "/dev/log_system")	== 0 ||
	    strcmp(link, "/dev/log_radio")	== 0)
		return true;

	return false;
}
#endif

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
	if (!dir)
		return log_warn(-1, "Failed to open directory");

	fddir = dirfd(dir);

	while ((direntp = readdir(dir))) {
		int ret;
		struct lxc_list *cur;
		bool matched = false;

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

		/* Keep state clients that wait on reboots. */
		if (conf) {
			lxc_list_for_each(cur, &conf->state_clients) {
				struct lxc_state_client *client = cur->elem;

				if (client->clientfd != fd)
					continue;

				matched = true;
				break;
			}
		}

		if (matched)
			continue;

		if (current_config && fd == current_config->logfd)
			continue;

		if (match_stdfds(fd))
			continue;

#ifdef HAVE_DLOG
		if (match_dlog_fds(direntp))
			continue;

#endif
		if (closeall) {
			close(fd);
			closedir(dir);
			INFO("Closed inherited fd %d", fd);
			goto restart;
		}
		WARN("Inherited fd %d", fd);
	}

	/* Only enable syslog at this point to avoid the above logging function
	 * to open a new fd and make the check_inherited function enter an
	 * infinite loop.
	 */
	lxc_log_enable_syslog();

	closedir(dir); /* cannot fail */
	return 0;
}

static int setup_signal_fd(sigset_t *oldmask)
{
	int ret;
	sigset_t mask;
	const int signals[] = {SIGBUS, SIGILL, SIGSEGV, SIGWINCH};

	/* Block everything except serious error signals. */
	ret = sigfillset(&mask);
	if (ret < 0)
		return -EBADF;

	for (int sig = 0; sig < (sizeof(signals) / sizeof(signals[0])); sig++) {
		ret = sigdelset(&mask, signals[sig]);
		if (ret < 0)
			return -EBADF;
	}

	ret = pthread_sigmask(SIG_BLOCK, &mask, oldmask);
	if (ret < 0)
		return log_error_errno(-EBADF, errno,
				       "Failed to set signal mask");

	ret = signalfd(-1, &mask, SFD_CLOEXEC);
	if (ret < 0)
		return log_error_errno(-EBADF,
				       errno, "Failed to create signal file descriptor");

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
	if (ret < 0)
		return log_error(LXC_MAINLOOP_ERROR, "Failed to read signal info from signal file descriptor %d", fd);

	if (ret != sizeof(siginfo))
		return log_error(LXC_MAINLOOP_ERROR, "Unexpected size for struct signalfd_siginfo");

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
		if (hdlr->pidfd >= 0)
			lxc_raw_pidfd_send_signal(hdlr->pidfd, SIGTERM, NULL, 0);
		else
			kill(hdlr->pid, SIGTERM);
		INFO("Killing %d since terminal hung up", hdlr->pid);
		return hdlr->init_died ? LXC_MAINLOOP_CLOSE
				       : LXC_MAINLOOP_CONTINUE;
	}

	if (siginfo.ssi_signo != SIGCHLD) {
		if (hdlr->pidfd >= 0)
			lxc_raw_pidfd_send_signal(hdlr->pidfd,
						  siginfo.ssi_signo, NULL, 0);
		else
			kill(hdlr->pid, siginfo.ssi_signo);
		INFO("Forwarded signal %d to pid %d", siginfo.ssi_signo, hdlr->pid);
		return hdlr->init_died ? LXC_MAINLOOP_CLOSE
				       : LXC_MAINLOOP_CONTINUE;
	}

	/* More robustness, protect ourself from a SIGCHLD sent
	 * by a process different from the container init.
	 */
	if (siginfo.ssi_pid != hdlr->pid) {
		NOTICE("Received %d from pid %d instead of container init %d",
		       siginfo.ssi_signo, siginfo.ssi_pid, hdlr->pid);
		return hdlr->init_died ? LXC_MAINLOOP_CLOSE
				       : LXC_MAINLOOP_CONTINUE;
	}

	if (siginfo.ssi_code == CLD_STOPPED) {
		INFO("Container init process was stopped");
		return hdlr->init_died ? LXC_MAINLOOP_CLOSE
				       : LXC_MAINLOOP_CONTINUE;
	}

	if (siginfo.ssi_code == CLD_CONTINUED) {
		INFO("Container init process was continued");
		return hdlr->init_died ? LXC_MAINLOOP_CLOSE
				       : LXC_MAINLOOP_CONTINUE;
	}

	return log_debug(LXC_MAINLOOP_CLOSE, "Container init process %d exited", hdlr->pid);
}

int lxc_serve_state_clients(const char *name, struct lxc_handler *handler,
			    lxc_state_t state)
{
	size_t retlen;
	ssize_t ret;
	struct lxc_list *cur, *next;
	struct lxc_msg msg = {.type = lxc_msg_state, .value = state};

	if (state == THAWED)
		handler->state = RUNNING;
	else
		handler->state = state;

	TRACE("Set container state to %s", lxc_state2str(state));

	if (lxc_list_empty(&handler->conf->state_clients))
		return log_trace(0, "No state clients registered");

	retlen = strlcpy(msg.name, name, sizeof(msg.name));
	if (retlen >= sizeof(msg.name))
		return -E2BIG;

	lxc_list_for_each_safe(cur, &handler->conf->state_clients, next) {
		struct lxc_state_client *client = cur->elem;

		if (client->states[state] == 0) {
			TRACE("State %s not registered for state client %d",
			      lxc_state2str(state), client->clientfd);
			continue;
		}

		TRACE("Sending state %s to state client %d",
		      lxc_state2str(state), client->clientfd);

		ret = lxc_send_nointr(client->clientfd, &msg, sizeof(msg), MSG_NOSIGNAL);
		if (ret <= 0)
			SYSERROR("Failed to send message to client");

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

	if (!handler->daemonize ||
            handler->state_socket_pair[1] < 0 ||
	    state == STARTING)
		return 0;

	/* Close read end of the socket pair. */
	close_prot_errno_disarm(handler->state_socket_pair[0]);

again:
	ret = lxc_abstract_unix_send_credential(handler->state_socket_pair[1],
						&(int){state}, sizeof(int));
	if (ret < 0) {
		SYSERROR("Failed to send state to %d", handler->state_socket_pair[1]);

		if (errno == EINTR)
			goto again;

		return -1;
	}

	if (ret != sizeof(int))
		return log_error(-1, "Message too long : %d", handler->state_socket_pair[1]);

	TRACE("Sent container state \"%s\" to %d", lxc_state2str(state),
	      handler->state_socket_pair[1]);

	/* Close write end of the socket pair. */
	close_prot_errno_disarm(handler->state_socket_pair[1]);

	return 0;
}

int lxc_set_state(const char *name, struct lxc_handler *handler,
		  lxc_state_t state)
{
	int ret;

	ret = lxc_serve_state_socket_pair(name, handler, state);
	if (ret < 0)
		return log_error(-1, "Failed to synchronize via anonymous pair of unix sockets");

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

	ret = lxc_seccomp_setup_proxy(&handler->conf->seccomp, &descr, handler);
	if (ret < 0) {
		ERROR("Failed to setup seccomp proxy");
		goto out_mainloop_console;
	}

	if (has_console) {
		struct lxc_terminal *console = &handler->conf->console;

		ret = lxc_terminal_mainloop_add(&descr, console);
		if (ret < 0) {
			ERROR("Failed to add console handlers to mainloop");
			goto out_mainloop_console;
		}

		ret = lxc_terminal_mainloop_add(&descr_console, console);
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
	close_prot_errno_disarm(descr.epfd);
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
	TRACE("Closed signal file descriptor %d", handler->sigfd);
	close_prot_errno_disarm(handler->sigfd);

	return ret;
}

void lxc_zero_handler(struct lxc_handler *handler)
{
	memset(handler, 0, sizeof(struct lxc_handler));

	handler->state = STOPPED;

	handler->pinfd = -EBADF;

	handler->pidfd = -EBADF;

	handler->sigfd = -EBADF;

	for (int i = 0; i < LXC_NS_MAX; i++)
		handler->nsfd[i] = -EBADF;

	handler->data_sock[0] = -EBADF;
	handler->data_sock[1] = -EBADF;

	handler->state_socket_pair[0] = -EBADF;
	handler->state_socket_pair[1] = -EBADF;

	handler->sync_sock[0] = -EBADF;
	handler->sync_sock[1] = -EBADF;
}

void lxc_free_handler(struct lxc_handler *handler)
{
	close_prot_errno_disarm(handler->pinfd);
	close_prot_errno_disarm(handler->pidfd);
	close_prot_errno_disarm(handler->sigfd);
	lxc_put_nsfds(handler);
	if (handler->conf && handler->conf->reboot == REBOOT_NONE)
		close_prot_errno_disarm(handler->conf->maincmd_fd);
	close_prot_errno_disarm(handler->monitor_status_fd);
	close_prot_errno_disarm(handler->state_socket_pair[0]);
	close_prot_errno_disarm(handler->state_socket_pair[1]);
	cgroup_exit(handler->cgroup_ops);
	handler->conf = NULL;
	free_disarm(handler);
}

struct lxc_handler *lxc_init_handler(const char *name, struct lxc_conf *conf,
				     const char *lxcpath, bool daemonize)
{
	int ret;
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
	handler->conf = conf;
	handler->lxcpath = lxcpath;
	handler->init_died = false;
	handler->data_sock[0] = -EBADF;
	handler->data_sock[1] = -EBADF;
	handler->monitor_status_fd = -EBADF;
	handler->pinfd = -EBADF;
	handler->pidfd = -EBADF;
	handler->sigfd = -EBADF;
	handler->state_socket_pair[0] = -EBADF;
	handler->state_socket_pair[1] = -EBADF;
	if (handler->conf->reboot == REBOOT_NONE)
		lxc_list_init(&handler->conf->state_clients);

	for (int i = 0; i < LXC_NS_MAX; i++)
		handler->nsfd[i] = -EBADF;

	handler->name = name;
	if (daemonize)
		handler->transient_pid = lxc_raw_getpid();
	else
		handler->transient_pid = -1;

	if (daemonize && handler->conf->reboot == REBOOT_NONE) {
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

	if (handler->conf->reboot == REBOOT_NONE) {
		handler->conf->maincmd_fd = lxc_cmd_init(name, lxcpath, "command");
		if (handler->conf->maincmd_fd < 0) {
			ERROR("Failed to set up command socket");
			goto on_error;
		}
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
	__do_close int status_fd = -EBADF;
	int ret;
	const char *loglevel;
	struct lxc_conf *conf = handler->conf;

	handler->monitor_pid = lxc_raw_getpid();
	status_fd = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
	if (status_fd < 0)
		return log_error_errno(-1, errno, "Failed to open monitor status fd");

	lsm_init();
	TRACE("Initialized LSM");

	/* Begin by setting the state to STARTING. */
	ret = lxc_set_state(name, handler, STARTING);
	if (ret < 0)
		return log_error(-1, "Failed to set state to \"%s\"", lxc_state2str(STARTING));
	TRACE("Set container state to \"STARTING\"");

	/* Start of environment variable setup for hooks. */
	ret = setenv("LXC_NAME", name, 1);
	if (ret < 0)
		SYSERROR("Failed to set environment variable: LXC_NAME=%s", name);

	if (conf->rcfile) {
		ret = setenv("LXC_CONFIG_FILE", conf->rcfile, 1);
		if (ret < 0)
			SYSERROR("Failed to set environment variable: LXC_CONFIG_FILE=%s", conf->rcfile);
	}

	if (conf->rootfs.mount) {
		ret = setenv("LXC_ROOTFS_MOUNT", conf->rootfs.mount, 1);
		if (ret < 0)
			SYSERROR("Failed to set environment variable: LXC_ROOTFS_MOUNT=%s", conf->rootfs.mount);
	}

	if (conf->rootfs.path) {
		ret = setenv("LXC_ROOTFS_PATH", conf->rootfs.path, 1);
		if (ret < 0)
			SYSERROR("Failed to set environment variable: LXC_ROOTFS_PATH=%s", conf->rootfs.path);
	}

	if (conf->console.path) {
		ret = setenv("LXC_CONSOLE", conf->console.path, 1);
		if (ret < 0)
			SYSERROR("Failed to set environment variable: LXC_CONSOLE=%s", conf->console.path);
	}

	if (conf->console.log_path) {
		ret = setenv("LXC_CONSOLE_LOGPATH", conf->console.log_path, 1);
		if (ret < 0)
			SYSERROR("Failed to set environment variable: LXC_CONSOLE_LOGPATH=%s", conf->console.log_path);
	}

	if (cgns_supported()) {
		ret = setenv("LXC_CGNS_AWARE", "1", 1);
		if (ret < 0)
			SYSERROR("Failed to set environment variable LXC_CGNS_AWARE=1");
	}

	loglevel = lxc_log_priority_to_string(lxc_log_get_level());
	ret = setenv("LXC_LOG_LEVEL", loglevel, 1);
	if (ret < 0)
		SYSERROR("Set environment variable LXC_LOG_LEVEL=%s", loglevel);

	if (conf->hooks_version == 0)
		ret = setenv("LXC_HOOK_VERSION", "0", 1);
	else
		ret = setenv("LXC_HOOK_VERSION", "1", 1);
	if (ret < 0)
		SYSERROR("Failed to set environment variable LXC_HOOK_VERSION=%u", conf->hooks_version);
	/* End of environment variable setup for hooks. */

	TRACE("Set environment variables");

	ret = run_lxc_hooks(name, "pre-start", conf, NULL);
	if (ret < 0)
		return log_error(-1, "Failed to run lxc.hook.pre-start for container \"%s\"", name);
	TRACE("Ran pre-start hooks");

	/* The signal fd has to be created before forking otherwise if the child
	 * process exits before we setup the signal fd, the event will be lost
	 * and the command will be stuck.
	 */
	handler->sigfd = setup_signal_fd(&handler->oldmask);
	if (handler->sigfd < 0)
		return log_error(-1, "Failed to setup SIGCHLD fd handler.");
	TRACE("Set up signal fd");

	/* Do this after setting up signals since it might unblock SIGWINCH. */
	ret = lxc_terminal_setup(conf);
	if (ret < 0) {
		ERROR("Failed to create console");
		goto out_restore_sigmask;
	}
	TRACE("Created console");

	ret = lxc_terminal_map_ids(conf, &conf->console);
	if (ret < 0) {
		ERROR("Failed to chown console");
		goto out_delete_terminal;
	}
	TRACE("Chowned console");

	handler->cgroup_ops = cgroup_init(handler->conf);
	if (!handler->cgroup_ops) {
		ERROR("Failed to initialize cgroup driver");
		goto out_delete_terminal;
	}
	TRACE("Initialized cgroup driver");

	ret = lxc_read_seccomp_config(conf);
	if (ret < 0)
		return log_error(-1, "Failed loading seccomp policy");
	TRACE("Read seccomp policy");

	ret = lsm_process_prepare(conf, handler->lxcpath);
	if (ret < 0) {
		ERROR("Failed to initialize LSM");
		goto out_delete_terminal;
	}
	TRACE("Initialized LSM");

	INFO("Container \"%s\" is initialized", name);
	handler->monitor_status_fd = move_fd(status_fd);
	return 0;

out_delete_terminal:
	lxc_terminal_delete(&handler->conf->console);

out_restore_sigmask:
	(void)pthread_sigmask(SIG_SETMASK, &handler->oldmask, NULL);

	return -1;
}

void lxc_end(struct lxc_handler *handler)
{
	int ret;
	pid_t self;
	struct lxc_list *cur, *next;
	char *namespaces[LXC_NS_MAX + 1];
	size_t namespace_count = 0;
	const char *name = handler->name;
	struct cgroup_ops *cgroup_ops = handler->cgroup_ops;

	/* The STOPPING state is there for future cleanup code which can take
	 * awhile.
	 */
	lxc_set_state(name, handler, STOPPING);

	self = lxc_raw_getpid();
	for (int i = 0; i < LXC_NS_MAX; i++) {
		if (handler->nsfd[i] < 0)
			continue;

		if (handler->conf->hooks_version == 0)
			ret = asprintf(&namespaces[namespace_count],
				      "%s:/proc/%d/fd/%d", ns_info[i].proc_name,
				      self, handler->nsfd[i]);
		else
			ret = asprintf(&namespaces[namespace_count],
				      "/proc/%d/fd/%d", self, handler->nsfd[i]);
		if (ret < 0) {
			SYSERROR("Failed to allocate memory");
			break;
		}

		if (handler->conf->hooks_version == 0) {
			namespace_count++;
			continue;
		}

		ret = setenv(ns_info[i].env_name, namespaces[namespace_count], 1);
		if (ret < 0)
			SYSERROR("Failed to set environment variable %s=%s",
				 ns_info[i].env_name, namespaces[namespace_count]);
		else
			TRACE("Set environment variable %s=%s",
			      ns_info[i].env_name, namespaces[namespace_count]);

		namespace_count++;
	}
	namespaces[namespace_count] = NULL;

	if (handler->conf->reboot > REBOOT_NONE) {
		ret = setenv("LXC_TARGET", "reboot", 1);
		if (ret < 0)
			SYSERROR("Failed to set environment variable: LXC_TARGET=reboot");
	}

	if (handler->conf->reboot == REBOOT_NONE) {
		ret = setenv("LXC_TARGET", "stop", 1);
		if (ret < 0)
			SYSERROR("Failed to set environment variable: LXC_TARGET=stop");
	}

	if (handler->conf->hooks_version == 0)
		ret = run_lxc_hooks(name, "stop", handler->conf, namespaces);
	else
		ret = run_lxc_hooks(name, "stop", handler->conf, NULL);
	if (ret < 0)
		ERROR("Failed to run \"lxc.hook.stop\" hook");

	while (namespace_count--)
		free(namespaces[namespace_count]);

	lsm_process_cleanup(handler->conf, handler->lxcpath);

	if (cgroup_ops) {
		cgroup_ops->payload_destroy(cgroup_ops, handler);
		cgroup_ops->monitor_destroy(cgroup_ops, handler);
	}

	if (handler->conf->reboot == REBOOT_NONE) {
		/* For all new state clients simply close the command socket.
		 * This will inform all state clients that the container is
		 * STOPPED and also prevents a race between a open()/close() on
		 * the command socket causing a new process to get ECONNREFUSED
		 * because we haven't yet closed the command socket.
		 */
		close_prot_errno_disarm(handler->conf->maincmd_fd);
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
	} else {
		lxc_set_state(name, handler, STOPPED);
		TRACE("Set container state to \"STOPPED\"");
	}

	/* Avoid lingering namespace references. */
	lxc_put_nsfds(handler);

	ret = run_lxc_hooks(name, "post-stop", handler->conf, NULL);
	if (ret < 0) {
		ERROR("Failed to run lxc.hook.post-stop for container \"%s\"", name);
		if (handler->conf->reboot > REBOOT_NONE) {
			WARN("Container will be stopped instead of rebooted");
			handler->conf->reboot = REBOOT_NONE;

			ret = setenv("LXC_TARGET", "stop", 1);
			if (ret < 0)
				WARN("Failed to set environment variable: LXC_TARGET=stop");
		}
	}

	/* Reset mask set by setup_signal_fd. */
	ret = pthread_sigmask(SIG_SETMASK, &handler->oldmask, NULL);
	if (ret < 0)
		SYSWARN("Failed to restore signal mask");

	lxc_terminal_delete(&handler->conf->console);
	lxc_delete_tty(&handler->conf->ttys);

	/* The command socket is now closed, no more state clients can register
	 * themselves from now on. So free the list of state clients.
	 */
	lxc_list_for_each_safe(cur, &handler->conf->state_clients, next) {
		struct lxc_state_client *client = cur->elem;

		/* Keep state clients that want to be notified about reboots. */
		if ((handler->conf->reboot > REBOOT_NONE) &&
		    (client->states[RUNNING] == 2))
			continue;

		/* close state client socket */
		lxc_list_del(cur);
		close(client->clientfd);
		free(cur->elem);
		free(cur);
	}

	if (handler->conf->ephemeral == 1 && handler->conf->reboot != REBOOT_REQ)
		lxc_destroy_container_on_signal(handler, name);

	lxc_free_handler(handler);
}

void lxc_abort(struct lxc_handler *handler)
{
	int ret = 0;
	int status;

	lxc_set_state(handler->name, handler, ABORTING);

	if (handler->pidfd >= 0) {
		ret = lxc_raw_pidfd_send_signal(handler->pidfd, SIGKILL, NULL, 0);
		if (ret)
			SYSWARN("Failed to send SIGKILL via pidfd %d for process %d",
				handler->pidfd, handler->pid);
	}

	if ((!ret || errno != ESRCH) && handler->pid > 0)
		if (kill(handler->pid, SIGKILL))
			SYSWARN("Failed to send SIGKILL to %d", handler->pid);

	do {
		ret = waitpid(-1, &status, 0);
	} while (ret > 0);
}

static int do_start(void *data)
{
	struct lxc_handler *handler = data;
	__lxc_unused __do_close int data_sock0 = handler->data_sock[0],
					   data_sock1 = handler->data_sock[1];
	__do_close int status_fd = -EBADF;
	int ret;
	uid_t new_uid;
	gid_t new_gid;
	struct lxc_list *iterator;
	uid_t nsuid = 0;
	gid_t nsgid = 0;
	int devnull_fd = -1;

	lxc_sync_fini_parent(handler);

	if (lxc_abstract_unix_recv_fds(data_sock1, &status_fd, 1, NULL, 0) < 0) {
		ERROR("Failed to receive status file descriptor to child process");
		goto out_warn_father;
	}

	/* This prctl must be before the synchro, so if the parent dies before
	 * we set the parent death signal, we will detect its death with the
	 * synchro right after, otherwise we have a window where the parent can
	 * exit before we set the pdeath signal leading to a unsupervized
	 * container.
	 */
	ret = lxc_set_death_signal(SIGKILL, handler->monitor_pid, status_fd);
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
	close_prot_errno_disarm(handler->pinfd);

	ret = lxc_sync_wait_parent(handler, LXC_SYNC_STARTUP);
	if (ret < 0)
		goto out_warn_father;

	/* Unshare CLONE_NEWNET after CLONE_NEWUSER. See
	 * https://github.com/lxc/lxd/issues/1978.
	 */
	if ((handler->ns_clone_flags & (CLONE_NEWNET | CLONE_NEWUSER)) ==
	    (CLONE_NEWNET | CLONE_NEWUSER)) {
		ret = unshare(CLONE_NEWNET);
		if (ret < 0) {
			SYSERROR("Failed to unshare CLONE_NEWNET");
			goto out_warn_father;
		}
		INFO("Unshared CLONE_NEWNET");
	}

	/* Tell the parent task it can begin to configure the container and wait
	 * for it to finish.
	 */
	ret = lxc_sync_barrier_parent(handler, LXC_SYNC_CONFIGURE);
	if (ret < 0)
		goto out_error;

	if (handler->ns_clone_flags & CLONE_NEWNET) {
		ret = lxc_network_recv_from_parent(handler);
		if (ret < 0) {
			ERROR("Failed to receive veth names from parent");
			goto out_warn_father;
		}
	}

	/* If we are in a new user namespace, become root there to have
	 * privilege over our namespace.
	 */
	if (!lxc_list_empty(&handler->conf->id_map)) {
		if (!handler->conf->root_nsuid_map)
			nsuid = handler->conf->init_uid;

		if (!handler->conf->root_nsgid_map)
			nsgid = handler->conf->init_gid;

		/* Drop groups only after we switched to a valid gid in the new
		 * user namespace.
		 */
		if (!lxc_setgroups(0, NULL) &&
		    (handler->am_root || errno != EPERM))
			goto out_warn_father;

		if (!lxc_switch_uid_gid(nsuid, nsgid))
			goto out_warn_father;

		ret = prctl(PR_SET_DUMPABLE, prctl_arg(1), prctl_arg(0),
			    prctl_arg(0), prctl_arg(0));
		if (ret < 0)
			goto out_warn_father;

		/* set{g,u}id() clears deathsignal */
		ret = lxc_set_death_signal(SIGKILL, handler->monitor_pid, status_fd);
		if (ret < 0) {
			SYSERROR("Failed to set PR_SET_PDEATHSIG to SIGKILL");
			goto out_warn_father;
		}
	}

	ret = access(handler->lxcpath, X_OK);
	if (ret != 0) {
		print_top_failing_dir(handler->lxcpath);
		goto out_warn_father;
	}

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
	if (handler->daemonize && !handler->conf->autodev) {
		char path[PATH_MAX];

		ret = snprintf(path, sizeof(path), "%s/dev/null",
			       handler->conf->rootfs.mount);
		if (ret < 0 || ret >= sizeof(path))
			goto out_warn_father;

		ret = access(path, F_OK);
		if (ret != 0) {
			devnull_fd = open_devnull();

			if (devnull_fd < 0)
				goto out_warn_father;
			WARN("Using /dev/null from the host for container init's standard file descriptors. Migration will not work");
		}
	}

	/* Ask father to setup cgroups and wait for him to finish. */
	ret = lxc_sync_barrier_parent(handler, LXC_SYNC_CGROUP);
	if (ret < 0)
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
	if (handler->ns_clone_flags & CLONE_NEWCGROUP) {
		ret = unshare(CLONE_NEWCGROUP);
		if (ret < 0) {
			if (errno != EINVAL) {
				SYSERROR("Failed to unshare CLONE_NEWCGROUP");
				goto out_warn_father;
			}

			handler->ns_clone_flags &= ~CLONE_NEWCGROUP;
			SYSINFO("Kernel does not support CLONE_NEWCGROUP");
		} else {
			INFO("Unshared CLONE_NEWCGROUP");
		}
	}

	/* Add the requested environment variables to the current environment to
	 * allow them to be used by the various hooks, such as the start hook
	 * below.
	 */
	lxc_list_for_each(iterator, &handler->conf->environment) {
		ret = putenv((char *)iterator->elem);
		if (ret < 0) {
			SYSERROR("Failed to set environment variable: %s",
				 (char *)iterator->elem);
			goto out_warn_father;
		}
	}

	/* Setup the container, ip, names, utsname, ... */
	ret = lxc_setup(handler);
	if (ret < 0) {
		ERROR("Failed to setup container \"%s\"", handler->name);
		goto out_warn_father;
	}

	/* Set the label to change to when we exec(2) the container's init. */
	ret = lsm_process_label_set(NULL, handler->conf, true);
	if (ret < 0)
		goto out_warn_father;

	/* Set PR_SET_NO_NEW_PRIVS after we changed the lsm label. If we do it
	 * before we aren't allowed anymore.
	 */
	if (handler->conf->no_new_privs) {
		ret = prctl(PR_SET_NO_NEW_PRIVS, prctl_arg(1), prctl_arg(0),
			    prctl_arg(0), prctl_arg(0));
		if (ret < 0) {
			SYSERROR("Could not set PR_SET_NO_NEW_PRIVS to block execve() gainable privileges");
			goto out_warn_father;
		}
		DEBUG("Set PR_SET_NO_NEW_PRIVS to block execve() gainable privileges");
	}

	/* Some init's such as busybox will set sane tty settings on stdin,
	 * stdout, stderr which it thinks is the console. We already set them
	 * the way we wanted on the real terminal, and we want init to do its
	 * setup on its console ie. the pty allocated in lxc_terminal_setup() so
	 * make sure that that pty is stdin,stdout,stderr.
	 */
	 if (handler->conf->console.slave >= 0) {
		 if (handler->daemonize || !handler->conf->is_execute)
			 ret = set_stdfds(handler->conf->console.slave);
		 else
			 ret = lxc_terminal_set_stdfds(handler->conf->console.slave);
		 if (ret < 0) {
			ERROR("Failed to redirect std{in,out,err} to pty file descriptor %d",
			      handler->conf->console.slave);
			goto out_warn_father;
		 }
	 }

	/* If we mounted a temporary proc, then unmount it now. */
	tmp_proc_unmount(handler->conf);

	ret = lxc_seccomp_load(handler->conf);
	if (ret < 0)
		goto out_warn_father;

	ret = lxc_seccomp_send_notifier_fd(&handler->conf->seccomp, data_sock0);
	if (ret < 0) {
		SYSERROR("Failed to send seccomp notify fd to parent");
		goto out_warn_father;
	}

	ret = run_lxc_hooks(handler->name, "start", handler->conf, NULL);
	if (ret < 0) {
		ERROR("Failed to run lxc.hook.start for container \"%s\"",
		      handler->name);
		goto out_warn_father;
	}

	close_prot_errno_disarm(handler->sigfd);

	if (handler->conf->console.slave < 0 && handler->daemonize) {
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

	close_prot_errno_disarm(devnull_fd);

	setsid();

	if (handler->conf->init_cwd) {
		ret = chdir(handler->conf->init_cwd);
		if (ret < 0) {
			SYSERROR("Could not change directory to \"%s\"",
				 handler->conf->init_cwd);
			goto out_warn_father;
		}
	}

	ret = lxc_sync_barrier_parent(handler, LXC_SYNC_CGROUP_LIMITS);
	if (ret < 0)
		goto out_warn_father;

	/* Reset the environment variables the user requested in a clear
	 * environment.
	 */
	ret = clearenv();
	/* Don't error out though. */
	if (ret < 0)
		SYSERROR("Failed to clear environment.");

	lxc_list_for_each(iterator, &handler->conf->environment) {
		ret = putenv((char *)iterator->elem);
		if (ret < 0) {
			SYSERROR("Failed to set environment variable: %s",
				 (char *)iterator->elem);
			goto out_warn_father;
		}
	}

	ret = putenv("container=lxc");
	if (ret < 0) {
		SYSERROR("Failed to set environment variable: container=lxc");
		goto out_warn_father;
	}

	if (handler->conf->ttys.tty_names) {
		ret = putenv(handler->conf->ttys.tty_names);
		if (ret < 0) {
			SYSERROR("Failed to set environment variable for container ptys");
			goto out_warn_father;
		}
	}

	/* The container has been setup. We can now switch to an unprivileged
	 * uid/gid.
	 */
	new_uid = handler->conf->init_uid;
	new_gid = handler->conf->init_gid;

	/* Avoid unnecessary syscalls. */
	if (new_uid == nsuid)
		new_uid = LXC_INVALID_UID;

	if (new_gid == nsgid)
		new_gid = LXC_INVALID_GID;

	/* If we are in a new user namespace we already dropped all groups when
	 * we switched to root in the new user namespace further above. Only
	 * drop groups if we can, so ensure that we have necessary privilege.
	 */
	if (lxc_list_empty(&handler->conf->id_map))
		#if HAVE_LIBCAP
		if (lxc_proc_cap_is_set(CAP_SETGID, CAP_EFFECTIVE))
		#endif
			if (!lxc_setgroups(0, NULL))
				goto out_warn_father;

	if (!lxc_switch_uid_gid(new_uid, new_gid))
		goto out_warn_father;

	ret = lxc_ambient_caps_down();
	if (ret < 0) {
		ERROR("Failed to clear ambient capabilities");
		goto out_warn_father;
	}

	if (handler->conf->monitor_signal_pdeath != SIGKILL) {
		ret = lxc_set_death_signal(handler->conf->monitor_signal_pdeath,
					   handler->monitor_pid, status_fd);
		if (ret < 0) {
			SYSERROR("Failed to set PR_SET_PDEATHSIG to %d",
				 handler->conf->monitor_signal_pdeath);
			goto out_warn_father;
		}
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
	close_prot_errno_disarm(devnull_fd);

	return -1;
}

static int lxc_recv_ttys_from_child(struct lxc_handler *handler)
{
	int i;
	struct lxc_terminal_info *tty;
	int ret = -1;
	int sock = handler->data_sock[1];
	struct lxc_conf *conf = handler->conf;
	struct lxc_tty_info *ttys = &conf->ttys;

	if (!conf->ttys.max)
		return 0;

	ttys->tty = malloc(sizeof(*ttys->tty) * ttys->max);
	if (!ttys->tty)
		return -1;

	for (i = 0; i < conf->ttys.max; i++) {
		int ttyfds[2];

		ret = lxc_abstract_unix_recv_fds(sock, ttyfds, 2, NULL, 0);
		if (ret < 0)
			break;

		tty = &ttys->tty[i];
		tty->busy = -1;
		tty->master = ttyfds[0];
		tty->slave = ttyfds[1];
		TRACE("Received pty with master fd %d and slave fd %d from child", tty->master, tty->slave);
	}

	if (ret < 0)
		SYSERROR("Failed to receive %zu ttys from child", ttys->max);
	else
		TRACE("Received %zu ttys from child", ttys->max);

	return ret;
}

int resolve_clone_flags(struct lxc_handler *handler)
{
	int i;
	struct lxc_conf *conf = handler->conf;

	for (i = 0; i < LXC_NS_MAX; i++) {
		if (conf->ns_keep) {
			if (!(conf->ns_keep & ns_info[i].clone_flag))
				handler->ns_clone_flags |= ns_info[i].clone_flag;
		} else if (conf->ns_clone) {
			if ((conf->ns_clone & ns_info[i].clone_flag))
				handler->ns_clone_flags |= ns_info[i].clone_flag;
		} else {
			if (i == LXC_NS_USER && lxc_list_empty(&handler->conf->id_map))
				continue;

			if (i == LXC_NS_NET && lxc_requests_empty_network(handler))
				continue;

			if (i == LXC_NS_CGROUP && !cgns_supported())
				continue;

			handler->ns_clone_flags |= ns_info[i].clone_flag;
		}

		if (!conf->ns_share[i])
			continue;

		handler->ns_clone_flags &= ~ns_info[i].clone_flag;
		TRACE("Sharing %s namespace", ns_info[i].proc_name);
	}

	return 0;
}

/* Note that this function is used with clone(CLONE_VM). Some glibc versions
 * used to reset the pid/tid to -1 when CLONE_VM was used without CLONE_THREAD.
 * But since the memory between parent and child is shared on CLONE_VM this
 * would invalidate the getpid() cache that glibc used to maintain and so
 * getpid() in the child would return the parent's pid. This is all fixed in
 * newer glibc versions where the getpid() cache is removed and the pid/tid is
 * not reset anymore.
 * However, if for whatever reason you - dear committer - somehow need to get the
 * pid of the dummy intermediate process for do_share_ns() you need to call
 * lxc_raw_getpid(). The next lxc_raw_clone() call does not employ CLONE_VM and
 * will be fine.
 */
static inline int do_share_ns(void *arg)
{
	int i, flags, ret;
	struct lxc_handler *handler = arg;

	for (i = 0; i < LXC_NS_MAX; i++) {
		if (handler->nsfd[i] < 0)
			continue;

		ret = setns(handler->nsfd[i], 0);
		if (ret < 0) {
			/*
			 * Note that joining a user and/or mount namespace
			 * requires the process is not multithreaded otherwise
			 * setns() will fail here.
			 */
			SYSERROR("Failed to inherit %s namespace",
				 ns_info[i].proc_name);
			return -1;
		}

		DEBUG("Inherited %s namespace", ns_info[i].proc_name);
	}

	flags = handler->ns_on_clone_flags;
	flags |= CLONE_PARENT;
	handler->pid = lxc_raw_clone_cb(do_start, handler, CLONE_PIDFD | flags,
					&handler->pidfd);
	if (handler->pid < 0)
		return -1;

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
	__do_close int data_sock0 = -EBADF, data_sock1 = -EBADF;
	int i, ret;
	char pidstr[20];
	bool wants_to_map_ids;
	struct lxc_list *id_map;
	const char *name = handler->name;
	const char *lxcpath = handler->lxcpath;
	bool share_ns = false;
	struct lxc_conf *conf = handler->conf;
	struct cgroup_ops *cgroup_ops = handler->cgroup_ops;

	id_map = &conf->id_map;
	wants_to_map_ids = !lxc_list_empty(id_map);

	for (i = 0; i < LXC_NS_MAX; i++) {
		if (!conf->ns_share[i])
			continue;

		handler->nsfd[i] = lxc_inherit_namespace(conf->ns_share[i], lxcpath, ns_info[i].proc_name);
		if (handler->nsfd[i] < 0)
			return -1;

		share_ns = true;
	}

	ret = lxc_sync_init(handler);
	if (ret < 0)
		return -1;

	ret = socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0,
			 handler->data_sock);
	if (ret < 0)
		goto out_sync_fini;
	data_sock0 = handler->data_sock[0];
	data_sock1 = handler->data_sock[1];

	ret = resolve_clone_flags(handler);
	if (ret < 0)
		goto out_sync_fini;

	if (handler->ns_clone_flags & CLONE_NEWNET) {
		ret = lxc_find_gateway_addresses(handler);
		if (ret) {
			ERROR("Failed to find gateway addresses");
			goto out_sync_fini;
		}
	}

	if (!cgroup_ops->payload_create(cgroup_ops, handler)) {
		ERROR("Failed creating cgroups");
		goto out_delete_net;
	}

	/* If the rootfs is not a blockdev, prevent the container from marking
	 * it readonly.
	 * If the container is unprivileged then skip rootfs pinning.
	 */
	if (!wants_to_map_ids) {
		handler->pinfd = pin_rootfs(conf->rootfs.path);
		if (handler->pinfd == -EBADF)
			INFO("Failed to pin the rootfs for container \"%s\"", handler->name);
	}

	/* Create a process in a new set of namespaces. */
	handler->ns_on_clone_flags = handler->ns_clone_flags;
	if (handler->ns_clone_flags & CLONE_NEWUSER) {
		/* If CLONE_NEWUSER and CLONE_NEWNET was requested, we need to
		 * clone a new user namespace first and only later unshare our
		 * network namespace to ensure that network devices ownership is
		 * set up correctly.
		 */
		handler->ns_on_clone_flags &= ~CLONE_NEWNET;
	}
	/* The cgroup namespace gets unshare()ed not clone()ed. */
	handler->ns_on_clone_flags &= ~CLONE_NEWCGROUP;

	if (share_ns) {
		pid_t attacher_pid;

		attacher_pid = lxc_clone(do_share_ns, handler,
					 CLONE_VFORK | CLONE_VM | CLONE_FILES, NULL);
		if (attacher_pid < 0) {
			SYSERROR(LXC_CLONE_ERROR);
			goto out_delete_net;
		}

		ret = wait_for_pid(attacher_pid);
		if (ret < 0) {
			SYSERROR("Intermediate process failed");
			goto out_delete_net;
		}
	} else {
		handler->pid = lxc_raw_clone_cb(do_start, handler,
						CLONE_PIDFD | handler->ns_on_clone_flags,
						&handler->pidfd);
	}
	if (handler->pid < 0) {
		SYSERROR(LXC_CLONE_ERROR);
		goto out_delete_net;
	}
	TRACE("Cloned child process %d", handler->pid);

	/* Verify that we can actually make use of pidfds. */
	if (!lxc_can_use_pidfd(handler->pidfd))
		close_prot_errno_disarm(handler->pidfd);

	ret = snprintf(pidstr, 20, "%d", handler->pid);
	if (ret < 0 || ret >= 20)
		goto out_delete_net;

	ret = setenv("LXC_PID", pidstr, 1);
	if (ret < 0)
		SYSERROR("Failed to set environment variable: LXC_PID=%s", pidstr);

	for (i = 0; i < LXC_NS_MAX; i++)
		if (handler->ns_on_clone_flags & ns_info[i].clone_flag)
			INFO("Cloned %s", ns_info[i].flag_name);

	if (!lxc_try_preserve_namespaces(handler, handler->ns_on_clone_flags, handler->pid)) {
		ERROR("Failed to preserve cloned namespaces for lxc.hook.stop");
		goto out_delete_net;
	}

	lxc_sync_fini_child(handler);

	if (lxc_abstract_unix_send_fds(handler->data_sock[0], &handler->monitor_status_fd, 1, NULL, 0) < 0) {
		ERROR("Failed to send status file descriptor to child process");
		goto out_delete_net;
	}
	close_prot_errno_disarm(handler->monitor_status_fd);

	/* Map the container uids. The container became an invalid userid the
	 * moment it was cloned with CLONE_NEWUSER. This call doesn't change
	 * anything immediately, but allows the container to setuid(0) (0 being
	 * mapped to something else on the host.) later to become a valid uid
	 * again.
	 */
	if (wants_to_map_ids) {
		if (!handler->conf->ns_share[LXC_NS_USER] &&
		    (handler->conf->ns_keep & CLONE_NEWUSER) == 0) {
			ret = lxc_map_ids(id_map, handler->pid);
			if (ret < 0) {
				ERROR("Failed to set up id mapping.");
				goto out_delete_net;
			}
		}
	}

	ret = lxc_sync_wake_child(handler, LXC_SYNC_STARTUP);
	if (ret < 0)
		goto out_delete_net;

	ret = lxc_sync_wait_child(handler, LXC_SYNC_CONFIGURE);
	if (ret < 0)
		goto out_delete_net;

	if (!cgroup_ops->setup_limits_legacy(cgroup_ops, handler->conf, false)) {
		ERROR("Failed to setup cgroup limits for container \"%s\"", name);
		goto out_delete_net;
	}

	if (!cgroup_ops->payload_enter(cgroup_ops, handler)) {
		goto out_delete_net;
	}

	if (!cgroup_ops->payload_delegate_controllers(cgroup_ops)) {
		ERROR("Failed to delegate controllers to payload cgroup");
		goto out_delete_net;
	}

	if (!cgroup_ops->setup_limits(cgroup_ops, handler)) {
		ERROR("Failed to setup cgroup limits for container \"%s\"", name);
		goto out_delete_net;
	}

	if (!cgroup_ops->chown(cgroup_ops, handler->conf))
		goto out_delete_net;

	/* If not done yet, we're now ready to preserve the network namespace */
	if (handler->nsfd[LXC_NS_NET] < 0) {
		ret = lxc_try_preserve_ns(handler->pid, "net");
		if (ret < 0) {
			if (ret != -EOPNOTSUPP) {
				SYSERROR("Failed to preserve net namespace");
				goto out_delete_net;
			}
		} else {
			handler->nsfd[LXC_NS_NET] = ret;
			DEBUG("Preserved net namespace via fd %d", ret);
		}
	}
	ret = lxc_netns_set_nsid(handler->nsfd[LXC_NS_NET]);
	if (ret < 0)
		SYSWARN("Failed to allocate new network namespace id");
	else
		TRACE("Allocated new network namespace id");

	/* Create the network configuration. */
	if (handler->ns_clone_flags & CLONE_NEWNET) {
		ret = lxc_create_network(handler);
		if (ret < 0) {
			ERROR("Failed to create the network");
			goto out_delete_net;
		}

		ret = lxc_network_send_to_child(handler);
		if (ret < 0) {
			ERROR("Failed to send veth names to child");
			goto out_delete_net;
		}
	}

	if (!lxc_list_empty(&conf->procs)) {
		ret = setup_proc_filesystem(&conf->procs, handler->pid);
		if (ret < 0)
			goto out_delete_net;
	}

	/* Tell the child to continue its initialization. We'll get
	 * LXC_SYNC_CGROUP when it is ready for us to setup cgroups.
	 */
	ret = lxc_sync_barrier_child(handler, LXC_SYNC_POST_CONFIGURE);
	if (ret < 0)
		goto out_delete_net;

	if (!lxc_list_empty(&conf->limits)) {
		ret = setup_resource_limits(&conf->limits, handler->pid);
		if (ret < 0) {
			ERROR("Failed to setup resource limits");
			goto out_delete_net;
		}
	}

	ret = lxc_sync_barrier_child(handler, LXC_SYNC_CGROUP_UNSHARE);
	if (ret < 0)
		goto out_delete_net;

	if (!cgroup_ops->setup_limits_legacy(cgroup_ops, handler->conf, true)) {
		ERROR("Failed to setup legacy device cgroup controller limits");
		goto out_delete_net;
	}
	TRACE("Set up legacy device cgroup controller limits");

	if (!cgroup_ops->devices_activate(cgroup_ops, handler)) {
		ERROR("Failed to setup cgroup2 device controller limits");
		goto out_delete_net;
	}
	TRACE("Set up cgroup2 device controller limits");

	if (handler->ns_clone_flags & CLONE_NEWCGROUP) {
		/* Now we're ready to preserve the cgroup namespace */
		ret = lxc_try_preserve_ns(handler->pid, "cgroup");
		if (ret < 0) {
			if (ret != -EOPNOTSUPP) {
				SYSERROR("Failed to preserve cgroup namespace");
				goto out_delete_net;
			}
		} else {
			handler->nsfd[LXC_NS_CGROUP] = ret;
			DEBUG("Preserved cgroup namespace via fd %d", ret);
		}
	}

	cgroup_ops->payload_finalize(cgroup_ops);
	TRACE("Finished setting up cgroups");

	/* Run any host-side start hooks */
	ret = run_lxc_hooks(name, "start-host", conf, NULL);
	if (ret < 0) {
		ERROR("Failed to run lxc.hook.start-host");
		goto out_delete_net;
	}

	/* Tell the child to complete its initialization and wait for it to exec
	 * or return an error. (The child will never return
	 * LXC_SYNC_READY_START+1. It will either close the sync pipe, causing
	 * lxc_sync_barrier_child to return success, or return a different
	 * value, causing us to error out).
	 */
	ret = lxc_sync_barrier_child(handler, LXC_SYNC_READY_START);
	if (ret < 0)
		goto out_delete_net;

	if (handler->ns_clone_flags & CLONE_NEWNET) {
		ret = lxc_network_recv_name_and_ifindex_from_child(handler);
		if (ret < 0) {
			ERROR("Failed to receive names and ifindices for network devices from child");
			goto out_delete_net;
		}
	}

	/* Now all networks are created, network devices are moved into place,
	 * and the correct names and ifindices in the respective namespaces have
	 * been recorded. The corresponding structs have now all been filled. So
	 * log them for debugging purposes.
	 */
	lxc_log_configured_netdevs(conf);

	/* Read tty fds allocated by child. */
	ret = lxc_recv_ttys_from_child(handler);
	if (ret < 0) {
		ERROR("Failed to receive tty info from child process");
		goto out_delete_net;
	}

	ret = lxc_seccomp_recv_notifier_fd(&handler->conf->seccomp, data_sock1);
	if (ret < 0) {
		SYSERROR("Failed to receive seccomp notify fd from child");
		goto out_delete_net;
	}

	ret = handler->ops->post_start(handler, handler->data);
	if (ret < 0)
		goto out_abort;

	ret = lxc_set_state(name, handler, RUNNING);
	if (ret < 0) {
		ERROR("Failed to set state to \"%s\"", lxc_state2str(RUNNING));
		goto out_abort;
	}

	lxc_sync_fini(handler);

	return 0;

out_delete_net:
	if (handler->ns_clone_flags & CLONE_NEWNET)
		lxc_delete_network(handler);

out_abort:
	lxc_abort(handler);

out_sync_fini:
	lxc_sync_fini(handler);
	close_prot_errno_disarm(handler->pinfd);

	return -1;
}

int __lxc_start(struct lxc_handler *handler, struct lxc_operations *ops,
		void *data, const char *lxcpath, bool daemonize, int *error_num)
{
	int ret, status;
	const char *name = handler->name;
	struct lxc_conf *conf = handler->conf;
	struct cgroup_ops *cgroup_ops;

	ret = lxc_init(name, handler);
	if (ret < 0) {
		ERROR("Failed to initialize container \"%s\"", name);
		goto out_abort;
	}
	handler->ops = ops;
	handler->data = data;
	handler->daemonize = daemonize;
	cgroup_ops = handler->cgroup_ops;

	if (!attach_block_device(handler->conf)) {
		ERROR("Failed to attach block device");
		ret = -1;
		goto out_abort;
	}

	if (!cgroup_ops->monitor_create(cgroup_ops, handler)) {
		ERROR("Failed to create monitor cgroup");
		ret = -1;
		goto out_abort;
	}

	if (!cgroup_ops->monitor_enter(cgroup_ops, handler)) {
		ERROR("Failed to enter monitor cgroup");
		ret = -1;
		goto out_abort;
	}

	if (!cgroup_ops->monitor_delegate_controllers(cgroup_ops)) {
		ERROR("Failed to delegate controllers to monitor cgroup");
		ret = -1;
		goto out_abort;
	}

	if (geteuid() == 0 && !lxc_list_empty(&conf->id_map)) {
		/* If the backing store is a device, mount it here and now. */
		if (rootfs_is_blockdev(conf)) {
			ret = unshare(CLONE_NEWNS);
			if (ret < 0) {
				ERROR("Failed to unshare CLONE_NEWNS");
				goto out_abort;
			}
			INFO("Unshared CLONE_NEWNS");

			remount_all_slave();
			ret = lxc_setup_rootfs_prepare_root(conf, name, lxcpath);
			if (ret < 0) {
				ERROR("Error setting up rootfs mount as root before spawn");
				goto out_abort;
			}
			INFO("Set up container rootfs as host root");
		}
	}

	ret = lxc_spawn(handler);
	if (ret < 0) {
		ERROR("Failed to spawn container \"%s\"", name);
		goto out_detach_blockdev;
	}

	handler->conf->reboot = REBOOT_NONE;

	ret = lxc_poll(name, handler);
	if (ret) {
		ERROR("LXC mainloop exited with error: %d", ret);
		goto out_delete_network;
	}

	if (!handler->init_died && handler->pid > 0) {
		ERROR("Child process is not killed");
		ret = -1;
		goto out_delete_network;
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
			DEBUG("Container \"%s\" is halting", name);
			break;
		case SIGHUP: /* reboot */
			DEBUG("Container \"%s\" is rebooting", name);
			handler->conf->reboot = REBOOT_REQ;
			break;
		case SIGSYS: /* seccomp */
			DEBUG("Container \"%s\" violated its seccomp policy", name);
			break;
		default:
			DEBUG("Unknown exit status for container \"%s\" init %d", name, WTERMSIG(status));
			break;
		}
	}

	ret = lxc_restore_phys_nics_to_netns(handler);
	if (ret < 0)
		ERROR("Failed to move physical network devices back to parent network namespace");

	close_prot_errno_disarm(handler->pinfd);

	lxc_monitor_send_exit_code(name, status, handler->lxcpath);
	lxc_error_set_and_log(handler->pid, status);
	if (error_num)
		*error_num = handler->exit_status;

/* These are not the droids you are looking for. */
__private_goto1:
	lxc_delete_network(handler);

__private_goto2:
	detach_block_device(handler->conf);

__private_goto3:
	lxc_end(handler);

	return ret;

/* These are the droids you are looking for. */
out_abort:
	lxc_abort(handler);
	goto __private_goto3;

out_detach_blockdev:
	lxc_abort(handler);
	goto __private_goto2;

out_delete_network:
	lxc_abort(handler);
	goto __private_goto1;
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

int lxc_start(char *const argv[], struct lxc_handler *handler,
	      const char *lxcpath, bool daemonize, int *error_num)
{
	struct start_args start_arg = {
		.argv = argv,
	};

	TRACE("Doing lxc_start");
	return __lxc_start(handler, &start_ops, &start_arg, lxcpath, daemonize, error_num);
}

static void lxc_destroy_container_on_signal(struct lxc_handler *handler,
					    const char *name)
{
	char destroy[PATH_MAX];
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

	ret = snprintf(destroy, PATH_MAX, "%s/%s", handler->lxcpath, name);
	if (ret < 0 || ret >= PATH_MAX) {
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

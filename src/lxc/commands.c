/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <caps.h>
#include <errno.h>
#include <fcntl.h>
#include <malloc.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "af_unix.h"
#include "cgroup.h"
#include "cgroups/cgroup2_devices.h"
#include "commands.h"
#include "commands_utils.h"
#include "conf.h"
#include "config.h"
#include "confile.h"
#include "log.h"
#include "lxc.h"
#include "lxclock.h"
#include "lxcseccomp.h"
#include "mainloop.h"
#include "memory_utils.h"
#include "monitor.h"
#include "start.h"
#include "terminal.h"
#include "utils.h"

/*
 * This file provides the different functions for clients to query/command the
 * server. The client is typically some lxc tool and the server is typically the
 * container (ie. lxc-start).
 *
 * Each command is transactional, the clients send a request to the server and
 * the server answers the request with a message giving the request's status
 * (zero or a negative errno value). Both the request and response may contain
 * additional data.
 *
 * Each command is wrapped in a ancillary message in order to pass a credential
 * making possible to the server to check if the client is allowed to ask for
 * this command or not.
 *
 * IMPORTANTLY: Note that semantics for current commands are fixed. If you wish
 * to make any changes to how, say, LXC_CMD_GET_CONFIG_ITEM works by adding
 * information to the end of cmd.data, then you must introduce a new
 * LXC_CMD_GET_CONFIG_ITEM_V2 define with a new number. You may wish to also
 * mark LXC_CMD_GET_CONFIG_ITEM deprecated in commands.h.
 *
 * This is necessary in order to avoid having a newly compiled lxc command
 * communicating with a running (old) monitor from crashing the running
 * container.
 */

lxc_log_define(commands, lxc);

static const char *lxc_cmd_str(lxc_cmd_t cmd)
{
	static const char *const cmdname[LXC_CMD_MAX] = {
		[LXC_CMD_CONSOLE]			= "console",
		[LXC_CMD_TERMINAL_WINCH]      		= "terminal_winch",
		[LXC_CMD_STOP]                		= "stop",
		[LXC_CMD_GET_STATE]           		= "get_state",
		[LXC_CMD_GET_INIT_PID]        		= "get_init_pid",
		[LXC_CMD_GET_CLONE_FLAGS]     		= "get_clone_flags",
		[LXC_CMD_GET_CGROUP]          		= "get_cgroup",
		[LXC_CMD_GET_CONFIG_ITEM]     		= "get_config_item",
		[LXC_CMD_GET_NAME]            		= "get_name",
		[LXC_CMD_GET_LXCPATH]         		= "get_lxcpath",
		[LXC_CMD_ADD_STATE_CLIENT]		= "add_state_client",
		[LXC_CMD_CONSOLE_LOG]			= "console_log",
		[LXC_CMD_SERVE_STATE_CLIENTS]		= "serve_state_clients",
		[LXC_CMD_SECCOMP_NOTIFY_ADD_LISTENER]	= "seccomp_notify_add_listener",
		[LXC_CMD_ADD_BPF_DEVICE_CGROUP]		= "add_bpf_device_cgroup",
		[LXC_CMD_FREEZE]			= "freeze",
		[LXC_CMD_UNFREEZE]			= "unfreeze",
		[LXC_CMD_GET_CGROUP2_FD]		= "get_cgroup2_fd",
		[LXC_CMD_GET_INIT_PIDFD]        	= "get_init_pidfd",
		[LXC_CMD_GET_LIMITING_CGROUP]		= "get_limiting_cgroup",
		[LXC_CMD_GET_LIMITING_CGROUP2_FD]	= "get_limiting_cgroup2_fd",
		[LXC_CMD_GET_DEVPTS_FD]			= "get_devpts_fd",
		[LXC_CMD_GET_SECCOMP_NOTIFY_FD]		= "get_seccomp_notify_fd",
	};

	if (cmd >= LXC_CMD_MAX)
		return "Invalid request";

	return cmdname[cmd];
}

/*
 * lxc_cmd_rsp_recv: Receive a response to a command
 *
 * @sock  : the socket connected to the container
 * @cmd   : command to put response in
 *
 * Returns the size of the response message or < 0 on failure
 *
 * Note that if the command response datalen > 0, then data is
 * a malloc()ed buffer and should be free()ed by the caller. If
 * the response data is <= a void * worth of data, it will be
 * stored directly in data and datalen will be 0.
 *
 * As a special case, the response for LXC_CMD_CONSOLE is created
 * here as it contains an fd for the ptx pty passed through the
 * unix socket.
 */
static int lxc_cmd_rsp_recv(int sock, struct lxc_cmd_rr *cmd)
{
	__do_close int fd_rsp = -EBADF;
	int ret;
	struct lxc_cmd_rsp *rsp = &cmd->rsp;

	ret = lxc_abstract_unix_recv_fds(sock, &fd_rsp, 1, rsp, sizeof(*rsp));
	if (ret < 0)
		return log_warn_errno(-1,
				      errno, "Failed to receive response for command \"%s\"",
				      lxc_cmd_str(cmd->req.cmd));
	TRACE("Command \"%s\" received response", lxc_cmd_str(cmd->req.cmd));

	if (cmd->req.cmd == LXC_CMD_CONSOLE) {
		struct lxc_cmd_console_rsp_data *rspdata;

		/* recv() returns 0 bytes when a tty cannot be allocated,
		 * rsp->ret is < 0 when the peer permission check failed
		 */
		if (ret == 0 || rsp->ret < 0)
			return 0;

		rspdata = malloc(sizeof(*rspdata));
		if (!rspdata)
			return log_warn_errno(-1,
					      ENOMEM, "Failed to receive response for command \"%s\"",
					      lxc_cmd_str(cmd->req.cmd));

		rspdata->ptxfd = move_fd(fd_rsp);
		rspdata->ttynum = PTR_TO_INT(rsp->data);
		rsp->data = rspdata;
	}

	if (cmd->req.cmd == LXC_CMD_GET_CGROUP2_FD ||
	    cmd->req.cmd == LXC_CMD_GET_LIMITING_CGROUP2_FD)
	{
		int cgroup2_fd = move_fd(fd_rsp);
		rsp->data = INT_TO_PTR(cgroup2_fd);
	}

	if (cmd->req.cmd == LXC_CMD_GET_INIT_PIDFD) {
		int init_pidfd = move_fd(fd_rsp);
		rsp->data = INT_TO_PTR(init_pidfd);
	}

	if (cmd->req.cmd == LXC_CMD_GET_DEVPTS_FD) {
		int devpts_fd = move_fd(fd_rsp);
		rsp->data = INT_TO_PTR(devpts_fd);
	}

	if (cmd->req.cmd == LXC_CMD_GET_SECCOMP_NOTIFY_FD) {
		int seccomp_notify_fd = move_fd(fd_rsp);
		rsp->data = INT_TO_PTR(seccomp_notify_fd);
	}

	if (rsp->datalen == 0)
		return log_debug(ret,
				 "Response data length for command \"%s\" is 0",
				 lxc_cmd_str(cmd->req.cmd));

	if ((rsp->datalen > LXC_CMD_DATA_MAX) &&
	    (cmd->req.cmd != LXC_CMD_CONSOLE_LOG))
		return log_error(-1, "Response data for command \"%s\" is too long: %d bytes > %d",
				 lxc_cmd_str(cmd->req.cmd), rsp->datalen,
				 LXC_CMD_DATA_MAX);

	if (cmd->req.cmd == LXC_CMD_CONSOLE_LOG) {
		rsp->data = malloc(rsp->datalen + 1);
		((char *)rsp->data)[rsp->datalen] = '\0';
	} else {
		rsp->data = malloc(rsp->datalen);
	}
	if (!rsp->data)
		return log_error_errno(-1,
				       ENOMEM, "Failed to allocate response buffer for command \"%s\"",
				       lxc_cmd_str(cmd->req.cmd));

	ret = lxc_recv_nointr(sock, rsp->data, rsp->datalen, 0);
	if (ret != rsp->datalen)
		return log_error_errno(-1,
				       errno, "Failed to receive response data for command \"%s\"",
				       lxc_cmd_str(cmd->req.cmd));

	return ret;
}

/*
 * lxc_cmd_rsp_send: Send a command response
 *
 * @fd   : file descriptor of socket to send response on
 * @rsp  : response to send
 *
 * Returns 0 on success, < 0 on failure
 */
static int lxc_cmd_rsp_send(int fd, struct lxc_cmd_rsp *rsp)
{
	ssize_t ret;

	errno = EMSGSIZE;
	ret = lxc_send_nointr(fd, rsp, sizeof(*rsp), MSG_NOSIGNAL);
	if (ret < 0 || (size_t)ret != sizeof(*rsp))
		return log_error_errno(-1, errno, "Failed to send command response %zd", ret);

	if (!rsp->data || rsp->datalen <= 0)
		return 0;

	errno = EMSGSIZE;
	ret = lxc_send_nointr(fd, rsp->data, rsp->datalen, MSG_NOSIGNAL);
	if (ret < 0 || ret != (ssize_t)rsp->datalen)
		return log_warn_errno(-1, errno, "Failed to send command response data %zd", ret);

	return 0;
}

static int lxc_cmd_send(const char *name, struct lxc_cmd_rr *cmd,
			const char *lxcpath, const char *hashed_sock_name)
{
	__do_close int client_fd = -EBADF;
	ssize_t ret = -1;

	client_fd = lxc_cmd_connect(name, lxcpath, hashed_sock_name, "command");
	if (client_fd < 0)
		return -1;

	ret = lxc_abstract_unix_send_credential(client_fd, &cmd->req,
						sizeof(cmd->req));
	if (ret < 0 || (size_t)ret != sizeof(cmd->req))
		return -1;

	if (cmd->req.cmd == LXC_CMD_SECCOMP_NOTIFY_ADD_LISTENER) {
		int notify_fd = PTR_TO_INT(cmd->req.data);
		ret = lxc_abstract_unix_send_fds(client_fd, &notify_fd, 1, NULL, 0);
		if (ret <= 0)
			return -1;
	} else {
		if (cmd->req.datalen <= 0)
			return move_fd(client_fd);

		errno = EMSGSIZE;
		ret = lxc_send_nointr(client_fd, (void *)cmd->req.data,
				      cmd->req.datalen, MSG_NOSIGNAL);
		if (ret < 0 || ret != (ssize_t)cmd->req.datalen)
			return -1;
	}

	return move_fd(client_fd);
}

/*
 * lxc_cmd: Connect to the specified running container, send it a command
 * request and collect the response
 *
 * @name           : name of container to connect to
 * @cmd            : command with initialized request to send
 * @stopped        : output indicator if the container was not running
 * @lxcpath        : the lxcpath in which the container is running
 *
 * Returns the size of the response message on success, < 0 on failure
 *
 * Note that there is a special case for LXC_CMD_CONSOLE. For this command
 * the fd cannot be closed because it is used as a placeholder to indicate
 * that a particular tty slot is in use. The fd is also used as a signal to
 * the container that when the caller dies or closes the fd, the container
 * will notice the fd on its side of the socket in its mainloop select and
 * then free the slot with lxc_cmd_fd_cleanup(). The socket fd will be
 * returned in the cmd response structure.
 */
static int lxc_cmd(const char *name, struct lxc_cmd_rr *cmd, int *stopped,
		   const char *lxcpath, const char *hashed_sock_name)
{
	__do_close int client_fd = -EBADF;
	int ret = -1;
	bool stay_connected = false;

	if (cmd->req.cmd == LXC_CMD_CONSOLE ||
	    cmd->req.cmd == LXC_CMD_ADD_STATE_CLIENT)
		stay_connected = true;

	*stopped = 0;

	client_fd = lxc_cmd_send(name, cmd, lxcpath, hashed_sock_name);
	if (client_fd < 0) {
		if (errno == ECONNREFUSED || errno == EPIPE)
			*stopped = 1;

		return log_trace_errno(-1, errno, "Command \"%s\" failed to connect command socket",
				       lxc_cmd_str(cmd->req.cmd));
	}

	ret = lxc_cmd_rsp_recv(client_fd, cmd);
	if (ret < 0 && errno == ECONNRESET)
		*stopped = 1;

	TRACE("Opened new command socket connection fd %d for command \"%s\"",
	      client_fd, lxc_cmd_str(cmd->req.cmd));

	if (stay_connected && ret > 0)
		cmd->rsp.ret = move_fd(client_fd);

	return ret;
}

int lxc_try_cmd(const char *name, const char *lxcpath)
{
	int stopped, ret;
	struct lxc_cmd_rr cmd = {
		.req = { .cmd = LXC_CMD_GET_INIT_PID },
	};

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath, NULL);
	if (stopped)
		return 0;
	if (ret > 0 && cmd.rsp.ret < 0) {
		errno = cmd.rsp.ret;
		return -1;
	}
	if (ret > 0)
		return 0;

	/* At this point we weren't denied access, and the container *was*
	 * started. There was some inexplicable error in the protocol.  I'm not
	 * clear on whether we should return -1 here, but we didn't receive a
	 * -EACCES, so technically it's not that we're not allowed to control
	 * the container - it's just not behaving.
	 */
	return 0;
}

/*
 * Validate that the input is a proper string parameter. If not,
 * send an EINVAL response and return -1.
 *
 * Precondition: there is non-zero-length data available.
 */
static int validate_string_request(int fd, const struct lxc_cmd_req *req)
{
	int ret;
	size_t maxlen = req->datalen - 1;
	const char *data = req->data;

	if (data[maxlen] == 0 && strnlen(data, maxlen) == maxlen)
		return 0;

	struct lxc_cmd_rsp rsp = {
		.ret = -EINVAL,
		.datalen = 0,
		.data = NULL,
	};

	ret = lxc_cmd_rsp_send(fd, &rsp);
	if (ret < 0)
		return LXC_CMD_REAP_CLIENT_FD;

	return -1;
}

/* Implementations of the commands and their callbacks */

/*
 * lxc_cmd_get_init_pid: Get pid of the container's init process
 *
 * @name      : name of container to connect to
 * @lxcpath   : the lxcpath in which the container is running
 *
 * Returns the pid on success, < 0 on failure
 */
pid_t lxc_cmd_get_init_pid(const char *name, const char *lxcpath)
{
	int ret, stopped;
	pid_t pid = -1;
	struct lxc_cmd_rr cmd = {
		.req = {
			.cmd = LXC_CMD_GET_INIT_PID
		},
		.rsp = {
			.data = PID_TO_PTR(pid)
		}
	};

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath, NULL);
	if (ret < 0)
		return -1;

	pid = PTR_TO_PID(cmd.rsp.data);
	if (pid < 0)
		return -1;

	/* We need to assume that pid_t can actually hold any pid given to us
	 * by the kernel. If it can't it's a libc bug.
	 */
	return (pid_t)pid;
}

static int lxc_cmd_get_init_pid_callback(int fd, struct lxc_cmd_req *req,
					 struct lxc_handler *handler,
					 struct lxc_epoll_descr *descr)
{
	int ret;
	struct lxc_cmd_rsp rsp = {
		.data = PID_TO_PTR(handler->pid)
	};

	ret = lxc_cmd_rsp_send(fd, &rsp);
	if (ret < 0)
		return LXC_CMD_REAP_CLIENT_FD;

	return 0;
}

int lxc_cmd_get_init_pidfd(const char *name, const char *lxcpath)
{
	int ret, stopped;
	struct lxc_cmd_rr cmd = {
		.req = {
			.cmd = LXC_CMD_GET_INIT_PIDFD,
		},
	};

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath, NULL);
	if (ret < 0)
		return log_debug_errno(-1, errno, "Failed to process init pidfd command");

	if (cmd.rsp.ret < 0)
		return log_debug_errno(-EBADF, errno, "Failed to receive init pidfd");

	return PTR_TO_INT(cmd.rsp.data);
}

static int lxc_cmd_get_init_pidfd_callback(int fd, struct lxc_cmd_req *req,
					   struct lxc_handler *handler,
					   struct lxc_epoll_descr *descr)
{
	struct lxc_cmd_rsp rsp = {
		.ret = 0,
	};
	int ret;

	if (handler->pidfd < 0)
		rsp.ret = -EBADF;
	ret = lxc_abstract_unix_send_fds(fd, &handler->pidfd, 1, &rsp, sizeof(rsp));
	if (ret < 0)
		return log_error(LXC_CMD_REAP_CLIENT_FD, "Failed to send init pidfd");

	return 0;
}

int lxc_cmd_get_devpts_fd(const char *name, const char *lxcpath)
{
	int ret, stopped;
	struct lxc_cmd_rr cmd = {
		.req = {
			.cmd = LXC_CMD_GET_DEVPTS_FD,
		},
	};

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath, NULL);
	if (ret < 0)
		return log_debug_errno(-1, errno, "Failed to process devpts fd command");

	if (cmd.rsp.ret < 0)
		return log_debug_errno(-EBADF, errno, "Failed to receive devpts fd");

	return PTR_TO_INT(cmd.rsp.data);
}

static int lxc_cmd_get_devpts_fd_callback(int fd, struct lxc_cmd_req *req,
					  struct lxc_handler *handler,
					  struct lxc_epoll_descr *descr)
{
	struct lxc_cmd_rsp rsp = {
		.ret = 0,
	};
	int ret;

	if (!handler->conf || handler->conf->devpts_fd < 0) {
		rsp.ret = -EBADF;
		ret = lxc_abstract_unix_send_fds(fd, NULL, 0, &rsp, sizeof(rsp));
	} else {
		ret = lxc_abstract_unix_send_fds(fd, &handler->conf->devpts_fd, 1, &rsp, sizeof(rsp));
	}
	if (ret < 0)
		return log_error(LXC_CMD_REAP_CLIENT_FD, "Failed to send devpts fd");

	return 0;
}

int lxc_cmd_get_seccomp_notify_fd(const char *name, const char *lxcpath)
{
#if HAVE_DECL_SECCOMP_NOTIFY_FD
	int ret, stopped;
	struct lxc_cmd_rr cmd = {
		.req = {
			.cmd = LXC_CMD_GET_SECCOMP_NOTIFY_FD,
		},
	};

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath, NULL);
	if (ret < 0)
		return log_debug_errno(-1, errno, "Failed to process seccomp notify fd command");

	if (cmd.rsp.ret < 0)
		return log_debug_errno(-EBADF, errno, "Failed to receive seccomp notify fd");

	return PTR_TO_INT(cmd.rsp.data);
#else
	return ret_errno(EOPNOTSUPP);
#endif
}

static int lxc_cmd_get_seccomp_notify_fd_callback(int fd, struct lxc_cmd_req *req,
						  struct lxc_handler *handler,
						  struct lxc_epoll_descr *descr)
{
#if HAVE_DECL_SECCOMP_NOTIFY_FD
	struct lxc_cmd_rsp rsp = {
		.ret = 0,
	};
	int ret;

	if (!handler->conf || handler->conf->seccomp.notifier.notify_fd < 0)
		rsp.ret = -EBADF;
	ret = lxc_abstract_unix_send_fds(fd, &handler->conf->seccomp.notifier.notify_fd, 1, &rsp, sizeof(rsp));
	if (ret < 0)
		return log_error(LXC_CMD_REAP_CLIENT_FD, "Failed to send seccomp notify fd");

	return 0;
#else
	return ret_errno(EOPNOTSUPP);
#endif
}

/*
 * lxc_cmd_get_clone_flags: Get clone flags container was spawned with
 *
 * @name      : name of container to connect to
 * @lxcpath   : the lxcpath in which the container is running
 *
 * Returns the clone flags on success, < 0 on failure
 */
int lxc_cmd_get_clone_flags(const char *name, const char *lxcpath)
{
	int ret, stopped;
	struct lxc_cmd_rr cmd = {
		.req = {
			.cmd = LXC_CMD_GET_CLONE_FLAGS,
		},
	};

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath, NULL);
	if (ret < 0)
		return ret;

	return PTR_TO_INT(cmd.rsp.data);
}

static int lxc_cmd_get_clone_flags_callback(int fd, struct lxc_cmd_req *req,
					    struct lxc_handler *handler,
					    struct lxc_epoll_descr *descr)
{
	int ret;
	struct lxc_cmd_rsp rsp = {
		.data = INT_TO_PTR(handler->ns_clone_flags),
	};

	ret = lxc_cmd_rsp_send(fd, &rsp);
	if (ret < 0)
		return LXC_CMD_REAP_CLIENT_FD;

	return 0;
}

static char *lxc_cmd_get_cgroup_path_do(const char *name, const char *lxcpath,
					const char *subsystem,
					lxc_cmd_t command)
{
	int ret, stopped;
	struct lxc_cmd_rr cmd = {
		.req = {
			.cmd = command,
			.data = subsystem,
			.datalen = 0,
		},
	};

	cmd.req.data = subsystem;
	cmd.req.datalen = 0;
	if (subsystem)
		cmd.req.datalen = strlen(subsystem) + 1;

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath, NULL);
	if (ret < 0)
		return NULL;

	if (ret == 0) {
		if (command == LXC_CMD_GET_LIMITING_CGROUP) {
			/*
			 * This may indicate that the container was started
			 * under an ealier version before
			 * `cgroup_advanced_isolation` as implemented, there
			 * it sees an unknown command and just closes the
			 * socket, sending us an EOF.
			 */
			return lxc_cmd_get_cgroup_path_do(name, lxcpath,
							  subsystem,
							  LXC_CMD_GET_CGROUP);
		}
		return NULL;
	}

	if (cmd.rsp.ret < 0 || cmd.rsp.datalen < 0)
		return NULL;

	return cmd.rsp.data;
}

/*
 * lxc_cmd_get_cgroup_path: Calculate a container's cgroup path for a
 * particular subsystem. This is the cgroup path relative to the root
 * of the cgroup filesystem.
 *
 * @name      : name of container to connect to
 * @lxcpath   : the lxcpath in which the container is running
 * @subsystem : the subsystem being asked about
 *
 * Returns the path on success, NULL on failure. The caller must free() the
 * returned path.
 */
char *lxc_cmd_get_cgroup_path(const char *name, const char *lxcpath,
			      const char *subsystem)
{
	return lxc_cmd_get_cgroup_path_do(name, lxcpath, subsystem,
					  LXC_CMD_GET_CGROUP);
}

/*
 * lxc_cmd_get_limiting_cgroup_path: Calculate a container's limiting cgroup
 * path for a particular subsystem. This is the cgroup path relative to the
 * root of the cgroup filesystem. This may be the same as the path returned by
 * lxc_cmd_get_cgroup_path if the container doesn't have a limiting path prefix
 * set.
 *
 * @name      : name of container to connect to
 * @lxcpath   : the lxcpath in which the container is running
 * @subsystem : the subsystem being asked about
 *
 * Returns the path on success, NULL on failure. The caller must free() the
 * returned path.
 */
char *lxc_cmd_get_limiting_cgroup_path(const char *name, const char *lxcpath,
				       const char *subsystem)
{
	return lxc_cmd_get_cgroup_path_do(name, lxcpath, subsystem,
					  LXC_CMD_GET_LIMITING_CGROUP);
}

static int lxc_cmd_get_cgroup_callback_do(int fd, struct lxc_cmd_req *req,
					  struct lxc_handler *handler,
					  struct lxc_epoll_descr *descr,
					  bool limiting_cgroup)
{
	int ret;
	const char *path;
	const void *reqdata;
	struct lxc_cmd_rsp rsp;
	struct cgroup_ops *cgroup_ops = handler->cgroup_ops;
	const char *(*get_fn)(struct cgroup_ops *ops, const char *controller);

	if (req->datalen > 0) {
		ret = validate_string_request(fd, req);
		if (ret != 0)
			return ret;
		reqdata = req->data;
	} else {
		reqdata = NULL;
	}

	get_fn = (limiting_cgroup ? cgroup_ops->get_limiting_cgroup
				  : cgroup_ops->get_cgroup);

	path = get_fn(cgroup_ops, reqdata);

	if (!path)
		return -1;

	rsp.ret = 0;
	rsp.datalen = strlen(path) + 1;
	rsp.data = (char *)path;

	ret = lxc_cmd_rsp_send(fd, &rsp);
	if (ret < 0)
		return LXC_CMD_REAP_CLIENT_FD;

	return 0;
}

static int lxc_cmd_get_cgroup_callback(int fd, struct lxc_cmd_req *req,
				       struct lxc_handler *handler,
				       struct lxc_epoll_descr *descr)
{
	return lxc_cmd_get_cgroup_callback_do(fd, req, handler, descr, false);
}

static int lxc_cmd_get_limiting_cgroup_callback(int fd, struct lxc_cmd_req *req,
						struct lxc_handler *handler,
						struct lxc_epoll_descr *descr)
{
	return lxc_cmd_get_cgroup_callback_do(fd, req, handler, descr, true);
}

/*
 * lxc_cmd_get_config_item: Get config item the running container
 *
 * @name     : name of container to connect to
 * @item     : the configuration item to retrieve (ex: lxc.net.0.veth.pair)
 * @lxcpath  : the lxcpath in which the container is running
 *
 * Returns the item on success, NULL on failure. The caller must free() the
 * returned item.
 */
char *lxc_cmd_get_config_item(const char *name, const char *item,
			      const char *lxcpath)
{
	int ret, stopped;
	struct lxc_cmd_rr cmd = {
		.req = { .cmd = LXC_CMD_GET_CONFIG_ITEM,
			 .data = item,
			 .datalen = strlen(item) + 1,
		       },
	};

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath, NULL);
	if (ret < 0)
		return NULL;

	if (cmd.rsp.ret == 0)
		return cmd.rsp.data;

	return NULL;
}

static int lxc_cmd_get_config_item_callback(int fd, struct lxc_cmd_req *req,
					    struct lxc_handler *handler,
					    struct lxc_epoll_descr *descr)
{
	__do_free char *cidata = NULL;
	int cilen;
	struct lxc_config_t *item;
	struct lxc_cmd_rsp rsp;

	memset(&rsp, 0, sizeof(rsp));
	item = lxc_get_config(req->data);
	if (!item)
		goto err1;

	cilen = item->get(req->data, NULL, 0, handler->conf, NULL);
	if (cilen <= 0)
		goto err1;

	cidata = must_realloc(NULL, cilen + 1);
	if (item->get(req->data, cidata, cilen + 1, handler->conf, NULL) != cilen)
		goto err1;

	cidata[cilen] = '\0';
	rsp.data = cidata;
	rsp.datalen = cilen + 1;
	rsp.ret = 0;
	goto out;

err1:
	rsp.ret = -1;
out:
	cilen = lxc_cmd_rsp_send(fd, &rsp);
	if (cilen < 0)
		return LXC_CMD_REAP_CLIENT_FD;

	return 0;
}

/*
 * lxc_cmd_get_state: Get current state of the container
 *
 * @name      : name of container to connect to
 * @lxcpath   : the lxcpath in which the container is running
 *
 * Returns the state on success, < 0 on failure
 */
int lxc_cmd_get_state(const char *name, const char *lxcpath)
{
	int ret, stopped;
	struct lxc_cmd_rr cmd = {
		.req = {
			.cmd = LXC_CMD_GET_STATE,
		},
	};

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath, NULL);
	if (ret < 0 && stopped)
		return STOPPED;

	if (ret < 0)
		return -1;

	if (!ret)
		return log_warn(-1, "Container \"%s\" has stopped before sending its state", name);

	return log_debug(PTR_TO_INT(cmd.rsp.data),
			 "Container \"%s\" is in \"%s\" state", name,
			 lxc_state2str(PTR_TO_INT(cmd.rsp.data)));
}

static int lxc_cmd_get_state_callback(int fd, struct lxc_cmd_req *req,
				      struct lxc_handler *handler,
				      struct lxc_epoll_descr *descr)
{
	int ret;
	struct lxc_cmd_rsp rsp = {
		.data = INT_TO_PTR(handler->state),
	};

	ret = lxc_cmd_rsp_send(fd, &rsp);
	if (ret < 0)
		return LXC_CMD_REAP_CLIENT_FD;

	return 0;
}

/*
 * lxc_cmd_stop: Stop the container previously started with lxc_start. All
 * the processes running inside this container will be killed.
 *
 * @name     : name of container to connect to
 * @lxcpath  : the lxcpath in which the container is running
 *
 * Returns 0 on success, < 0 on failure
 */
int lxc_cmd_stop(const char *name, const char *lxcpath)
{
	int ret, stopped;
	struct lxc_cmd_rr cmd = {
		.req = {
			.cmd = LXC_CMD_STOP,
		},
	};

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath, NULL);
	if (ret < 0) {
		if (stopped)
			return log_info(0, "Container \"%s\" is already stopped", name);

		return -1;
	}

	/* We do not expect any answer, because we wait for the connection to be
	 * closed.
	 */
	if (ret > 0)
		return log_error_errno(-1, -cmd.rsp.ret, "Failed to stop container \"%s\"", name);

	return log_info(0, "Container \"%s\" has stopped", name);
}

static int lxc_cmd_stop_callback(int fd, struct lxc_cmd_req *req,
				 struct lxc_handler *handler,
				 struct lxc_epoll_descr *descr)
{
	struct lxc_cmd_rsp rsp;
	int stopsignal = SIGKILL;
	struct cgroup_ops *cgroup_ops = handler->cgroup_ops;
	int ret;

	if (handler->conf->stopsignal)
		stopsignal = handler->conf->stopsignal;
	memset(&rsp, 0, sizeof(rsp));

	if (handler->pidfd >= 0)
		rsp.ret = lxc_raw_pidfd_send_signal(handler->pidfd, stopsignal, NULL, 0);
	else
		rsp.ret = kill(handler->pid, stopsignal);
	if (!rsp.ret) {
		if (handler->pidfd >= 0)
			TRACE("Sent signal %d to pidfd %d", stopsignal, handler->pidfd);
		else
			TRACE("Sent signal %d to pidfd %d", stopsignal, handler->pid);

		ret = cgroup_ops->unfreeze(cgroup_ops, -1);
		if (ret)
			WARN("Failed to unfreeze container \"%s\"", handler->name);

		return 0;
	} else {
		rsp.ret = -errno;
	}

	ret = lxc_cmd_rsp_send(fd, &rsp);
	if (ret < 0)
		return LXC_CMD_REAP_CLIENT_FD;

	return 0;
}

/*
 * lxc_cmd_terminal_winch: noop
 *
 * @name      : name of container to connect to
 * @lxcpath   : the lxcpath in which the container is running
 *
 * Returns 0 on success, < 0 on failure
 */
int lxc_cmd_terminal_winch(const char *name, const char *lxcpath)
{
	return 0;
}

static int lxc_cmd_terminal_winch_callback(int fd, struct lxc_cmd_req *req,
					   struct lxc_handler *handler,
					   struct lxc_epoll_descr *descr)
{
	/* should never be called */
	return log_error_errno(-1, ENOSYS, "Called lxc_cmd_terminal_winch_callback()");
}

/*
 * lxc_cmd_console: Open an fd to a tty in the container
 *
 * @name           : name of container to connect to
 * @ttynum         : in:  the tty to open or -1 for next available
 *                 : out: the tty allocated
 * @fd             : out: file descriptor for ptx side of pty
 * @lxcpath        : the lxcpath in which the container is running
 *
 * Returns fd holding tty allocated on success, < 0 on failure
 */
int lxc_cmd_console(const char *name, int *ttynum, int *fd, const char *lxcpath)
{
	__do_free struct lxc_cmd_console_rsp_data *rspdata = NULL;
	int ret, stopped;
	struct lxc_cmd_rr cmd = {
		.req = {
			.cmd	= LXC_CMD_CONSOLE,
			.data	= INT_TO_PTR(*ttynum),
		},
	};

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath, NULL);
	if (ret < 0)
		return ret;

	rspdata = cmd.rsp.data;
	if (cmd.rsp.ret < 0)
		return log_error_errno(-1, -cmd.rsp.ret, "Denied access to tty");

	if (ret == 0)
		return log_error(-1, "tty number %d invalid, busy or all ttys busy", *ttynum);

	if (rspdata->ptxfd < 0)
		return log_error(-1, "Unable to allocate fd for tty %d", rspdata->ttynum);

	ret = cmd.rsp.ret; /* socket fd */
	*fd = rspdata->ptxfd;
	*ttynum = rspdata->ttynum;

	return log_info(ret, "Alloced fd %d for tty %d via socket %d", *fd, rspdata->ttynum, ret);
}

static int lxc_cmd_console_callback(int fd, struct lxc_cmd_req *req,
				    struct lxc_handler *handler,
				    struct lxc_epoll_descr *descr)
{
	int ptxfd, ret;
	struct lxc_cmd_rsp rsp;
	int ttynum = PTR_TO_INT(req->data);

	ptxfd = lxc_terminal_allocate(handler->conf, fd, &ttynum);
	if (ptxfd < 0)
		return LXC_CMD_REAP_CLIENT_FD;

	memset(&rsp, 0, sizeof(rsp));
	rsp.data = INT_TO_PTR(ttynum);
	ret = lxc_abstract_unix_send_fds(fd, &ptxfd, 1, &rsp, sizeof(rsp));
	if (ret < 0) {
		lxc_terminal_free(handler->conf, fd);
		return log_error_errno(LXC_CMD_REAP_CLIENT_FD, errno,
				       "Failed to send tty to client");
	}

	return 0;
}

/*
 * lxc_cmd_get_name: Returns the name of the container
 *
 * @hashed_sock_name: hashed socket name
 *
 * Returns the name on success, NULL on failure.
 */
char *lxc_cmd_get_name(const char *hashed_sock_name)
{
	int ret, stopped;
	struct lxc_cmd_rr cmd = {
		.req = {
			.cmd = LXC_CMD_GET_NAME,
		},
	};

	ret = lxc_cmd(NULL, &cmd, &stopped, NULL, hashed_sock_name);
	if (ret < 0)
		return NULL;

	if (cmd.rsp.ret == 0)
		return cmd.rsp.data;

	return NULL;
}

static int lxc_cmd_get_name_callback(int fd, struct lxc_cmd_req *req,
				     struct lxc_handler *handler,
				     struct lxc_epoll_descr *descr)
{
	int ret;
	struct lxc_cmd_rsp rsp;

	memset(&rsp, 0, sizeof(rsp));

	rsp.data = (char *)handler->name;
	rsp.datalen = strlen(handler->name) + 1;
	rsp.ret = 0;

	ret = lxc_cmd_rsp_send(fd, &rsp);
	if (ret < 0)
		return LXC_CMD_REAP_CLIENT_FD;

	return 0;
}

/*
 * lxc_cmd_get_lxcpath: Returns the lxcpath of the container
 *
 * @hashed_sock_name: hashed socket name
 *
 * Returns the lxcpath on success, NULL on failure.
 */
char *lxc_cmd_get_lxcpath(const char *hashed_sock_name)
{
	int ret, stopped;
	struct lxc_cmd_rr cmd = {
		.req = {
			.cmd = LXC_CMD_GET_LXCPATH,
		},
	};

	ret = lxc_cmd(NULL, &cmd, &stopped, NULL, hashed_sock_name);
	if (ret < 0)
		return NULL;

	if (cmd.rsp.ret == 0)
		return cmd.rsp.data;

	return NULL;
}

static int lxc_cmd_get_lxcpath_callback(int fd, struct lxc_cmd_req *req,
					struct lxc_handler *handler,
					struct lxc_epoll_descr *descr)
{
	int ret;
	struct lxc_cmd_rsp rsp = {
		.ret		= 0,
		.data		= (char *)handler->lxcpath,
		.datalen	= strlen(handler->lxcpath) + 1,
	};

	ret = lxc_cmd_rsp_send(fd, &rsp);
	if (ret < 0)
		return LXC_CMD_REAP_CLIENT_FD;

	return 0;
}

int lxc_cmd_add_state_client(const char *name, const char *lxcpath,
			     lxc_state_t states[MAX_STATE],
			     int *state_client_fd)
{
	__do_close int clientfd = -EBADF;
	int state, stopped;
	ssize_t ret;
	struct lxc_cmd_rr cmd = {
		.req = {
			.cmd     = LXC_CMD_ADD_STATE_CLIENT,
			.data    = states,
			.datalen = (sizeof(lxc_state_t) * MAX_STATE)
		},
	};

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath, NULL);
	if (states[STOPPED] != 0 && stopped != 0)
		return STOPPED;

	if (ret < 0) {
		if (errno != ECONNREFUSED)
			SYSERROR("Failed to execute command");

		return -1;
	}

	/* We should now be guaranteed to get an answer from the state sending
	 * function.
	 */
	clientfd = cmd.rsp.ret;
	if (clientfd < 0)
		return log_error_errno(-1, -clientfd, "Failed to receive socket fd");

	state = PTR_TO_INT(cmd.rsp.data);
	if (state < MAX_STATE)
		return log_trace(state, "Container is already in requested state %s", lxc_state2str(state));

	*state_client_fd = move_fd(clientfd);
	TRACE("State connection fd %d ready to listen for container state changes", *state_client_fd);
	return MAX_STATE;
}

static int lxc_cmd_add_state_client_callback(__owns int fd, struct lxc_cmd_req *req,
					     struct lxc_handler *handler,
					     struct lxc_epoll_descr *descr)
{
	int ret;
	struct lxc_cmd_rsp rsp = {0};

	if (req->datalen < 0)
		return LXC_CMD_REAP_CLIENT_FD;

	if (req->datalen != (sizeof(lxc_state_t) * MAX_STATE))
		return LXC_CMD_REAP_CLIENT_FD;

	if (!req->data)
		return LXC_CMD_REAP_CLIENT_FD;

	rsp.ret = lxc_add_state_client(fd, handler, (lxc_state_t *)req->data);
	if (rsp.ret < 0)
		return LXC_CMD_REAP_CLIENT_FD;

	rsp.data = INT_TO_PTR(rsp.ret);

	ret = lxc_cmd_rsp_send(fd, &rsp);
	if (ret < 0)
		return LXC_CMD_REAP_CLIENT_FD;

	return 0;
}

int lxc_cmd_add_bpf_device_cgroup(const char *name, const char *lxcpath,
				  struct device_item *device)
{
#ifdef HAVE_STRUCT_BPF_CGROUP_DEV_CTX
	int stopped = 0;
	struct lxc_cmd_rr cmd = {
		.req = {
			.cmd     = LXC_CMD_ADD_BPF_DEVICE_CGROUP,
			.data    = device,
			.datalen = sizeof(struct device_item),
		},
	};
	int ret;

	if (strlen(device->access) > STRLITERALLEN("rwm"))
		return log_error_errno(-1, EINVAL, "Invalid access mode specified %s",
				       device->access);

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath, NULL);
	if (ret < 0 || cmd.rsp.ret < 0)
		return log_error_errno(-1, errno, "Failed to add new bpf device cgroup rule");

	return 0;
#else
	return ret_set_errno(-1, ENOSYS);
#endif
}

static int lxc_cmd_add_bpf_device_cgroup_callback(int fd, struct lxc_cmd_req *req,
						  struct lxc_handler *handler,
						  struct lxc_epoll_descr *descr)
{
#ifdef HAVE_STRUCT_BPF_CGROUP_DEV_CTX
	__do_bpf_program_free struct bpf_program *devices = NULL;
	struct lxc_cmd_rsp rsp = {0};
	struct lxc_conf *conf = handler->conf;
	struct cgroup_ops *cgroup_ops = handler->cgroup_ops;
	struct hierarchy *unified = cgroup_ops->unified;
	int ret;
	struct lxc_list *it;
	struct device_item *device;
	struct bpf_program *devices_old;

	if (req->datalen <= 0)
		return LXC_CMD_REAP_CLIENT_FD;

	if (req->datalen != sizeof(struct device_item))
		return LXC_CMD_REAP_CLIENT_FD;

	if (!req->data)
		return LXC_CMD_REAP_CLIENT_FD;
	device = (struct device_item *)req->data;

	rsp.ret = -1;
	if (!unified)
		goto respond;

	ret = bpf_list_add_device(conf, device);
	if (ret < 0)
		goto respond;

	devices = bpf_program_new(BPF_PROG_TYPE_CGROUP_DEVICE);
	if (!devices)
		goto respond;

	ret = bpf_program_init(devices);
	if (ret)
		goto respond;

	lxc_list_for_each(it, &conf->devices) {
		struct device_item *cur = it->elem;

		ret = bpf_program_append_device(devices, cur);
		if (ret)
			goto respond;
	}

	ret = bpf_program_finalize(devices);
	if (ret)
		goto respond;

	ret = bpf_program_cgroup_attach(devices, BPF_CGROUP_DEVICE,
					unified->container_full_path,
					BPF_F_ALLOW_MULTI);
	if (ret)
		goto respond;

	/* Replace old bpf program. */
	devices_old = move_ptr(cgroup_ops->cgroup2_devices);
	cgroup_ops->cgroup2_devices = move_ptr(devices);
	devices = move_ptr(devices_old);

	rsp.ret = 0;

respond:
	ret = lxc_cmd_rsp_send(fd, &rsp);
	if (ret < 0)
		return LXC_CMD_REAP_CLIENT_FD;

	return 0;
#else
	return ret_set_errno(-1, ENOSYS);
#endif
}

int lxc_cmd_console_log(const char *name, const char *lxcpath,
			struct lxc_console_log *log)
{
	int ret, stopped;
	struct lxc_cmd_console_log data;
	struct lxc_cmd_rr cmd;

	data.clear = log->clear;
	data.read = log->read;
	data.read_max = *log->read_max;

	cmd.req.cmd = LXC_CMD_CONSOLE_LOG;
	cmd.req.data = &data;
	cmd.req.datalen = sizeof(struct lxc_cmd_console_log);

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath, NULL);
	if (ret < 0)
		return ret;

	/* There is nothing to be read from the buffer. So clear any values we
	 * where passed to clearly indicate to the user that nothing went wrong.
	 */
	if (cmd.rsp.ret == -ENODATA || cmd.rsp.ret == -EFAULT || cmd.rsp.ret == -ENOENT) {
		*log->read_max = 0;
		log->data = NULL;
	}

	/* This is a proper error so don't touch any values we were passed. */
	if (cmd.rsp.ret < 0)
		return cmd.rsp.ret;

	*log->read_max = cmd.rsp.datalen;
	log->data = cmd.rsp.data;

	return 0;
}

static int lxc_cmd_console_log_callback(int fd, struct lxc_cmd_req *req,
					struct lxc_handler *handler,
					struct lxc_epoll_descr *descr)
{
	struct lxc_cmd_rsp rsp;
	uint64_t buffer_size = handler->conf->console.buffer_size;
	const struct lxc_cmd_console_log *log = req->data;
	struct lxc_ringbuf *buf = &handler->conf->console.ringbuf;

	rsp.ret = -EFAULT;
	rsp.datalen = 0;
	rsp.data = NULL;
	if (buffer_size <= 0)
		goto out;

	if (log->read || log->write_logfile)
		rsp.datalen = lxc_ringbuf_used(buf);

	if (log->read)
		rsp.data = lxc_ringbuf_get_read_addr(buf);

	if (log->read_max > 0 && (log->read_max <= rsp.datalen))
		rsp.datalen = log->read_max;

	/* there's nothing to read */
	rsp.ret = -ENODATA;
	if (log->read && (buf->r_off == buf->w_off))
		goto out;

	rsp.ret = 0;
	if (log->clear)
		lxc_ringbuf_clear(buf); /* clear the ringbuffer */
	else if (rsp.datalen > 0)
		lxc_ringbuf_move_read_addr(buf, rsp.datalen);

out:
	return lxc_cmd_rsp_send(fd, &rsp);
}

int lxc_cmd_serve_state_clients(const char *name, const char *lxcpath,
				lxc_state_t state)
{
	int stopped;
	ssize_t ret;
	struct lxc_cmd_rr cmd = {
		.req = {
			.cmd  = LXC_CMD_SERVE_STATE_CLIENTS,
			.data = INT_TO_PTR(state)
		},
	};

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath, NULL);
	if (ret < 0)
		return log_error_errno(-1, errno, "Failed to serve state clients");

	return 0;
}

static int lxc_cmd_serve_state_clients_callback(int fd, struct lxc_cmd_req *req,
						struct lxc_handler *handler,
						struct lxc_epoll_descr *descr)
{
	int ret;
	lxc_state_t state = PTR_TO_INT(req->data);
	struct lxc_cmd_rsp rsp = {0};

	ret = lxc_serve_state_clients(handler->name, handler, state);
	if (ret < 0)
		return LXC_CMD_REAP_CLIENT_FD;

	ret = lxc_cmd_rsp_send(fd, &rsp);
	if (ret < 0)
		return LXC_CMD_REAP_CLIENT_FD;

	return 0;
}

int lxc_cmd_seccomp_notify_add_listener(const char *name, const char *lxcpath,
					int fd,
					/* unused */ unsigned int command,
					/* unused */ unsigned int flags)
{

#ifdef HAVE_SECCOMP_NOTIFY
	int ret, stopped;
	struct lxc_cmd_rr cmd = {
		.req = {
			.cmd = LXC_CMD_SECCOMP_NOTIFY_ADD_LISTENER,
			.data = INT_TO_PTR(fd),
		},
	};

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath, NULL);
	if (ret < 0)
		return log_error_errno(-1, errno, "Failed to add seccomp listener");

	return cmd.rsp.ret;
#else
	return ret_set_errno(-1, ENOSYS);
#endif
}

static int lxc_cmd_seccomp_notify_add_listener_callback(int fd,
							struct lxc_cmd_req *req,
							struct lxc_handler *handler,
							struct lxc_epoll_descr *descr)
{
	struct lxc_cmd_rsp rsp = {0};

#ifdef HAVE_SECCOMP_NOTIFY
	int ret;
	__do_close int recv_fd = -EBADF;

	ret = lxc_abstract_unix_recv_fds(fd, &recv_fd, 1, NULL, 0);
	if (ret <= 0) {
		rsp.ret = -errno;
		goto out;
	}

	if (!handler->conf->seccomp.notifier.wants_supervision ||
	    handler->conf->seccomp.notifier.proxy_fd < 0) {
		SYSERROR("No seccomp proxy fd specified");
		rsp.ret = -EINVAL;
		goto out;
	}

	ret = lxc_mainloop_add_handler(descr, recv_fd, seccomp_notify_handler,
				       handler);
	if (ret < 0) {
		rsp.ret = -errno;
		goto out;
	}
	move_fd(recv_fd);

out:
#else
	rsp.ret = -ENOSYS;

#endif
	return lxc_cmd_rsp_send(fd, &rsp);
}

int lxc_cmd_freeze(const char *name, const char *lxcpath, int timeout)
{
	int ret, stopped;
	struct lxc_cmd_rr cmd = {
		.req = {
			.cmd = LXC_CMD_FREEZE,
			.data = INT_TO_PTR(timeout),
		},
	};

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath, NULL);
	if (ret <= 0 || cmd.rsp.ret < 0)
		return log_error_errno(-1, errno, "Failed to freeze container");

	return cmd.rsp.ret;
}

static int lxc_cmd_freeze_callback(int fd, struct lxc_cmd_req *req,
				   struct lxc_handler *handler,
				   struct lxc_epoll_descr *descr)
{
	int timeout = PTR_TO_INT(req->data);
	struct lxc_cmd_rsp rsp = {
		.ret = -ENOENT,
	};
	struct cgroup_ops *ops = handler->cgroup_ops;

	if (pure_unified_layout(ops))
		rsp.ret = ops->freeze(ops, timeout);

	return lxc_cmd_rsp_send(fd, &rsp);
}

int lxc_cmd_unfreeze(const char *name, const char *lxcpath, int timeout)
{
	int ret, stopped;
	struct lxc_cmd_rr cmd = {
		.req = {
			.cmd = LXC_CMD_UNFREEZE,
			.data = INT_TO_PTR(timeout),
		},
	};

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath, NULL);
	if (ret <= 0 || cmd.rsp.ret < 0)
		return log_error_errno(-1, errno, "Failed to unfreeze container");

	return cmd.rsp.ret;
}

static int lxc_cmd_unfreeze_callback(int fd, struct lxc_cmd_req *req,
				   struct lxc_handler *handler,
				   struct lxc_epoll_descr *descr)
{
	int timeout = PTR_TO_INT(req->data);
	struct lxc_cmd_rsp rsp = {
		.ret = -ENOENT,
	};
	struct cgroup_ops *ops = handler->cgroup_ops;

	if (pure_unified_layout(ops))
		rsp.ret = ops->unfreeze(ops, timeout);

	return lxc_cmd_rsp_send(fd, &rsp);
}

int lxc_cmd_get_cgroup2_fd(const char *name, const char *lxcpath)
{
	int ret, stopped;
	struct lxc_cmd_rr cmd = {
		.req = {
			.cmd = LXC_CMD_GET_CGROUP2_FD,
		},
	};

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath, NULL);
	if (ret < 0)
		return -1;

	if (cmd.rsp.ret < 0)
		return log_debug_errno(cmd.rsp.ret, -cmd.rsp.ret, "Failed to receive cgroup2 fd");

	return PTR_TO_INT(cmd.rsp.data);
}

static int lxc_cmd_get_cgroup2_fd_callback_do(int fd, struct lxc_cmd_req *req,
					      struct lxc_handler *handler,
					      struct lxc_epoll_descr *descr,
					      bool limiting_cgroup)
{
	struct lxc_cmd_rsp rsp = {
		.ret = -EINVAL,
	};
	struct cgroup_ops *ops = handler->cgroup_ops;
	int ret, send_fd;

	if (!pure_unified_layout(ops) || !ops->unified)
		return lxc_cmd_rsp_send(fd, &rsp);

	send_fd = limiting_cgroup ? ops->unified->cgfd_limit
				  : ops->unified->cgfd_con;

	rsp.ret = 0;
	ret = lxc_abstract_unix_send_fds(fd, &send_fd, 1, &rsp, sizeof(rsp));
	if (ret < 0)
		return log_error(LXC_CMD_REAP_CLIENT_FD, "Failed to send cgroup2 fd");

	return 0;
}

static int lxc_cmd_get_cgroup2_fd_callback(int fd, struct lxc_cmd_req *req,
					   struct lxc_handler *handler,
					   struct lxc_epoll_descr *descr)
{
	return lxc_cmd_get_cgroup2_fd_callback_do(fd, req, handler, descr,
						  false);
}

static int lxc_cmd_get_limiting_cgroup2_fd_callback(int fd,
						    struct lxc_cmd_req *req,
						    struct lxc_handler *handler,
						    struct lxc_epoll_descr *descr)
{
	return lxc_cmd_get_cgroup2_fd_callback_do(fd, req, handler, descr,
						  true);
}

static int lxc_cmd_process(int fd, struct lxc_cmd_req *req,
			   struct lxc_handler *handler,
			   struct lxc_epoll_descr *descr)
{
	typedef int (*callback)(int, struct lxc_cmd_req *, struct lxc_handler *,
				struct lxc_epoll_descr *);

	callback cb[LXC_CMD_MAX] = {
		[LXC_CMD_CONSOLE]			= lxc_cmd_console_callback,
		[LXC_CMD_TERMINAL_WINCH]              	= lxc_cmd_terminal_winch_callback,
		[LXC_CMD_STOP]                        	= lxc_cmd_stop_callback,
		[LXC_CMD_GET_STATE]                   	= lxc_cmd_get_state_callback,
		[LXC_CMD_GET_INIT_PID]                	= lxc_cmd_get_init_pid_callback,
		[LXC_CMD_GET_CLONE_FLAGS]             	= lxc_cmd_get_clone_flags_callback,
		[LXC_CMD_GET_CGROUP]                  	= lxc_cmd_get_cgroup_callback,
		[LXC_CMD_GET_CONFIG_ITEM]             	= lxc_cmd_get_config_item_callback,
		[LXC_CMD_GET_NAME]                    	= lxc_cmd_get_name_callback,
		[LXC_CMD_GET_LXCPATH]                 	= lxc_cmd_get_lxcpath_callback,
		[LXC_CMD_ADD_STATE_CLIENT]            	= lxc_cmd_add_state_client_callback,
		[LXC_CMD_CONSOLE_LOG]                 	= lxc_cmd_console_log_callback,
		[LXC_CMD_SERVE_STATE_CLIENTS]         	= lxc_cmd_serve_state_clients_callback,
		[LXC_CMD_SECCOMP_NOTIFY_ADD_LISTENER] 	= lxc_cmd_seccomp_notify_add_listener_callback,
		[LXC_CMD_ADD_BPF_DEVICE_CGROUP]		= lxc_cmd_add_bpf_device_cgroup_callback,
		[LXC_CMD_FREEZE]			= lxc_cmd_freeze_callback,
		[LXC_CMD_UNFREEZE]			= lxc_cmd_unfreeze_callback,
		[LXC_CMD_GET_CGROUP2_FD]		= lxc_cmd_get_cgroup2_fd_callback,
		[LXC_CMD_GET_INIT_PIDFD]                = lxc_cmd_get_init_pidfd_callback,
		[LXC_CMD_GET_LIMITING_CGROUP]           = lxc_cmd_get_limiting_cgroup_callback,
		[LXC_CMD_GET_LIMITING_CGROUP2_FD]       = lxc_cmd_get_limiting_cgroup2_fd_callback,
		[LXC_CMD_GET_DEVPTS_FD]			= lxc_cmd_get_devpts_fd_callback,
		[LXC_CMD_GET_SECCOMP_NOTIFY_FD]		= lxc_cmd_get_seccomp_notify_fd_callback,
	};

	if (req->cmd >= LXC_CMD_MAX)
		return log_trace_errno(-1, EINVAL, "Invalid command id %d", req->cmd);

	return cb[req->cmd](fd, req, handler, descr);
}

static void lxc_cmd_fd_cleanup(int fd, struct lxc_handler *handler,
			       struct lxc_epoll_descr *descr, const lxc_cmd_t cmd)
{
	lxc_terminal_free(handler->conf, fd);
	lxc_mainloop_del_handler(descr, fd);

	if (cmd == LXC_CMD_ADD_STATE_CLIENT) {
		struct lxc_list *cur, *next;

		lxc_list_for_each_safe(cur, &handler->conf->state_clients, next) {
			struct lxc_state_client *client = cur->elem;

			if (client->clientfd != fd)
				continue;

			/*
			 * Only kick client from list so it can't be found
			 * anymore. The actual close happens, as for all other
			 * file descriptors, below.
			 */
			lxc_list_del(cur);
			free(cur->elem);
			free(cur);

			/*
			 * No need to walk the whole list. If we found the state
			 * client fd there can't be a second one.
			 */
			TRACE("Found state client fd %d in state client list for command \"%s\"", fd, lxc_cmd_str(cmd));
			break;
		}

		/*
		 * We didn't add the state client to the list. Either because
		 * we failed to allocate memory (unlikely) or because the state
		 * was already reached by the time we were ready to add it. So
		 * fallthrough and clean it up.
		 */
		TRACE("Closing state client fd %d for command \"%s\"", fd, lxc_cmd_str(cmd));
	}

	TRACE("Closing client fd %d for command \"%s\"", fd, lxc_cmd_str(cmd));
	close(fd);
}

static int lxc_cmd_handler(int fd, uint32_t events, void *data,
			   struct lxc_epoll_descr *descr)
{
	__do_free void *reqdata = NULL;
	int ret;
	struct lxc_cmd_req req;
	struct lxc_handler *handler = data;

	ret = lxc_abstract_unix_rcv_credential(fd, &req, sizeof(req));
	if (ret < 0) {
		SYSERROR("Failed to receive data on command socket for command \"%s\"", lxc_cmd_str(req.cmd));

		if (errno == EACCES) {
			/* We don't care for the peer, just send and close. */
			struct lxc_cmd_rsp rsp = {
				.ret = -EPERM,
			};

			lxc_cmd_rsp_send(fd, &rsp);
		}

		goto out_close;
	}

	if (ret == 0)
		goto out_close;

	if (ret != sizeof(req)) {
		WARN("Failed to receive full command request. Ignoring request for \"%s\"", lxc_cmd_str(req.cmd));
		goto out_close;
	}

	if ((req.datalen > LXC_CMD_DATA_MAX) && (req.cmd != LXC_CMD_CONSOLE_LOG)) {
		ERROR("Received command data length %d is too large for command \"%s\"", req.datalen, lxc_cmd_str(req.cmd));
		goto out_close;
	}

	if (req.datalen > 0) {
		reqdata = must_realloc(NULL, req.datalen);
		ret = lxc_recv_nointr(fd, reqdata, req.datalen, 0);
		if (ret != req.datalen) {
			WARN("Failed to receive full command request. Ignoring request for \"%s\"", lxc_cmd_str(req.cmd));
			goto out_close;
		}

		req.data = reqdata;
	}

	ret = lxc_cmd_process(fd, &req, handler, descr);
	if (ret) {
		/* This is not an error, but only a request to close fd. */
		goto out_close;
	}

out:
	return LXC_MAINLOOP_CONTINUE;

out_close:
	lxc_cmd_fd_cleanup(fd, handler, descr, req.cmd);
	goto out;
}

static int lxc_cmd_accept(int fd, uint32_t events, void *data,
			  struct lxc_epoll_descr *descr)
{
	__do_close int connection = -EBADF;
	int opt = 1, ret = -1;

	connection = accept(fd, NULL, 0);
	if (connection < 0)
		return log_error_errno(LXC_MAINLOOP_ERROR, errno, "Failed to accept connection to run command");

	ret = fcntl(connection, F_SETFD, FD_CLOEXEC);
	if (ret < 0)
		return log_error_errno(ret, errno, "Failed to set close-on-exec on incoming command connection");

	ret = setsockopt(connection, SOL_SOCKET, SO_PASSCRED, &opt, sizeof(opt));
	if (ret < 0)
		return log_error_errno(ret, errno, "Failed to enable necessary credentials on command socket");

	ret = lxc_mainloop_add_handler(descr, connection, lxc_cmd_handler, data);
	if (ret)
		return log_error(ret, "Failed to add command handler");

	TRACE("Accepted new client as fd %d on command server fd %d", connection, fd);
	move_fd(connection);
	return ret;
}

int lxc_cmd_init(const char *name, const char *lxcpath, const char *suffix)
{
	__do_close int fd = -EBADF;
	int ret;
	char path[LXC_AUDS_ADDR_LEN] = {0};

	ret = lxc_make_abstract_socket_name(path, sizeof(path), name, lxcpath, NULL, suffix);
	if (ret < 0)
		return -1;

	fd = lxc_abstract_unix_open(path, SOCK_STREAM, 0);
	if (fd < 0) {
		if (errno == EADDRINUSE)
			ERROR("Container \"%s\" appears to be already running", name);

		return log_error_errno(-1, errno, "Failed to create command socket %s", &path[1]);
	}

	ret = fcntl(fd, F_SETFD, FD_CLOEXEC);
	if (ret < 0)
		return log_error_errno(-1, errno, "Failed to set FD_CLOEXEC on command socket file descriptor");

	return log_trace(move_fd(fd), "Created abstract unix socket \"%s\"", &path[1]);
}

int lxc_cmd_mainloop_add(const char *name, struct lxc_epoll_descr *descr,
			 struct lxc_handler *handler)
{
	int ret;

	ret = lxc_mainloop_add_handler(descr, handler->conf->maincmd_fd, lxc_cmd_accept, handler);
	if (ret < 0)
		return log_error(ret, "Failed to add handler for command socket fd %d", handler->conf->maincmd_fd);

	return ret;
}

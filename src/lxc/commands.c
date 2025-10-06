/* SPDX-License-Identifier: LGPL-2.1+ */

#include "config.h"

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
#include "cgroups/cgroup.h"
#include "cgroups/cgroup2_devices.h"
#include "commands.h"
#include "commands_utils.h"
#include "conf.h"
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
		[LXC_CMD_GET_TTY_FD]                    = "get_tty_fd",
		[LXC_CMD_TERMINAL_WINCH]                = "terminal_winch",
		[LXC_CMD_STOP]                          = "stop",
		[LXC_CMD_GET_STATE]                     = "get_state",
		[LXC_CMD_GET_INIT_PID]                  = "get_init_pid",
		[LXC_CMD_GET_CLONE_FLAGS]               = "get_clone_flags",
		[LXC_CMD_GET_CGROUP]                    = "get_cgroup",
		[LXC_CMD_GET_CONFIG_ITEM]               = "get_config_item",
		[LXC_CMD_GET_NAME]                      = "get_name",
		[LXC_CMD_GET_LXCPATH]                   = "get_lxcpath",
		[LXC_CMD_ADD_STATE_CLIENT]              = "add_state_client",
		[LXC_CMD_CONSOLE_LOG]                   = "console_log",
		[LXC_CMD_SERVE_STATE_CLIENTS]           = "serve_state_clients",
		[LXC_CMD_SECCOMP_NOTIFY_ADD_LISTENER]   = "seccomp_notify_add_listener",
		[LXC_CMD_ADD_BPF_DEVICE_CGROUP]         = "add_bpf_device_cgroup",
		[LXC_CMD_FREEZE]                        = "freeze",
		[LXC_CMD_UNFREEZE]                      = "unfreeze",
		[LXC_CMD_GET_CGROUP2_FD]                = "get_cgroup2_fd",
		[LXC_CMD_GET_INIT_PIDFD]                = "get_init_pidfd",
		[LXC_CMD_GET_LIMIT_CGROUP]              = "get_limit_cgroup",
		[LXC_CMD_GET_LIMIT_CGROUP2_FD]          = "get_limit_cgroup2_fd",
		[LXC_CMD_GET_DEVPTS_FD]                 = "get_devpts_fd",
		[LXC_CMD_GET_SECCOMP_NOTIFY_FD]         = "get_seccomp_notify_fd",
		[LXC_CMD_GET_CGROUP_CTX]                = "get_cgroup_ctx",
		[LXC_CMD_GET_CGROUP_FD]                 = "get_cgroup_fd",
		[LXC_CMD_GET_LIMIT_CGROUP_FD]           = "get_limit_cgroup_fd",
		[LXC_CMD_GET_SYSTEMD_SCOPE]             = "get_systemd_scope",
	};

	if (cmd >= LXC_CMD_MAX)
		return "Invalid request";

	return cmdname[cmd];
}

static int __transfer_cgroup_ctx_fds(struct unix_fds *fds, struct cgroup_ctx *ctx)
{
	/* This shouldn't be able to happen but better safe than sorry. */
	if (ctx->fd_len != fds->fd_count_ret ||
	    fds->fd_count_ret > CGROUP_CTX_MAX_FD)
		return syswarn_set(-EINVAL, "Unexpected number of file descriptors received %u != %u",
				   ctx->fd_len, fds->fd_count_ret);

	memcpy(ctx->fd, fds->fd, ctx->fd_len * sizeof(__s32));
	fds->fd_count_ret = 0;
	return 0;
}

static int __transfer_cgroup_fd(struct unix_fds *fds, struct cgroup_fd *fd)
{
	fd->fd = move_fd(fds->fd[0]);
	return 0;
}

static ssize_t lxc_cmd_rsp_recv_fds(int fd_sock, struct unix_fds *fds,
				    struct lxc_cmd_rsp *rsp,
				    const char *cur_cmdstr)
{
	ssize_t ret;

	ret = lxc_abstract_unix_recv_fds(fd_sock, fds, rsp, sizeof(*rsp));
	if (ret < 0)
		return log_error(ret, "Failed to receive file descriptors for command \"%s\"", cur_cmdstr);

	/*
	 * If we end up here with fewer or more file descriptors the caller
	 * must have set flags to indicate that they are fine with this.
	 * Otherwise the call would have failed.
	 */

	if (fds->flags & UNIX_FDS_RECEIVED_EXACT)
		return log_debug(ret, "Received exact number of file descriptors %u == %u for command \"%s\"",
				 fds->fd_count_max, fds->fd_count_ret, cur_cmdstr);

	if (fds->flags & UNIX_FDS_RECEIVED_LESS)
		return log_debug(ret, "Received less file descriptors %u < %u for command \"%s\"",
				 fds->fd_count_ret, fds->fd_count_max, cur_cmdstr);

	if (fds->flags & UNIX_FDS_RECEIVED_MORE)
		return log_debug(ret, "Received more file descriptors (excessive fds were automatically closed) %u > %u for command \"%s\"",
				 fds->fd_count_ret, fds->fd_count_max, cur_cmdstr);

	DEBUG("Command \"%s\" received response", cur_cmdstr);
	return ret;
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
 * As a special case, the response for LXC_CMD_GET_TTY_FD is created here as
 * it contains an fd for the ptx pty passed through the unix socket.
 */
static ssize_t lxc_cmd_rsp_recv(int sock, struct lxc_cmd_rr *cmd)
{
	__do_free void *__data = NULL;
	call_cleaner(put_unix_fds) struct unix_fds *fds = &(struct unix_fds){
		.fd[0 ... KERNEL_SCM_MAX_FD - 1] = -EBADF,
	};
	struct lxc_cmd_rsp *rsp = &cmd->rsp;
	int cur_cmd = cmd->req.cmd;
	const char *cur_cmdstr;
	ssize_t bytes_recv;

	/*
	 * Determine whether this command will receive file descriptors and how
	 * many at most.
	 */
	cur_cmdstr = lxc_cmd_str(cur_cmd);
	switch (cur_cmd) {
	case LXC_CMD_GET_CGROUP_FD:
		__fallthrough;
	case LXC_CMD_GET_LIMIT_CGROUP_FD:
		__fallthrough;
	case LXC_CMD_GET_CGROUP2_FD:
		__fallthrough;
	case LXC_CMD_GET_LIMIT_CGROUP2_FD:
		__fallthrough;
	case LXC_CMD_GET_INIT_PIDFD:
		__fallthrough;
	case LXC_CMD_GET_SECCOMP_NOTIFY_FD:
		__fallthrough;
	case LXC_CMD_GET_DEVPTS_FD:
		fds->fd_count_max = 1;
		/*
		 * The kernel might not support the required features or the
		 * server might be too old.
		 */
		fds->flags = UNIX_FDS_ACCEPT_EXACT | UNIX_FDS_ACCEPT_NONE;
		break;
	case LXC_CMD_GET_TTY_FD:
		/*
		 * The requested terminal can be busy so it's perfectly fine
		 * for LXC_CMD_GET_TTY to receive no file descriptor.
		 */
		fds->fd_count_max = 1;
		fds->flags = UNIX_FDS_ACCEPT_EXACT | UNIX_FDS_ACCEPT_NONE;
		break;
	case LXC_CMD_GET_CGROUP_CTX:
		fds->fd_count_max = CGROUP_CTX_MAX_FD;
		/* 
		 * The container might run without any cgroup support at all,
		 * i.e. no writable cgroup hierarchy was found.
		 */
		fds->flags |= UNIX_FDS_ACCEPT_LESS  | UNIX_FDS_ACCEPT_NONE ;
		break;
	default:
		fds->fd_count_max = 0;
		break;
	}

	/* Receive the first response including file descriptors if any. */
	bytes_recv = lxc_cmd_rsp_recv_fds(sock, fds, rsp, cur_cmdstr);
	if (bytes_recv < 0)
		return bytes_recv;

	/*
	 * Ensure that no excessive data is sent unless someone retrieves the
	 * console ringbuffer.
	 */
	if ((rsp->datalen > LXC_CMD_DATA_MAX) &&
	    (cur_cmd != LXC_CMD_CONSOLE_LOG))
		return syserror_set(-E2BIG, "Response data for command \"%s\" is too long: %d bytes > %d",
				    cur_cmdstr, rsp->datalen, LXC_CMD_DATA_MAX);

	/*
	 * Prepare buffer for any command that expects to receive additional
	 * data. Note that some don't want any additional data.
	 */
	switch (cur_cmd) {
	case LXC_CMD_GET_CGROUP2_FD:		/* no data */
		__fallthrough;
	case LXC_CMD_GET_LIMIT_CGROUP2_FD:	/* no data */
		__fallthrough;
	case LXC_CMD_GET_INIT_PIDFD:		/* no data */
		__fallthrough;
	case LXC_CMD_GET_DEVPTS_FD:		/* no data */
		__fallthrough;
	case LXC_CMD_GET_SECCOMP_NOTIFY_FD:	/* no data */
		rsp->data = INT_TO_PTR(move_fd(fds->fd[0]));
		return log_debug(0, "Finished processing \"%s\" with file descriptor %d", cur_cmdstr, PTR_TO_INT(rsp->data));
	case LXC_CMD_GET_CGROUP_FD:		/* data */
		__fallthrough;
	case LXC_CMD_GET_LIMIT_CGROUP_FD:	/* data */
		if ((size_t)rsp->datalen > sizeof(struct cgroup_fd))
			return syserror_set(-EINVAL, "Invalid response size from server for \"%s\"", cur_cmdstr);

		/* Don't pointlessly allocate. */
		rsp->data = (void *)cmd->req.data;
		break;
	case LXC_CMD_GET_CGROUP_CTX:		/* data */
		if ((size_t)rsp->datalen > sizeof(struct cgroup_ctx))
			return syserror_set(-EINVAL, "Invalid response size from server for \"%s\"", cur_cmdstr);

		/* Don't pointlessly allocate. */
		rsp->data = (void *)cmd->req.data;
		break;
	case LXC_CMD_GET_TTY_FD:			/* data */
		/*
		 * recv() returns 0 bytes when a tty cannot be allocated,
		 * rsp->ret is < 0 when the peer permission check failed.
		 */
		if (bytes_recv == 0 || rsp->ret < 0)
			return 0;

		__data = malloc(sizeof(struct lxc_cmd_tty_rsp_data));
		if (__data) {
			struct lxc_cmd_tty_rsp_data *tty = __data;

			tty->ptxfd	= move_fd(fds->fd[0]);
			tty->ttynum	= PTR_TO_INT(rsp->data);
			rsp->datalen	= 0;
			rsp->data	= tty;
			break;
		}
		return syserror_set(-ENOMEM, "Failed to receive response for command \"%s\"", cur_cmdstr);
	case LXC_CMD_CONSOLE_LOG:		/* data */
		if (rsp->datalen > 0)
			__data = zalloc(rsp->datalen + 1);
		rsp->data = __data;
		break;
	default:				/* catch any additional command */
		if (rsp->datalen > 0) {
			__data = zalloc(rsp->datalen);
			rsp->data = __data;
		}
		break;
	}

	if (rsp->datalen > 0) {
		int err;

		/*
		 * All commands ending up here expect data so rsp->data must be valid.
		 * Either static or allocated memory.
		 */
		if (!rsp->data)
			return syserror_set(-ENOMEM, "Failed to prepare response buffer for command \"%s\"",
					    cur_cmdstr);

		bytes_recv = lxc_recv_nointr(sock, rsp->data, rsp->datalen, 0);
		if (bytes_recv != rsp->datalen)
			return syserror("Failed to receive response data for command \"%s\": %zd != %d",
					cur_cmdstr, bytes_recv, rsp->datalen);

		switch (cur_cmd) {
		case LXC_CMD_GET_CGROUP_CTX:
			err = __transfer_cgroup_ctx_fds(fds, rsp->data);
			break;
		case LXC_CMD_GET_CGROUP_FD:
			__fallthrough;
		case LXC_CMD_GET_LIMIT_CGROUP_FD:
			err = __transfer_cgroup_fd(fds, rsp->data);
			break;
		default:
			err = 0;
		}
		if (err < 0)
			return syserror_ret(err, "Failed to transfer file descriptors for command \"%s\"", cur_cmdstr);
	}

	move_ptr(__data);
	return bytes_recv;
}

/*
 * lxc_cmd_rsp_send: Send a command response
 *
 * @fd   : file descriptor of socket to send response on
 * @rsp  : response to send
 *
 * Returns 0 on success, < 0 on failure
 */
static int __lxc_cmd_rsp_send(int fd, struct lxc_cmd_rsp *rsp)
{
	ssize_t ret;

	ret = lxc_send_nointr(fd, rsp, sizeof(*rsp), MSG_NOSIGNAL);
	if (ret < 0 || (size_t)ret != sizeof(*rsp))
		return syserror("Failed to send command response %zd", ret);

	if (!rsp->data || rsp->datalen <= 0)
		return 0;

	ret = lxc_send_nointr(fd, rsp->data, rsp->datalen, MSG_NOSIGNAL);
	if (ret < 0 || ret != (ssize_t)rsp->datalen)
		return syswarn("Failed to send command response %zd", ret);

	return 0;
}

static inline int lxc_cmd_rsp_send_reap(int fd, struct lxc_cmd_rsp *rsp)
{
	int ret;

	ret = __lxc_cmd_rsp_send(fd, rsp);
	if (ret < 0)
		return ret;

	return LXC_CMD_REAP_CLIENT_FD;
}

static inline int lxc_cmd_rsp_send_keep(int fd, struct lxc_cmd_rsp *rsp)
{
	int ret;

	ret = __lxc_cmd_rsp_send(fd, rsp);
	if (ret < 0)
		return ret;

	return 0;
}

static inline int rsp_one_fd_reap(int fd, int fd_send, struct lxc_cmd_rsp *rsp)
{
	ssize_t ret;

	ret = lxc_abstract_unix_send_fds(fd, &fd_send, 1, rsp, sizeof(*rsp));
	if (ret < 0)
		return ret;

	if (rsp->data && rsp->datalen > 0) {
		ret = lxc_send_nointr(fd, rsp->data, rsp->datalen, MSG_NOSIGNAL);
		if (ret < 0 || ret != (ssize_t)rsp->datalen)
			return syswarn("Failed to send command response %zd", ret);
	}

	return LXC_CMD_REAP_CLIENT_FD;
}

static inline int rsp_one_fd_keep(int fd, int fd_send, struct lxc_cmd_rsp *rsp)
{
	int ret;

	ret = rsp_one_fd_reap(fd, fd_send, rsp);
	if (ret == LXC_CMD_REAP_CLIENT_FD)
		ret = LXC_CMD_KEEP_CLIENT_FD;

	return ret;
}

__access_r(3, 2) static int rsp_many_fds_reap(int fd, __u32 fds_len,
					      const __s32 fds[static 2],
					      struct lxc_cmd_rsp *rsp)
{
	ssize_t ret;

	if (fds_len > KERNEL_SCM_MAX_FD) {
		rsp->ret = -E2BIG;
		return lxc_cmd_rsp_send_reap(fd, rsp);
	} else if (fds_len == 0) {
		rsp->ret = -ENOENT;
		return lxc_cmd_rsp_send_reap(fd, rsp);
	}

	ret = lxc_abstract_unix_send_fds(fd, fds, fds_len, rsp, sizeof(*rsp));
	if (ret < 0)
		return ret;

	if (rsp->data && rsp->datalen > 0) {
		ret = lxc_send_nointr(fd, rsp->data, rsp->datalen, MSG_NOSIGNAL);
		if (ret < 0 || ret != (ssize_t)rsp->datalen)
			return syswarn("Failed to send command response %zd", ret);
	}

	return LXC_CMD_REAP_CLIENT_FD;
}

static int lxc_cmd_send(const char *name, struct lxc_cmd_rr *cmd,
			const char *lxcpath, const char *hashed_sock_name, int rcv_timeout)
{
	__do_close int client_fd = -EBADF;
	ssize_t ret = -1;

	client_fd = lxc_cmd_connect(name, lxcpath, hashed_sock_name, "command", rcv_timeout);
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
 * lxc_cmd_timeout: Connect to the specified running container, send it a command
 * request and collect the response with timeout
 *
 * @name             : name of container to connect to
 * @cmd              : command with initialized request to send
 * @stopped          : output indicator if the container was not running
 * @lxcpath          : the lxcpath in which the container is running
 * @hashed_sock_name : the hashed name of the socket (optional, can be NULL)
 * @rcv_timeout      : SO_RCVTIMEO for LXC client_fd socket
 *
 * Returns the size of the response message on success, < 0 on failure
 *
 * Note that there is a special case for LXC_CMD_GET_TTY_FD. For this command
 * the fd cannot be closed because it is used as a placeholder to indicate that
 * a particular tty slot is in use. The fd is also used as a signal to the
 * container that when the caller dies or closes the fd, the container will
 * notice the fd on its side of the socket in its mainloop select and then free
 * the slot with lxc_cmd_fd_cleanup(). The socket fd will be returned in the
 * cmd response structure.
 */
static ssize_t lxc_cmd_timeout(const char *name, struct lxc_cmd_rr *cmd, bool *stopped,
		       const char *lxcpath, const char *hashed_sock_name, int rcv_timeout)
{
	__do_close int client_fd = -EBADF;
	bool stay_connected = false;
	ssize_t ret;

	if (cmd->req.cmd == LXC_CMD_GET_TTY_FD ||
	    cmd->req.cmd == LXC_CMD_ADD_STATE_CLIENT)
		stay_connected = true;

	*stopped = 0;

	/*
	 * We don't want to change anything for the case when the client
	 * socket fd lifetime is longer than the lxc_cmd_timeout() execution.
	 * So it's better not to set SO_RCVTIMEO for client_fd,
	 * because it'll have an affect on the entire socket lifetime.
	 */
	if (stay_connected)
		rcv_timeout = 0;

	client_fd = lxc_cmd_send(name, cmd, lxcpath, hashed_sock_name, rcv_timeout);
	if (client_fd < 0) {
		if (errno == ECONNREFUSED || errno == EPIPE)
			*stopped = 1;

		return systrace("Command \"%s\" failed to connect command socket", lxc_cmd_str(cmd->req.cmd));
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

static ssize_t lxc_cmd(const char *name, struct lxc_cmd_rr *cmd, bool *stopped,
		       const char *lxcpath, const char *hashed_sock_name)
{
	return lxc_cmd_timeout(name, cmd, stopped, lxcpath, hashed_sock_name, 0);
}

int lxc_try_cmd(const char *name, const char *lxcpath)
{
	bool stopped = false;
	ssize_t ret;
	struct lxc_cmd_rr cmd;

	lxc_cmd_init(&cmd, LXC_CMD_GET_INIT_PID);

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath, NULL);
	if (stopped)
		return 0;
	if (ret > 0 && cmd.rsp.ret < 0) {
		errno = cmd.rsp.ret;
		return -1;
	}
	if (ret > 0)
		return 0;

	/*
	 * At this point we weren't denied access, and the container *was*
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
	size_t maxlen = req->datalen - 1;
	const char *data = req->data;

	if (data[maxlen] == 0 && strnlen(data, maxlen) == maxlen)
		return 0;

	struct lxc_cmd_rsp rsp = {
		.ret		= -EINVAL,
		.datalen	= 0,
		.data		= NULL,
	};

	return lxc_cmd_rsp_send_reap(fd, &rsp);
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
	bool stopped = false;
	ssize_t ret;
	pid_t pid;
	struct lxc_cmd_rr cmd;

	lxc_cmd_init(&cmd, LXC_CMD_GET_INIT_PID);

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath, NULL);
	if (ret < 0)
		return -1;

	pid = PTR_TO_PID(cmd.rsp.data);
	if (pid < 0)
		return -1;

	/*
	 * We need to assume that pid_t can actually hold any pid given to us
	 * by the kernel. If it can't it's a libc bug.
	 */
	return (pid_t)pid;
}

static int lxc_cmd_get_init_pid_callback(int fd, struct lxc_cmd_req *req,
					 struct lxc_handler *handler,
					 struct lxc_async_descr *descr)
{
	struct lxc_cmd_rsp rsp = {
		.data = PID_TO_PTR(handler->pid),
	};

	return lxc_cmd_rsp_send_reap(fd, &rsp);
}

int lxc_cmd_get_init_pidfd(const char *name, const char *lxcpath)
{
	bool stopped = false;
	int fd;
	ssize_t ret;
	struct lxc_cmd_rr cmd;

	lxc_cmd_init(&cmd, LXC_CMD_GET_INIT_PIDFD);

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath, NULL);
	if (ret < 0)
		return sysdebug("Failed to process \"%s\"",
				lxc_cmd_str(LXC_CMD_GET_INIT_PIDFD));

	if (cmd.rsp.ret < 0)
		return sysdebug_set(cmd.rsp.ret, "Failed to receive file descriptor for \"%s\"",
				    lxc_cmd_str(LXC_CMD_GET_INIT_PIDFD));

	fd = PTR_TO_INT(cmd.rsp.data);
	if (fd < 0)
		return sysdebug_set(fd, "Received invalid file descriptor for \"%s\"",
				    lxc_cmd_str(LXC_CMD_GET_INIT_PIDFD));

	return fd;
}

static int lxc_cmd_get_init_pidfd_callback(int fd, struct lxc_cmd_req *req,
					   struct lxc_handler *handler,
					   struct lxc_async_descr *descr)
{
	struct lxc_cmd_rsp rsp = {
		.ret = -EBADF,
	};

	if (handler->pidfd < 0)
		return lxc_cmd_rsp_send_reap(fd, &rsp);

	rsp.ret = 0;
	return rsp_one_fd_reap(fd, handler->pidfd, &rsp);
}

int lxc_cmd_get_devpts_fd(const char *name, const char *lxcpath)
{
	bool stopped = false;
	int fd;
	ssize_t ret;
	struct lxc_cmd_rr cmd;

	lxc_cmd_init(&cmd, LXC_CMD_GET_DEVPTS_FD);

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath, NULL);
	if (ret < 0)
		return sysdebug("Failed to process \"%s\"",
				lxc_cmd_str(LXC_CMD_GET_DEVPTS_FD));

	if (cmd.rsp.ret < 0)
		return sysdebug_set(cmd.rsp.ret, "Failed to receive file descriptor for \"%s\"",
				    lxc_cmd_str(LXC_CMD_GET_DEVPTS_FD));

	fd = PTR_TO_INT(cmd.rsp.data);
	if (fd < 0)
		return sysdebug_set(fd, "Received invalid file descriptor for \"%s\"",
				    lxc_cmd_str(LXC_CMD_GET_DEVPTS_FD));
	return fd;
}

static int lxc_cmd_get_devpts_fd_callback(int fd, struct lxc_cmd_req *req,
					  struct lxc_handler *handler,
					  struct lxc_async_descr *descr)
{
	struct lxc_cmd_rsp rsp = {
		.ret = -EBADF,
	};

	if (handler->conf->devpts_fd < 0)
		return lxc_cmd_rsp_send_reap(fd, &rsp);

	rsp.ret = 0;
	return rsp_one_fd_reap(fd, handler->conf->devpts_fd, &rsp);
}

int lxc_cmd_get_seccomp_notify_fd(const char *name, const char *lxcpath)
{
#if HAVE_DECL_SECCOMP_NOTIFY_FD
	bool stopped = false;
	int fd;
	ssize_t ret;
	struct lxc_cmd_rr cmd;

	lxc_cmd_init(&cmd, LXC_CMD_GET_SECCOMP_NOTIFY_FD);

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath, NULL);
	if (ret < 0)
		return sysdebug("Failed to process \"%s\"",
				lxc_cmd_str(LXC_CMD_GET_SECCOMP_NOTIFY_FD));

	if (cmd.rsp.ret < 0)
		return sysdebug_set(cmd.rsp.ret, "Failed to receive file descriptor for \"%s\"",
				    lxc_cmd_str(LXC_CMD_GET_SECCOMP_NOTIFY_FD));

	fd = PTR_TO_INT(cmd.rsp.data);
	if (fd < 0)
		return sysdebug_set(fd, "Received invalid file descriptor for \"%s\"",
				    lxc_cmd_str(LXC_CMD_GET_SECCOMP_NOTIFY_FD));
	return fd;
#else
	return ret_errno(ENOSYS);
#endif
}

static int lxc_cmd_get_seccomp_notify_fd_callback(int fd, struct lxc_cmd_req *req,
						  struct lxc_handler *handler,
						  struct lxc_async_descr *descr)
{
#if HAVE_DECL_SECCOMP_NOTIFY_FD
	struct lxc_cmd_rsp rsp = {
		.ret = -EBADF,
	};

	if (handler->conf->seccomp.notifier.notify_fd < 0)
		return lxc_cmd_rsp_send_reap(fd, &rsp);

	rsp.ret = 0;
	return rsp_one_fd_reap(fd, handler->conf->seccomp.notifier.notify_fd, &rsp);
#else
	return syserror_set(-EOPNOTSUPP, "Seccomp notifier not supported");
#endif
}

int lxc_cmd_get_cgroup_ctx(const char *name, const char *lxcpath,
			   size_t size_ret_ctx, struct cgroup_ctx *ret_ctx)
{
	bool stopped = false;
	ssize_t ret;
	struct lxc_cmd_rr cmd;

	lxc_cmd_init(&cmd, LXC_CMD_GET_CGROUP_CTX);
	lxc_cmd_data(&cmd, size_ret_ctx, ret_ctx);

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath, NULL);
	if (ret < 0)
		return sysdebug("Failed to process \"%s\"",
				lxc_cmd_str(LXC_CMD_GET_CGROUP_CTX));

	if (cmd.rsp.ret < 0) {
		/* Container does not have any writable cgroups. */
		if (ret_ctx->fd_len == 0)
			return 0;

		return sysdebug_set(cmd.rsp.ret, "Failed to receive file descriptor for \"%s\"",
				    lxc_cmd_str(LXC_CMD_GET_CGROUP_CTX));
	}

	return 0;
}

static int lxc_cmd_get_cgroup_ctx_callback(int fd, struct lxc_cmd_req *req,
					   struct lxc_handler *handler,
					   struct lxc_async_descr *descr)
{
	struct lxc_cmd_rsp rsp = {
		.ret = EINVAL,
	};
	struct cgroup_ops *cgroup_ops = handler->cgroup_ops;
	struct cgroup_ctx ctx_server = {};
	ssize_t ret;

	ret = copy_struct_from_client(sizeof(struct cgroup_ctx), &ctx_server,
				      req->datalen, req->data);
	if (ret < 0)
		return lxc_cmd_rsp_send_reap(fd, &rsp);

	ret = prepare_cgroup_ctx(cgroup_ops, &ctx_server);
	if (ret < 0) {
		rsp.ret = ret;
		return lxc_cmd_rsp_send_reap(fd, &rsp);
	}

	rsp.ret = 0;
	rsp.data = &ctx_server;
	rsp.datalen = min(sizeof(struct cgroup_ctx), (size_t)req->datalen);
	return rsp_many_fds_reap(fd, ctx_server.fd_len, ctx_server.fd, &rsp);
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
	bool stopped = false;
	ssize_t ret;
	struct lxc_cmd_rr cmd;

	lxc_cmd_init(&cmd, LXC_CMD_GET_CLONE_FLAGS);

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath, NULL);
	if (ret < 0)
		return ret;

	return PTR_TO_INT(cmd.rsp.data);
}

static int lxc_cmd_get_clone_flags_callback(int fd, struct lxc_cmd_req *req,
					    struct lxc_handler *handler,
					    struct lxc_async_descr *descr)
{
	struct lxc_cmd_rsp rsp = {
		.data = INT_TO_PTR(handler->ns_clone_flags),
	};

	return lxc_cmd_rsp_send_reap(fd, &rsp);
}

static char *lxc_cmd_get_cgroup_path_callback(const char *name,
					      const char *lxcpath,
					      const char *controller,
					      lxc_cmd_t command)
{
	bool stopped = false;
	ssize_t ret;
	struct lxc_cmd_rr cmd;

	lxc_cmd_init(&cmd, command);
	if (controller)
		lxc_cmd_data(&cmd, strlen(controller) + 1, controller);

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath, NULL);
	if (ret < 0)
		return NULL;

	if (ret == 0) {
		if (command == LXC_CMD_GET_LIMIT_CGROUP) {
			/*
			 * This may indicate that the container was started
			 * under an ealier version before
			 * `cgroup_advanced_isolation` as implemented, there
			 * it sees an unknown command and just closes the
			 * socket, sending us an EOF.
			 */
			return lxc_cmd_get_cgroup_path_callback(name, lxcpath,
								controller,
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
 * particular controller. This is the cgroup path relative to the root
 * of the cgroup filesystem.
 *
 * @name      : name of container to connect to
 * @lxcpath   : the lxcpath in which the container is running
 * @controller : the controller being asked about
 *
 * Returns the path on success, NULL on failure. The caller must free() the
 * returned path.
 */
char *lxc_cmd_get_cgroup_path(const char *name, const char *lxcpath,
			      const char *controller)
{
	return lxc_cmd_get_cgroup_path_callback(name, lxcpath, controller,
						LXC_CMD_GET_CGROUP);
}

/*
 * lxc_cmd_get_limit_cgroup_path: Calculate a container's limit cgroup
 * path for a particular controller. This is the cgroup path relative to the
 * root of the cgroup filesystem. This may be the same as the path returned by
 * lxc_cmd_get_cgroup_path if the container doesn't have a limit path prefix
 * set.
 *
 * @name      : name of container to connect to
 * @lxcpath   : the lxcpath in which the container is running
 * @controller : the controller being asked about
 *
 * Returns the path on success, NULL on failure. The caller must free() the
 * returned path.
 */
char *lxc_cmd_get_limit_cgroup_path(const char *name, const char *lxcpath,
				    const char *controller)
{
	return lxc_cmd_get_cgroup_path_callback(name, lxcpath, controller,
						LXC_CMD_GET_LIMIT_CGROUP);
}

static int __lxc_cmd_get_cgroup_callback(int fd, struct lxc_cmd_req *req,
					 struct lxc_handler *handler,
					 struct lxc_async_descr *descr,
					 bool limiting_cgroup)
{
	ssize_t ret;
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

	get_fn = (limiting_cgroup ? cgroup_ops->get_limit_cgroup
				  : cgroup_ops->get_cgroup);

	path = get_fn(cgroup_ops, reqdata);

	if (!path)
		return -1;

	rsp.ret = 0;
	rsp.datalen = strlen(path) + 1;
	rsp.data = (char *)path;

	return lxc_cmd_rsp_send_reap(fd, &rsp);
}

static int lxc_cmd_get_cgroup_callback(int fd, struct lxc_cmd_req *req,
				       struct lxc_handler *handler,
				       struct lxc_async_descr *descr)
{
	return __lxc_cmd_get_cgroup_callback(fd, req, handler, descr, false);
}

static int lxc_cmd_get_limit_cgroup_callback(int fd, struct lxc_cmd_req *req,
					     struct lxc_handler *handler,
					     struct lxc_async_descr *descr)
{
	return __lxc_cmd_get_cgroup_callback(fd, req, handler, descr, true);
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
	bool stopped = false;
	ssize_t ret;
	struct lxc_cmd_rr cmd;

	if (is_empty_string(item))
		return NULL;

	lxc_cmd_init(&cmd, LXC_CMD_GET_CONFIG_ITEM);
	lxc_cmd_data(&cmd, strlen(item) + 1, item);

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath, NULL);
	if (ret < 0)
		return NULL;

	if (cmd.rsp.ret == 0)
		return cmd.rsp.data;

	return NULL;
}

static int lxc_cmd_get_config_item_callback(int fd, struct lxc_cmd_req *req,
					    struct lxc_handler *handler,
					    struct lxc_async_descr *descr)
{
	__do_free char *cidata = NULL;
	int cilen;
	struct lxc_config_t *item;
	struct lxc_cmd_rsp rsp;

	memset(&rsp, 0, sizeof(rsp));
	item = lxc_get_config(req->data);
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
	return lxc_cmd_rsp_send_reap(fd, &rsp);
}

/*
 * lxc_cmd_get_state: Get current state of the container
 *
 * @name      : name of container to connect to
 * @lxcpath   : the lxcpath in which the container is running
 *
 * Returns the state on success, < 0 on failure
 */
int lxc_cmd_get_state(const char *name, const char *lxcpath, int timeout)
{
	bool stopped = false;
	ssize_t ret;
	struct lxc_cmd_rr cmd;

	lxc_cmd_init(&cmd, LXC_CMD_GET_STATE);

	ret = lxc_cmd_timeout(name, &cmd, &stopped, lxcpath, NULL, timeout);
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
				      struct lxc_async_descr *descr)
{
	struct lxc_cmd_rsp rsp = {
		.data = INT_TO_PTR(handler->state),
	};

	return lxc_cmd_rsp_send_reap(fd, &rsp);
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
	bool stopped = false;
	ssize_t ret;
	struct lxc_cmd_rr cmd;

	lxc_cmd_init(&cmd, LXC_CMD_STOP);

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
				 struct lxc_async_descr *descr)
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

		if (pure_unified_layout(cgroup_ops))
			ret = __cgroup_unfreeze(cgroup_ops->unified->dfd_lim, -1);
		else
			ret = cgroup_ops->unfreeze(cgroup_ops, -1);
		if (ret)
			WARN("Failed to unfreeze container \"%s\"", handler->name);

		return 0;
	} else {
		rsp.ret = -errno;
	}

	return lxc_cmd_rsp_send_reap(fd, &rsp);
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
					   struct lxc_async_descr *descr)
{
	/* should never be called */
	return syserror_set(-ENOSYS, "Called lxc_cmd_terminal_winch_callback()");
}

/*
 * lxc_cmd_get_tty_fd: Open an fd to a tty in the container
 *
 * @name           : name of container to connect to
 * @ttynum         : in:  the tty to open or -1 for next available
 *                 : out: the tty allocated
 * @fd             : out: file descriptor for ptx side of pty
 * @lxcpath        : the lxcpath in which the container is running
 *
 * Returns fd holding tty allocated on success, < 0 on failure
 */
int lxc_cmd_get_tty_fd(const char *name, int *ttynum, int *fd, const char *lxcpath)
{
	__do_free struct lxc_cmd_tty_rsp_data *rspdata = NULL;
	bool stopped = false;
	ssize_t ret;
	struct lxc_cmd_rr cmd;

	lxc_cmd_init(&cmd, LXC_CMD_GET_TTY_FD);
	lxc_cmd_data(&cmd, ENCODE_INTO_PTR_LEN, INT_TO_PTR(*ttynum));

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath, NULL);
	if (ret < 0)
		return sysdebug("Failed to process \"%s\"",
				lxc_cmd_str(LXC_CMD_GET_TTY_FD));

	rspdata = cmd.rsp.data;
	if (cmd.rsp.ret < 0)
		return log_error_errno(-1, -cmd.rsp.ret, "Denied access to tty");

	if (ret == 0)
		return log_error(-1, "tty number %d invalid, busy or all ttys busy", *ttynum);

	if (rspdata->ptxfd < 0)
		return log_error(-1, "Unable to allocate fd for tty %d", rspdata->ttynum);

	ret	= cmd.rsp.ret; /* socket fd */
	*fd	= rspdata->ptxfd;
	*ttynum = rspdata->ttynum;

	INFO("Alloced fd %d for tty %d via socket %zd", *fd, rspdata->ttynum, ret);
	return ret;
}

static int lxc_cmd_get_tty_fd_callback(int fd, struct lxc_cmd_req *req,
				       struct lxc_handler *handler,
				       struct lxc_async_descr *descr)
{
	struct lxc_cmd_rsp rsp = {
		.ret = -EBADF,
	};
	int ptxfd, ret, ttynum;

	ttynum = PTR_TO_INT(req->data);
	ptxfd = lxc_terminal_allocate(handler->conf, fd, &ttynum);
	if (ptxfd < 0)
		return lxc_cmd_rsp_send_reap(fd, &rsp);

	rsp.ret = 0;
	rsp.data = INT_TO_PTR(ttynum);
	ret = rsp_one_fd_keep(fd, ptxfd, &rsp);
	if (ret < 0) {
		lxc_terminal_free(handler->conf, fd);
		return ret;
	}

	DEBUG("Send tty to client");
	return ret;
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
	bool stopped = false;
	ssize_t ret;
	struct lxc_cmd_rr cmd;

	lxc_cmd_init(&cmd, LXC_CMD_GET_NAME);

	ret = lxc_cmd(NULL, &cmd, &stopped, NULL, hashed_sock_name);
	if (ret < 0)
		return NULL;

	if (cmd.rsp.ret == 0)
		return cmd.rsp.data;

	return NULL;
}

static int lxc_cmd_get_name_callback(int fd, struct lxc_cmd_req *req,
				     struct lxc_handler *handler,
				     struct lxc_async_descr *descr)
{
	struct lxc_cmd_rsp rsp;

	memset(&rsp, 0, sizeof(rsp));

	rsp.data = (char *)handler->name;
	rsp.datalen = strlen(handler->name) + 1;
	rsp.ret = 0;

	return lxc_cmd_rsp_send_reap(fd, &rsp);
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
	bool stopped = false;
	ssize_t ret;
	struct lxc_cmd_rr cmd;

	lxc_cmd_init(&cmd, LXC_CMD_GET_LXCPATH);

	ret = lxc_cmd(NULL, &cmd, &stopped, NULL, hashed_sock_name);
	if (ret < 0)
		return NULL;

	if (cmd.rsp.ret == 0)
		return cmd.rsp.data;

	return NULL;
}

static int lxc_cmd_get_lxcpath_callback(int fd, struct lxc_cmd_req *req,
					struct lxc_handler *handler,
					struct lxc_async_descr *descr)
{
	struct lxc_cmd_rsp rsp = {
		.ret		= 0,
		.data		= (char *)handler->lxcpath,
		.datalen	= strlen(handler->lxcpath) + 1,
	};

	return lxc_cmd_rsp_send_reap(fd, &rsp);
}

char *lxc_cmd_get_systemd_scope(const char *name, const char *lxcpath)
{
	bool stopped = false;
	ssize_t ret;
	struct lxc_cmd_rr cmd;

	lxc_cmd_init(&cmd, LXC_CMD_GET_SYSTEMD_SCOPE);

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath, NULL);
	if (ret < 0)
		return NULL;

	if (cmd.rsp.ret == 0)
		return cmd.rsp.data;

	return NULL;
}

static int lxc_cmd_get_systemd_scope_callback(int fd, struct lxc_cmd_req *req,
					     struct lxc_handler *handler,
					     struct lxc_async_descr *descr)
{
	__do_free char *scope = NULL;
	struct lxc_cmd_rsp rsp = {
		.ret = -EINVAL,
	};

	// cgroup_meta.systemd_scope is the full cgroup path to the scope.
	// The caller just wants the actual scope name, that is, basename().
	// (XXX - or do we want the caller to massage it?  I'm undecided)
	if (handler->conf->cgroup_meta.systemd_scope) {
		scope = strrchr(handler->conf->cgroup_meta.systemd_scope, '/');
		if (scope && *scope)
			scope++;
		if (scope && *scope)
			scope = strdup(scope);
	}

	if (!scope)
		goto out;

	rsp.ret = 0;
	rsp.data = scope;
	rsp.datalen = strlen(scope) + 1;

out:
	return lxc_cmd_rsp_send_reap(fd, &rsp);
}

int lxc_cmd_add_state_client(const char *name, const char *lxcpath,
			     lxc_state_t states[static MAX_STATE],
			     int *state_client_fd)
{
	__do_close int clientfd = -EBADF;
	bool stopped = false;
	int state;
	ssize_t ret;
	struct lxc_cmd_rr cmd;

	lxc_cmd_init(&cmd, LXC_CMD_ADD_STATE_CLIENT);
	lxc_cmd_data(&cmd, (sizeof(lxc_state_t) * MAX_STATE), states);

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
					     struct lxc_async_descr *descr)
{
	struct lxc_cmd_rsp rsp = {
		.ret = -EINVAL,
	};

	if (req->datalen < 0)
		goto reap_fd;

	if (req->datalen != (sizeof(lxc_state_t) * MAX_STATE))
		goto reap_fd;

	if (!req->data)
		goto reap_fd;

	rsp.ret = lxc_add_state_client(fd, handler, (lxc_state_t *)req->data);
	if (rsp.ret < 0)
		goto reap_fd;

	rsp.data = INT_TO_PTR(rsp.ret);

	return lxc_cmd_rsp_send_keep(fd, &rsp);

reap_fd:
	return lxc_cmd_rsp_send_reap(fd, &rsp);
}

int lxc_cmd_add_bpf_device_cgroup(const char *name, const char *lxcpath,
				  struct device_item *device)
{
	bool stopped = false;
	ssize_t ret;
	struct lxc_cmd_rr cmd;

	if (strlen(device->access) > STRLITERALLEN("rwm"))
		return syserror_set(-EINVAL, "Invalid access mode specified %s", device->access);

	lxc_cmd_init(&cmd, LXC_CMD_ADD_BPF_DEVICE_CGROUP);
	lxc_cmd_data(&cmd, sizeof(struct device_item), device);

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath, NULL);
	if (ret < 0)
		return syserror_set(ret, "Failed to process new bpf device cgroup command");

	if (cmd.rsp.ret < 0)
		return syserror_set(cmd.rsp.ret, "Failed to add new bpf device cgroup rule");

	return 0;
}

static int lxc_cmd_add_bpf_device_cgroup_callback(int fd, struct lxc_cmd_req *req,
						  struct lxc_handler *handler,
						  struct lxc_async_descr *descr)
{
	struct lxc_cmd_rsp rsp = {
		.ret = -EINVAL,
	};
	struct lxc_conf *conf;

	if (req->datalen <= 0)
		goto out;

	if (req->datalen != sizeof(struct device_item))
		goto out;

	if (!req->data)
		goto out;

	conf = handler->conf;
	if (!bpf_cgroup_devices_update(handler->cgroup_ops,
				       &conf->bpf_devices,
				       (struct device_item *)req->data))
		rsp.ret = -1;
	else
		rsp.ret = 0;

out:
	return lxc_cmd_rsp_send_reap(fd, &rsp);
}

int lxc_cmd_console_log(const char *name, const char *lxcpath,
			struct lxc_console_log *log)
{
	bool stopped = false;
	struct lxc_cmd_console_log data = {
		.clear		= log->clear,
		.read		= log->read,
		.read_max	= *log->read_max,
	};
	ssize_t ret;
	struct lxc_cmd_rr cmd;

	lxc_cmd_init(&cmd, LXC_CMD_CONSOLE_LOG);
	lxc_cmd_data(&cmd, sizeof(struct lxc_cmd_console_log), &data);

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

	*log->read_max	= cmd.rsp.datalen;
	log->data	= cmd.rsp.data;

	return 0;
}

static int lxc_cmd_console_log_callback(int fd, struct lxc_cmd_req *req,
					struct lxc_handler *handler,
					struct lxc_async_descr *descr)
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

	if (log->read_max > 0 && (log->read_max <= (uint64_t)rsp.datalen))
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
	return lxc_cmd_rsp_send_reap(fd, &rsp);
}

int lxc_cmd_serve_state_clients(const char *name, const char *lxcpath,
				lxc_state_t state)
{
	bool stopped = false;
	ssize_t ret;
	struct lxc_cmd_rr cmd;

	lxc_cmd_init(&cmd, LXC_CMD_SERVE_STATE_CLIENTS);
	lxc_cmd_data(&cmd, ENCODE_INTO_PTR_LEN, INT_TO_PTR(state));

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath, NULL);
	if (ret < 0)
		return log_error_errno(-1, errno, "Failed to serve state clients");

	return 0;
}

static int lxc_cmd_serve_state_clients_callback(int fd, struct lxc_cmd_req *req,
						struct lxc_handler *handler,
						struct lxc_async_descr *descr)
{
	int ret;
	lxc_state_t state = PTR_TO_INT(req->data);
	struct lxc_cmd_rsp rsp = {0};

	ret = lxc_serve_state_clients(handler->name, handler, state);
	if (ret < 0)
		return ret;

	return lxc_cmd_rsp_send_reap(fd, &rsp);
}

int lxc_cmd_seccomp_notify_add_listener(const char *name, const char *lxcpath,
					int fd,
					/* unused */ unsigned int command,
					/* unused */ unsigned int flags)
{

#if HAVE_DECL_SECCOMP_NOTIFY_FD
	bool stopped = false;
	ssize_t ret;
	struct lxc_cmd_rr cmd;

	lxc_cmd_init(&cmd, LXC_CMD_SECCOMP_NOTIFY_ADD_LISTENER);
	lxc_cmd_data(&cmd, ENCODE_INTO_PTR_LEN, INT_TO_PTR(fd));

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
							struct lxc_async_descr *descr)
{
	struct lxc_cmd_rsp rsp = {0};

#if HAVE_DECL_SECCOMP_NOTIFY_FD
	int ret;
	__do_close int recv_fd = -EBADF;

	ret = lxc_abstract_unix_recv_one_fd(fd, &recv_fd, NULL, 0);
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

	ret = lxc_mainloop_add_handler(descr, recv_fd,
				       seccomp_notify_handler,
				       seccomp_notify_cleanup_handler,
				       handler, "seccomp_notify_handler");
	if (ret < 0) {
		rsp.ret = -errno;
		goto out;
	}
	move_fd(recv_fd);

out:
#else
	rsp.ret = -ENOSYS;

#endif
	return lxc_cmd_rsp_send_reap(fd, &rsp);
}

int lxc_cmd_freeze(const char *name, const char *lxcpath, int timeout)
{
	bool stopped = false;
	ssize_t ret;
	struct lxc_cmd_rr cmd;

	lxc_cmd_init(&cmd, LXC_CMD_FREEZE);
	lxc_cmd_data(&cmd, ENCODE_INTO_PTR_LEN, INT_TO_PTR(timeout));

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath, NULL);
	if (ret <= 0 || cmd.rsp.ret < 0)
		return log_error_errno(-1, errno, "Failed to freeze container");

	return cmd.rsp.ret;
}

static int lxc_cmd_freeze_callback(int fd, struct lxc_cmd_req *req,
				   struct lxc_handler *handler,
				   struct lxc_async_descr *descr)
{
	int timeout = PTR_TO_INT(req->data);
	struct lxc_cmd_rsp rsp = {
		.ret = -ENOENT,
	};
	struct cgroup_ops *ops = handler->cgroup_ops;

	if (pure_unified_layout(ops))
		rsp.ret = ops->freeze(ops, timeout);

	return lxc_cmd_rsp_send_reap(fd, &rsp);
}

int lxc_cmd_unfreeze(const char *name, const char *lxcpath, int timeout)
{
	bool stopped = false;
	ssize_t ret;
	struct lxc_cmd_rr cmd;

	lxc_cmd_init(&cmd, LXC_CMD_UNFREEZE);
	lxc_cmd_data(&cmd, ENCODE_INTO_PTR_LEN, INT_TO_PTR(timeout));

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath, NULL);
	if (ret <= 0 || cmd.rsp.ret < 0)
		return log_error_errno(-1, errno, "Failed to unfreeze container");

	return cmd.rsp.ret;
}

static int lxc_cmd_unfreeze_callback(int fd, struct lxc_cmd_req *req,
				   struct lxc_handler *handler,
				   struct lxc_async_descr *descr)
{
	int timeout = PTR_TO_INT(req->data);
	struct lxc_cmd_rsp rsp = {
		.ret = -ENOENT,
	};
	struct cgroup_ops *ops = handler->cgroup_ops;

	if (pure_unified_layout(ops))
		rsp.ret = ops->unfreeze(ops, timeout);

	return lxc_cmd_rsp_send_reap(fd, &rsp);
}

int lxc_cmd_get_cgroup_fd(const char *name, const char *lxcpath,
			  size_t size_ret_fd, struct cgroup_fd *ret_fd)
{
	bool stopped = false;
	ssize_t ret;
	struct lxc_cmd_rr cmd;

	lxc_cmd_init(&cmd, LXC_CMD_GET_CGROUP_FD);
	lxc_cmd_data(&cmd, sizeof(struct cgroup_fd), ret_fd);

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath, NULL);
	if (ret < 0)
		return sysdebug("Failed to process \"%s\"",
				lxc_cmd_str(LXC_CMD_GET_CGROUP_FD));

	if (cmd.rsp.ret < 0)
		return sysdebug_set(cmd.rsp.ret, "Failed to receive file descriptor for \"%s\"",
				    lxc_cmd_str(LXC_CMD_GET_CGROUP_FD));

	return 0;
}

int lxc_cmd_get_limit_cgroup_fd(const char *name, const char *lxcpath,
				size_t size_ret_fd, struct cgroup_fd *ret_fd)
{
	bool stopped = false;
	ssize_t ret;
	struct lxc_cmd_rr cmd;

	lxc_cmd_init(&cmd, LXC_CMD_GET_LIMIT_CGROUP_FD);
	lxc_cmd_data(&cmd, sizeof(struct cgroup_fd), ret_fd);

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath, NULL);
	if (ret < 0)
		return sysdebug("Failed to process \"%s\"",
				lxc_cmd_str(LXC_CMD_GET_CGROUP_FD));

	if (cmd.rsp.ret < 0)
		return sysdebug_set(cmd.rsp.ret, "Failed to receive file descriptor for \"%s\"",
				    lxc_cmd_str(LXC_CMD_GET_CGROUP_FD));

	return 0;
}

static int __lxc_cmd_get_cgroup_fd_callback(int fd, struct lxc_cmd_req *req,
					    struct lxc_handler *handler,
					    struct lxc_async_descr *descr,
					    bool limit)
{
	struct lxc_cmd_rsp rsp = {
		.ret = -EINVAL,
	};
	struct cgroup_ops *ops = handler->cgroup_ops;
	struct cgroup_fd fd_server = {};
	int ret;

	ret = copy_struct_from_client(sizeof(struct cgroup_fd), &fd_server,
				      req->datalen, req->data);
	if (ret < 0)
		return lxc_cmd_rsp_send_reap(fd, &rsp);

	if (strnlen(fd_server.controller, MAX_CGROUP_ROOT_NAMELEN) == 0)
		return lxc_cmd_rsp_send_reap(fd, &rsp);

	ret = prepare_cgroup_fd(ops, &fd_server, limit);
	if (ret < 0) {
		rsp.ret = ret;
		return lxc_cmd_rsp_send_reap(fd, &rsp);
	}

	rsp.ret		= 0;
	rsp.data	= &fd_server;
	rsp.datalen	= min(sizeof(struct cgroup_fd), (size_t)req->datalen);
	return rsp_one_fd_reap(fd, fd_server.fd, &rsp);
}

static int lxc_cmd_get_cgroup_fd_callback(int fd, struct lxc_cmd_req *req,
					  struct lxc_handler *handler,
					  struct lxc_async_descr *descr)
{
	return __lxc_cmd_get_cgroup_fd_callback(fd, req, handler, descr, false);
}

static int lxc_cmd_get_limit_cgroup_fd_callback(int fd, struct lxc_cmd_req *req,
						struct lxc_handler *handler,
						struct lxc_async_descr *descr)
{
	return __lxc_cmd_get_cgroup_fd_callback(fd, req, handler, descr, true);
}

int lxc_cmd_get_cgroup2_fd(const char *name, const char *lxcpath)
{
	bool stopped = false;
	int fd;
	ssize_t ret;
	struct lxc_cmd_rr cmd;

	lxc_cmd_init(&cmd, LXC_CMD_GET_CGROUP2_FD);

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath, NULL);
	if (ret < 0)
		return sysdebug("Failed to process \"%s\"",
				lxc_cmd_str(LXC_CMD_GET_CGROUP2_FD));

	if (cmd.rsp.ret < 0)
		return sysdebug_set(cmd.rsp.ret, "Failed to receive file descriptor for \"%s\"",
				    lxc_cmd_str(LXC_CMD_GET_CGROUP2_FD));

	fd = PTR_TO_INT(cmd.rsp.data);
	if (fd < 0)
		return sysdebug_set(fd, "Received invalid file descriptor for \"%s\"",
				    lxc_cmd_str(LXC_CMD_GET_CGROUP2_FD));
	return fd;
}

int lxc_cmd_get_limit_cgroup2_fd(const char *name, const char *lxcpath)
{
	bool stopped = false;
	int fd;
	ssize_t ret;
	struct lxc_cmd_rr cmd;

	lxc_cmd_init(&cmd, LXC_CMD_GET_LIMIT_CGROUP2_FD);

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath, NULL);
	if (ret < 0)
		return sysdebug("Failed to process \"%s\"",
				lxc_cmd_str(LXC_CMD_GET_CGROUP2_FD));

	if (cmd.rsp.ret < 0)
		return sysdebug_set(cmd.rsp.ret, "Failed to receive file descriptor for \"%s\"",
				    lxc_cmd_str(LXC_CMD_GET_CGROUP2_FD));

	fd = PTR_TO_INT(cmd.rsp.data);
	if (fd < 0)
		return sysdebug_set(fd, "Received invalid file descriptor for \"%s\"",
				    lxc_cmd_str(LXC_CMD_GET_CGROUP2_FD));
	return fd;
}

static int __lxc_cmd_get_cgroup2_fd_callback(int fd, struct lxc_cmd_req *req,
					     struct lxc_handler *handler,
					     struct lxc_async_descr *descr,
					     bool limiting_cgroup)
{
	struct lxc_cmd_rsp rsp = {
		.ret = -EINVAL,
	};
	struct cgroup_ops *ops = handler->cgroup_ops;
	int send_fd;

	if (!pure_unified_layout(ops) || !ops->unified)
		return lxc_cmd_rsp_send_reap(fd, &rsp);

	send_fd = limiting_cgroup ? ops->unified->dfd_lim
				  : ops->unified->dfd_con;

	if (send_fd < 0) {
		rsp.ret = -EBADF;
		return lxc_cmd_rsp_send_reap(fd, &rsp);
	}

	rsp.ret = 0;
	return rsp_one_fd_reap(fd, send_fd, &rsp);
}

static int lxc_cmd_get_cgroup2_fd_callback(int fd, struct lxc_cmd_req *req,
					   struct lxc_handler *handler,
					   struct lxc_async_descr *descr)
{
	return __lxc_cmd_get_cgroup2_fd_callback(fd, req, handler, descr, false);
}

static int lxc_cmd_get_limit_cgroup2_fd_callback(int fd, struct lxc_cmd_req *req,
						 struct lxc_handler *handler,
						 struct lxc_async_descr *descr)
{
	return __lxc_cmd_get_cgroup2_fd_callback(fd, req, handler, descr, true);
}

static int lxc_cmd_rsp_send_enosys(int fd, int id)
{
	struct lxc_cmd_rsp rsp = {
		.ret = -ENOSYS,
	};

	__lxc_cmd_rsp_send(fd, &rsp);
	return syserror_set(-ENOSYS, "Invalid command id %d", id);
}

static int lxc_cmd_process(int fd, struct lxc_cmd_req *req,
			   struct lxc_handler *handler,
			   struct lxc_async_descr *descr)
{
	typedef int (*callback)(int, struct lxc_cmd_req *, struct lxc_handler *,
				struct lxc_async_descr *);

	callback cb[LXC_CMD_MAX] = {
		[LXC_CMD_GET_TTY_FD]                    = lxc_cmd_get_tty_fd_callback,
		[LXC_CMD_TERMINAL_WINCH]                = lxc_cmd_terminal_winch_callback,
		[LXC_CMD_STOP]                          = lxc_cmd_stop_callback,
		[LXC_CMD_GET_STATE]                     = lxc_cmd_get_state_callback,
		[LXC_CMD_GET_INIT_PID]                  = lxc_cmd_get_init_pid_callback,
		[LXC_CMD_GET_CLONE_FLAGS]               = lxc_cmd_get_clone_flags_callback,
		[LXC_CMD_GET_CGROUP]                    = lxc_cmd_get_cgroup_callback,
		[LXC_CMD_GET_CONFIG_ITEM]               = lxc_cmd_get_config_item_callback,
		[LXC_CMD_GET_NAME]                      = lxc_cmd_get_name_callback,
		[LXC_CMD_GET_LXCPATH]                   = lxc_cmd_get_lxcpath_callback,
		[LXC_CMD_ADD_STATE_CLIENT]              = lxc_cmd_add_state_client_callback,
		[LXC_CMD_CONSOLE_LOG]                   = lxc_cmd_console_log_callback,
		[LXC_CMD_SERVE_STATE_CLIENTS]           = lxc_cmd_serve_state_clients_callback,
		[LXC_CMD_SECCOMP_NOTIFY_ADD_LISTENER]   = lxc_cmd_seccomp_notify_add_listener_callback,
		[LXC_CMD_ADD_BPF_DEVICE_CGROUP]         = lxc_cmd_add_bpf_device_cgroup_callback,
		[LXC_CMD_FREEZE]                        = lxc_cmd_freeze_callback,
		[LXC_CMD_UNFREEZE]                      = lxc_cmd_unfreeze_callback,
		[LXC_CMD_GET_CGROUP2_FD]                = lxc_cmd_get_cgroup2_fd_callback,
		[LXC_CMD_GET_INIT_PIDFD]                = lxc_cmd_get_init_pidfd_callback,
		[LXC_CMD_GET_LIMIT_CGROUP]              = lxc_cmd_get_limit_cgroup_callback,
		[LXC_CMD_GET_LIMIT_CGROUP2_FD]          = lxc_cmd_get_limit_cgroup2_fd_callback,
		[LXC_CMD_GET_DEVPTS_FD]                 = lxc_cmd_get_devpts_fd_callback,
		[LXC_CMD_GET_SECCOMP_NOTIFY_FD]         = lxc_cmd_get_seccomp_notify_fd_callback,
		[LXC_CMD_GET_CGROUP_CTX]                = lxc_cmd_get_cgroup_ctx_callback,
		[LXC_CMD_GET_CGROUP_FD]                 = lxc_cmd_get_cgroup_fd_callback,
		[LXC_CMD_GET_LIMIT_CGROUP_FD]           = lxc_cmd_get_limit_cgroup_fd_callback,
		[LXC_CMD_GET_SYSTEMD_SCOPE]             = lxc_cmd_get_systemd_scope_callback,
	};

	if (req->cmd >= LXC_CMD_MAX)
		return lxc_cmd_rsp_send_enosys(fd,  req->cmd);

	return cb[req->cmd](fd, req, handler, descr);
}

static void lxc_cmd_fd_cleanup(int fd, struct lxc_handler *handler,
			       const lxc_cmd_t cmd)
{
	if (cmd == LXC_CMD_ADD_STATE_CLIENT) {
		struct lxc_state_client *client, *nclient;

		list_for_each_entry_safe(client, nclient, &handler->conf->state_clients, head) {
			if (client->clientfd != fd)
				continue;

			list_del(&client->head);
			free(client);

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
		TRACE("Deleted state client fd %d for command \"%s\"", fd, lxc_cmd_str(cmd));
	}

	/*
	 * We're not closing the client fd here. They will instead be notified
	 * from the mainloop when it calls the cleanup handler. This will cause
	 * a slight delay but is semantically cleaner then what we used to do.
	 */
}

static int lxc_cmd_cleanup_handler(int fd, void *data)
{
	struct lxc_handler *handler = data;

	lxc_terminal_free(handler->conf, fd);
	close(fd);
	TRACE("Closing client fd %d for \"%s\"", fd, __FUNCTION__);
	return 0;

}

static int lxc_cmd_handler(int fd, uint32_t events, void *data,
			   struct lxc_async_descr *descr)
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

			__lxc_cmd_rsp_send(fd, &rsp);
		}

		goto out;
	}

	if (ret == 0)
		goto out;

	if (ret != sizeof(req)) {
		WARN("Failed to receive full command request. Ignoring request for \"%s\"", lxc_cmd_str(req.cmd));
		goto out;
	}

	if ((req.datalen > LXC_CMD_DATA_MAX) && (req.cmd != LXC_CMD_CONSOLE_LOG)) {
		ERROR("Received command data length %d is too large for command \"%s\"", req.datalen, lxc_cmd_str(req.cmd));
		goto out;
	}

	if (req.datalen > 0) {
		reqdata = must_realloc(NULL, req.datalen);
		ret = lxc_recv_nointr(fd, reqdata, req.datalen, 0);
		if (ret != req.datalen) {
			WARN("Failed to receive full command request. Ignoring request for \"%s\"", lxc_cmd_str(req.cmd));
			goto out;
		}

		req.data = reqdata;
	}

	ret = lxc_cmd_process(fd, &req, handler, descr);
	if (ret < 0) {
		DEBUG("Failed to process command %s; cleaning up client fd %d", lxc_cmd_str(req.cmd), fd);
		goto out;
	}

	if (ret == LXC_CMD_REAP_CLIENT_FD) {
		TRACE("Processed command %s; cleaning up client fd %d", lxc_cmd_str(req.cmd), fd);
		goto out;
	}

	TRACE("Processed command %s; keeping client fd %d", lxc_cmd_str(req.cmd), fd);
	return LXC_MAINLOOP_CONTINUE;

out:
	lxc_cmd_fd_cleanup(fd, handler, req.cmd);
	return LXC_MAINLOOP_DISARM;
}

static int lxc_cmd_accept(int fd, uint32_t events, void *data,
			  struct lxc_async_descr *descr)
{
	__do_close int connection = -EBADF;
	int opt = 1, ret = -1;

	connection = accept4(fd, NULL, 0, SOCK_CLOEXEC);
	if (connection < 0)
		return log_error_errno(LXC_MAINLOOP_ERROR, errno, "Failed to accept connection to run command");

	ret = setsockopt(connection, SOL_SOCKET, SO_PASSCRED, &opt, sizeof(opt));
	if (ret < 0)
		return log_error_errno(ret, errno, "Failed to enable necessary credentials on command socket");

	ret = lxc_mainloop_add_oneshot_handler(descr, connection,
					       lxc_cmd_handler,
					       lxc_cmd_cleanup_handler,
					       data, "lxc_cmd_handler");
	if (ret)
		return log_error(ret, "Failed to add command handler");

	TRACE("Accepted new client as fd %d on command server fd %d", connection, fd);
	move_fd(connection);
	return ret;
}

int lxc_server_init(const char *name, const char *lxcpath, const char *suffix)
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

	return log_trace(move_fd(fd), "Created abstract unix socket \"%s\"", &path[1]);
}

int lxc_cmd_mainloop_add(const char *name, struct lxc_async_descr *descr,
			 struct lxc_handler *handler)
{
	int ret;

	ret = lxc_mainloop_add_handler(descr, handler->conf->maincmd_fd,
				       lxc_cmd_accept,
				       default_cleanup_handler,
				       handler, "lxc_cmd_accept");
	if (ret < 0)
		return log_error(ret, "Failed to add handler for command socket fd %d", handler->conf->maincmd_fd);

	return ret;
}

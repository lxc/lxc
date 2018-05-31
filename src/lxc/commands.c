/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2009
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

#include <caps.h>
#include <errno.h>
#include <fcntl.h>
#include <malloc.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "af_unix.h"
#include "cgroup.h"
#include "commands.h"
#include "commands_utils.h"
#include "conf.h"
#include "confile.h"
#include "log.h"
#include "lxc.h"
#include "lxclock.h"
#include "mainloop.h"
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

lxc_log_define(lxc_commands, lxc);

static const char *lxc_cmd_str(lxc_cmd_t cmd)
{
	static const char *const cmdname[LXC_CMD_MAX] = {
		[LXC_CMD_CONSOLE]             = "console",
		[LXC_CMD_TERMINAL_WINCH]      = "terminal_winch",
		[LXC_CMD_STOP]                = "stop",
		[LXC_CMD_GET_STATE]           = "get_state",
		[LXC_CMD_GET_INIT_PID]        = "get_init_pid",
		[LXC_CMD_GET_CLONE_FLAGS]     = "get_clone_flags",
		[LXC_CMD_GET_CGROUP]          = "get_cgroup",
		[LXC_CMD_GET_CONFIG_ITEM]     = "get_config_item",
		[LXC_CMD_GET_NAME]            = "get_name",
		[LXC_CMD_GET_LXCPATH]         = "get_lxcpath",
		[LXC_CMD_ADD_STATE_CLIENT]    = "add_state_client",
		[LXC_CMD_CONSOLE_LOG]         = "console_log",
		[LXC_CMD_SERVE_STATE_CLIENTS] = "serve_state_clients",
	};

	if (cmd >= LXC_CMD_MAX)
		return "Unknown cmd";

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
 * here as it contains an fd for the master pty passed through the
 * unix socket.
 */
static int lxc_cmd_rsp_recv(int sock, struct lxc_cmd_rr *cmd)
{
	int ret, rspfd;
	struct lxc_cmd_rsp *rsp = &cmd->rsp;

	ret = lxc_abstract_unix_recv_fds(sock, &rspfd, 1, rsp, sizeof(*rsp));
	if (ret < 0) {
		WARN("%s - Failed to receive response for command \"%s\"",
		     strerror(errno), lxc_cmd_str(cmd->req.cmd));
		if (errno == ECONNRESET)
			return -ECONNRESET;

		return -1;
	}
	TRACE("Command \"%s\" received response", lxc_cmd_str(cmd->req.cmd));

	if (cmd->req.cmd == LXC_CMD_CONSOLE) {
		struct lxc_cmd_console_rsp_data *rspdata;

		/* recv() returns 0 bytes when a tty cannot be allocated,
		 * rsp->ret is < 0 when the peer permission check failed
		 */
		if (ret == 0 || rsp->ret < 0)
			return 0;

		rspdata = malloc(sizeof(*rspdata));
		if (!rspdata) {
			ERROR("Failed to allocate response buffer for command \"%s\"",
			      lxc_cmd_str(cmd->req.cmd));
			return -ENOMEM;
		}
		rspdata->masterfd = rspfd;
		rspdata->ttynum = PTR_TO_INT(rsp->data);
		rsp->data = rspdata;
	}

	if (rsp->datalen == 0) {
		DEBUG("Response data length for command \"%s\" is 0",
		      lxc_cmd_str(cmd->req.cmd));
		return ret;
	}

	if ((rsp->datalen > LXC_CMD_DATA_MAX) &&
	    (cmd->req.cmd != LXC_CMD_CONSOLE_LOG)) {
		errno = EFBIG;
		ERROR("%s - Response data for command \"%s\" is too long: %d "
		      "bytes > %d", strerror(errno), lxc_cmd_str(cmd->req.cmd),
		      rsp->datalen, LXC_CMD_DATA_MAX);
		return -EFBIG;
	}

	if (cmd->req.cmd == LXC_CMD_CONSOLE_LOG) {
		rsp->data = malloc(rsp->datalen + 1);
		((char *)rsp->data)[rsp->datalen] = '\0';
	} else {
		rsp->data = malloc(rsp->datalen);
	}
	if (!rsp->data) {
		errno = ENOMEM;
		ERROR("%s - Failed to allocate response buffer for command "
		      "\"%s\"", strerror(errno), lxc_cmd_str(cmd->req.cmd));
		return -ENOMEM;
	}

	ret = recv(sock, rsp->data, rsp->datalen, 0);
	if (ret != rsp->datalen) {
		ERROR("%s - Failed to receive response data for command \"%s\"",
		      lxc_cmd_str(cmd->req.cmd), strerror(errno));
		if (ret >= 0)
			ret = -1;
	}

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

	ret = send(fd, rsp, sizeof(*rsp), 0);
	if (ret < 0 || (size_t)ret != sizeof(*rsp)) {
		ERROR("%s - Failed to send command response %zd",
		      strerror(errno), ret);
		return -1;
	}

	if (rsp->datalen <= 0)
		return 0;

	ret = send(fd, rsp->data, rsp->datalen, 0);
	if (ret < 0 || ret != (ssize_t)rsp->datalen) {
		WARN("%s - Failed to send command response data %zd",
		     strerror(errno), ret);
		return -1;
	}

	return 0;
}

static int lxc_cmd_send(const char *name, struct lxc_cmd_rr *cmd,
			const char *lxcpath, const char *hashed_sock_name)
{
	int client_fd;
	ssize_t ret = -1;

	client_fd = lxc_cmd_connect(name, lxcpath, hashed_sock_name, "command");
	if (client_fd < 0) {
		if (client_fd == -ECONNREFUSED)
			return -ECONNREFUSED;

		return -1;
	}

	ret = lxc_abstract_unix_send_credential(client_fd, &cmd->req,
						sizeof(cmd->req));
	if (ret < 0 || (size_t)ret != sizeof(cmd->req)) {
		close(client_fd);

		if (errno == EPIPE)
			return -EPIPE;

		if (ret >= 0)
			return -EMSGSIZE;

		return -1;
	}

	if (cmd->req.datalen <= 0)
		return client_fd;

	ret = send(client_fd, cmd->req.data, cmd->req.datalen, MSG_NOSIGNAL);
	if (ret < 0 || ret != (ssize_t)cmd->req.datalen) {
		close(client_fd);

		if (errno == EPIPE)
			return -EPIPE;

		if (ret >= 0)
			return -EMSGSIZE;

		return -1;
	}

	return client_fd;
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
	int client_fd;
	int ret = -1;
	bool stay_connected = false;

	if (cmd->req.cmd == LXC_CMD_CONSOLE ||
	    cmd->req.cmd == LXC_CMD_ADD_STATE_CLIENT)
		stay_connected = true;

	*stopped = 0;

	client_fd = lxc_cmd_send(name, cmd, lxcpath, hashed_sock_name);
	if (client_fd < 0) {
		TRACE("%s - Command \"%s\" failed to connect command socket",
		      strerror(errno), lxc_cmd_str(cmd->req.cmd));
		if (client_fd == -ECONNREFUSED) {
			*stopped = 1;
			return -1;
		}

		if (client_fd == -EPIPE)
			goto epipe;

		goto out;
	}

	ret = lxc_cmd_rsp_recv(client_fd, cmd);
	if (ret == -ECONNRESET)
		*stopped = 1;
out:
	if (!stay_connected || ret <= 0)
		if (client_fd >= 0)
			close(client_fd);

	if (stay_connected && ret > 0)
		cmd->rsp.ret = client_fd;

	return ret;

epipe:
	*stopped = 1;
	return 0;
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

/* Implentations of the commands and their callbacks */

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
	struct lxc_cmd_rr cmd = {
		.req = { .cmd = LXC_CMD_GET_INIT_PID },
	};

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath, NULL);
	if (ret < 0)
		return ret;

	return PTR_TO_INT(cmd.rsp.data);
}

static int lxc_cmd_get_init_pid_callback(int fd, struct lxc_cmd_req *req,
					 struct lxc_handler *handler)
{
	struct lxc_cmd_rsp rsp = { .data = INT_TO_PTR(handler->pid) };

	return lxc_cmd_rsp_send(fd, &rsp);
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
		.req = { .cmd = LXC_CMD_GET_CLONE_FLAGS },
	};

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath, NULL);
	if (ret < 0)
		return ret;

	return PTR_TO_INT(cmd.rsp.data);
}

static int lxc_cmd_get_clone_flags_callback(int fd, struct lxc_cmd_req *req,
					    struct lxc_handler *handler)
{
	struct lxc_cmd_rsp rsp = { .data = INT_TO_PTR(handler->ns_clone_flags) };

	return lxc_cmd_rsp_send(fd, &rsp);
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
	int ret, stopped;
	struct lxc_cmd_rr cmd = {
		.req = {
			.cmd = LXC_CMD_GET_CGROUP,
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

	if (ret == 0)
		return NULL;

	if (cmd.rsp.ret < 0 || cmd.rsp.datalen < 0)
		return NULL;

	return cmd.rsp.data;
}

static int lxc_cmd_get_cgroup_callback(int fd, struct lxc_cmd_req *req,
				       struct lxc_handler *handler)
{
	const char *path;
	struct lxc_cmd_rsp rsp;
	struct cgroup_ops *cgroup_ops = handler->cgroup_ops;

	if (req->datalen > 0)
		path = cgroup_ops->get_cgroup(cgroup_ops, req->data);
	else
		path = cgroup_ops->get_cgroup(cgroup_ops, NULL);
	if (!path)
		return -1;

	rsp.ret = 0;
	rsp.datalen = strlen(path) + 1;
	rsp.data = (char *)path;

	return lxc_cmd_rsp_send(fd, &rsp);
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
					    struct lxc_handler *handler)
{
	int cilen;
	char *cidata;
	struct lxc_config_t *item;
	struct lxc_cmd_rsp rsp;

	memset(&rsp, 0, sizeof(rsp));
	item = lxc_get_config(req->data);
	if (!item)
		goto err1;

	cilen = item->get(req->data, NULL, 0, handler->conf, NULL);
	if (cilen <= 0)
		goto err1;

	cidata = alloca(cilen + 1);
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
	return lxc_cmd_rsp_send(fd, &rsp);
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
		.req = { .cmd = LXC_CMD_GET_STATE }
	};

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath, NULL);
	if (ret < 0 && stopped)
		return STOPPED;

	if (ret < 0)
		return -1;

	if (!ret) {
		WARN("Container \"%s\" has stopped before sending its state", name);
		return -1;
	}

	DEBUG("Container \"%s\" is in \"%s\" state", name,
	      lxc_state2str(PTR_TO_INT(cmd.rsp.data)));

	return PTR_TO_INT(cmd.rsp.data);
}

static int lxc_cmd_get_state_callback(int fd, struct lxc_cmd_req *req,
				      struct lxc_handler *handler)
{
	struct lxc_cmd_rsp rsp = { .data = INT_TO_PTR(handler->state) };

	return lxc_cmd_rsp_send(fd, &rsp);
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
		.req = { .cmd = LXC_CMD_STOP },
	};

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath, NULL);
	if (ret < 0) {
		if (stopped) {
			INFO("Container \"%s\" is already stopped", name);
			return 0;
		}

		return -1;
	}

	/* We do not expect any answer, because we wait for the connection to be
	 * closed.
	 */
	if (ret > 0) {
		ERROR("%s - Failed to stop container \"%s\"",
		      strerror(-cmd.rsp.ret), name);
		return -1;
	}

	INFO("Container \"%s\" has stopped", name);
	return 0;
}

static int lxc_cmd_stop_callback(int fd, struct lxc_cmd_req *req,
				 struct lxc_handler *handler)
{
	struct lxc_cmd_rsp rsp;
	int stopsignal = SIGKILL;
	struct cgroup_ops *cgroup_ops = handler->cgroup_ops;

	if (handler->conf->stopsignal)
		stopsignal = handler->conf->stopsignal;
	memset(&rsp, 0, sizeof(rsp));
	rsp.ret = kill(handler->pid, stopsignal);
	if (!rsp.ret) {
		/* We can't just use lxc_unfreeze() since we are already in the
		 * context of handling the STOP cmd in lxc-start, and calling
		 * lxc_unfreeze() would do another cmd (GET_CGROUP) which would
		 * deadlock us.
		 */
		if (cgroup_ops->unfreeze(cgroup_ops))
			return 0;

		ERROR("Failed to unfreeze container \"%s\"", handler->name);
		rsp.ret = -1;
	}

	return lxc_cmd_rsp_send(fd, &rsp);
}

/*
 * lxc_cmd_terminal_winch: To process as if a SIGWINCH were received
 *
 * @name      : name of container to connect to
 * @lxcpath   : the lxcpath in which the container is running
 *
 * Returns 0 on success, < 0 on failure
 */
int lxc_cmd_terminal_winch(const char *name, const char *lxcpath)
{
	int ret, stopped;
	struct lxc_cmd_rr cmd = {
		.req = { .cmd = LXC_CMD_TERMINAL_WINCH },
	};

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath, NULL);
	if (ret < 0)
		return ret;

	return 0;
}

static int lxc_cmd_terminal_winch_callback(int fd, struct lxc_cmd_req *req,
					   struct lxc_handler *handler)
{
	struct lxc_cmd_rsp rsp = { .data = 0 };

	lxc_terminal_sigwinch(SIGWINCH);

	return lxc_cmd_rsp_send(fd, &rsp);
}

/*
 * lxc_cmd_console: Open an fd to a tty in the container
 *
 * @name           : name of container to connect to
 * @ttynum         : in:  the tty to open or -1 for next available
 *                 : out: the tty allocated
 * @fd             : out: file descriptor for master side of pty
 * @lxcpath        : the lxcpath in which the container is running
 *
 * Returns fd holding tty allocated on success, < 0 on failure
 */
int lxc_cmd_console(const char *name, int *ttynum, int *fd, const char *lxcpath)
{
	int ret, stopped;
	struct lxc_cmd_console_rsp_data *rspdata;
	struct lxc_cmd_rr cmd = {
		.req = { .cmd = LXC_CMD_CONSOLE, .data = INT_TO_PTR(*ttynum) },
	};

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath, NULL);
	if (ret < 0)
		return ret;

	if (cmd.rsp.ret < 0) {
		ERROR("%s - Denied access to tty", strerror(-cmd.rsp.ret));
		ret = -1;
		goto out;
	}

	if (ret == 0) {
		ERROR("tty number %d invalid, busy or all ttys busy", *ttynum);
		ret = -1;
		goto out;
	}

	rspdata = cmd.rsp.data;
	if (rspdata->masterfd < 0) {
		ERROR("Unable to allocate fd for tty %d", rspdata->ttynum);
		goto out;
	}

	ret = cmd.rsp.ret; /* socket fd */
	*fd = rspdata->masterfd;
	*ttynum = rspdata->ttynum;
	INFO("Alloced fd %d for tty %d via socket %d", *fd, rspdata->ttynum, ret);

out:
	free(cmd.rsp.data);
	return ret;
}

static int lxc_cmd_console_callback(int fd, struct lxc_cmd_req *req,
				    struct lxc_handler *handler)
{
	int masterfd, ret;
	struct lxc_cmd_rsp rsp;
	int ttynum = PTR_TO_INT(req->data);

	masterfd = lxc_terminal_allocate(handler->conf, fd, &ttynum);
	if (masterfd < 0)
		goto out_close;

	memset(&rsp, 0, sizeof(rsp));
	rsp.data = INT_TO_PTR(ttynum);
	ret = lxc_abstract_unix_send_fds(fd, &masterfd, 1, &rsp, sizeof(rsp));
	if (ret < 0) {
		ERROR("Failed to send tty to client");
		lxc_terminal_free(handler->conf, fd);
		goto out_close;
	}

	return 0;

out_close:
	/* Special indicator to lxc_cmd_handler() to close the fd and do
	 * related cleanup.
	 */
	return 1;
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
		.req = { .cmd = LXC_CMD_GET_NAME},
	};

	ret = lxc_cmd(NULL, &cmd, &stopped, NULL, hashed_sock_name);
	if (ret < 0)
		return NULL;

	if (cmd.rsp.ret == 0)
		return cmd.rsp.data;

	return NULL;
}

static int lxc_cmd_get_name_callback(int fd, struct lxc_cmd_req *req,
				     struct lxc_handler *handler)
{
	struct lxc_cmd_rsp rsp;

	memset(&rsp, 0, sizeof(rsp));

	rsp.data = (char *)handler->name;
	rsp.datalen = strlen(handler->name) + 1;
	rsp.ret = 0;

	return lxc_cmd_rsp_send(fd, &rsp);
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
		.req = { .cmd = LXC_CMD_GET_LXCPATH},
	};

	ret = lxc_cmd(NULL, &cmd, &stopped, NULL, hashed_sock_name);
	if (ret < 0)
		return NULL;

	if (cmd.rsp.ret == 0)
		return cmd.rsp.data;

	return NULL;
}

static int lxc_cmd_get_lxcpath_callback(int fd, struct lxc_cmd_req *req,
					struct lxc_handler *handler)
{
	struct lxc_cmd_rsp rsp;

	memset(&rsp, 0, sizeof(rsp));

	rsp.ret = 0;
	rsp.data = (char *)handler->lxcpath;
	rsp.datalen = strlen(handler->lxcpath) + 1;

	return lxc_cmd_rsp_send(fd, &rsp);
}

int lxc_cmd_add_state_client(const char *name, const char *lxcpath,
			     lxc_state_t states[MAX_STATE],
			     int *state_client_fd)
{
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
			ERROR("%s - Failed to execute command", strerror(errno));
		return -1;
	}

	/* We should now be guaranteed to get an answer from the state sending
	 * function.
	 */
	if (cmd.rsp.ret < 0) {
		ERROR("%s - Failed to receive socket fd", strerror(-cmd.rsp.ret));
		return -1;
	}

	state = PTR_TO_INT(cmd.rsp.data);
	if (state < MAX_STATE) {
		TRACE("Container is already in requested state %s", lxc_state2str(state));
		close(cmd.rsp.ret);
		return state;
	}

	*state_client_fd = cmd.rsp.ret;
	TRACE("Added state client %d to state client list", cmd.rsp.ret);
	return MAX_STATE;
}

static int lxc_cmd_add_state_client_callback(int fd, struct lxc_cmd_req *req,
					     struct lxc_handler *handler)
{
	int ret;
	struct lxc_cmd_rsp rsp = {0};

	if (req->datalen < 0)
		goto reap_client_fd;

	if (req->datalen > (sizeof(lxc_state_t) * MAX_STATE))
		goto reap_client_fd;

	if (!req->data)
		goto reap_client_fd;

	rsp.ret = lxc_add_state_client(fd, handler, (lxc_state_t *)req->data);
	if (rsp.ret < 0)
		goto reap_client_fd;

	rsp.data = INT_TO_PTR(rsp.ret);

	ret = lxc_cmd_rsp_send(fd, &rsp);
	if (ret < 0)
		goto reap_client_fd;

	return 0;

reap_client_fd:
	/* Special indicator to lxc_cmd_handler() to close the fd and do related
	 * cleanup.
	 */
	return 1;
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
					struct lxc_handler *handler)
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
	if (ret < 0) {
		ERROR("%s - Failed to execute command", strerror(errno));
		return -1;
	}

	return 0;
}

static int lxc_cmd_serve_state_clients_callback(int fd, struct lxc_cmd_req *req,
						struct lxc_handler *handler)
{
	int ret;
	lxc_state_t state = PTR_TO_INT(req->data);
	struct lxc_cmd_rsp rsp = {0};

	ret = lxc_serve_state_clients(handler->name, handler, state);
	if (ret < 0)
		goto reap_client_fd;

	ret = lxc_cmd_rsp_send(fd, &rsp);
	if (ret < 0)
		goto reap_client_fd;

	return 0;

reap_client_fd:
	/* Special indicator to lxc_cmd_handler() to close the fd and do related
	 * cleanup.
	 */
	return 1;
}

static int lxc_cmd_process(int fd, struct lxc_cmd_req *req,
			   struct lxc_handler *handler)
{
	typedef int (*callback)(int, struct lxc_cmd_req *, struct lxc_handler *);

	callback cb[LXC_CMD_MAX] = {
		[LXC_CMD_CONSOLE]             = lxc_cmd_console_callback,
		[LXC_CMD_TERMINAL_WINCH]      = lxc_cmd_terminal_winch_callback,
		[LXC_CMD_STOP]                = lxc_cmd_stop_callback,
		[LXC_CMD_GET_STATE]           = lxc_cmd_get_state_callback,
		[LXC_CMD_GET_INIT_PID]        = lxc_cmd_get_init_pid_callback,
		[LXC_CMD_GET_CLONE_FLAGS]     = lxc_cmd_get_clone_flags_callback,
		[LXC_CMD_GET_CGROUP]          = lxc_cmd_get_cgroup_callback,
		[LXC_CMD_GET_CONFIG_ITEM]     = lxc_cmd_get_config_item_callback,
		[LXC_CMD_GET_NAME]            = lxc_cmd_get_name_callback,
		[LXC_CMD_GET_LXCPATH]         = lxc_cmd_get_lxcpath_callback,
		[LXC_CMD_ADD_STATE_CLIENT]    = lxc_cmd_add_state_client_callback,
		[LXC_CMD_CONSOLE_LOG]         = lxc_cmd_console_log_callback,
		[LXC_CMD_SERVE_STATE_CLIENTS] = lxc_cmd_serve_state_clients_callback,
	};

	if (req->cmd >= LXC_CMD_MAX) {
		ERROR("Undefined command id %d", req->cmd);
		return -1;
	}
	return cb[req->cmd](fd, req, handler);
}

static void lxc_cmd_fd_cleanup(int fd, struct lxc_handler *handler,
			       struct lxc_epoll_descr *descr,
			       const lxc_cmd_t cmd)
{
	struct lxc_state_client *client;
	struct lxc_list *cur, *next;

	lxc_terminal_free(handler->conf, fd);
	lxc_mainloop_del_handler(descr, fd);
	if (cmd != LXC_CMD_ADD_STATE_CLIENT) {
		close(fd);
		return;
	}

	lxc_list_for_each_safe(cur, &handler->conf->state_clients, next) {
		client = cur->elem;
		if (client->clientfd != fd)
			continue;

		/* kick client from list */
		lxc_list_del(cur);
		close(client->clientfd);
		free(cur->elem);
		free(cur);
		/* No need to walk the whole list. If we found the state client
		 * fd there can't be a second one.
		 */
		break;
	}
}

static int lxc_cmd_handler(int fd, uint32_t events, void *data,
			   struct lxc_epoll_descr *descr)
{
	int ret;
	struct lxc_cmd_req req;
	void *reqdata = NULL;
	struct lxc_handler *handler = data;

	ret = lxc_abstract_unix_rcv_credential(fd, &req, sizeof(req));
	if (ret == -EACCES) {
		/* We don't care for the peer, just send and close. */
		struct lxc_cmd_rsp rsp = {.ret = ret};

		lxc_cmd_rsp_send(fd, &rsp);
		goto out_close;
	}

	if (ret < 0) {
		SYSERROR("Failed to receive data on command socket for command "
			 "\"%s\"", lxc_cmd_str(req.cmd));
		goto out_close;
	}

	if (ret == 0)
		goto out_close;

	if (ret != sizeof(req)) {
		WARN("Failed to receive full command request. Ignoring request "
		     "for \"%s\"", lxc_cmd_str(req.cmd));
		ret = -1;
		goto out_close;
	}

	if ((req.datalen > LXC_CMD_DATA_MAX) &&
	    (req.cmd != LXC_CMD_CONSOLE_LOG)) {
		ERROR("Received command data length %d is too large for "
		      "command \"%s\"", req.datalen, lxc_cmd_str(req.cmd));
		errno = EFBIG;
		ret = -EFBIG;
		goto out_close;
	}

	if (req.datalen > 0) {
		/* LXC_CMD_CONSOLE_LOG needs to be able to allocate data
		 * that exceeds LXC_CMD_DATA_MAX: use malloc() for that.
		 */
		if (req.cmd == LXC_CMD_CONSOLE_LOG)
			reqdata = malloc(req.datalen);
		else
			reqdata = alloca(req.datalen);
		if (!reqdata) {
			ERROR("Failed to allocate memory for \"%s\" command",
			      lxc_cmd_str(req.cmd));
			errno = ENOMEM;
			ret = -ENOMEM;
			goto out_close;
		}

		ret = recv(fd, reqdata, req.datalen, 0);
		if (ret != req.datalen) {
			WARN("Failed to receive full command request. Ignoring "
			     "request for \"%s\"", lxc_cmd_str(req.cmd));
			ret = LXC_MAINLOOP_ERROR;
			goto out_close;
		}

		req.data = reqdata;
	}

	ret = lxc_cmd_process(fd, &req, handler);
	if (ret) {
		/* This is not an error, but only a request to close fd. */
		ret = LXC_MAINLOOP_CONTINUE;
		goto out_close;
	}

out:
	if (req.cmd == LXC_CMD_CONSOLE_LOG && reqdata)
		free(reqdata);

	return ret;

out_close:
	lxc_cmd_fd_cleanup(fd, handler, descr, req.cmd);
	goto out;
}

static int lxc_cmd_accept(int fd, uint32_t events, void *data,
			  struct lxc_epoll_descr *descr)
{
	int connection;
	int opt = 1, ret = -1;

	connection = accept(fd, NULL, 0);
	if (connection < 0) {
		SYSERROR("Failed to accept connection to run command.");
		return LXC_MAINLOOP_ERROR;
	}

	ret = fcntl(connection, F_SETFD, FD_CLOEXEC);
	if (ret < 0) {
		SYSERROR("Failed to set close-on-exec on incoming command connection");
		goto out_close;
	}

	ret = setsockopt(connection, SOL_SOCKET, SO_PASSCRED, &opt, sizeof(opt));
	if (ret < 0) {
		SYSERROR("Failed to enable necessary credentials on command socket");
		goto out_close;
	}

	ret = lxc_mainloop_add_handler(descr, connection, lxc_cmd_handler, data);
	if (ret) {
		ERROR("Failed to add command handler");
		goto out_close;
	}

out:
	return ret;

out_close:
	close(connection);
	goto out;
}

int lxc_cmd_init(const char *name, const char *lxcpath, const char *suffix)
{
	int fd, len, ret;
	char path[sizeof(((struct sockaddr_un *)0)->sun_path)] = {0};
	char *offset = &path[1];

	/* -2 here because this is an abstract unix socket so it needs a
	 * leading \0, and we null terminate, so it needs a trailing \0.
	 * Although null termination isn't required by the API, we do it anyway
	 * because we print the sockname out sometimes.
	 */
	len = sizeof(path) - 2;
	ret = lxc_make_abstract_socket_name(offset, len, name, lxcpath, NULL, suffix);
	if (ret < 0)
		return -1;
	TRACE("Creating abstract unix socket \"%s\"", offset);

	fd = lxc_abstract_unix_open(path, SOCK_STREAM, 0);
	if (fd < 0) {
		ERROR("%s - Failed to create command socket %s",
		      strerror(errno), offset);
		if (errno == EADDRINUSE)
			ERROR("Container \"%s\" appears to be already running", name);
		return -1;
	}

	ret = fcntl(fd, F_SETFD, FD_CLOEXEC);
	if (ret < 0) {
		SYSERROR("Failed to set FD_CLOEXEC on command socket file descriptor");
		close(fd);
		return -1;
	}

	return fd;
}

int lxc_cmd_mainloop_add(const char *name, struct lxc_epoll_descr *descr,
			 struct lxc_handler *handler)
{
	int ret;
	int fd = handler->conf->maincmd_fd;

	ret = lxc_mainloop_add_handler(descr, fd, lxc_cmd_accept, handler);
	if (ret < 0) {
		ERROR("Failed to add handler for command socket");
		close(fd);
	}

	return ret;
}

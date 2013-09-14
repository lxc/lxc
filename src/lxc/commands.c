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

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/poll.h>
#include <sys/param.h>
#include <malloc.h>
#include <stdlib.h>

#include <lxc/log.h>
#include <lxc/lxc.h>
#include <lxc/conf.h>
#include <lxc/start.h>	/* for struct lxc_handler */
#include <lxc/utils.h>
#include <lxc/cgroup.h>

#include "commands.h"
#include "console.h"
#include "confile.h"
#include "mainloop.h"
#include "af_unix.h"
#include "config.h"

/*
 * This file provides the different functions for clients to
 * query/command the server. The client is typically some lxc
 * tool and the server is typically the container (ie. lxc-start).
 *
 * Each command is transactional, the clients send a request to
 * the server and the server answers the request with a message
 * giving the request's status (zero or a negative errno value).
 * Both the request and response may contain addtional data.
 *
 * Each command is wrapped in a ancillary message in order to pass
 * a credential making possible to the server to check if the client
 * is allowed to ask for this command or not.
 *
 * IMPORTANTLY: Note that semantics for current commands are fixed.  If you
 * wish to make any changes to how, say, LXC_CMD_GET_CONFIG_ITEM works by
 * adding information to the end of cmd.data, then you must introduce a new
 * LXC_CMD_GET_CONFIG_ITEM_V2 define with a new number.  You may wish to
 * also mark LXC_CMD_GET_CONFIG_ITEM deprecated in commands.h.
 *
 * This is necessary in order to avoid having a newly compiled lxc command
 * communicating with a running (old) monitor from crashing the running
 * container.
 */

lxc_log_define(lxc_commands, lxc);

static int fill_sock_name(char *path, int len, const char *name,
			  const char *inpath)
{
	const char *lxcpath = NULL;
	int ret;

	if (!inpath) {
		lxcpath = default_lxc_path();
		if (!lxcpath) {
			ERROR("Out of memory getting lxcpath");
			return -1;
		}
	}
	ret = snprintf(path, len, "%s/%s/command", lxcpath ? lxcpath : inpath, name);

	if (ret < 0 || ret >= len) {
		ERROR("Name too long");
		return -1;
	}
	return 0;
}

static const char *lxc_cmd_str(lxc_cmd_t cmd)
{
	static const char *cmdname[LXC_CMD_MAX] = {
		[LXC_CMD_CONSOLE]         = "console",
		[LXC_CMD_STOP]            = "stop",
		[LXC_CMD_GET_STATE]       = "get_state",
		[LXC_CMD_GET_INIT_PID]    = "get_init_pid",
		[LXC_CMD_GET_CLONE_FLAGS] = "get_clone_flags",
		[LXC_CMD_GET_CGROUP]      = "get_cgroup",
		[LXC_CMD_GET_CONFIG_ITEM] = "get_config_item",
	};

	if (cmd < 0 || cmd >= LXC_CMD_MAX)
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
	int ret,rspfd;
	struct lxc_cmd_rsp *rsp = &cmd->rsp;

	ret = lxc_af_unix_recv_fd(sock, &rspfd, rsp, sizeof(*rsp));
	if (ret < 0) {
		ERROR("command %s failed to receive response",
		      lxc_cmd_str(cmd->req.cmd));
		return -1;
	}

	if (cmd->req.cmd == LXC_CMD_CONSOLE) {
		struct lxc_cmd_console_rsp_data *rspdata;

		/* recv() returns 0 bytes when a tty cannot be allocated,
		 * rsp->ret is < 0 when the peer permission check failed
		 */
		if (ret == 0 || rsp->ret < 0)
			return 0;

		rspdata = malloc(sizeof(*rspdata));
		if (!rspdata) {
			ERROR("command %s couldn't allocate response buffer",
			      lxc_cmd_str(cmd->req.cmd));
			return -1;
		}
		rspdata->masterfd = rspfd;
		rspdata->ttynum = PTR_TO_INT(rsp->data);
		rsp->data = rspdata;
	}

	if (rsp->datalen == 0)
		return ret;
	if (rsp->datalen > LXC_CMD_DATA_MAX) {
		ERROR("command %s response data %d too long",
		      lxc_cmd_str(cmd->req.cmd), rsp->datalen);
		errno = EFBIG;
		return -1;
	}

	rsp->data = malloc(rsp->datalen);
	if (!rsp->data) {
		ERROR("command %s unable to allocate response buffer",
		      lxc_cmd_str(cmd->req.cmd));
		return -1;
	}
	ret = recv(sock, rsp->data, rsp->datalen, 0);
	if (ret != rsp->datalen) {
		ERROR("command %s failed to receive response data",
		      lxc_cmd_str(cmd->req.cmd));
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
	int ret;

	ret = send(fd, rsp, sizeof(*rsp), 0);
	if (ret != sizeof(*rsp)) {
		ERROR("failed to send command response %d %s", ret,
		      strerror(errno));
		return -1;
	}

	if (rsp->datalen > 0) {
		ret = send(fd, rsp->data, rsp->datalen, 0);
		if (ret != rsp->datalen) {
			WARN("failed to send command response data %d %s", ret,
			      strerror(errno));
			return -1;
		}
	}
	return 0;
}

/*
 * lxc_cmd: Connect to the specified running container, send it a command
 * request and collect the response
 *
 * @name           : name of container to connect to
 * @cmd            : command with initialized reqest to send
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
		   const char *lxcpath)
{
	int sock, ret = -1;
	char path[sizeof(((struct sockaddr_un *)0)->sun_path)] = { 0 };
	char *offset = &path[1];
	int len;
	int stay_connected = cmd->req.cmd == LXC_CMD_CONSOLE;

	len = sizeof(path)-1;
	if (fill_sock_name(offset, len, name, lxcpath))
		return -1;

	sock = lxc_af_unix_connect(path);
	if (sock < 0) {
		if (errno == ECONNREFUSED)
			*stopped = 1;
		else
			SYSERROR("command %s failed to connect to '@%s'",
				 lxc_cmd_str(cmd->req.cmd), offset);
		return -1;
	}

	ret = lxc_af_unix_send_credential(sock, &cmd->req, sizeof(cmd->req));
	if (ret != sizeof(cmd->req)) {
		SYSERROR("command %s failed to send req to '@%s' %d",
			 lxc_cmd_str(cmd->req.cmd), offset, ret);
		if (ret >=0)
			ret = -1;
		goto out;
	}

	if (cmd->req.datalen > 0) {
		ret = send(sock, cmd->req.data, cmd->req.datalen, 0);
		if (ret != cmd->req.datalen) {
			SYSERROR("command %s failed to send request data to '@%s' %d",
				 lxc_cmd_str(cmd->req.cmd), offset, ret);
			if (ret >=0)
				ret = -1;
			goto out;
		}
	}

	ret = lxc_cmd_rsp_recv(sock, cmd);
out:
	if (!stay_connected || ret <= 0)
		close(sock);
	if (stay_connected && ret > 0)
		cmd->rsp.ret = sock;

	return ret;
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
	int ret, stopped = 0;
	struct lxc_cmd_rr cmd = {
		.req = { .cmd = LXC_CMD_GET_INIT_PID },
	};

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath);
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
	int ret, stopped = 0;
	struct lxc_cmd_rr cmd = {
		.req = { .cmd = LXC_CMD_GET_CLONE_FLAGS },
	};

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath);
	if (ret < 0)
		return ret;

	return PTR_TO_INT(cmd.rsp.data);
}

static int lxc_cmd_get_clone_flags_callback(int fd, struct lxc_cmd_req *req,
					    struct lxc_handler *handler)
{
	struct lxc_cmd_rsp rsp = { .data = INT_TO_PTR(handler->clone_flags) };

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
	int ret, stopped = 0;
	struct lxc_cmd_rr cmd = {
		.req = {
			.cmd = LXC_CMD_GET_CGROUP,
			.datalen = strlen(subsystem)+1,
			.data = subsystem,
		},
	};

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath);
	if (ret < 0)
		return NULL;

	if (!ret) {
		WARN("'%s' has stopped before sending its state", name);
		return NULL;
	}

	if (cmd.rsp.ret < 0 || cmd.rsp.datalen < 0) {
		ERROR("command %s failed for '%s': %s",
		      lxc_cmd_str(cmd.req.cmd), name,
		      strerror(-cmd.rsp.ret));
		return NULL;
	}

	return cmd.rsp.data;
}

static int lxc_cmd_get_cgroup_callback(int fd, struct lxc_cmd_req *req,
				       struct lxc_handler *handler)
{
	struct lxc_cmd_rsp rsp;
	char *path;

	if (req->datalen < 1)
		return -1;
        
	path = lxc_cgroup_get_hierarchy_path_handler(req->data, handler);
	if (!path)
		return -1;
	rsp.datalen = strlen(path) + 1,
	rsp.data = path;
	rsp.ret = 0;

	return lxc_cmd_rsp_send(fd, &rsp);
}

/*
 * lxc_cmd_get_config_item: Get config item the running container
 *
 * @name     : name of container to connect to
 * @item     : the configuration item to retrieve (ex: lxc.network.0.veth.pair)
 * @lxcpath  : the lxcpath in which the container is running
 *
 * Returns the item on success, NULL on failure. The caller must free() the
 * returned item.
 */
char *lxc_cmd_get_config_item(const char *name, const char *item,
			      const char *lxcpath)
{
	int ret, stopped = 0;
	struct lxc_cmd_rr cmd = {
		.req = { .cmd = LXC_CMD_GET_CONFIG_ITEM,
			 .data = item,
			 .datalen = strlen(item)+1,
		       },
	};

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath);
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
	struct lxc_cmd_rsp rsp;
	char *cidata;

	memset(&rsp, 0, sizeof(rsp));
	cilen = lxc_get_config_item(handler->conf, req->data, NULL, 0);
	if (cilen <= 0)
		goto err1;

	cidata = alloca(cilen + 1);
	if (lxc_get_config_item(handler->conf, req->data, cidata, cilen + 1) != cilen)
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
lxc_state_t lxc_cmd_get_state(const char *name, const char *lxcpath)
{
	int ret, stopped = 0;
	struct lxc_cmd_rr cmd = {
		.req = { .cmd = LXC_CMD_GET_STATE }
	};

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath);
	if (ret < 0 && stopped)
		return STOPPED;

	if (ret < 0)
		return -1;

	if (!ret) {
		WARN("'%s' has stopped before sending its state", name);
		return -1;
	}

	DEBUG("'%s' is in '%s' state", name,
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
	int ret, stopped = 0;
	struct lxc_cmd_rr cmd = {
		.req = { .cmd = LXC_CMD_STOP },
	};

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath);
	if (ret < 0) {
		if (stopped) {
			INFO("'%s' is already stopped", name);
			return 0;
		}
		return -1;
	}

	/* we do not expect any answer, because we wait for the connection to be
	 * closed
	 */
	if (ret > 0) {
		ERROR("failed to stop '%s': %s", name, strerror(-cmd.rsp.ret));
		return -1;
	}

	INFO("'%s' has stopped", name);
	return 0;
}

static int lxc_cmd_stop_callback(int fd, struct lxc_cmd_req *req,
				 struct lxc_handler *handler)
{
	struct lxc_cmd_rsp rsp;
	int ret;
	int stopsignal = SIGKILL;

	if (handler->conf->stopsignal)
		stopsignal = handler->conf->stopsignal;
	memset(&rsp, 0, sizeof(rsp));
	rsp.ret = kill(handler->pid, stopsignal);
	if (!rsp.ret) {
		char *path = lxc_cgroup_get_hierarchy_path_handler("freezer", handler);
		if (!path) {
			ERROR("container %s:%s is not in a freezer cgroup",
				handler->lxcpath, handler->name);
			return 0;
		}
		ret = lxc_unfreeze_bypath(path);
		if (!ret)
			return 0;

		ERROR("failed to unfreeze container");
		rsp.ret = ret;
	}

	return lxc_cmd_rsp_send(fd, &rsp);
}

/*
 * lxc_cmd_console_winch: To process as if a SIGWINCH were received
 *
 * @name      : name of container to connect to
 * @lxcpath   : the lxcpath in which the container is running
 *
 * Returns 0 on success, < 0 on failure
 */
int lxc_cmd_console_winch(const char *name, const char *lxcpath)
{
	int ret, stopped = 0;
	struct lxc_cmd_rr cmd = {
		.req = { .cmd = LXC_CMD_CONSOLE_WINCH },
	};

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath);
	if (ret < 0)
		return ret;

	return 0;
}

static int lxc_cmd_console_winch_callback(int fd, struct lxc_cmd_req *req,
					  struct lxc_handler *handler)
{
	struct lxc_cmd_rsp rsp = { .data = 0 };

	lxc_console_sigwinch(SIGWINCH);
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
	int ret, stopped = 0;
	struct lxc_cmd_console_rsp_data *rspdata;
	struct lxc_cmd_rr cmd = {
		.req = { .cmd = LXC_CMD_CONSOLE, .data = INT_TO_PTR(*ttynum) },
	};

	ret = lxc_cmd(name, &cmd, &stopped, lxcpath);
	if (ret < 0)
		return ret;

	if (cmd.rsp.ret < 0) {
		ERROR("console access denied: %s", strerror(-cmd.rsp.ret));
		ret = -1;
		goto out;
	}

	if (ret == 0) {
		ERROR("console %d invalid,busy or all consoles busy", *ttynum);
		ret = -1;
		goto out;
	}

	rspdata = cmd.rsp.data;
	if (rspdata->masterfd < 0) {
		ERROR("unable to allocate fd for tty %d", rspdata->ttynum);
		goto out;
	}

	ret = cmd.rsp.ret;	/* sock fd */
	*fd = rspdata->masterfd;
	*ttynum = rspdata->ttynum;
	INFO("tty %d allocated fd %d sock %d", rspdata->ttynum, *fd, ret);
out:
	free(cmd.rsp.data);
	return ret;
}

static int lxc_cmd_console_callback(int fd, struct lxc_cmd_req *req,
				    struct lxc_handler *handler)
{
	int ttynum = PTR_TO_INT(req->data);
	int masterfd;
	struct lxc_cmd_rsp rsp;

	masterfd = lxc_console_allocate(handler->conf, fd, &ttynum);
	if (masterfd < 0)
		goto out_close;

	memset(&rsp, 0, sizeof(rsp));
	rsp.data = INT_TO_PTR(ttynum);
	if (lxc_af_unix_send_fd(fd, masterfd, &rsp, sizeof(rsp)) < 0) {
		ERROR("failed to send tty to client");
		lxc_console_free(handler->conf, fd);
		goto out_close;
	}

	return 0;

out_close:
	/* special indicator to lxc_cmd_handler() to close the fd and do
	 * related cleanup
	 */
	return 1;
}



static int lxc_cmd_process(int fd, struct lxc_cmd_req *req,
			   struct lxc_handler *handler)
{
	typedef int (*callback)(int, struct lxc_cmd_req *, struct lxc_handler *);

	callback cb[LXC_CMD_MAX] = {
		[LXC_CMD_CONSOLE]         = lxc_cmd_console_callback,
		[LXC_CMD_CONSOLE_WINCH]   = lxc_cmd_console_winch_callback,
		[LXC_CMD_STOP]            = lxc_cmd_stop_callback,
		[LXC_CMD_GET_STATE]       = lxc_cmd_get_state_callback,
		[LXC_CMD_GET_INIT_PID]    = lxc_cmd_get_init_pid_callback,
		[LXC_CMD_GET_CLONE_FLAGS] = lxc_cmd_get_clone_flags_callback,
		[LXC_CMD_GET_CGROUP]      = lxc_cmd_get_cgroup_callback,
		[LXC_CMD_GET_CONFIG_ITEM] = lxc_cmd_get_config_item_callback,
	};

	if (req->cmd < 0 || req->cmd >= LXC_CMD_MAX) {
		ERROR("bad cmd %d recieved", req->cmd);
		return -1;
	}
	return cb[req->cmd](fd, req, handler);
}

static void lxc_cmd_fd_cleanup(int fd, struct lxc_handler *handler,
			       struct lxc_epoll_descr *descr)
{
	lxc_console_free(handler->conf, fd);
	lxc_mainloop_del_handler(descr, fd);
	close(fd);
}

static int lxc_cmd_handler(int fd, void *data, struct lxc_epoll_descr *descr)
{
	int ret;
	struct lxc_cmd_req req;
	struct lxc_handler *handler = data;

	ret = lxc_af_unix_rcv_credential(fd, &req, sizeof(req));
	if (ret == -EACCES) {
		/* we don't care for the peer, just send and close */
		struct lxc_cmd_rsp rsp = { .ret = ret };

		lxc_cmd_rsp_send(fd, &rsp);
		goto out_close;
	}

	if (ret < 0) {
		SYSERROR("failed to receive data on command socket");
		goto out_close;
	}

	if (!ret) {
		DEBUG("peer has disconnected");
		goto out_close;
	}

	if (ret != sizeof(req)) {
		WARN("partial request, ignored");
		ret = -1;
		goto out_close;
	}

	if (req.datalen > LXC_CMD_DATA_MAX) {
		ERROR("cmd data length %d too large", req.datalen);
		ret = -1;
		goto out_close;
	}

	if (req.datalen > 0) {
		void *reqdata;

		reqdata = alloca(req.datalen);
		ret = recv(fd, reqdata, req.datalen, 0);
		if (ret != req.datalen) {
			WARN("partial request, ignored");
			ret = -1;
			goto out_close;
		}
		req.data = reqdata;
	}

	ret = lxc_cmd_process(fd, &req, handler);
	if (ret) {
		/* this is not an error, but only a request to close fd */
		ret = 0;
		goto out_close;
	}

out:
	return ret;
out_close:
	lxc_cmd_fd_cleanup(fd, handler, descr);
	goto out;
}

static int lxc_cmd_accept(int fd, void *data, struct lxc_epoll_descr *descr)
{
	int opt = 1, ret = -1, connection;

	connection = accept(fd, NULL, 0);
	if (connection < 0) {
		SYSERROR("failed to accept connection");
		return -1;
	}

	if (fcntl(connection, F_SETFD, FD_CLOEXEC)) {
		SYSERROR("failed to set close-on-exec on incoming connection");
		goto out_close;
	}

	if (setsockopt(connection, SOL_SOCKET,
		       SO_PASSCRED, &opt, sizeof(opt))) {
		SYSERROR("failed to enable credential on socket");
		goto out_close;
	}

	ret = lxc_mainloop_add_handler(descr, connection, lxc_cmd_handler, data);
	if (ret) {
		ERROR("failed to add handler");
		goto out_close;
	}

out:
	return ret;

out_close:
	close(connection);
	goto out;
}

int lxc_cmd_init(const char *name, struct lxc_handler *handler,
		 const char *lxcpath)
{
	int fd;
	char path[sizeof(((struct sockaddr_un *)0)->sun_path)] = { 0 };
	char *offset = &path[1];
	int len;

	len = sizeof(path)-1;
	if (fill_sock_name(offset, len, name, lxcpath))
		return -1;

	fd = lxc_af_unix_open(path, SOCK_STREAM, 0);
	if (fd < 0) {
		ERROR("failed (%d) to create the command service point %s", errno, offset);
		if (errno == EADDRINUSE) {
			ERROR("##");
			ERROR("# The container appears to be already running!");
			ERROR("##");
		}
		return -1;
	}

	if (fcntl(fd, F_SETFD, FD_CLOEXEC)) {
		SYSERROR("failed to set sigfd to close-on-exec");
		close(fd);
		return -1;
	}

	handler->conf->maincmd_fd = fd;
	return 0;
}

int lxc_cmd_mainloop_add(const char *name,
			 struct lxc_epoll_descr *descr,
			 struct lxc_handler *handler)
{
	int ret, fd = handler->conf->maincmd_fd;

	ret = lxc_mainloop_add_handler(descr, fd, lxc_cmd_accept, handler);
	if (ret) {
		ERROR("failed to add handler for command socket");
		close(fd);
	}

	return ret;
}

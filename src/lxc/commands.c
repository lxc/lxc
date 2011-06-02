/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2009
 *
 * Authors:
 * Daniel Lezcano <dlezcano at fr.ibm.com>
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
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

#include <lxc/log.h>
#include <lxc/conf.h>
#include <lxc/start.h>	/* for struct lxc_handler */

#include "commands.h"
#include "mainloop.h"
#include "af_unix.h"
#include "config.h"

/*
 * This file provides the different functions to have the client
 * and the server to communicate
 *
 * Each command is transactional, the client send a request to
 * the server and the server answer the request with a message
 * giving the request's status (zero or a negative errno value).
 *
 * Each command is wrapped in a ancillary message in order to pass
 * a credential making possible to the server to check if the client
 * is allowed to ask for this command or not.
 *
 */

lxc_log_define(lxc_commands, lxc);

#define abstractname LXCPATH "/%s/command"

static int receive_answer(int sock, struct lxc_answer *answer)
{
	int ret;

	ret = lxc_af_unix_recv_fd(sock, &answer->fd, answer, sizeof(*answer));
	if (ret < 0)
		ERROR("failed to receive answer for the command");

	return ret;
}

static int __lxc_command(const char *name, struct lxc_command *command,
			 int *stopped, int stay_connected)
{
	int sock, ret = -1;
	char path[sizeof(((struct sockaddr_un *)0)->sun_path)] = { 0 };
	char *offset = &path[1];

	sprintf(offset, abstractname, name);

	sock = lxc_af_unix_connect(path);
	if (sock < 0 && errno == ECONNREFUSED) {
		*stopped = 1;
		return -1;
	}

	if (sock < 0) {
		SYSERROR("failed to connect to '@%s'", offset);
		return -1;
	}

	ret = lxc_af_unix_send_credential(sock, &command->request,
					sizeof(command->request));
	if (ret < 0) {
		SYSERROR("failed to send request to '@%s'", offset);
		goto out;
	}

	if (ret != sizeof(command->request)) {
		SYSERROR("message partially sent to '@%s'", offset);
		goto out;
	}

	ret = receive_answer(sock, &command->answer);
out:
	if (!stay_connected || ret < 0)
		close(sock);

	return ret;
}

extern int lxc_command(const char *name,
		       struct lxc_command *command, int *stopped)
{
	return __lxc_command(name, command, stopped, 0);
}

extern int lxc_command_connected(const char *name,
				 struct lxc_command *command, int *stopped)
{
	return __lxc_command(name, command, stopped, 1);
}


pid_t get_init_pid(const char *name)
{
	struct lxc_command command = {
		.request = { .type = LXC_COMMAND_PID },
	};

	int ret, stopped = 0;

	ret = lxc_command(name, &command, &stopped);
	if (ret < 0 && stopped) {
		ERROR("'%s' is not running", name);
		return -1;
	}

	if (ret < 0) {
		ERROR("failed to send command");
		return -1;
	}

	if (command.answer.ret) {
		ERROR("failed to retrieve the init pid: %s",
		      strerror(-command.answer.ret));
		return -1;
	}

	return command.answer.pid;
}

extern void lxc_console_remove_fd(int, struct lxc_tty_info *);
extern int  lxc_console_callback(int, struct lxc_request *, struct lxc_handler *);
extern int  lxc_stop_callback(int, struct lxc_request *, struct lxc_handler *);
extern int  lxc_state_callback(int, struct lxc_request *, struct lxc_handler *);
extern int  lxc_pid_callback(int, struct lxc_request *, struct lxc_handler *);

static int trigger_command(int fd, struct lxc_request *request,
			   struct lxc_handler *handler)
{
	typedef int (*callback)(int, struct lxc_request *, struct lxc_handler *);

	callback cb[LXC_COMMAND_MAX] = {
		[LXC_COMMAND_TTY]   = lxc_console_callback,
		[LXC_COMMAND_STOP]  = lxc_stop_callback,
		[LXC_COMMAND_STATE] = lxc_state_callback,
		[LXC_COMMAND_PID]   = lxc_pid_callback,
	};

	if (request->type < 0 || request->type >= LXC_COMMAND_MAX)
		return -1;

	return cb[request->type](fd, request, handler);
}

static void command_fd_cleanup(int fd, struct lxc_handler *handler,
			       struct lxc_epoll_descr *descr)
{
	lxc_console_remove_fd(fd, &handler->conf->tty_info);
	lxc_mainloop_del_handler(descr, fd);
	close(fd);
}

static int command_handler(int fd, void *data, struct lxc_epoll_descr *descr)
{
	int ret;
	struct lxc_request request;
	struct lxc_handler *handler = data;

	ret = lxc_af_unix_rcv_credential(fd, &request, sizeof(request));
	if (ret == -EACCES) {
		/* we don't care for the peer, just send and close */
		struct lxc_answer answer = { .ret = ret };
		send(fd, &answer, sizeof(answer), 0);
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

	if (ret != sizeof(request)) {
		WARN("partial request, ignored");
		goto out_close;
	}

	ret = trigger_command(fd, &request, handler);
	if (ret) {
		/* this is not an error, but only a request to close fd */
		ret = 0;
		goto out_close;
	}

out:
	return ret;
out_close:
	command_fd_cleanup(fd, handler, descr);
	goto out;
}

static int incoming_command_handler(int fd, void *data,
				    struct lxc_epoll_descr *descr)
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

	ret = lxc_mainloop_add_handler(descr, connection, command_handler, data);
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

extern int lxc_command_mainloop_add(const char *name,
				    struct lxc_epoll_descr *descr,
				    struct lxc_handler *handler)
{
	int ret, fd;
	char path[sizeof(((struct sockaddr_un *)0)->sun_path)] = { 0 };
	char *offset = &path[1];

	sprintf(offset, abstractname, name);

	fd = lxc_af_unix_open(path, SOCK_STREAM, 0);
	if (fd < 0) {
		ERROR("failed to create the command service point");
		return -1;
	}

	if (fcntl(fd, F_SETFD, FD_CLOEXEC)) {
		SYSERROR("failed to set sigfd to close-on-exec");
		close(fd);
		return -1;
	}

	ret = lxc_mainloop_add_handler(descr, fd, incoming_command_handler,
				       handler);
	if (ret) {
		ERROR("failed to add handler for command socket");
		close(fd);
	}

	return ret;
}

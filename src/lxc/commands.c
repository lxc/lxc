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
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/poll.h>
#include <sys/param.h>

#include <lxc/lxc.h>

#include "commands.h"
#include "mainloop.h"
#include "af_unix.h"

lxc_log_define(lxc_commands, lxc);

/*----------------------------------------------------------------------------
 * functions used by processes requesting command to lxc-start
 *--------------------------------------------------------------------------*/
static int receive_answer(int sock, struct lxc_answer *answer)
{
	int ret;

	ret = lxc_af_unix_recv_fd(sock, &answer->fd, answer, sizeof(*answer));
	if (ret < 0)
		ERROR("failed to receive answer for the command");

	return ret;
}

extern int lxc_command(const char *name, struct lxc_command *command)
{
	struct sockaddr_un addr = { 0 };
	int sock, ret = -1;
	char *offset = &addr.sun_path[1];

	snprintf(addr.sun_path, sizeof(addr.sun_path), "@%s", name);
	addr.sun_path[0] = '\0';

	sock = lxc_af_unix_connect(addr.sun_path);
	if (sock < 0) {
		WARN("failed to connect to '@%s': %s", offset, strerror(errno));
		return -1;
	}

	ret = lxc_af_unix_send_credential(sock, &command->request,
					sizeof(command->request));
	if (ret < 0) {
		SYSERROR("failed to send credentials");
		goto out_close;
	}

	if (ret != sizeof(command->request)) {
		SYSERROR("message only partially sent to '@%s'", offset);
		goto out_close;
	}

	ret = receive_answer(sock, &command->answer);
	if (ret < 0)
		goto out_close;
out:
	return ret;
out_close:
	close(sock);
	goto out;
}

/*----------------------------------------------------------------------------
 * functions used by lxc-start process
 *--------------------------------------------------------------------------*/
extern void lxc_console_remove_fd(int fd, struct lxc_tty_info *tty_info);
extern int lxc_console_callback(int fd, struct lxc_request *request,
			struct lxc_handler *handler);
extern int lxc_stop_callback(int fd, struct lxc_request *request,
			struct lxc_handler *handler);

static int trigger_command(int fd, struct lxc_request *request,
			struct lxc_handler *handler)
{
	typedef int (*callback)(int, struct lxc_request *,
				struct lxc_handler *);

	callback cb[LXC_COMMAND_MAX] = {
		[LXC_COMMAND_TTY] = lxc_console_callback,
		[LXC_COMMAND_STOP] = lxc_stop_callback,
	};

	if (request->type < 0 || request->type >= LXC_COMMAND_MAX)
		return -1;

	return cb[request->type](fd, request, handler);
}

static void command_fd_cleanup(int fd, struct lxc_handler *handler,
			struct lxc_epoll_descr *descr)
{
	lxc_console_remove_fd(fd, &handler->tty_info);
	lxc_mainloop_del_handler(descr, fd);
	close(fd);
}

static int command_handler(int fd, void *data,
			      struct lxc_epoll_descr *descr)
{
	int ret;
	struct lxc_request request;
	struct lxc_handler *handler = data;

	ret = lxc_af_unix_rcv_credential(fd, &request, sizeof(request));
	if (ret < 0 && ret == -EACCES) {
		/* we don't care for the peer, just send and close */
		struct lxc_answer answer = { .ret = ret };
		send(fd, &answer, sizeof(answer), 0);
		goto out_close;
	} else if (ret < 0) {
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
	int ret = 1, connection;

	connection = accept(fd, NULL, 0);
	if (connection < 0) {
		SYSERROR("failed to accept connection");
		return -1;
	}

	if (setsockopt(connection, SOL_SOCKET, SO_PASSCRED, &ret, sizeof(ret))) {
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

extern int lxc_command_mainloop_add(const char *name, struct lxc_epoll_descr *descr,
				    struct lxc_handler *handler)
{
	int ret, fd;
	struct sockaddr_un addr = { 0 };
	char *offset = &addr.sun_path[1];

	strcpy(offset, name);
	addr.sun_path[0] = '\0';

	fd = lxc_af_unix_open(addr.sun_path, SOCK_STREAM, 0);
	if (fd < 0) {
		ERROR("failed to create the command service point");
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

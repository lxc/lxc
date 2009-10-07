/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2008
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
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/un.h>

#include "af_unix.h"
#include "error.h"

#include <lxc/log.h>
#include "commands.h"

lxc_log_define(lxc_console, lxc);

static int receive_answer(int sock, struct lxc_answer *answer)
{
	int ret;

	ret = lxc_af_unix_recv_fd(sock, &answer->fd, answer, sizeof(*answer));
	if (ret < 0)
		ERROR("failed to receive answer for the command");

	return ret;
}

static int send_command(const char *name, struct lxc_command *command)
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

extern int lxc_console(const char *name, int ttynum, int *fd)
{
	int ret;
	struct lxc_command command = {
		.request = { .type = LXC_COMMAND_TTY, .data = ttynum },
	};

	ret = send_command(name, &command);
	if (ret < 0) {
		ERROR("failed to send command");
		return -1;
	}

	if (!ret) {
		ERROR("console denied by '%s'", name);
		return -1;
	}

	*fd = command.answer.fd;
	if (*fd <0) {
		ERROR("unable to allocate fd for tty %d", ttynum);
		return -1;
	}

	INFO("tty %d allocated", ttynum);
	return 0;
}

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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>

#include <lxc/log.h>
#include <lxc/start.h>

#include "lxc.h"
#include "commands.h"

lxc_log_define(lxc_stop, lxc);

int lxc_stop(const char *name)
{
	struct lxc_command command = {
		.request = { .type = LXC_COMMAND_STOP },
	};

	int ret, stopped = 0;

	ret = lxc_command(name, &command,&stopped);
	if (ret < 0 && stopped) {
		INFO("'%s' is already stopped", name);
		return 0;
	}

	if (ret < 0) {
		ERROR("failed to send command");
		return -1;
	}

	/* we do not expect any answer, because we wait for the connection to be
	 * closed
	 */
	if (ret > 0) {
		ERROR("failed to stop '%s': %s",
			name, strerror(-command.answer.ret));
		return -1;
	}

	INFO("'%s' has stopped", name);

	return 0;
}

/*----------------------------------------------------------------------------
 * functions used by lxc-start mainloop
 * to handle above command request.
 *--------------------------------------------------------------------------*/
extern int lxc_stop_callback(int fd, struct lxc_request *request,
			struct lxc_handler *handler)
{
	struct lxc_answer answer;
	int ret;

	answer.ret = kill(handler->pid, SIGKILL);
	if (!answer.ret) {
		ret = lxc_unfreeze(handler->name);
		if (!ret)
			return 0;

		ERROR("failed to unfreeze container");
		answer.ret = ret;
	}

	ret = send(fd, &answer, sizeof(answer), 0);
	if (ret < 0) {
		WARN("failed to send answer to the peer");
		goto out;
	}

	if (ret != sizeof(answer)) {
		ERROR("partial answer sent");
		goto out;
	}

out:
	return -1;
}


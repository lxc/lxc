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
#include <fcntl.h>

#include <lxc/lxc.h>
#include <lxc/log.h>
#include "commands.h"

lxc_log_define(lxc_stop, lxc);

#define MAXPIDLEN 20

int __lxc_stop(const char *name)
{
	char init[MAXPATHLEN];
	char val[MAXPIDLEN];
	int fd, ret = -1;
	size_t pid;

	if (lxc_check_lock(name) < 0)
		return ret;

	snprintf(init, MAXPATHLEN, LXCPATH "/%s/init", name);
	fd = open(init, O_RDONLY);
	if (fd < 0) {
		SYSERROR("failed to open init file for %s", name);
		goto out_close;
	}

	if (read(fd, val, sizeof(val)) < 0) {
		SYSERROR("failed to read %s", init);
		goto out_close;
	}

	pid = atoi(val);

	if (kill(pid, SIGKILL)) {
		SYSERROR("failed to kill %zd", pid);
		goto out_close;
	}

	ret = 0;

out_close:
	close(fd);
	return ret;
}

int lxc_stop(const char *name)
{
	struct lxc_command command = {
		.request = { .type = LXC_COMMAND_STOP },
	};

	int ret;

	ret = lxc_command(name, &command);
	if (ret < 0) {
		ERROR("failed to send command");
		return -1;
	}

	/* we do not expect any answer, because we wait for the connection to be
	 * closed
	 */
	if (ret > 0) {
		ERROR("stop request rejected for '%s': %s",
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
	if (!answer.ret)
		return 0;

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


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
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <net/if.h>

#include "error.h"
#include "af_unix.h"

#include <lxc/log.h>
#include <lxc/state.h>
#include <lxc/monitor.h>

lxc_log_define(lxc_monitor, lxc);

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 108
#endif

static void lxc_monitor_send(struct lxc_msg *msg)
{
	int fd;
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	char *offset = &addr.sun_path[1];

	strcpy(offset, "lxc-monitor");

	fd = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (fd < 0)
		return;

	sendto(fd, msg, sizeof(*msg), 0,
	       (const struct sockaddr *)&addr, sizeof(addr));

	close(fd);
}

void lxc_monitor_send_state(const char *name, lxc_state_t state)
{
	struct lxc_msg msg = { .type = lxc_msg_state,
			       .value = state };
	strncpy(msg.name, name, sizeof(msg.name));
	msg.name[sizeof(msg.name) - 1] = 0;

	lxc_monitor_send(&msg);
}

int lxc_monitor_open(void)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	char *offset = &addr.sun_path[1];
	int fd;

	strcpy(offset, "lxc-monitor");

	fd = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (fd < 0) {
		ERROR("socket : %s", strerror(errno));
		return -1;
	}

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr))) {
		ERROR("bind : %s", strerror(errno));
		close(fd);
		return -1;
	}

	return fd;
}

int lxc_monitor_read(int fd, struct lxc_msg *msg)
{
	struct sockaddr_un from;
	socklen_t len = sizeof(from);
	int ret;

	ret = recvfrom(fd, msg, sizeof(*msg), 0,
		       (struct sockaddr *)&from, &len);
	if (ret < 0) {
		SYSERROR("failed to receive state");
		return -1;
	}

	return ret;
}

int lxc_monitor_close(int fd)
{
	return close(fd);
}

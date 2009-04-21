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

lxc_log_define(lxc_console, lxc);

extern int lxc_console(const char *name, int ttynum, int *fd)
{
	struct sockaddr_un addr = { 0 };
	int sock, ret = -LXC_ERROR_TTY_EAGAIN;

	snprintf(addr.sun_path, sizeof(addr.sun_path), "@%s", name);
	addr.sun_path[0] = '\0';

	sock = lxc_af_unix_connect(addr.sun_path);
	if (sock < 0) {
		ERROR("failed to connect to the tty service");
		goto out_err;
	}

	ret = lxc_af_unix_send_credential(sock, &ttynum, sizeof(ttynum));
	if (ret < 0) {
		SYSERROR("failed to send credentials");
		goto out_err;
	}

	ret = lxc_af_unix_recv_fd(sock, fd, NULL, 0);
	if (ret < 0) {
		ERROR("failed to connect to the tty");
		goto out_err;
	}

	if (!ret) {
		ERROR("tty%d denied by '%s'", ttynum, name);
		ret = -LXC_ERROR_TTY_DENIED;
		goto out_err;
	}

	ret = 0;

out_err:
	close(sock);
	return ret;
}

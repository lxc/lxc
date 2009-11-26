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

#include <lxc/log.h>
#include <lxc/conf.h>
#include <lxc/start.h> 	/* for struct lxc_handler */

#include "commands.h"
#include "af_unix.h"

lxc_log_define(lxc_console, lxc);

extern int lxc_console(const char *name, int ttynum, int *fd)
{
	int ret, stopped = 0;
	struct lxc_command command = {
		.request = { .type = LXC_COMMAND_TTY, .data = ttynum },
	};

	ret = lxc_command(name, &command, &stopped);
	if (ret < 0 && stopped) {
		ERROR("'%s' is stopped", name);
		return -1;
	}

	if (ret < 0) {
		ERROR("failed to send command");
		return -1;
	}

	if (!ret) {
		ERROR("console denied by '%s'", name);
		return -1;
	}

	if (command.answer.ret) {
		ERROR("console access denied: %s",
			strerror(-command.answer.ret));
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

/*----------------------------------------------------------------------------
 * functions used by lxc-start mainloop
 * to handle above command request.
 *--------------------------------------------------------------------------*/
extern void lxc_console_remove_fd(int fd, struct lxc_tty_info *tty_info)
{
	int i;

	for (i = 0; i < tty_info->nbtty; i++) {

		if (tty_info->pty_info[i].busy != fd)
			continue;

		tty_info->pty_info[i].busy = 0;
	}

	return;
}

extern int lxc_console_callback(int fd, struct lxc_request *request,
			struct lxc_handler *handler)
{
	int ttynum = request->data;
	struct lxc_tty_info *tty_info = &handler->conf->tty_info;

	if (ttynum > 0) {
		if (ttynum > tty_info->nbtty)
			goto out_close;

		if (tty_info->pty_info[ttynum - 1].busy)
			goto out_close;

		goto out_send;
	}

	/* fixup index tty1 => [0] */
	for (ttynum = 1;
	     ttynum <= tty_info->nbtty && tty_info->pty_info[ttynum - 1].busy;
	     ttynum++);

	/* we didn't find any available slot for tty */
	if (ttynum > tty_info->nbtty)
		goto out_close;

out_send:
	if (lxc_af_unix_send_fd(fd, tty_info->pty_info[ttynum - 1].master,
				&ttynum, sizeof(ttynum)) < 0) {
		ERROR("failed to send tty to client");
		goto out_close;
	}

	tty_info->pty_info[ttynum - 1].busy = fd;

	return 0;

out_close:
	/* the close fd and related cleanup will be done by caller */
	return 1;
}


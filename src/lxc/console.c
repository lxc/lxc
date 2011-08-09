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
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pty.h>
#include <sys/types.h>
#include <sys/un.h>

#include "log.h"
#include "conf.h"
#include "start.h" 	/* for struct lxc_handler */
#include "caps.h"
#include "commands.h"
#include "mainloop.h"
#include "af_unix.h"

lxc_log_define(lxc_console, lxc);

extern int lxc_console(const char *name, int ttynum, int *fd)
{
	int ret, stopped = 0;
	struct lxc_command command = {
		.request = { .type = LXC_COMMAND_TTY, .data = ttynum },
	};

	ret = lxc_command_connected(name, &command, &stopped);
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

static int get_default_console(char **console)
{
	int fd;

	if (!access("/dev/tty", F_OK)) {
		fd = open("/dev/tty", O_RDWR);
		if (fd > 0) {
			close(fd);
			*console = strdup("/dev/tty");
			goto out;
		}
	}

	if (!access("/dev/null", F_OK)) {
		*console = strdup("/dev/null");
		goto out;
	}

	ERROR("No suitable default console");
out:
	return *console ? 0 : -1;
}

int lxc_create_console(struct lxc_conf *conf)
{
	struct termios tios;
	struct lxc_console *console = &conf->console;
	int fd;

	if (!conf->rootfs.path)
		return 0;

	if (!console->path && get_default_console(&console->path)) {
		ERROR("failed to get default console");
		return -1;
	}

	if (!strcmp(console->path, "none"))
		return 0;

	if (openpty(&console->master, &console->slave,
		    console->name, NULL, NULL)) {
		SYSERROR("failed to allocate a pty");
		return -1;
	}

	if (fcntl(console->master, F_SETFD, FD_CLOEXEC)) {
		SYSERROR("failed to set console master to close-on-exec");
		goto err;
	}

	if (fcntl(console->slave, F_SETFD, FD_CLOEXEC)) {
		SYSERROR("failed to set console slave to close-on-exec");
		goto err;
	}

	fd = lxc_unpriv(open(console->path, O_CLOEXEC | O_RDWR | O_CREAT |
			     O_APPEND, 0600));
	if (fd < 0) {
		SYSERROR("failed to open '%s'", console->path);
		goto err;
	}

	DEBUG("using '%s' as console", console->path);

	console->peer = fd;

	if (!isatty(console->peer))
		return 0;

	console->tios = malloc(sizeof(tios));
	if (!console->tios) {
		SYSERROR("failed to allocate memory");
		goto err;
	}

	/* Get termios */
	if (tcgetattr(console->peer, console->tios)) {
		SYSERROR("failed to get current terminal settings");
		goto err_free;
	}

	tios = *console->tios;

	/* Remove the echo characters and signal reception, the echo
	 * will be done below with master proxying */
	tios.c_iflag &= ~IGNBRK;
	tios.c_iflag &= BRKINT;
	tios.c_lflag &= ~(ECHO|ICANON|ISIG);
	tios.c_cc[VMIN] = 1;
	tios.c_cc[VTIME] = 0;

	/* Set new attributes */
	if (tcsetattr(console->peer, TCSAFLUSH, &tios)) {
		ERROR("failed to set new terminal settings");
		goto err_free;
	}

	return 0;

err_free:
	free(console->tios);
err:
	close(console->master);
	close(console->slave);
	return -1;
}

void lxc_delete_console(const struct lxc_console *console)
{
	if (console->tios &&
	    tcsetattr(console->peer, TCSAFLUSH, console->tios))
		WARN("failed to set old terminal settings");
	close(console->master);
	close(console->slave);
}

static int console_handler(int fd, void *data, struct lxc_epoll_descr *descr)
{
	struct lxc_console *console = (struct lxc_console *)data;
	char buf[1024];
	int r;

	r = read(fd, buf, sizeof(buf));
	if (r < 0) {
		SYSERROR("failed to read");
		return 1;
	}

	if (!r) {
		INFO("console client has exited");
		lxc_mainloop_del_handler(descr, fd);
		close(fd);
		return 0;
	}

	/* no output for the console, do nothing */
	if (console->peer == -1)
		return 0;

	if (console->peer == fd)
		r = write(console->master, buf, r);
	else
		r = write(console->peer, buf, r);

	return 0;
}

int lxc_console_mainloop_add(struct lxc_epoll_descr *descr,
			     struct lxc_handler *handler)
{
	struct lxc_conf *conf = handler->conf;
	struct lxc_console *console = &conf->console;

	if (!conf->rootfs.path) {
		INFO("no rootfs, no console.");
		return 0;
	}

	if (!console->path) {
		INFO("no console specified");
		return 0;
	}

	if (console->peer == -1) {
		INFO("no console will be used");
		return 0;
	}

	if (lxc_mainloop_add_handler(descr, console->master,
				     console_handler, console)) {
		ERROR("failed to add to mainloop console handler for '%d'",
		      console->master);
		return -1;
	}

	if (console->peer != -1 &&
	    lxc_mainloop_add_handler(descr, console->peer,
				     console_handler, console))
		WARN("console input disabled");

	return 0;
}

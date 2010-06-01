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

#define _GNU_SOURCE
#include <stdio.h>
#undef _GNU_SOURCE
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>
#include <signal.h>
#include <libgen.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <sys/ioctl.h>

#include "error.h"
#include "lxc.h"
#include "log.h"
#include "mainloop.h"
#include "arguments.h"

lxc_log_define(lxc_console_ui, lxc_console);

static char etoc(const char *expr)
{
	/* returns "control code" of given expression */
	char c = expr[0] == '^' ? expr[1] : expr[0];
	return 1 + ((c > 'Z') ? (c - 'a') : (c - 'Z'));
}

static int my_parser(struct lxc_arguments* args, int c, char* arg)
{
	switch (c) {
	case 't': args->ttynum = atoi(arg); break;
	case 'e': args->escape = etoc(arg); break;
	}
	return 0;
}

static const struct option my_longopts[] = {
	{"tty", required_argument, 0, 't'},
	{"escape", required_argument, 0, 'e'},
	LXC_COMMON_OPTIONS
};

static struct lxc_arguments my_args = {
	.progname = "lxc-console",
	.help     = "\
--name=NAME [--tty NUMBER]\n\
\n\
lxc-console logs on the container with the identifier NAME\n\
\n\
Options :\n\
  -n, --name=NAME      NAME for name of the container\n\
  -t, --tty=NUMBER     console tty number\n\
  -e, --escape=PREFIX  prefix for escape command\n",
	.options  = my_longopts,
	.parser   = my_parser,
	.checker  = NULL,
	.ttynum = -1,
	.escape = 1,
};

static int master = -1;

static void winsz(void)
{
	struct winsize wsz;
	if (ioctl(0, TIOCGWINSZ, &wsz) == 0)
		ioctl(master, TIOCSWINSZ, &wsz);
}

static void sigwinch(int sig)
{
	winsz();
}

static int setup_tios(int fd, struct termios *newtios, struct termios *oldtios)
{
	if (!isatty(fd)) {
		ERROR("'%d' is not a tty", fd);
		return -1;
	}

	/* Get current termios */
	if (tcgetattr(0, oldtios)) {
		SYSERROR("failed to get current terminal settings");
		return -1;
	}

	*newtios = *oldtios;

	/* Remove the echo characters and signal reception, the echo
	 * will be done below with master proxying */
	newtios->c_iflag &= ~IGNBRK;
	newtios->c_iflag &= BRKINT;
	newtios->c_lflag &= ~(ECHO|ICANON|ISIG);
	newtios->c_cc[VMIN] = 1;
	newtios->c_cc[VTIME] = 0;

	/* Set new attributes */
	if (tcsetattr(0, TCSAFLUSH, newtios)) {
		ERROR("failed to set new terminal settings");
		return -1;
	}

	return 0;
}

static int stdin_handler(int fd, void *data, struct lxc_epoll_descr *descr)
{
	static int wait4q = 0;
	int *peer = (int *)data;
	char c;

	if (read(0, &c, 1) < 0) {
		SYSERROR("failed to read");
		return 1;
	}

	/* we want to exit the console with Ctrl+a q */
	if (c == my_args.escape) {
		wait4q = !wait4q;
		return 0;
	}

	if (c == 'q' && wait4q)
		return 1;

	wait4q = 0;
	if (write(*peer, &c, 1) < 0) {
		SYSERROR("failed to write");
		return 1;
	}

	return 0;
}

static int master_handler(int fd, void *data, struct lxc_epoll_descr *descr)
{
	char buf[1024];
	int *peer = (int *)data;
	int r;

	r = read(fd, buf, sizeof(buf));
	if (r < 0) {
		SYSERROR("failed to read");
		return 1;
	}
	r = write(*peer, buf, r);

	return 0;
}

int main(int argc, char *argv[])
{
	int err, std_in = 1;
	struct lxc_epoll_descr descr;
	struct termios newtios, oldtios;

	err = lxc_arguments_parse(&my_args, argc, argv);
	if (err)
		return -1;

	err = lxc_log_init(my_args.log_file, my_args.log_priority,
			   my_args.progname, my_args.quiet);
	if (err)
		return -1;

	err = setup_tios(0, &newtios, &oldtios);
	if (err) {
		ERROR("failed to setup tios");
		return -1;
	}

	err = lxc_console(my_args.name, my_args.ttynum, &master);
	if (err)
		goto out;

	fprintf(stderr, "\nType <Ctrl+%c q> to exit the console\n",
                'a' + my_args.escape - 1);

	err = setsid();
	if (err)
		INFO("already group leader");

	if (signal(SIGWINCH, sigwinch) == SIG_ERR) {
		SYSERROR("failed to set SIGWINCH handler");
		err = -1;
		goto out;
	}

	winsz();

	err = lxc_mainloop_open(&descr);
	if (err) {
		ERROR("failed to create mainloop");
		goto out;
	}

	err = lxc_mainloop_add_handler(&descr, 0, stdin_handler, &master);
	if (err) {
		ERROR("failed to add handler for the stdin");
		goto out_mainloop_open;
	}

	err = lxc_mainloop_add_handler(&descr, master, master_handler, &std_in);
	if (err) {
		ERROR("failed to add handler for the master");
		goto out_mainloop_open;
	}

	err = lxc_mainloop(&descr);
	if (err) {
		ERROR("mainloop returned an error");
		goto out_mainloop_open;
	}

	err =  0;

out_mainloop_open:
	lxc_mainloop_close(&descr);

out:
	/* Restore previous terminal parameter */
	tcsetattr(0, TCSAFLUSH, &oldtios);
	
	/* Return to line it is */
	printf("\n");

	close(master);

	return err;
}

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

#include "error.h"
#include "lxc.h"
#include "arguments.h"

lxc_log_define(lxc_console, lxc);

static int my_parser(struct lxc_arguments* args, int c, char* arg)
{
	switch (c) {
	case 't': args->ttynum = atoi(arg); break;
	}
	return 0;
}

static const struct option my_longopts[] = {
	{"tty", required_argument, 0, 't'},
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
  -n, --name=NAME   NAME for name of the container\n\
  -t, --tty=NUMBER  console tty number\n",
	.options  = my_longopts,
	.parser   = my_parser,
	.checker  = NULL,
	.ttynum = -1,
};

int main(int argc, char *argv[])
{
	int master = -1;
	int wait4q = 0;
	int err;
	struct termios tios, oldtios;

	err = lxc_arguments_parse(&my_args, argc, argv);
	if (err)
		return -1;

	if (lxc_log_init(my_args.log_file, my_args.log_priority,
			 my_args.progname, my_args.quiet))
		return -1;

	/* Get current termios */
	if (tcgetattr(0, &tios)) {
		ERROR("failed to get current terminal settings : %s",
		      strerror(errno));
		return -1;
	}

	oldtios = tios;

	/* Remove the echo characters and signal reception, the echo
	 * will be done below with master proxying */
	tios.c_iflag &= ~IGNBRK;
	tios.c_iflag &= BRKINT;
	tios.c_lflag &= ~(ECHO|ICANON|ISIG);
	tios.c_cc[VMIN] = 1;
	tios.c_cc[VTIME] = 0;

	/* Set new attributes */
	if (tcsetattr(0, TCSAFLUSH, &tios)) {
		ERROR("failed to set new terminal settings : %s",
		      strerror(errno));
		return -1;
	}

	err = lxc_console(my_args.name, my_args.ttynum, &master);
	if (err)
		goto out;

	fprintf(stderr, "\nType <Ctrl+a q> to exit the console\n");

	setsid();

	err = 0;

	/* let's proxy the tty */
	for (;;) {
		char c;
		struct pollfd pfd[2] = {
			{ .fd = 0,
			  .events = POLLIN|POLLPRI,
			  .revents = 0 },
			{ .fd = master,
			  .events = POLLIN|POLLPRI,
			  .revents = 0 },
		};

		if (poll(pfd, 2, -1) < 0) {
			if (errno == EINTR)
				continue;
			SYSERROR("failed to poll");
			goto out_err;
		}
		
		/* read the "stdin" and write that to the master
		 */
		if (pfd[0].revents & POLLIN) {
			if (read(0, &c, 1) < 0) {
				SYSERROR("failed to read");
				goto out_err;
			}

			/* we want to exit the console with Ctrl+a q */
			if (c == 1) {
				wait4q = !wait4q;
				continue;
			}

			if (c == 'q' && wait4q)
				goto out;

			wait4q = 0;
			if (write(master, &c, 1) < 0) {
				SYSERROR("failed to write");
				goto out_err;
			}
		}

		/* other side has closed the connection */
		if (pfd[1].revents & POLLHUP)
			goto out;

		/* read the master and write to "stdout" */
		if (pfd[1].revents & POLLIN) {
			if (read(master, &c, 1) < 0) {
				SYSERROR("failed to read");
				goto out_err;
			}
			printf("%c", c);
			fflush(stdout);
		}
	}
out:
	/* Restore previous terminal parameter */
	tcsetattr(0, TCSAFLUSH, &oldtios);
	
	/* Return to line it is */
	printf("\n");

	close(master);

	return err;

out_err:
	err = -1;
	goto out;
}

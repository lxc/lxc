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
#include <libgen.h>
#include <unistd.h>
#include <string.h>
#include <termios.h>
#include <errno.h>
#include <signal.h>
#include <sys/param.h>
#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>

#include <lxc/lxc.h>
#include <lxc/log.h>
#include "arguments.h"

lxc_log_define(lxc_start, lxc);

static const struct option my_longopts[] = {
	LXC_COMMON_OPTIONS
};

static struct lxc_arguments my_args = {
	.progname = "lxc-start",
	.help     = "\
--name=NAME -- COMMAND\n\
\n\
lxc-start start COMMAND in specified container NAME\n\
\n\
Options :\n\
  -n, --name=NAME      NAME for name of the container",
	.options  = my_longopts,
	.parser   = NULL,
	.checker  = NULL,
};

static int save_tty(struct termios *tios)
{
	if (!isatty(0))
		return 0;

	if (tcgetattr(0, tios))
		WARN("failed to get current terminal settings : %s",
		     strerror(errno));

	return 0;
}

static int restore_tty(struct termios *tios)
{
	struct termios current_tios;
	void (*oldhandler)(int);
	int ret;

	if (!isatty(0))
		return 0;

	if (tcgetattr(0, &current_tios)) {
		ERROR("failed to get current terminal settings : %s",
		      strerror(errno));
		return -1;
	}

	if (!memcmp(tios, &current_tios, sizeof(*tios)))
		return 0;


	oldhandler = signal(SIGTTOU, SIG_IGN);
	ret = tcsetattr(0, TCSADRAIN, tios);
	if (ret)
		ERROR("failed to restore terminal attributes");
	signal(SIGTTOU, oldhandler);

	return ret;
}

int main(int argc, char *argv[])
{
	char *const *args;
	int err = -1;
	struct termios tios;

	char *const default_args[] = {
		"/sbin/init",
		'\0',
	};

	if (lxc_arguments_parse(&my_args, argc, argv))
		return err;

	if (!my_args.argc)
		args = default_args; 
	else
		args = my_args.argv;

	if (lxc_log_init(my_args.log_file, my_args.log_priority,
			 my_args.progname, my_args.quiet))
		return err;

	save_tty(&tios);

	err = lxc_start(my_args.name, args);

	restore_tty(&tios);

	return err;
}


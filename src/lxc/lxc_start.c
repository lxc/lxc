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
#include <sys/param.h>
#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>

#include <lxc/lxc.h>
#include <lxc/log.h>

lxc_log_define(lxc_start, lxc);

void usage(char *cmd)
{
	fprintf(stderr, "%s <command>\n", basename(cmd));
	fprintf(stderr, "\t -n <name>   : name of the container\n");
	_exit(1);
}

int main(int argc, char *argv[])
{
	char *name = NULL;
	char **args;
	int opt, err = LXC_ERROR_INTERNAL, nbargs = 0;
	struct termios tios;

	char *default_args[] = {
		"/sbin/init",
		'\0',
	};

	while ((opt = getopt(argc, argv, "n:")) != -1) {
		switch (opt) {
		case 'n':
			name = optarg;
			break;
		}

		nbargs++;
	}

	if (!argv[optind] || !strlen(argv[optind]))
		args = default_args; 
	else {
		args = &argv[optind];
		argc -= nbargs;
	}

	if (!name)
		usage(argv[0]);

	if (tcgetattr(0, &tios)) {
		ERROR("failed to get current terminal settings");
		fprintf(stderr, "%s\n", lxc_strerror(err));
		return 1;
	}

	err = lxc_start(name, args);
	if (err) {
		fprintf(stderr, "%s\n", lxc_strerror(err));
		err = 1;
	}

	if (tcsetattr(0, TCSAFLUSH, &tios))
		SYSERROR("failed to restore terminal attributes");

	return err;
}


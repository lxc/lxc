/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2010
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
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <fcntl.h>

#include "log.h"
#include "lxc.h"
#include "caps.h"
#include "conf.h"
#include "config.h"
#include "confile.h"
#include "arguments.h"

lxc_log_define(lxc_restart_ui, lxc_restart);

static struct lxc_list defines;

static int my_checker(const struct lxc_arguments* args)
{
	if ((!args->statefile) && (args->statefd == -1)) {
		lxc_error(args, "no statefile specified");
		return -1;
	}

	if ((args->statefile) && (args->statefd != -1)) {
		lxc_error(args, "--statefile AND --statefd abnormally set");
		return -1;
	}

	return 0;
}

static int my_parser(struct lxc_arguments* args, int c, char* arg)
{
	switch (c) {
	case 'S': args->statefile = arg; break;
	case 'f': args->rcfile = arg; break;
	case 'p': args->flags = LXC_FLAG_PAUSE; break;
	case 's': return lxc_config_define_add(&defines, arg);
	case 'd': {
			int fd;
			fd = lxc_arguments_str_to_int(args, arg);
			if (fd < 0)
				return -1;

			args->statefd = fd;
			break;
		}
	}

	return 0;
}

static const struct option my_longopts[] = {
	{"statefile", required_argument, 0, 'S'},
	{"statefd", required_argument, 0, 'd'},
	{"rcfile", required_argument, 0, 'f'},
	{"pause", no_argument, 0, 'p'},
	{"define", required_argument, 0, 's'},
	LXC_COMMON_OPTIONS
};

static struct lxc_arguments my_args = {
	.progname = "lxc-restart",
	.help     = "\
--name=NAME --statefile FILE\n\
\n\
lxc-restart restarts from FILE the NAME container\n\
\n\
Options :\n\
  -n, --name=NAME      NAME for name of the container\n\
  -p, --pause          do not unfreeze the container after the restart\n\
  -S, --statefile=FILE read the container state from this file, or\n\
  -d, --statefd=FD read the container state from this file descriptor\n\
  -f, --rcfile=FILE Load configuration file FILE\n\
  -s, --define KEY=VAL Assign VAL to configuration variable KEY\n",
	.options  = my_longopts,
	.parser   = my_parser,
	.checker  = my_checker,

	.statefd  = -1,
};

int main(int argc, char *argv[])
{
	int sfd = -1;
	int ret;
	char *rcfile = NULL;
	struct lxc_conf *conf;

	lxc_list_init(&defines);

	if (lxc_caps_init())
		return -1;

	if (lxc_arguments_parse(&my_args, argc, argv))
		return -1;

	if (lxc_log_init(my_args.log_file, my_args.log_priority,
			 my_args.progname, my_args.quiet))
		return -1;

	/* rcfile is specified in the cli option */
	if (my_args.rcfile)
		rcfile = (char *)my_args.rcfile;
	else {
		int rc;

		rc = asprintf(&rcfile, LXCPATH "/%s/config", my_args.name);
		if (rc == -1) {
			SYSERROR("failed to allocate memory");
			return -1;
		}

		/* container configuration does not exist */
		if (access(rcfile, F_OK)) {
			free(rcfile);
			rcfile = NULL;
		}
	}

	conf = lxc_conf_init();
	if (!conf) {
		ERROR("failed to initialize configuration");
		return -1;
	}

	if (rcfile && lxc_config_read(rcfile, conf)) {
		ERROR("failed to read configuration file");
		return -1;
	}

	if (lxc_config_define_load(&defines, conf))
		return -1;

	if (my_args.statefd != -1)
		sfd = my_args.statefd;

#define OPEN_READ_MODE O_RDONLY | O_CLOEXEC | O_LARGEFILE
	if (my_args.statefile) {
		sfd = open(my_args.statefile, OPEN_READ_MODE, 0);
		if (sfd < 0) {
			ERROR("'%s' open failure : %m", my_args.statefile);
			return sfd;
		}
	}

	ret = lxc_restart(my_args.name, sfd, conf, my_args.flags);

	if (my_args.statefile)
		close(sfd);
	return ret;
}

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
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#include <lxc/lxc.h>
#include <lxc/log.h>
#include <lxc/utils.h>

#include "arguments.h"
#include "config.h"
#include "caps.h"

lxc_log_define(lxc_checkpoint_ui, lxc_checkpoint);

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
	case 'k': args->flags = LXC_FLAG_HALT; break;
	case 'p': args->flags = LXC_FLAG_PAUSE; break;
	case 'S': args->statefile = arg; break;
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
	{"kill", no_argument, 0, 'k'},
	{"pause", no_argument, 0, 'p'},
	{"statefile", required_argument, 0, 'S'},
	{"statefd", required_argument, 0, 'd'},
	LXC_COMMON_OPTIONS
};

static struct lxc_arguments my_args = {
	.progname = "lxc-checkpoint",
	.help     = "\
--name=NAME --statefile FILE\n\
\n\
lxc-checkpoint checkpoints in FILE the NAME container\n\
\n\
Options :\n\
  -n, --name=NAME      NAME for name of the container\n\
  -k, --kill           stop the container after checkpoint\n\
  -p, --pause          don't unfreeze the container after the checkpoint\n\
  -S, --statefile=FILE write the container state into this file, or\n\
  -d, --statefd=FD write the container state into this file descriptor\n",

	.options  = my_longopts,
	.parser   = my_parser,
	.checker  = my_checker,

	.statefd  = -1,
};

int main(int argc, char *argv[])
{
	int ret;
	int sfd = -1;

	if (lxc_caps_init())
		return -1;

	ret = lxc_arguments_parse(&my_args, argc, argv);
	if (ret)
		return ret;

	ret = lxc_log_init(my_args.log_file, my_args.log_priority,
			   my_args.progname, my_args.quiet);
	if (ret)
		return ret;

	if (my_args.statefd != -1)
		sfd = my_args.statefd;

#define OPEN_WRITE_MODE O_CREAT | O_RDWR | O_EXCL | O_CLOEXEC | O_LARGEFILE
	if (my_args.statefile) {
		sfd = open(my_args.statefile, OPEN_WRITE_MODE, 0600);
		if (sfd < 0) {
			ERROR("'%s' open failure : %m", my_args.statefile);
			return sfd;
		}
	}

	ret = lxc_checkpoint(my_args.name, sfd, my_args.flags);

	assert(ret == 0 || ret == -1);

	if (ret)
		ERROR("failed to checkpoint '%s'", my_args.name);
	else
		INFO("'%s' checkpointed", my_args.name);

	if (my_args.statefile)
		close(sfd);
	return ret;
}

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

#include "../config.h"
#include <stdio.h>
#undef _GNU_SOURCE
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

#include <lxc/log.h>
#include <lxc/start.h>	/* for struct lxc_handler */
#include <lxc/utils.h>
#include <lxc/error.h>

lxc_log_define(lxc_restart, lxc);

struct restart_args {
	int sfd;
	int flags;
};

static int restart(struct lxc_handler *handler, void* data)
{
	struct restart_args *arg __attribute__ ((unused)) = data;

	ERROR("'restart' function not implemented");
	return -1;
}

static int post_restart(struct lxc_handler *handler, void* data)
{
	struct restart_args *arg __attribute__ ((unused)) = data;

	NOTICE("'%s' container restarting with pid '%d'", handler->name,
	       handler->pid);
	return 0;
}

static struct lxc_operations restart_ops = {
	.start = restart,
	.post_start = post_restart
};

int lxc_restart(const char *name, int sfd, struct lxc_conf *conf, int flags)
{
	struct restart_args restart_arg = {
		.sfd = sfd,
		.flags = flags
	};

	if (lxc_check_inherited(sfd))
		return -1;

	return __lxc_start(name, conf, &restart_ops, &restart_arg);
}

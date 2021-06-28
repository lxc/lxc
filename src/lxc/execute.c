/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "conf.h"
#include "config.h"
#include "log.h"
#include "start.h"
#include "process_utils.h"
#include "utils.h"
#include "initutils.h"

lxc_log_define(execute, start);

static int execute_start(struct lxc_handler *handler, void* data)
{
	int argc = 0;
	struct execute_args *my_args = data;

	while (my_args->argv[argc++]);

	lxc_container_init(argc, my_args->argv, my_args->quiet);
}

static int execute_post_start(struct lxc_handler *handler, void* data)
{
	struct execute_args *my_args = data;
	NOTICE("'%s' started with pid '%d'", my_args->argv[0], handler->pid);
	return 0;
}

static struct lxc_operations execute_start_ops = {
	.start = execute_start,
	.post_start = execute_post_start
};

int lxc_execute(const char *name, char *const argv[], int quiet,
		struct lxc_handler *handler, const char *lxcpath,
		bool daemonize, int *error_num)
{
	struct execute_args args = {.argv = argv, .quiet = quiet};

	TRACE("Doing lxc_execute");
	handler->conf->is_execute = true;
	return __lxc_start(handler, &execute_start_ops, &args, lxcpath,
			   daemonize, error_num);
}

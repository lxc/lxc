/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2008
 *
 * Authors:
 * Daniel Lezcano <daniel.lezcano at free.fr>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include "conf.h"
#include "log.h"
#include "start.h"
#include "utils.h"

lxc_log_define(lxc_execute, lxc_start);

static int execute_start(struct lxc_handler *handler, void* data)
{
	int argc_add, j;
	char **argv;
	int argc = 0, i = 0, logfd = -1;
	struct execute_args *my_args = data;
	char logfile[LXC_PROC_PID_FD_LEN];

	while (my_args->argv[argc++]);

	/* lxc-init -n name -- [argc] NULL -> 5 */
	argc_add = 5;
	if (my_args->quiet)
		argc_add++;

	if (!handler->conf->rootfs.path)
		argc_add += 2;

	if (lxc_log_has_valid_level())
		argc_add += 2;

	if (current_config->logfd != -1 || lxc_log_fd != -1)
		argc_add += 2;

	argv = malloc((argc + argc_add) * sizeof(*argv));
	if (!argv) {
		SYSERROR("Allocating init args failed");
		goto out1;
	}

	if (my_args->init_path)
		argv[i++] = my_args->init_path;
	else
		argv[i++] = "lxc-init";

	argv[i++] = "-n";
	argv[i++] = (char *)handler->name;

	if (lxc_log_has_valid_level()) {
		argv[i++] = "-l";
		argv[i++] = (char *)lxc_log_priority_to_string(lxc_log_get_level());
	}

	if (current_config->logfd != -1 || lxc_log_fd != -1) {
		int ret;
		int to_dup = current_config->logfd;

		if (current_config->logfd == -1)
			to_dup = lxc_log_fd;

		logfd = dup(to_dup);
		if (logfd < 0) {
			SYSERROR("Failed to duplicate log file descriptor");
			goto out2;
		}

		ret = snprintf(logfile, sizeof(logfile), "/proc/1/fd/%d", logfd);
		if (ret < 0 || (size_t)ret >= sizeof(logfile))
			goto out3;

		argv[i++] = "-o";
		argv[i++] = logfile;
	}

	if (my_args->quiet)
		argv[i++] = "--quiet";

	if (!handler->conf->rootfs.path) {
		argv[i++] = "-P";
		argv[i++] = (char *)handler->lxcpath;
	}

	argv[i++] = "--";
	for (j = 0; j < argc; j++)
		argv[i++] = my_args->argv[j];
	argv[i++] = NULL;

	NOTICE("Exec'ing \"%s\"", my_args->argv[0]);

	if (my_args->init_fd >= 0)
#ifdef __NR_execveat
		syscall(__NR_execveat, my_args->init_fd, "", argv, environ, AT_EMPTY_PATH);
#else
		ERROR("System seems to be missing execveat syscall number");
#endif
	else
		execvp(argv[0], argv);
	SYSERROR("Failed to exec %s", argv[0]);

out3:
	close(logfd);
out2:
	free(argv);
out1:
	return 1;
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
		bool backgrounded, int *error_num)
{
	struct execute_args args = {.argv = argv, .quiet = quiet};

	TRACE("Doing lxc_execute");
	handler->conf->is_execute = true;
	return __lxc_start(name, handler, &execute_start_ops, &args, lxcpath,
			   backgrounded, error_num);
}

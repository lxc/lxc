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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>

#include "log.h"
#include "start.h"

lxc_log_define(lxc_execute, lxc_start);

struct execute_args {
	char *const *argv;
	int quiet;
};

/* historically lxc-init has been under /usr/lib/lxc.  Now with
 * multi-arch it can be under /usr/lib/$ARCH/lxc.  Serge thinks
 * it makes more sense to put it under /sbin.
 * If /usr/lib/$ARCH/lxc exists and is used, then LXCINITDIR will
 * point to it.
 */
static char *choose_init(void)
{
	char *retv = malloc(PATH_MAX);
	int ret;
	struct stat mystat;
	if (!retv)
		return NULL;

	ret = snprintf(retv, PATH_MAX, LXCINITDIR "/lxc/lxc-init");
	if (ret < 0 || ret >= PATH_MAX) {
		ERROR("pathname too long");
		return NULL;
	}

	ret = stat(retv, &mystat);
	if (ret == 0)
		return retv;

	ret = snprintf(retv, PATH_MAX, "/usr/lib/lxc/lxc-init");
	if (ret < 0 || ret >= PATH_MAX) {
		ERROR("pathname too long");
		return NULL;
	}
	ret = stat(retv, &mystat);
	if (ret == 0)
		return retv;
	ret = snprintf(retv, PATH_MAX, "/sbin/lxc-init");
	if (ret < 0 || ret >= PATH_MAX) {
		ERROR("pathname too long");
		return NULL;
	}
	ret = stat(retv, &mystat);
	if (ret == 0)
		return retv;
	return NULL;
}

static int execute_start(struct lxc_handler *handler, void* data)
{
	int j, i = 0;
	struct execute_args *my_args = data;
	char **argv;
	int argc = 0;
	char *initpath;

	while (my_args->argv[argc++]);

	argv = malloc((argc + my_args->quiet ? 5 : 4) * sizeof(*argv));
	if (!argv)
		return 1;

	initpath = choose_init();
	if (!initpath) {
		ERROR("Failed to find an lxc-init");
		return 1;
	}
	argv[i++] = initpath;
	if (my_args->quiet)
		argv[i++] = "--quiet";
	argv[i++] = "--";
	for (j = 0; j < argc; j++)
		argv[i++] = my_args->argv[j];
	argv[i++] = NULL;

	NOTICE("exec'ing '%s'", my_args->argv[0]);

	execvp(argv[0], argv);
	SYSERROR("failed to exec %s", argv[0]);
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
		struct lxc_conf *conf, const char *lxcpath)
{
	struct execute_args args = {
		.argv = argv,
		.quiet = quiet
	};

	if (lxc_check_inherited(conf, -1))
		return -1;

	return __lxc_start(name, conf, &execute_start_ops, &args, lxcpath);
}

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
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/types.h>

#include <lxc/lxc.h>
#include <lxc/log.h>

#include "commands.h"
#include "arguments.h"

static bool state;
static bool pid;
static char *test_state = NULL;
static char **key = NULL;
static int keys = 0;

static int my_parser(struct lxc_arguments* args, int c, char* arg)
{
	switch (c) {
	case 'c':
		key = realloc(key, keys+1 * sizeof(key[0]));
		key[keys] = arg;
		keys++;
		break;
	case 's': state = true; break;
	case 'p': pid = true; break;
	case 't': test_state = arg; break;
	}
	return 0;
}

static const struct option my_longopts[] = {
	{"config", required_argument, 0, 'c'},
	{"state", no_argument, 0, 's'},
	{"pid", no_argument, 0, 'p'},
	{"state-is", required_argument, 0, 't'},
	LXC_COMMON_OPTIONS,
};

static struct lxc_arguments my_args = {
	.progname = "lxc-info",
	.help     = "\
--name=NAME\n\
\n\
lxc-info display some information about a container with the identifier NAME\n\
\n\
Options :\n\
  -n, --name=NAME       NAME for name of the container\n\
  -c, --config=KEY      show configuration variable KEY from running container\n\
  -p, --pid             shows the process id of the init container\n\
  -s, --state           shows the state of the container\n\
  -t, --state-is=STATE  test if current state is STATE\n\
                        returns success if it matches, false otherwise\n",
	.options  = my_longopts,
	.parser   = my_parser,
	.checker  = NULL,
};

int main(int argc, char *argv[])
{
	int ret,i;

	ret = lxc_arguments_parse(&my_args, argc, argv);
	if (ret)
		return 1;

	if (lxc_log_init(my_args.name, my_args.log_file, my_args.log_priority,
			 my_args.progname, my_args.quiet, my_args.lxcpath[0]))
		return 1;

	if (!state && !pid && keys <= 0)
		state = pid = true;

	if (state || test_state) {
		ret = lxc_getstate(my_args.name, my_args.lxcpath[0]);
		if (ret < 0)
			return 1;
		if (test_state)
			return strcmp(lxc_state2str(ret), test_state) != 0;

		printf("state:%10s\n", lxc_state2str(ret));
	}

	if (pid) {
		pid_t initpid;

		initpid = lxc_cmd_get_init_pid(my_args.name, my_args.lxcpath[0]);
		if (initpid >= 0)
			printf("pid:%10d\n", initpid);
	}

	for(i = 0; i < keys; i++) {
		char *val;

		val = lxc_cmd_get_config_item(my_args.name, key[i], my_args.lxcpath[0]);
		if (val) {
			printf("%s = %s\n", key[i], val);
			free(val);
		} else {
			fprintf(stderr, "%s unset or invalid\n", key[i]);
		}
	}

	return 0;
}

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
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <unistd.h>
#include <regex.h>
#include <sys/types.h>

#include <lxc/lxc.h>
#include <lxc/log.h>
#include <lxc/monitor.h>
#include "arguments.h"

lxc_log_define(lxc_monitor_ui, lxc_monitor);

static const struct option my_longopts[] = {
	LXC_COMMON_OPTIONS
};

static struct lxc_arguments my_args = {
	.progname = "lxc-monitor",
	.help     = "\
--name=NAME\n\
\n\
lxc-monitor monitors the state of the NAME container\n\
\n\
Options :\n\
  -n, --name=NAME   NAME for name of the container\n\
                    NAME may be a regular expression",
	.options  = my_longopts,
	.parser   = NULL,
	.checker  = NULL,
};

int main(int argc, char *argv[])
{
	char *regexp;
	struct lxc_msg msg;
	regex_t preg;
	int fd;

	if (lxc_arguments_parse(&my_args, argc, argv))
		return -1;

	if (lxc_log_init(my_args.log_file, my_args.log_priority,
			 my_args.progname, my_args.quiet))
		return -1;

	regexp = malloc(strlen(my_args.name) + 3);
	if (!regexp) {
		ERROR("failed to allocate memory");
		return -1;
	}
	sprintf(regexp, "^%s$", my_args.name);

	if (regcomp(&preg, regexp, REG_NOSUB|REG_EXTENDED)) {
		ERROR("failed to compile the regex '%s'", my_args.name);
		return -1;
	}

	fd = lxc_monitor_open();
	if (fd < 0)
		return -1;

	for (;;) {
		if (lxc_monitor_read(fd, &msg) < 0)
			return -1;

		if (regexec(&preg, msg.name, 0, NULL, 0))
			continue;

		switch (msg.type) {
		case lxc_msg_state:
			printf("'%s' changed state to [%s]\n", 
			       msg.name, lxc_state2str(msg.value));
			break;
		default:
			/* ignore garbage */
			break;
		}
	}

	regfree(&preg);

	return 0;
}


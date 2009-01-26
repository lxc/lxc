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
#include <string.h>
#include <libgen.h>
#include <unistd.h>
#include <regex.h>
#include <sys/types.h>

#include <lxc/lxc.h>

void usage(char *cmd)
{
	fprintf(stderr, "%s <command>\n", basename(cmd));
	fprintf(stderr, "\t -n <name>   : name of the container or regular expression\n");
	_exit(1);
}

int main(int argc, char *argv[])
{
	char *name = NULL;
	char *regexp;
	struct lxc_msg msg;
	regex_t preg;
	int fd, opt;

	while ((opt = getopt(argc, argv, "n:")) != -1) {
		switch (opt) {
		case 'n':
			name = optarg;
			break;
		}
	}

	if (!name)
		usage(argv[0]);

	regexp = malloc(strlen(name) + 3);
	sprintf(regexp, "^%s$", name);

	if (regcomp(&preg, regexp, REG_NOSUB|REG_EXTENDED)) {
		fprintf(stderr, "failed to compile the regex '%s'\n",
			name);
		return 1;
	}

	fd = lxc_monitor_open();
	if (fd < 0) {
		fprintf(stderr, "failed to open monitor for '%s'\n", name);
		return -1;
	}

	for (;;) {
		if (lxc_monitor_read(fd, &msg) < 0) {
			fprintf(stderr, 
				"failed to read monitor's message for '%s'\n", 
				name);
			return -1;
		}

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


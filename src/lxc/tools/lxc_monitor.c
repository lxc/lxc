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
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <unistd.h>
#include <regex.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <poll.h>

#include "lxc.h"
#include "log.h"
#include "monitor.h"
#include "arguments.h"

lxc_log_define(lxc_monitor_ui, lxc);

static bool quit_monitord;

static int my_parser(struct lxc_arguments* args, int c, char* arg)
{
	switch (c) {
	case 'Q': quit_monitord = true; break;
	}
	return 0;
}

static const struct option my_longopts[] = {
	{"quit", no_argument, 0, 'Q'},
	LXC_COMMON_OPTIONS
};

static struct lxc_arguments my_args = {
	.progname = "lxc-monitor",
	.help     = "\
[--name=NAME]\n\
\n\
lxc-monitor monitors the state of the NAME container\n\
\n\
Options :\n\
  -n, --name=NAME   NAME of the container\n\
                    NAME may be a regular expression\n\
  -Q, --quit        tell lxc-monitord to quit\n",
	.name     = ".*",
	.options  = my_longopts,
	.parser   = my_parser,
	.checker  = NULL,
	.lxcpath_additional = -1,
};

static void close_fds(struct pollfd *fds, nfds_t nfds)
{
	nfds_t i;

	if (nfds < 1)
		return;

	for (i = 0; i < nfds; ++i) {
		close(fds[i].fd);
	}
}

int main(int argc, char *argv[])
{
	char *regexp;
	struct lxc_msg msg;
	regex_t preg;
	struct pollfd *fds;
	nfds_t nfds;
	int len, rc_main, rc_snp, i;

	rc_main = 0;

	if (lxc_arguments_parse(&my_args, argc, argv))
		return 1;

	if (!my_args.log_file)
		my_args.log_file = "none";

	if (lxc_log_init(my_args.name, my_args.log_file, my_args.log_priority,
			 my_args.progname, my_args.quiet, my_args.lxcpath[0]))
		return 1;
	lxc_log_options_no_override();

	if (quit_monitord) {
		int ret = EXIT_SUCCESS;
		for (i = 0; i < my_args.lxcpath_cnt; i++) {
			int fd;

			fd = lxc_monitor_open(my_args.lxcpath[i]);
			if (fd < 0) {
				ERROR("Unable to open monitor on path: %s", my_args.lxcpath[i]);
				ret = EXIT_FAILURE;
				continue;
			}
			if (write(fd, "quit", 4) < 0) {
				SYSERROR("Unable to close monitor on path: %s", my_args.lxcpath[i]);
				ret = EXIT_FAILURE;
				close(fd);
				continue;
			}
			close(fd);
		}
		return ret;
	}

	len = strlen(my_args.name) + 3;
	regexp = malloc(len + 3);
	if (!regexp) {
		ERROR("failed to allocate memory");
		return 1;
	}
	rc_snp = snprintf(regexp, len, "^%s$", my_args.name);
	if (rc_snp < 0 || rc_snp >= len) {
		ERROR("Name too long");
		rc_main = 1;
		goto error;
	}

	if (regcomp(&preg, regexp, REG_NOSUB|REG_EXTENDED)) {
		ERROR("failed to compile the regex '%s'", my_args.name);
		rc_main = 1;
		goto error;
	}

	fds = malloc(my_args.lxcpath_cnt * sizeof(struct pollfd));
	if (!fds) {
		SYSERROR("out of memory");
		rc_main = -1;
		goto cleanup;
	}

	nfds = my_args.lxcpath_cnt;
	for (i = 0; i < nfds; i++) {
		int fd;

		lxc_monitord_spawn(my_args.lxcpath[i]);

		fd = lxc_monitor_open(my_args.lxcpath[i]);
		if (fd < 0) {
			close_fds(fds, i);
			rc_main = 1;
			goto cleanup;
		}
		fds[i].fd = fd;
		fds[i].events = POLLIN;
		fds[i].revents = 0;
	}

	setlinebuf(stdout);

	for (;;) {
		if (lxc_monitor_read_fdset(fds, nfds, &msg, -1) < 0) {
			rc_main = 1;
			goto close_and_clean;
		}

		msg.name[sizeof(msg.name)-1] = '\0';
		if (regexec(&preg, msg.name, 0, NULL, 0))
			continue;

		switch (msg.type) {
		case lxc_msg_state:
			printf("'%s' changed state to [%s]\n",
			       msg.name, lxc_state2str(msg.value));
			break;
		case lxc_msg_exit_code:
			printf("'%s' exited with status [%d]\n",
			       msg.name, WEXITSTATUS(msg.value));
			break;
		default:
			/* ignore garbage */
			break;
		}
	}

close_and_clean:
	close_fds(fds, nfds);

cleanup:
	regfree(&preg);
	free(fds);

error:
	free(regexp);

	return rc_main;
}

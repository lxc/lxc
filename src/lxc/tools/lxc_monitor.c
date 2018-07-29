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
#define __STDC_FORMAT_MACROS
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libgen.h>
#include <poll.h>
#include <regex.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <lxc/lxccontainer.h>

#include "af_unix.h"
#include "arguments.h"
#include "log.h"
#include "monitor.h"
#include "state.h"
#include "utils.h"

#define LXC_MONITORD_PATH LIBEXECDIR "/lxc/lxc-monitord"

static bool quit_monitord;

lxc_log_define(lxc_monitor, lxc);

static int my_parser(struct lxc_arguments *args, int c, char *arg)
{
	switch (c) {
	case 'Q':
		quit_monitord = true;
		break;
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

	for (i = 0; i < nfds; ++i)
		close(fds[i].fd);
}

static int lxc_tool_check_inherited(bool closeall, int *fds_to_ignore, size_t len_fds)
{
	struct dirent *direntp;
	int fd, fddir;
	size_t i;
	DIR *dir;

restart:
	dir = opendir("/proc/self/fd");
	if (!dir) {
		SYSERROR("Failed to open directory");
		return -1;
	}

	fddir = dirfd(dir);

	while ((direntp = readdir(dir))) {
		if (!strcmp(direntp->d_name, "."))
			continue;

		if (!strcmp(direntp->d_name, ".."))
			continue;

		if (lxc_safe_int(direntp->d_name, &fd) < 0)
			continue;

		for (i = 0; i < len_fds; i++)
			if (fds_to_ignore[i] == fd)
				break;

		if (fd == fddir || (i < len_fds && fd == fds_to_ignore[i]))
			continue;

		if (fd == 0 || fd == 1 || fd == 2)
			continue;

		if (closeall) {
			close(fd);
			closedir(dir);
			goto restart;
		}
	}

	closedir(dir);
	return 0;
}

/* Used to spawn a monitord either on startup of a daemon container, or when
 * lxc-monitor starts.
 */
static int lxc_tool_monitord_spawn(const char *lxcpath)
{
	int ret;
	int pipefd[2];
	char pipefd_str[LXC_NUMSTRLEN64];
	pid_t pid1, pid2;

	char *const args[] = {
		LXC_MONITORD_PATH,
		(char *)lxcpath,
		pipefd_str,
		NULL,
	};

	/* double fork to avoid zombies when monitord exits */
	pid1 = fork();
	if (pid1 < 0) {
		SYSERROR("Failed to fork()");
		return -1;
	}

	if (pid1) {
		if (waitpid(pid1, NULL, 0) != pid1)
			return -1;

		return 0;
	}

	if (pipe(pipefd) < 0) {
		SYSERROR("Failed to create pipe");
		_exit(EXIT_FAILURE);
	}

	pid2 = fork();
	if (pid2 < 0) {
		SYSERROR("Failed to fork()");
		_exit(EXIT_FAILURE);
	}

	if (pid2) {
		char c;

		/* Wait for daemon to create socket. */
		close(pipefd[1]);

		/* Sync with child, we're ignoring the return from read
		 * because regardless if it works or not, either way we've
		 * synced with the child process. the if-empty-statement
		 * construct is to quiet the warn-unused-result warning.
		 */
		if (lxc_read_nointr(pipefd[0], &c, 1))
			;

		close(pipefd[0]);

		_exit(EXIT_SUCCESS);
	}

	if (setsid() < 0) {
		SYSERROR("Failed to setsid()");
		_exit(EXIT_FAILURE);
	}

	lxc_tool_check_inherited(true, &pipefd[1], 1);
	if (null_stdfds() < 0) {
		ERROR("Failed to dup2() standard file descriptors to /dev/null");
		_exit(EXIT_FAILURE);
	}

	close(pipefd[0]);

	ret = snprintf(pipefd_str, LXC_NUMSTRLEN64, "%d", pipefd[1]);
	if (ret < 0 || ret >= LXC_NUMSTRLEN64) {
		ERROR("Failed to create pid argument to pass to monitord");
		_exit(EXIT_FAILURE);
	}

	execvp(args[0], args);
	SYSERROR("Failed to exec lxc-monitord");

	_exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	char *regexp;
	struct lxc_msg msg;
	regex_t preg;
	struct pollfd *fds;
	nfds_t nfds;
	int len, rc_main, rc_snp, i;
	struct lxc_log log;

	rc_main = EXIT_FAILURE;

	if (lxc_arguments_parse(&my_args, argc, argv))
		exit(rc_main);

	/* Only create log if explicitly instructed */
	if (my_args.log_file || my_args.log_priority) {
		log.name = my_args.name;
		log.file = my_args.log_file;
		log.level = my_args.log_priority;
		log.prefix = my_args.progname;
		log.quiet = my_args.quiet;
		log.lxcpath = my_args.lxcpath[0];

		if (lxc_log_init(&log))
			exit(rc_main);
	}

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

			if (lxc_write_nointr(fd, "quit", 4) < 0) {
				SYSERROR("Unable to close monitor on path: %s", my_args.lxcpath[i]);
				ret = EXIT_FAILURE;
				close(fd);
				continue;
			}

			close(fd);
		}

		exit(ret);
	}

	len = strlen(my_args.name) + 3;
	regexp = malloc(len + 3);
	if (!regexp) {
		ERROR("Failed to allocate memory");
		exit(rc_main);
	}

	rc_snp = snprintf(regexp, len, "^%s$", my_args.name);
	if (rc_snp < 0 || rc_snp >= len) {
		ERROR("Name too long");
		goto error;
	}

	if (regcomp(&preg, regexp, REG_NOSUB|REG_EXTENDED)) {
		ERROR("Failed to compile the regex '%s'", my_args.name);
		goto error;
	}

	fds = malloc(my_args.lxcpath_cnt * sizeof(struct pollfd));
	if (!fds) {
		ERROR("Out of memory");
		goto cleanup;
	}

	nfds = my_args.lxcpath_cnt;

	for (i = 0; (unsigned long)i < nfds; i++) {
		int fd;

		lxc_tool_monitord_spawn(my_args.lxcpath[i]);

		fd = lxc_monitor_open(my_args.lxcpath[i]);
		if (fd < 0) {
			close_fds(fds, i);
			goto cleanup;
		}

		fds[i].fd = fd;
		fds[i].events = POLLIN;
		fds[i].revents = 0;
	}

	setlinebuf(stdout);

	for (;;) {
		if (lxc_monitor_read_fdset(fds, nfds, &msg, -1) < 0)
			goto close_and_clean;

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

	rc_main = 0;

close_and_clean:
	close_fds(fds, nfds);

cleanup:
	regfree(&preg);
	free(fds);

error:
	free(regexp);

	exit(rc_main);
}

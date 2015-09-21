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
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <libgen.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#define _GNU_SOURCE
#include <getopt.h>

#include "log.h"
#include "caps.h"
#include "error.h"
#include "initutils.h"

lxc_log_define(lxc_init, lxc);

static int quiet;

static const struct option options[] = {
	{ "name",        required_argument, NULL, 'n' },
	{ "logpriority", required_argument, NULL, 'l' },
	{ "quiet",       no_argument,       NULL, 'q' },
	{ "lxcpath",     required_argument, NULL, 'P' },
	{ 0, 0, 0, 0 },
};

static sig_atomic_t was_interrupted = 0;

static void interrupt_handler(int sig)
{
	if (!was_interrupted)
		was_interrupted = sig;
}

static void usage(void) {
	fprintf(stderr, "Usage: lxc-init [OPTION]...\n\n"
		"Common options :\n"
		"  -n, --name=NAME          NAME of the container\n"
		"  -l, --logpriority=LEVEL  Set log priority to LEVEL\n"
		"  -q, --quiet              Don't produce any output\n"
		"  -P, --lxcpath=PATH       Use specified container path\n"
		"  -?, --help               Give this help list\n"
		"\n"
		"Mandatory or optional arguments to long options are also mandatory or optional\n"
		"for any corresponding short options.\n"
		"\n"
		"NOTE: lxc-init is intended for use by lxc internally\n"
		"      and does not need to be run by hand\n\n");
}

int main(int argc, char *argv[])
{
	pid_t pid;
	int err;
	char **aargv;
	sigset_t mask, omask;
	int i, have_status = 0, shutdown = 0;
	int opt;
	char *lxcpath = NULL, *name = NULL, *logpriority = NULL;

	while ((opt = getopt_long(argc, argv, "n:l:qP:", options, NULL)) != -1) {
		switch(opt) {
		case 'n':
			name = optarg;
			break;
		case 'l':
			logpriority = optarg;
			break;
		case 'q':
			quiet = 1;
 			break;
		case 'P':
			lxcpath = optarg;
			break;
		default: /* '?' */
			usage();
			exit(EXIT_FAILURE);
		}
	}

	err = lxc_log_init(name, name ? NULL : "none", logpriority,
			   basename(argv[0]), quiet, lxcpath);
	if (err < 0)
		exit(EXIT_FAILURE);
	lxc_log_options_no_override();

	if (!argv[optind]) {
		ERROR("missing command to launch");
		exit(EXIT_FAILURE);
	}

	aargv = &argv[optind];

	/*
	 * mask all the signals so we are safe to install a
	 * signal handler and to fork
	 */
	if (sigfillset(&mask) ||
	    sigdelset(&mask, SIGILL) ||
	    sigdelset(&mask, SIGSEGV) ||
	    sigdelset(&mask, SIGBUS) ||
	    sigprocmask(SIG_SETMASK, &mask, &omask)) {
		SYSERROR("failed to set signal mask");
		exit(EXIT_FAILURE);
	}

	for (i = 1; i < NSIG; i++) {
		struct sigaction act;

		/* Exclude some signals: ILL, SEGV and BUS are likely to
		 * reveal a bug and we want a core. STOP and KILL cannot be
		 * handled anyway: they're here for documentation.
		 */
		if (i == SIGILL ||
		    i == SIGSEGV ||
		    i == SIGBUS ||
		    i == SIGSTOP ||
		    i == SIGKILL ||
		    i == 32 || i == 33)
			continue;

		if (sigfillset(&act.sa_mask) ||
		    sigdelset(&act.sa_mask, SIGILL) ||
		    sigdelset(&act.sa_mask, SIGSEGV) ||
		    sigdelset(&act.sa_mask, SIGBUS) ||
		    sigdelset(&act.sa_mask, SIGSTOP) ||
		    sigdelset(&act.sa_mask, SIGKILL)) {
			ERROR("failed to set signal");
			exit(EXIT_FAILURE);
		}

		act.sa_flags = 0;
		act.sa_handler = interrupt_handler;
		if (sigaction(i, &act, NULL) && errno != EINVAL) {
			SYSERROR("failed to sigaction");
			exit(EXIT_FAILURE);
		}
	}

	lxc_setup_fs();

	pid = fork();

	if (pid < 0)
		exit(EXIT_FAILURE);

	if (!pid) {

		/* restore default signal handlers */
		for (i = 1; i < NSIG; i++)
			signal(i, SIG_DFL);

		if (sigprocmask(SIG_SETMASK, &omask, NULL)) {
			SYSERROR("failed to set signal mask");
			exit(EXIT_FAILURE);
		}

		NOTICE("about to exec '%s'", aargv[0]);

		execvp(aargv[0], aargv);
		ERROR("failed to exec: '%s' : %m", aargv[0]);
		exit(err);
	}

	/* let's process the signals now */
	if (sigdelset(&omask, SIGALRM) ||
	    sigprocmask(SIG_SETMASK, &omask, NULL)) {
		SYSERROR("failed to set signal mask");
		exit(EXIT_FAILURE);
	}

	/* no need of other inherited fds but stderr */
	close(fileno(stdin));
	close(fileno(stdout));

	err = EXIT_SUCCESS;
	for (;;) {
		int status;
		pid_t waited_pid;

		switch (was_interrupted) {

		case 0:
			break;

		case SIGPWR:
		case SIGTERM:
			if (!shutdown) {
				shutdown = 1;
				kill(-1, SIGTERM);
				alarm(1);
			}
			break;

		case SIGALRM:
			kill(-1, SIGKILL);
			break;

		default:
			kill(pid, was_interrupted);
			break;
		}

		was_interrupted = 0;
		waited_pid = wait(&status);
		if (waited_pid < 0) {
			if (errno == ECHILD)
				goto out;
			if (errno == EINTR)
				continue;

			ERROR("failed to wait child : %s",
			      strerror(errno));
			goto out;
		}

		/* reset timer each time a process exited */
		if (shutdown)
			alarm(1);

		/*
		 * keep the exit code of started application
		 * (not wrapped pid) and continue to wait for
		 * the end of the orphan group.
		 */
		if (waited_pid == pid && !have_status) {
			err = lxc_error_set_and_log(waited_pid, status);
			have_status = 1;
		}
	}
out:
	if (err < 0)
		exit(EXIT_FAILURE);
	exit(err);
}

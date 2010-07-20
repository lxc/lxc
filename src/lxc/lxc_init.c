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
#include "utils.h"

lxc_log_define(lxc_init, lxc);

static int quiet;

static struct option options[] = {
	{ "quiet", no_argument, &quiet, 1 },
	{ 0, 0, 0, 0 },
};

static	int was_interrupted = 0;

int main(int argc, char *argv[])
{

	void interrupt_handler(int sig)
	{
		if (!was_interrupted)
			was_interrupted = sig;
	}

	pid_t pid;
	int nbargs = 0;
	int err = -1;
	char **aargv;
	sigset_t mask, omask;
	int i, shutdown = 0;

	while (1) {
		int ret = getopt_long_only(argc, argv, "", options, NULL);
		if (ret == -1) {
			break;
		}
		if  (ret == '?')
			exit(err);

		nbargs++;
	}

	if (lxc_caps_init())
		exit(err);

	if (lxc_log_init(NULL, 0, basename(argv[0]), quiet))
		exit(err);

	if (!argv[optind]) {
		ERROR("missing command to launch");
		exit(err);
	}

	aargv = &argv[optind];
	argc -= nbargs;

        /*
	 * mask all the signals so we are safe to install a
	 * signal handler and to fork
	 */
	sigfillset(&mask);
	sigprocmask(SIG_SETMASK, &mask, &omask);

	for (i = 1; i < NSIG; i++) {
		struct sigaction act;

		sigfillset(&act.sa_mask);
		sigdelset(&mask, SIGILL);
		sigdelset(&mask, SIGSEGV);
		sigdelset(&mask, SIGBUS);
		act.sa_flags = 0;
		act.sa_handler = interrupt_handler;
		sigaction(i, &act, NULL);
	}

	if (lxc_setup_fs())
		exit(err);

	if (lxc_caps_reset())
		exit(err);

	pid = fork();

	if (pid < 0)
		exit(err);

	if (!pid) {

		/* restore default signal handlers */
		for (i = 1; i < NSIG; i++)
			signal(i, SIG_DFL);

		sigprocmask(SIG_SETMASK, &omask, NULL);

		NOTICE("about to exec '%s'", aargv[0]);

		execvp(aargv[0], aargv);
		ERROR("failed to exec: '%s' : %m", aargv[0]);
		exit(err);
	}

	/* let's process the signals now */
	sigdelset(&omask, SIGALRM);
	sigprocmask(SIG_SETMASK, &omask, NULL);

	/* no need of other inherited fds but stderr */
	close(fileno(stdin));
	close(fileno(stdout));

	err = 0;
	for (;;) {
		int status;
		int orphan = 0;
		pid_t waited_pid;

		switch (was_interrupted) {

		case 0:
			break;

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
		if ((waited_pid != pid) || (orphan ==1))
			continue;
		orphan = 1;
		err = lxc_error_set_and_log(waited_pid, status);
	}
out:
	return err;
}

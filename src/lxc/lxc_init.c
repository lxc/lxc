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
#include <sys/capability.h>
#define _GNU_SOURCE
#include <getopt.h>

#include <lxc/log.h>
#include <lxc/error.h>
#include "utils.h"

lxc_log_define(lxc_init, lxc);

static int quiet;

static struct option options[] = {
	{ "quiet", no_argument, &quiet, 1 },
	{ 0, 0, 0, 0 },
};

static	int was_interrupted = 0;

static int cap_reset(void)
{
	cap_t cap = cap_init();
	int ret = 0;

	if (!cap) {
		ERROR("cap_init() failed : %m");
		return -1;
	}

	if (cap_set_proc(cap)) {
		ERROR("cap_set_proc() failed : %m");
		ret = -1;
	}

	cap_free(cap);
	return ret;
}

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
	int i;

	while (1) {
		int ret = getopt_long_only(argc, argv, "", options, NULL);
		if (ret == -1) {
			break;
		}
		if  (ret == '?')
			exit(err);

		nbargs++;
	}

	if (lxc_log_init(NULL, 0, basename(argv[0]), quiet))
		exit(err);

	if (!argv[optind]) {
		ERROR("missing command to launch");
		exit(err);
	}

	aargv = &argv[optind];
	argc -= nbargs;

	sigfillset(&mask);
	sigprocmask(SIG_SETMASK, &mask, &omask);

	for (i = 1; i < NSIG; i++) {
		struct sigaction act;

		sigfillset(&act.sa_mask);
		act.sa_flags = 0;
		act.sa_handler = interrupt_handler;
		sigaction(i, &act, NULL);
	}

	if (lxc_setup_fs())
		exit(err);

	if (cap_reset())
		exit(err);

	pid = fork();

	if (pid < 0)
		exit(err);

	if (!pid) {

		for (i = 1; i < NSIG; i++)
			signal(i, SIG_DFL);
		sigprocmask(SIG_SETMASK, &omask, NULL);

		NOTICE("about to exec '%s'", aargv[0]);

		execvp(aargv[0], aargv);
		ERROR("failed to exec: '%s' : %m", aargv[0]);
		exit(err);
	}

	sigprocmask(SIG_SETMASK, &omask, NULL);

	/* no need of other inherited fds but stderr */
	close(fileno(stdin));
	close(fileno(stdout));

	err = 0;
	for (;;) {
		int status;
		int orphan = 0;
		pid_t waited_pid;

		if (was_interrupted) {
			kill(pid, was_interrupted);
			was_interrupted = 0;
		}

		waited_pid = wait(&status);
		if (waited_pid < 0) {
			if (errno == ECHILD)
				goto out;
			if (errno == EINTR)
				continue;
			ERROR("failed to wait child : %s", strerror(errno));
			goto out;
		}

		/*
		 * keep the exit code of started application (not wrapped pid)
		 * and continue to wait for the end of the orphan group.
		 */
		if ((waited_pid != pid) || (orphan ==1))
			continue;
		orphan = 1;
		err = lxc_error_set_and_log(waited_pid, status);
	}
out:
	return err;
}

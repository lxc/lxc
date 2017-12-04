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
#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <lxc/lxccontainer.h>

#include "tools/arguments.h"
#include "error.h"
#include "initutils.h"
#include "log.h"

lxc_log_define(lxc_init, lxc);

static sig_atomic_t was_interrupted = 0;

static void interrupt_handler(int sig)
{
	if (!was_interrupted)
		was_interrupted = sig;
}

static const struct option my_longopts[] = {
	LXC_COMMON_OPTIONS
};

static int my_parser(struct lxc_arguments *args, int c, char *arg)
{
	return 0;
}

static struct lxc_arguments my_args = {
	.progname = "lxc-init",
	.help     = "\
--name=NAME -- COMMAND\n\
\n\
lxc-init start a COMMAND as PID 2 inside a container\n\
\n\
Options :\n\
  -n, --name=NAME        NAME of the container\n\
",
	.options   = my_longopts,
	.parser    = my_parser,
};

int main(int argc, char *argv[])
{
	int i, ret;
	pid_t pid, sid;
	struct sigaction act;
	struct lxc_log log;
	sigset_t mask, omask;
	int have_status = 0, shutdown = 0;

	if (lxc_arguments_parse(&my_args, argc, argv))
		exit(EXIT_FAILURE);

	log.name = my_args.name;
	log.file = my_args.log_file;
	log.level = my_args.log_priority;
	log.prefix = my_args.progname;
	log.quiet = my_args.quiet;
	log.lxcpath = my_args.lxcpath[0];

	ret = lxc_log_init(&log);
	if (ret < 0)
		exit(EXIT_FAILURE);
	lxc_log_options_no_override();

	if (!my_args.argc) {
		ERROR("Please specify a command to execute");
		exit(EXIT_FAILURE);
	}

	/* Mask all the signals so we are safe to install a signal handler and
	 * to fork.
	 */
	ret = sigfillset(&mask);
	if (ret < 0)
		exit(EXIT_FAILURE);

	ret = sigdelset(&mask, SIGILL);
	if (ret < 0)
		exit(EXIT_FAILURE);

	ret = sigdelset(&mask, SIGSEGV);
	if (ret < 0)
		exit(EXIT_FAILURE);

	ret = sigdelset(&mask, SIGBUS);
	if (ret < 0)
		exit(EXIT_FAILURE);

	ret = sigprocmask(SIG_SETMASK, &mask, &omask);
	if (ret < 0)
		exit(EXIT_FAILURE);

	ret = sigfillset(&act.sa_mask);
	if (ret < 0)
		exit(EXIT_FAILURE);

	ret = sigdelset(&act.sa_mask, SIGILL);
	if (ret < 0)
		exit(EXIT_FAILURE);

	ret = sigdelset(&act.sa_mask, SIGSEGV);
	if (ret < 0)
		exit(EXIT_FAILURE);

	ret = sigdelset(&act.sa_mask, SIGBUS);
	if (ret < 0)
		exit(EXIT_FAILURE);

	ret = sigdelset(&act.sa_mask, SIGSTOP);
	if (ret < 0)
		exit(EXIT_FAILURE);

	ret = sigdelset(&act.sa_mask, SIGKILL);
	if (ret < 0)
		exit(EXIT_FAILURE);

	act.sa_flags = 0;
	act.sa_handler = interrupt_handler;

	for (i = 1; i < NSIG; i++) {
		/* Exclude some signals: ILL, SEGV and BUS are likely to reveal
		 * a bug and we want a core. STOP and KILL cannot be handled
		 * anyway: they're here for documentation. 32 and 33 are not
		 * defined.
		 */
		if (i == SIGILL || i == SIGSEGV || i == SIGBUS ||
		    i == SIGSTOP || i == SIGKILL || i == 32 || i == 33)
			continue;

		ret = sigaction(i, &act, NULL);
		if (ret < 0) {
			if (errno == EINVAL)
				continue;

			SYSERROR("Failed to change signal action");
			exit(EXIT_FAILURE);
		}
	}

	lxc_setup_fs();

	pid = fork();
	if (pid < 0)
		exit(EXIT_FAILURE);

	if (!pid) {
		/* restore default signal handlers */
		for (i = 1; i < NSIG; i++) {
			sighandler_t sigerr;
			sigerr = signal(i, SIG_DFL);
			if (sigerr == SIG_ERR) {
				DEBUG("%s - Failed to reset to default action "
				      "for signal \"%d\": %d", strerror(errno),
				      i, pid);
			}
		}

		ret = sigprocmask(SIG_SETMASK, &omask, NULL);
		if (ret < 0) {
			SYSERROR("Failed to set signal mask");
			exit(EXIT_FAILURE);
		}

		sid = setsid();
		if (sid < 0)
			DEBUG("Failed to make child session leader");

                if (ioctl(STDIN_FILENO, TIOCSCTTY, 0) < 0)
                        DEBUG("Failed to set controlling terminal");

		NOTICE("Exec'ing \"%s\"", my_args.argv[0]);

		ret = execvp(my_args.argv[0], my_args.argv);
		ERROR("%s - Failed to exec \"%s\"", strerror(errno), my_args.argv[0]);
		exit(ret);
	}

	INFO("Attempting to set proc title to \"init\"");
	setproctitle("init");

	/* Let's process the signals now. */
	ret = sigdelset(&omask, SIGALRM);
	if (ret < 0)
		exit(EXIT_FAILURE);

	ret = sigprocmask(SIG_SETMASK, &omask, NULL);
	if (ret < 0) {
		SYSERROR("Failed to set signal mask");
		exit(EXIT_FAILURE);
	}

	/* No need of other inherited fds but stderr. */
	close(STDIN_FILENO);
	close(STDOUT_FILENO);

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
				ret = kill(-1, SIGTERM);
				if (ret < 0)
					DEBUG("%s - Failed to send SIGTERM to "
					      "all children", strerror(errno));
				alarm(1);
			}
			break;
		case SIGALRM:
			ret = kill(-1, SIGKILL);
			if (ret < 0)
				DEBUG("%s - Failed to send SIGKILL to all "
				      "children", strerror(errno));
			break;
		default:
			ret = kill(pid, was_interrupted);
			if (ret < 0)
				DEBUG("%s - Failed to send signal \"%d\" to "
				      "%d", strerror(errno), was_interrupted, pid);
			break;
		}
		ret = EXIT_SUCCESS;

		was_interrupted = 0;
		waited_pid = wait(&status);
		if (waited_pid < 0) {
			if (errno == ECHILD)
				goto out;

			if (errno == EINTR)
				continue;

			ERROR("%s - Failed to wait on child %d",
			      strerror(errno), pid);
			goto out;
		}

		/* Reset timer each time a process exited. */
		if (shutdown)
			alarm(1);

		/* Keep the exit code of the started application (not wrapped
		 * pid) and continue to wait for the end of the orphan group.
		 */
		if (waited_pid == pid && !have_status) {
			ret = lxc_error_set_and_log(waited_pid, status);
			have_status = 1;
		}
	}
out:
	if (ret < 0)
		exit(EXIT_FAILURE);
	exit(ret);
}

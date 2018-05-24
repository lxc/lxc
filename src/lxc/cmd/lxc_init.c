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
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <ctype.h>

#include <lxc/lxccontainer.h>
#include <lxc/version.h>

#include "error.h"
#include "initutils.h"
#include "log.h"
#include "namespace.h"
#include "parse.h"

/* option keys for long only options */
#define OPT_USAGE 0x1000
#define OPT_VERSION OPT_USAGE - 1

#define QUOTE(macro) #macro
#define QUOTEVAL(macro) QUOTE(macro)

lxc_log_define(lxc_init, lxc);

static sig_atomic_t was_interrupted = 0;

static void interrupt_handler(int sig)
{
	if (!was_interrupted)
		was_interrupted = sig;
}

static struct option long_options[] = {
	    { "name",        required_argument, 0, 'n'         },
	    { "help",        no_argument,       0, 'h'         },
	    { "usage",       no_argument,       0, OPT_USAGE   },
	    { "version",     no_argument,       0, OPT_VERSION },
	    { "quiet",       no_argument,       0, 'q'         },
	    { "logfile",     required_argument, 0, 'o'         },
	    { "logpriority", required_argument, 0, 'l'         },
	    { "lxcpath",     required_argument, 0, 'P'         },
	    { 0,             0,                 0, 0           }
	};
static char short_options[] = "n:hqo:l:P:";

struct arguments {
	const struct option *options;
	const char *shortopts;

	const char *name;
	char *log_file;
	char *log_priority;
	bool quiet;
	const char *lxcpath;

	/* remaining arguments */
	char *const *argv;
	int argc;
};

static int arguments_parse(struct arguments *my_args, int argc,
			       char *const argv[]);

static struct arguments my_args = {
	.options   = long_options,
	.shortopts = short_options
};

static void prevent_forking(void)
{
	FILE *f;
	size_t len = 0;
	char *line = NULL;
	char path[MAXPATHLEN];

	f = fopen("/proc/self/cgroup", "r");
	if (!f)
		return;

	while (getline(&line, &len, f) != -1) {
		int fd, ret;
		char *p, *p2;

		p = strchr(line, ':');
		if (!p)
			continue;
		p++;
		p2 = strchr(p, ':');
		if (!p2)
			continue;
		*p2 = '\0';

		/* This is a cgroup v2 entry. Skip it. */
		if ((p2 - p) == 0)
			continue;

		if (strcmp(p, "pids") != 0)
			continue;
		p2++;

		p2 += lxc_char_left_gc(p2, strlen(p2));
		p2[lxc_char_right_gc(p2, strlen(p2))] = '\0';

		ret = snprintf(path, sizeof(path),
			       "/sys/fs/cgroup/pids/%s/pids.max", p2);
		if (ret < 0 || (size_t)ret >= sizeof(path)) {
			ERROR("Failed to create string");
			goto on_error;
		}

		fd = open(path, O_WRONLY);
		if (fd < 0) {
			SYSERROR("Failed to open \"%s\"", path);
			goto on_error;
		}

		ret = write(fd, "1", 1);
		if (ret != 1)
			SYSERROR("Failed to write to \"%s\"", path);

		close(fd);
		break;
	}

on_error:
	free(line);
	fclose(f);
}

static void kill_children(pid_t pid)
{
	FILE *f;
	char path[PATH_MAX];
	int ret;

	ret = snprintf(path, sizeof(path), "/proc/%d/task/%d/children", pid, pid);
	if (ret < 0 || (size_t)ret >= sizeof(path)) {
		ERROR("Failed to create string");
		return;
	}

	f = fopen(path, "r");
	if (!f) {
		SYSERROR("Failed to open %s", path);
		return;
	}

	while (!feof(f)) {
		pid_t pid;

		if (fscanf(f, "%d ", &pid) != 1) {
			ERROR("Failed to retrieve pid");
			fclose(f);
			return;
		}

		kill_children(pid);
		kill(pid, SIGKILL);
	}

	fclose(f);
}

static void remove_self(void)
{
	int ret;
	ssize_t n;
	char path[MAXPATHLEN] = {0};

	n = readlink("/proc/self/exe", path, sizeof(path));
	if (n < 0 || n >= MAXPATHLEN) {
		SYSERROR("Failed to readlink \"/proc/self/exe\"");
		return;
	}
	path[n] = '\0';

	ret = umount2(path, MNT_DETACH);
	if (ret < 0) {
		SYSERROR("Failed to unmount \"%s\"", path);
		return;
	}

	ret = unlink(path);
	if (ret < 0) {
		SYSERROR("Failed to unlink \"%s\"", path);
		return;
	}
}

int main(int argc, char *argv[])
{
	int i, ret;
	pid_t pid, sid;
	struct sigaction act;
	struct lxc_log log;
	sigset_t mask, omask;
	int have_status = 0, exit_with = 1, shutdown = 0;

	if (arguments_parse(&my_args, argc, argv))
		exit(EXIT_FAILURE);

	log.prefix = "lxc-init";
	log.name = my_args.name;
	log.file = my_args.log_file;
	log.level = my_args.log_priority;
	log.quiet = my_args.quiet;
	log.lxcpath = my_args.lxcpath;

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

	ret = pthread_sigmask(SIG_SETMASK, &mask, &omask);
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

	remove_self();

	pid = fork();
	if (pid < 0)
		exit(EXIT_FAILURE);

	if (!pid) {
		/* restore default signal handlers */
		for (i = 1; i < NSIG; i++) {
			sighandler_t sigerr;

			if (i == SIGILL || i == SIGSEGV || i == SIGBUS ||
			    i == SIGSTOP || i == SIGKILL || i == 32 || i == 33)
				continue;

			sigerr = signal(i, SIG_DFL);
			if (sigerr == SIG_ERR) {
				DEBUG("%s - Failed to reset to default action "
				      "for signal \"%d\": %d", strerror(errno),
				      i, pid);
			}
		}

		ret = pthread_sigmask(SIG_SETMASK, &omask, NULL);
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

	ret = pthread_sigmask(SIG_SETMASK, &omask, NULL);
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
		/* Some applications send SIGHUP in order to get init to reload
		 * its configuration. We don't want to forward this onto the
		 * application itself, because it probably isn't expecting this
		 * signal since it was expecting init to do something with it.
		 *
		 * Instead, let's explicitly ignore it here. The actual
		 * terminal case is handled in the monitor's handler, which
		 * sends this task a SIGTERM in the case of a SIGHUP, which is
		 * what we want.
		 */
		case SIGHUP:
			break;
		case SIGPWR:
		case SIGTERM:
			if (!shutdown) {
				pid_t mypid = lxc_raw_getpid();

				shutdown = 1;
				prevent_forking();
				if (mypid != 1) {
					kill_children(mypid);
				} else {
					ret = kill(-1, SIGTERM);
					if (ret < 0)
						DEBUG("%s - Failed to send SIGTERM to "
						      "all children", strerror(errno));
				}
				alarm(1);
			}
			break;
		case SIGALRM: {
			pid_t mypid = lxc_raw_getpid();

			prevent_forking();
			if (mypid != 1) {
				kill_children(mypid);
			} else {
				ret = kill(-1, SIGKILL);
				if (ret < 0)
					DEBUG("%s - Failed to send SIGTERM to "
					      "all children", strerror(errno));
			}
			break;
		}
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
			exit_with = lxc_error_set_and_log(waited_pid, status);
			have_status = 1;
		}
	}
out:
	if (ret < 0)
		exit(EXIT_FAILURE);
	exit(exit_with);
}

static void print_usage(const struct option longopts[])

{
	fprintf(stderr, "Usage: lxc-init [-n|--name=NAME] [-h|--help] [--usage] [--version] \n\
		[-q|--quiet] [-o|--logfile=LOGFILE] [-l|--logpriority=LOGPRIORITY] [-P|--lxcpath=LXCPATH]\n");
	exit(0);
}

static void print_version()
{
	printf("%s\n", LXC_VERSION);
	exit(0);
}

static void print_help()
{
	fprintf(stderr, "\
Usage: lxc-init --name=NAME -- COMMAND\n\
\n\
  lxc-init start a COMMAND as PID 2 inside a container\n\
\n\
Options :\n\
  -n, --name=NAME                  NAME of the container\n\
  -o, --logfile=FILE               Output log to FILE instead of stderr\n\
  -l, --logpriority=LEVEL          Set log priority to LEVEL\n\
  -q, --quiet                      Don't produce any output\n\
  -P, --lxcpath=PATH               Use specified container path\n\
  -?, --help                       Give this help list\n\
      --usage                      Give a short usage message\n\
      --version                    Print the version number\n\
\n\
Mandatory or optional arguments to long options are also mandatory or optional\n\
for any corresponding short options.\n\
\n\
See the lxc-init man page for further information.\n\n");

}

static int arguments_parse(struct arguments *args, int argc,
			       char *const argv[])
{
	while (true) {
		int c;
		int index = 0;

		c = getopt_long(argc, argv, args->shortopts, args->options, &index);
		if (c == -1)
			break;
		switch (c) {
		case 'n':
			args->name = optarg;
			break;
		case 'o':
			args->log_file = optarg;
			break;
		case 'l':
			args->log_priority = optarg;
			break;
		case 'q':
			args->quiet = true;
			break;
		case 'P':
			remove_trailing_slashes(optarg);
			args->lxcpath = optarg;
			break;
		case OPT_USAGE:
			print_usage(args->options);
		case OPT_VERSION:
			print_version();
		case '?':
			print_help();
			exit(EXIT_FAILURE);
		case 'h':
			print_help();
			exit(EXIT_SUCCESS);
		}
	}

	/*
	 * Reclaim the remaining command arguments
	 */
	args->argv = &argv[optind];
	args->argc = argc - optind;

	/* If no lxcpath was given, use default */
	if (!args->lxcpath) {
		args->lxcpath = lxc_global_config_value("lxc.lxcpath");
	}

	/* Check the command options */
	if (!args->name) {
		if(!args->quiet)
			fprintf(stderr, "lxc-init: missing container name, use --name option\n");
		return -1;
	}

	return 0;
}

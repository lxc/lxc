/*
 *
 * Copyright © 2014 Tycho Andersen <tycho.andersen@canonical.com>.
 * Copyright © 2014 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <lxc/lxccontainer.h>

#include "log.h"
#include "config.h"
#include "lxc.h"
#include "arguments.h"
#include "utils.h"

static char *checkpoint_dir = NULL;
static bool stop = false;
static bool verbose = false;
static bool do_restore = false;
static bool daemonize_set = false;

static const struct option my_longopts[] = {
	{"checkpoint-dir", required_argument, 0, 'D'},
	{"stop", no_argument, 0, 's'},
	{"verbose", no_argument, 0, 'v'},
	{"restore", no_argument, 0, 'r'},
	{"daemon", no_argument, 0, 'd'},
	{"foreground", no_argument, 0, 'F'},
	LXC_COMMON_OPTIONS
};

static int my_checker(const struct lxc_arguments *args)
{
	if (do_restore && stop) {
		lxc_error(args, "-s not compatible with -r.");
		return -1;

	} else if (!do_restore && daemonize_set) {
		lxc_error(args, "-d/-F not compatible with -r.");
		return -1;
	}

	if (checkpoint_dir == NULL) {
		lxc_error(args, "-D is required.");
		return -1;
	}

	return 0;
}

static int my_parser(struct lxc_arguments *args, int c, char *arg)
{
	switch (c) {
	case 'D':
		checkpoint_dir = strdup(arg);
		if (!checkpoint_dir)
			return -1;
		break;
	case 's':
		stop = true;
		break;
	case 'v':
		verbose = true;
		break;
	case 'r':
		do_restore = true;
		break;
	case 'd':
		args->daemonize = 1;
		daemonize_set = true;
		break;
	case 'F':
		args->daemonize = 0;
		daemonize_set = true;
		break;
	}
	return 0;
}

static struct lxc_arguments my_args = {
	.progname  = "lxc-checkpoint",
	.help      = "\
--name=NAME\n\
\n\
lxc-checkpoint checkpoints and restores a container\n\
  Serializes a container's running state to disk to allow restoring it in\n\
  its running state at a later time.\n\
\n\
Options :\n\
  -n, --name=NAME           NAME of the container\n\
  -r, --restore             Restore container\n\
  -D, --checkpoint-dir=DIR  directory to save the checkpoint in\n\
  -v, --verbose             Enable verbose criu logs\n\
  Checkpoint options:\n\
  -s, --stop                Stop the container after checkpointing.\n\
  Restore options:\n\
  -d, --daemon              Daemonize the container (default)\n\
  -F, --foreground          Start with the current tty attached to /dev/console\n\
",
	.options   = my_longopts,
	.parser    = my_parser,
	.daemonize = 1,
	.checker   = my_checker,
};

static bool checkpoint(struct lxc_container *c)
{
	bool ret;

	if (!c->is_running(c)) {
		fprintf(stderr, "%s not running, not checkpointing.\n", my_args.name);
		lxc_container_put(c);
		return false;
	}

	ret = c->checkpoint(c, checkpoint_dir, stop, verbose);
	lxc_container_put(c);

	if (!ret) {
		fprintf(stderr, "Checkpointing %s failed.\n", my_args.name);
		return false;
	}

	return true;
}

static bool restore_finalize(struct lxc_container *c)
{
	bool ret = c->restore(c, checkpoint_dir, verbose);
	if (!ret) {
		fprintf(stderr, "Restoring %s failed.\n", my_args.name);
	}

	lxc_container_put(c);
	return ret;
}

static bool restore(struct lxc_container *c)
{
	if (c->is_running(c)) {
		fprintf(stderr, "%s is running, not restoring.\n", my_args.name);
		lxc_container_put(c);
		return false;
	}

	if (my_args.daemonize) {
		pid_t pid;

		pid = fork();
		if (pid < 0) {
			perror("fork");
			return false;
		}

		if (pid == 0) {
			close(0);
			close(1);

			exit(!restore_finalize(c));
		} else {
			return wait_for_pid(pid) == 0;
		}
	} else {
		int status;

		if (!restore_finalize(c))
			return false;

		if (waitpid(-1, &status, 0) < 0)
			return false;

		return WIFEXITED(status) && WEXITSTATUS(status) == 0;
	}
}

int main(int argc, char *argv[])
{
	struct lxc_container *c;
	bool ret;

	if (lxc_arguments_parse(&my_args, argc, argv))
		exit(1);

	if (!my_args.log_file)
		my_args.log_file = "none";

	if (lxc_log_init(my_args.name, my_args.log_file, my_args.log_priority,
			 my_args.progname, my_args.quiet, my_args.lxcpath[0]))
		exit(1);

	lxc_log_options_no_override();

	c = lxc_container_new(my_args.name, my_args.lxcpath[0]);
	if (!c) {
		fprintf(stderr, "System error loading %s\n", my_args.name);
		exit(1);
	}

	if (!c->may_control(c)) {
		fprintf(stderr, "Insufficent privileges to control %s\n", my_args.name);
		lxc_container_put(c);
		exit(1);
	}

	if (!c->is_defined(c)) {
		fprintf(stderr, "%s is not defined\n", my_args.name);
		lxc_container_put(c);
		exit(1);
	}


	if (do_restore)
		ret = restore(c);
	else
		ret = checkpoint(c);

	return !ret;
}

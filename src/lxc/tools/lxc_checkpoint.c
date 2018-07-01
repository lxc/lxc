/*
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

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <lxc/lxccontainer.h>

#include "arguments.h"
#include "log.h"
#include "utils.h"

static char *checkpoint_dir = NULL;
static bool stop = false;
static bool verbose = false;
static bool do_restore = false;
static bool daemonize_set = false;
static bool pre_dump = false;
static char *predump_dir = NULL;
static char *actionscript_path = NULL;

#define OPT_PREDUMP_DIR OPT_USAGE + 1

static const struct option my_longopts[] = {
	{"checkpoint-dir", required_argument, 0, 'D'},
	{"action-script", required_argument, 0, 'A'},
	{"stop", no_argument, 0, 's'},
	{"verbose", no_argument, 0, 'v'},
	{"restore", no_argument, 0, 'r'},
	{"daemon", no_argument, 0, 'd'},
	{"foreground", no_argument, 0, 'F'},
	{"pre-dump", no_argument, 0, 'p'},
	{"predump-dir", required_argument, 0, OPT_PREDUMP_DIR},
	LXC_COMMON_OPTIONS
};

lxc_log_define(lxc_checkpoint, lxc);

static int my_checker(const struct lxc_arguments *args)
{
	if (do_restore && stop) {
		ERROR("-s not compatible with -r");
		return -1;

	} else if (!do_restore && daemonize_set) {
		ERROR("-d/-F not compatible with -r");
		return -1;
	}

	if (!checkpoint_dir) {
		ERROR("-D is required");
		return -1;
	}

	if (pre_dump && do_restore) {
		ERROR("-p not compatible with -r");
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
        case 'A':
		actionscript_path = strdup(arg);
		if (!actionscript_path)
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
	case 'p':
		pre_dump = true;
		break;
	case OPT_PREDUMP_DIR:
		predump_dir = strdup(arg);
		if (!predump_dir)
			return -1;
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
  -A, --action-script=PATH  Path to criu action script\n\
  Checkpoint options:\n\
  -s, --stop                Stop the container after checkpointing.\n\
  -p, --pre-dump            Only pre-dump the memory of the container.\n\
                            Container keeps on running and following\n\
                            checkpoints will only dump the changes.\n\
  --predump-dir=DIR         path to images from previous dump (relative to -D)\n\
  Restore options:\n\
  -d, --daemon              Daemonize the container (default)\n\
  -F, --foreground          Start with the current tty attached to /dev/console\n\
  --rcfile=FILE             Load configuration file FILE\n\
",
	.options   = my_longopts,
	.parser    = my_parser,
	.daemonize = 1,
	.checker   = my_checker,
};

static bool checkpoint(struct lxc_container *c)
{
	struct migrate_opts opts;
	bool ret;
	int mode;

	if (!c->is_running(c)) {
		ERROR("%s not running, not checkpointing", my_args.name);
		lxc_container_put(c);
		return false;
	}

	memset(&opts, 0, sizeof(opts));

	opts.directory = checkpoint_dir;
	opts.stop = stop;
	opts.verbose = verbose;
	opts.predump_dir = predump_dir;
	opts.action_script = actionscript_path;

	if (pre_dump)
		mode = MIGRATE_PRE_DUMP;
	else
		mode = MIGRATE_DUMP;

	ret = c->migrate(c, mode, &opts, sizeof(opts));
	lxc_container_put(c);

	/* the migrate() API does not negate the return code like
	 * checkpoint() and restore() does. */
	if (ret) {
		ERROR("Checkpointing %s failed", my_args.name);
		return false;
	}

	return true;
}

static bool restore_finalize(struct lxc_container *c)
{
	struct migrate_opts opts;
	bool ret;

	memset(&opts, 0, sizeof(opts));

	opts.directory = checkpoint_dir;
	opts.verbose = verbose;
	opts.stop = stop;
	opts.action_script = actionscript_path;

	ret = c->migrate(c, MIGRATE_RESTORE, &opts, sizeof(opts));
	if (ret) {
		ERROR("Restoring %s failed", my_args.name);
		return false;
	}

	lxc_container_put(c);
	return true;
}

static bool restore(struct lxc_container *c)
{
	if (c->is_running(c)) {
		ERROR("%s is running, not restoring", my_args.name);
		lxc_container_put(c);
		return false;
	}

	if (my_args.daemonize) {
		pid_t pid;

		pid = fork();
		if (pid < 0) {
			SYSERROR("Failed to fork");
			return false;
		}

		if (pid == 0) {
			close(0);
			close(1);

			_exit(!restore_finalize(c));
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
	struct lxc_log log;
	bool ret;

	if (lxc_arguments_parse(&my_args, argc, argv))
		exit(EXIT_FAILURE);

	/* Only create log if explicitly instructed */
	if (my_args.log_file || my_args.log_priority) {
		log.name = my_args.name;
		log.file = my_args.log_file;
		log.level = my_args.log_priority;
		log.prefix = my_args.progname;
		log.quiet = my_args.quiet;
		log.lxcpath = my_args.lxcpath[0];

		if (lxc_log_init(&log))
			exit(EXIT_FAILURE);
	}

	c = lxc_container_new(my_args.name, my_args.lxcpath[0]);
	if (!c) {
		ERROR("System error loading %s", my_args.name);
		exit(EXIT_FAILURE);
	}

	if (my_args.rcfile) {
		c->clear_config(c);

		if (!c->load_config(c, my_args.rcfile)) {
			ERROR("Failed to load rcfile");
			lxc_container_put(c);
			exit(EXIT_FAILURE);
		}

		c->configfile = strdup(my_args.rcfile);
		if (!c->configfile) {
			ERROR("Out of memory setting new config filename");
			lxc_container_put(c);
			exit(EXIT_FAILURE);
		}
	}

	if (!c->may_control(c)) {
		ERROR("Insufficent privileges to control %s", my_args.name);
		lxc_container_put(c);
		exit(EXIT_FAILURE);
	}

	if (!c->is_defined(c)) {
		ERROR("%s is not defined", my_args.name);
		lxc_container_put(c);
		exit(EXIT_FAILURE);
	}


	if (do_restore)
		ret = restore(c);
	else
		ret = checkpoint(c);

	free(actionscript_path);
	free(checkpoint_dir);
	free(predump_dir);

	if (!ret)
		exit(EXIT_FAILURE);

	exit(EXIT_SUCCESS);
}

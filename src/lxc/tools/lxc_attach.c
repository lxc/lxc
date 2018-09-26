/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2010
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include <lxc/lxccontainer.h>

#include "arguments.h"
#include "attach.h"
#include "caps.h"
#include "config.h"
#include "confile.h"
#include "log.h"
#include "utils.h"

lxc_log_define(lxc_attach, lxc);

static int my_parser(struct lxc_arguments *args, int c, char *arg);
static int add_to_simple_array(char ***array, ssize_t *capacity, char *value);
static bool stdfd_is_pty(void);
static int lxc_attach_create_log_file(const char *log_file);

static int elevated_privileges;
static signed long new_personality = -1;
static int namespace_flags = -1;
static int remount_sys_proc;
static lxc_attach_env_policy_t env_policy = LXC_ATTACH_KEEP_ENV;
static char **extra_env;
static ssize_t extra_env_size;
static char **extra_keep;
static ssize_t extra_keep_size;

static const struct option my_longopts[] = {
	{"elevated-privileges", optional_argument, 0, 'e'},
	{"arch", required_argument, 0, 'a'},
	{"namespaces", required_argument, 0, 's'},
	{"remount-sys-proc", no_argument, 0, 'R'},
	/* TODO: decide upon short option names */
	{"clear-env", no_argument, 0, 500},
	{"keep-env", no_argument, 0, 501},
	{"keep-var", required_argument, 0, 502},
	{"set-var", required_argument, 0, 'v'},
	{"pty-log", required_argument, 0, 'L'},
	{"rcfile", required_argument, 0, 'f'},
	LXC_COMMON_OPTIONS
};

static struct lxc_arguments my_args = {
	.progname     = "lxc-attach",
	.help         = "\
--name=NAME [-- COMMAND]\n\
\n\
Execute the specified COMMAND - enter the container NAME\n\
\n\
Options :\n\
  -n, --name=NAME   NAME of the container\n\
  -e, --elevated-privileges=PRIVILEGES\n\
                    Use elevated privileges instead of those of the\n\
                    container. If you don't specify privileges to be\n\
                    elevated as OR'd list: CAP, CGROUP and LSM (capabilities,\n\
                    cgroup and restrictions, respectively) then all of them\n\
                    will be elevated.\n\
                    WARNING: This may leak privileges into the container.\n\
                    Use with care.\n\
  -a, --arch=ARCH   Use ARCH for program instead of container's own\n\
                    architecture.\n\
  -s, --namespaces=FLAGS\n\
                    Don't attach to all the namespaces of the container\n\
                    but just to the following OR'd list of flags:\n\
                    MOUNT, PID, UTSNAME, IPC, USER or NETWORK.\n\
                    WARNING: Using -s implies -e with all privileges\n\
                    elevated, it may therefore leak privileges into the\n\
                    container. Use with care.\n\
  -R, --remount-sys-proc\n\
                    Remount /sys and /proc if not attaching to the\n\
                    mount namespace when using -s in order to properly\n\
                    reflect the correct namespace context. See the\n\
                    lxc-attach(1) manual page for details.\n\
      --clear-env   Clear all environment variables before attaching.\n\
                    The attached shell/program will start with only\n\
                    container=lxc set.\n\
      --keep-env    Keep all current environment variables. This\n\
                    is the current default behaviour, but is likely to\n\
                    change in the future.\n\
  -L, --pty-log=FILE\n\
                    Log pty output to FILE\n\
  -v, --set-var     Set an additional variable that is seen by the\n\
                    attached program in the container. May be specified\n\
                    multiple times.\n\
      --keep-var    Keep an additional environment variable. Only\n\
                    applicable if --clear-env is specified. May be used\n\
                    multiple times.\n\
  -f, --rcfile=FILE\n\
                    Load configuration file FILE\n\
",
	.options      = my_longopts,
	.parser       = my_parser,
	.checker      = NULL,
	.log_priority = "ERROR",
	.log_file     = "none",
};

static int my_parser(struct lxc_arguments *args, int c, char *arg)
{
	int ret;

	switch (c) {
	case 'e':
		ret = lxc_fill_elevated_privileges(arg, &elevated_privileges);
		if (ret)
			return -1;
		break;
	case 'R': remount_sys_proc = 1; break;
	case 'a':
		new_personality = lxc_config_parse_arch(arg);
		if (new_personality < 0) {
			ERROR("Invalid architecture specified: %s", arg);
			return -1;
		}
		break;
	case 's':
		namespace_flags = 0;

		if (lxc_namespace_2_std_identifiers(arg) < 0)
			return -1;

		ret = lxc_fill_namespace_flags(arg, &namespace_flags);
		if (ret)
			return -1;

		/* -s implies -e */
		lxc_fill_elevated_privileges(NULL, &elevated_privileges);
		break;
	case 500: /* clear-env */
		env_policy = LXC_ATTACH_CLEAR_ENV;
		break;
	case 501: /* keep-env */
		env_policy = LXC_ATTACH_KEEP_ENV;
		break;
	case 502: /* keep-var */
		ret = add_to_simple_array(&extra_keep, &extra_keep_size, arg);
		if (ret < 0) {
			ERROR("Failed to alloc memory");
			return -1;
		}
		break;
	case 'v':
		ret = add_to_simple_array(&extra_env, &extra_env_size, arg);
		if (ret < 0) {
			ERROR("Failed to alloc memory");
			return -1;
		}
		break;
	case 'L':
		args->console_log = arg;
		break;
	case 'f':
		args->rcfile = arg;
		break;
	}

	return 0;
}

static int add_to_simple_array(char ***array, ssize_t *capacity, char *value)
{
	ssize_t count = 0;

	if (!array)
		return -1;

	if (*array)
		for (; (*array)[count]; count++);

	/* we have to reallocate */
	if (count >= *capacity - 1) {
		ssize_t new_capacity = ((count + 1) / 32 + 1) * 32;

		char **new_array = realloc((void*)*array, sizeof(char *) * new_capacity);
		if (!new_array)
			return -1;

		memset(&new_array[count], 0, sizeof(char*)*(new_capacity - count));

		*array = new_array;
		*capacity = new_capacity;
	}

	if (!(*array))
		return -1;

	(*array)[count] = value;
	return 0;
}

static bool stdfd_is_pty(void)
{
	if (isatty(STDIN_FILENO))
		return true;

	if (isatty(STDOUT_FILENO))
		return true;

	if (isatty(STDERR_FILENO))
		return true;

	return false;
}

static int lxc_attach_create_log_file(const char *log_file)
{
	int fd;

	fd = open(log_file, O_CLOEXEC | O_RDWR | O_CREAT | O_APPEND, 0600);
	if (fd < 0) {
		ERROR("Failed to open log file \"%s\"", log_file);
		return -1;
	}

	return fd;
}

int main(int argc, char *argv[])
{
	int ret = -1;
	int wexit = 0;
	struct lxc_log log;
	pid_t pid;
	lxc_attach_options_t attach_options = LXC_ATTACH_OPTIONS_DEFAULT;
	lxc_attach_command_t command = (lxc_attach_command_t){.program = NULL};

	if (lxc_caps_init())
		exit(EXIT_FAILURE);

	if (lxc_arguments_parse(&my_args, argc, argv))
		exit(EXIT_FAILURE);

	log.name = my_args.name;
	log.file = my_args.log_file;
	log.level = my_args.log_priority;
	log.prefix = my_args.progname;
	log.quiet = my_args.quiet;
	log.lxcpath = my_args.lxcpath[0];

	if (lxc_log_init(&log))
		exit(EXIT_FAILURE);

	if (geteuid())
		if (access(my_args.lxcpath[0], O_RDONLY) < 0) {
			ERROR("You lack access to %s", my_args.lxcpath[0]);
			exit(EXIT_FAILURE);
		}

	struct lxc_container *c = lxc_container_new(my_args.name, my_args.lxcpath[0]);
	if (!c)
		exit(EXIT_FAILURE);

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
		ERROR("Insufficent privileges to control %s", c->name);
		lxc_container_put(c);
		exit(EXIT_FAILURE);
	}

	if (remount_sys_proc)
		attach_options.attach_flags |= LXC_ATTACH_REMOUNT_PROC_SYS;

	if (elevated_privileges)
		attach_options.attach_flags &= ~(elevated_privileges);

	if (stdfd_is_pty())
		attach_options.attach_flags |= LXC_ATTACH_TERMINAL;

	attach_options.namespaces = namespace_flags;
	attach_options.personality = new_personality;
	attach_options.env_policy = env_policy;
	attach_options.extra_env_vars = extra_env;
	attach_options.extra_keep_env = extra_keep;

	if (my_args.argc > 0) {
		command.program = my_args.argv[0];
		command.argv = (char**)my_args.argv;
	}

	if (my_args.console_log) {
		attach_options.log_fd = lxc_attach_create_log_file(my_args.console_log);
		if (attach_options.log_fd < 0)
			goto out;
	}

	if (command.program)
		ret = c->attach(c, lxc_attach_run_command, &command, &attach_options, &pid);
	else
		ret = c->attach(c, lxc_attach_run_shell, NULL, &attach_options, &pid);
	if (ret < 0)
		goto out;

	ret = lxc_wait_for_pid_status(pid);
	if (ret < 0)
		goto out;

	if (WIFEXITED(ret))
		wexit = WEXITSTATUS(ret);

out:
	lxc_container_put(c);
	if (ret >= 0)
		exit(wexit);

	exit(EXIT_FAILURE);
}

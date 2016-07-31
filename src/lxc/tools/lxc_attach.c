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

#include "config.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include <lxc/lxccontainer.h>

#include "attach.h"
#include "arguments.h"
#include "caps.h"
#include "confile.h"
#include "console.h"
#include "log.h"
#include "list.h"
#include "mainloop.h"
#include "utils.h"

#if HAVE_PTY_H
#include <pty.h>
#else
#include <../include/openpty.h>
#endif

lxc_log_define(lxc_attach_ui, lxc);

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
	LXC_COMMON_OPTIONS
};

static int elevated_privileges = 0;
static signed long new_personality = -1;
static int namespace_flags = -1;
static int remount_sys_proc = 0;
static lxc_attach_env_policy_t env_policy = LXC_ATTACH_KEEP_ENV;
static char **extra_env = NULL;
static ssize_t extra_env_size = 0;
static char **extra_keep = NULL;
static ssize_t extra_keep_size = 0;

static int add_to_simple_array(char ***array, ssize_t *capacity, char *value)
{
	ssize_t count = 0;

	assert(array);

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

	assert(*array);

	(*array)[count] = value;
	return 0;
}

static int my_parser(struct lxc_arguments* args, int c, char* arg)
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
			lxc_error(args, "invalid architecture specified: %s", arg);
			return -1;
		}
		break;
	case 's':
		namespace_flags = 0;
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
			lxc_error(args, "memory allocation error");
			return -1;
		}
		break;
	case 'v':
		ret = add_to_simple_array(&extra_env, &extra_env_size, arg);
		if (ret < 0) {
			lxc_error(args, "memory allocation error");
			return -1;
		}
		break;
	case 'L':
		args->console_log = arg;
		break;
	}

	return 0;
}

static struct lxc_arguments my_args = {
	.progname = "lxc-attach",
	.help     = "\
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
                    multiple times.\n",
	.options  = my_longopts,
	.parser   = my_parser,
	.checker  = NULL,
};

struct wrapargs {
	lxc_attach_options_t *options;
	lxc_attach_command_t *command;
	struct lxc_console *console;
	int ptyfd;
};

/* Minimalistic login_tty() implementation. */
static int login_pty(int fd)
{
	setsid();
	if (ioctl(fd, TIOCSCTTY, NULL) < 0)
		return -1;
	if (lxc_console_set_stdfds(fd) < 0)
		return -1;
	if (fd > STDERR_FILENO)
		close(fd);
	return 0;
}

static int get_pty_on_host_callback(void *p)
{
	struct wrapargs *wrap = p;

	close(wrap->console->master);
	if (login_pty(wrap->console->slave) < 0)
		return -1;

	if (wrap->command->program)
		lxc_attach_run_command(wrap->command);
	else
		lxc_attach_run_shell(NULL);
	return -1;
}

static int get_pty_on_host(struct lxc_container *c, struct wrapargs *wrap, int *pid)
{
	int ret = -1;
	struct wrapargs *args = wrap;
	struct lxc_epoll_descr descr;
	struct lxc_conf *conf;
	struct lxc_tty_state *ts;

	INFO("Trying to allocate a pty on the host");

	if (!isatty(args->ptyfd)) {
		ERROR("Standard file descriptor does not refer to a pty\n.");
		return -1;
	}

	conf = c->lxc_conf;
	free(conf->console.log_path);
	if (my_args.console_log)
		conf->console.log_path = strdup(my_args.console_log);
	else
		conf->console.log_path = NULL;

	/* In the case of lxc-attach our peer pty will always be the current
	 * controlling terminal. We clear whatever was set by the user for
	 * lxc.console.path here and set it to "/dev/tty". Doing this will (a)
	 * prevent segfaults when the container has been setup with
	 * lxc.console = none and (b) provide an easy way to ensure that we
	 * always do the correct thing. strdup() must be used since console.path
	 * is free()ed when we call lxc_container_put(). */
	free(conf->console.path);
	conf->console.path = strdup("/dev/tty");
	if (!conf->console.path)
		return -1;

	/* Create pty on the host. */
	if (lxc_console_create(conf) < 0)
		return -1;
	ts = conf->console.tty_state;
	conf->console.descr = &descr;

	/* Shift ttys to container. */
	if (ttys_shift_ids(conf) < 0) {
		ERROR("Failed to shift tty into container");
		goto err1;
	}

	/* Send wrapper function on its way. */
	wrap->console = &conf->console;
	if (c->attach(c, get_pty_on_host_callback, wrap, wrap->options, pid) < 0)
		goto err1;
	close(conf->console.slave); /* Close slave side. */

	ret = lxc_mainloop_open(&descr);
	if (ret) {
		ERROR("failed to create mainloop");
		goto err2;
	}

	if (lxc_console_mainloop_add(&descr, conf) < 0) {
		ERROR("Failed to add handlers to lxc mainloop.");
		goto err3;
	}

	ret = lxc_mainloop(&descr, -1);
	if (ret) {
		ERROR("mainloop returned an error");
		goto err3;
	}
	ret = 0;

err3:
	lxc_mainloop_close(&descr);
err2:
	if (ts->sigfd != -1)
		lxc_console_sigwinch_fini(ts);
err1:
	lxc_console_delete(&conf->console);

	return ret;
}

static int stdfd_is_pty(void)
{
	if (isatty(STDIN_FILENO))
		return STDIN_FILENO;
	if (isatty(STDOUT_FILENO))
		return STDOUT_FILENO;
	if (isatty(STDERR_FILENO))
		return STDERR_FILENO;

	return -1;
}

int main(int argc, char *argv[])
{
	int ret = -1, r;
	int wexit = 0;
	pid_t pid;
	lxc_attach_options_t attach_options = LXC_ATTACH_OPTIONS_DEFAULT;
	lxc_attach_command_t command = (lxc_attach_command_t){.program = NULL};

	r = lxc_caps_init();
	if (r)
		exit(EXIT_FAILURE);

	r = lxc_arguments_parse(&my_args, argc, argv);
	if (r)
		exit(EXIT_FAILURE);

	if (!my_args.log_file)
		my_args.log_file = "none";

	r = lxc_log_init(my_args.name, my_args.log_file, my_args.log_priority,
			   my_args.progname, my_args.quiet, my_args.lxcpath[0]);
	if (r)
		exit(EXIT_FAILURE);
	lxc_log_options_no_override();

	if (geteuid()) {
		if (access(my_args.lxcpath[0], O_RDWR) < 0) {
			if (!my_args.quiet)
				fprintf(stderr, "You lack access to %s\n", my_args.lxcpath[0]);
			exit(EXIT_FAILURE);
		}
	}

	struct lxc_container *c = lxc_container_new(my_args.name, my_args.lxcpath[0]);
	if (!c)
		exit(EXIT_FAILURE);

	if (!c->may_control(c)) {
		fprintf(stderr, "Insufficent privileges to control %s\n", c->name);
		lxc_container_put(c);
		exit(EXIT_FAILURE);
	}

	if (!c->is_defined(c)) {
		fprintf(stderr, "Error: container %s is not defined\n", c->name);
		lxc_container_put(c);
		exit(EXIT_FAILURE);
	}

	if (remount_sys_proc)
		attach_options.attach_flags |= LXC_ATTACH_REMOUNT_PROC_SYS;
	if (elevated_privileges)
		attach_options.attach_flags &= ~(elevated_privileges);
	attach_options.namespaces = namespace_flags;
	attach_options.personality = new_personality;
	attach_options.env_policy = env_policy;
	attach_options.extra_env_vars = extra_env;
	attach_options.extra_keep_env = extra_keep;

	if (my_args.argc > 0) {
		command.program = my_args.argv[0];
		command.argv = (char**)my_args.argv;
	}

	struct wrapargs wrap = (struct wrapargs){
		.command = &command,
			.options = &attach_options
	};

	wrap.ptyfd = stdfd_is_pty();
	if (wrap.ptyfd >= 0) {
		if ((!isatty(STDOUT_FILENO) || !isatty(STDERR_FILENO)) && my_args.console_log) {
			fprintf(stderr, "-L/--pty-log can only be used when stdout and stderr refer to a pty.\n");
			goto out;
		}
		ret = get_pty_on_host(c, &wrap, &pid);
	} else {
		if (my_args.console_log) {
			fprintf(stderr, "-L/--pty-log can only be used when stdout and stderr refer to a pty.\n");
			goto out;
		}
		if (command.program)
			ret = c->attach(c, lxc_attach_run_command, &command, &attach_options, &pid);
		else
			ret = c->attach(c, lxc_attach_run_shell, NULL, &attach_options, &pid);
	}

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

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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#define _GNU_SOURCE
#include <sys/wait.h>
#include <sys/types.h>

#include "attach.h"
#include "arguments.h"
#include "config.h"
#include "confile.h"
#include "namespace.h"
#include "caps.h"
#include "log.h"
#include "utils.h"

lxc_log_define(lxc_attach_ui, lxc);

static const struct option my_longopts[] = {
	{"elevated-privileges", no_argument, 0, 'e'},
	{"arch", required_argument, 0, 'a'},
	{"namespaces", required_argument, 0, 's'},
	{"remount-sys-proc", no_argument, 0, 'R'},
	/* TODO: decide upon short option names */
	{"clear-env", no_argument, 0, 500},
	{"keep-env", no_argument, 0, 501},
	LXC_COMMON_OPTIONS
};

static int elevated_privileges = 0;
static signed long new_personality = -1;
static int namespace_flags = -1;
static int remount_sys_proc = 0;
static lxc_attach_env_policy_t env_policy = LXC_ATTACH_KEEP_ENV;

static int my_parser(struct lxc_arguments* args, int c, char* arg)
{
	int ret;

	switch (c) {
	case 'e': elevated_privileges = 1; break;
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
		elevated_privileges = 1;
		break;
        case 500: /* clear-env */
                env_policy = LXC_ATTACH_CLEAR_ENV;
                break;
        case 501: /* keep-env */
                env_policy = LXC_ATTACH_KEEP_ENV;
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
  -n, --name=NAME   NAME for name of the container\n\
  -e, --elevated-privileges\n\
                    Use elevated privileges (capabilities, cgroup\n\
                    restrictions) instead of those of the container.\n\
                    WARNING: This may leak privleges into the container.\n\
                    Use with care.\n\
  -a, --arch=ARCH   Use ARCH for program instead of container's own\n\
                    architecture.\n\
  -s, --namespaces=FLAGS\n\
                    Don't attach to all the namespaces of the container\n\
                    but just to the following OR'd list of flags:\n\
                    MOUNT, PID, UTSNAME, IPC, USER or NETWORK\n\
                    WARNING: Using -s implies -e, it may therefore\n\
                    leak privileges into the container. Use with care.\n\
  -R, --remount-sys-proc\n\
                    Remount /sys and /proc if not attaching to the\n\
                    mount namespace when using -s in order to properly\n\
                    reflect the correct namespace context. See the\n\
                    lxc-attach(1) manual page for details.\n\
      --clear-env\n\
                    Clear all environment variables before attaching.\n\
                    The attached shell/program will start with only\n\
                    container=lxc set.\n\
      --keep-env\n\
                    Keep all current enivornment variables. This\n\
                    is the current default behaviour, but is likely to\n\
                    change in the future.\n",
	.options  = my_longopts,
	.parser   = my_parser,
	.checker  = NULL,
};

int main(int argc, char *argv[])
{
	int ret;
	pid_t pid;
	lxc_attach_options_t attach_options = LXC_ATTACH_OPTIONS_DEFAULT;
	lxc_attach_command_t command;

	ret = lxc_caps_init();
	if (ret)
		return ret;

	ret = lxc_arguments_parse(&my_args, argc, argv);
	if (ret)
		return ret;

	ret = lxc_log_init(my_args.name, my_args.log_file, my_args.log_priority,
			   my_args.progname, my_args.quiet, my_args.lxcpath[0]);
	if (ret)
		return ret;

	if (remount_sys_proc)
		attach_options.attach_flags |= LXC_ATTACH_REMOUNT_PROC_SYS;
	if (elevated_privileges)
		attach_options.attach_flags &= ~(LXC_ATTACH_MOVE_TO_CGROUP | LXC_ATTACH_DROP_CAPABILITIES | LXC_ATTACH_APPARMOR);
	attach_options.namespaces = namespace_flags;
	attach_options.personality = new_personality;
	attach_options.env_policy = env_policy;

	if (my_args.argc) {
		command.program = my_args.argv[0];
		command.argv = (char**)my_args.argv;
		ret = lxc_attach(my_args.name, my_args.lxcpath[0], lxc_attach_run_command, &command, &attach_options, &pid);
	} else {
		ret = lxc_attach(my_args.name, my_args.lxcpath[0], lxc_attach_run_shell, NULL, &attach_options, &pid);
	}

	if (ret < 0)
		return -1;

	ret = lxc_wait_for_pid_status(pid);
	if (ret < 0)
		return -1;

	if (WIFEXITED(ret))
		return WEXITSTATUS(ret);

	return -1;
}

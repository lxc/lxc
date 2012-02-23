/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2010
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

#define _GNU_SOURCE
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <stdlib.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/personality.h>

#include "attach.h"
#include "commands.h"
#include "arguments.h"
#include "caps.h"
#include "attach.h"
#include "confile.h"
#include "start.h"
#include "sync.h"
#include "log.h"

lxc_log_define(lxc_attach_ui, lxc);

static const struct option my_longopts[] = {
	{"elevated-privileges", no_argument, 0, 'e'},
	{"arch", required_argument, 0, 'a'},
	LXC_COMMON_OPTIONS
};

static int elevated_privileges = 0;
static signed long new_personality = -1;

static int my_parser(struct lxc_arguments* args, int c, char* arg)
{
	switch (c) {
	case 'e': elevated_privileges = 1; break;
	case 'a':
		new_personality = lxc_config_parse_arch(arg);
		if (new_personality < 0) {
			lxc_error(args, "invalid architecture specified: %s", arg);
			return -1;
		}
		break;
	}

	return 0;
}

static struct lxc_arguments my_args = {
	.progname = "lxc-attach",
	.help     = "\
--name=NAME\n\
\n\
Execute the specified command - enter the container NAME\n\
\n\
Options :\n\
  -n, --name=NAME   NAME for name of the container\n\
  -e, --elevated-privileges\n\
                    Use elevated privileges (capabilities, cgroup\n\
                    restrictions) instead of those of the container.\n\
                    WARNING: This may leak privleges into the container.\n\
                    Use with care.\n\
  -a, --arch=ARCH   Use ARCH for program instead of container's own\n\
                    architecture.\n",
	.options  = my_longopts,
	.parser   = my_parser,
	.checker  = NULL,
};

int main(int argc, char *argv[], char *envp[])
{
	int ret;
	pid_t pid, init_pid;
	struct passwd *passwd;
	struct lxc_proc_context_info *init_ctx;
	struct lxc_handler *handler;
	uid_t uid;
	char *curdir;

	ret = lxc_caps_init();
	if (ret)
		return ret;

	ret = lxc_arguments_parse(&my_args, argc, argv);
	if (ret)
		return ret;

	ret = lxc_log_init(my_args.log_file, my_args.log_priority,
			   my_args.progname, my_args.quiet);
	if (ret)
		return ret;

	init_pid = get_init_pid(my_args.name);
	if (init_pid < 0) {
		ERROR("failed to get the init pid");
		return -1;
	}

	init_ctx = lxc_proc_get_context_info(init_pid);
	if (!init_ctx) {
		ERROR("failed to get context of the init process, pid = %d", init_pid);
		return -1;
	}

	/* hack: we need sync.h infrastructure - and that needs a handler */
	handler = calloc(1, sizeof(*handler));

	if (lxc_sync_init(handler)) {
		ERROR("failed to initialize synchronization socket");
		return -1;
	}

	pid = fork();

	if (pid < 0) {
		SYSERROR("failed to fork");
		return -1;
	}

	if (pid) {
		int status;

		lxc_sync_fini_child(handler);

		/* wait until the child has done configuring itself before
		 * we put it in a cgroup that potentially limits these
		 * possibilities */
		if (lxc_sync_wait_child(handler, LXC_SYNC_CONFIGURE))
			return -1;

		if (!elevated_privileges && lxc_attach_proc_to_cgroups(pid, init_ctx))
			return -1;

		/* tell the child we are done initializing */
		if (lxc_sync_wake_child(handler, LXC_SYNC_POST_CONFIGURE))
			return -1;

		lxc_sync_fini(handler);

	again:
		if (waitpid(pid, &status, 0) < 0) {
			if (errno == EINTR)
				goto again;
			SYSERROR("failed to wait '%d'", pid);
			return -1;
		}

		if (WIFEXITED(status))
			return WEXITSTATUS(status);

		return -1;
	}

	if (!pid) {
		lxc_sync_fini_parent(handler);

		curdir = get_current_dir_name();

		ret = lxc_attach_to_ns(init_pid);
		if (ret < 0) {
			ERROR("failed to enter the namespace");
			return -1;
		}

		if (curdir && chdir(curdir))
			WARN("could not change directory to '%s'", curdir);

		free(curdir);

		if (new_personality < 0)
			new_personality = init_ctx->personality;

		if (personality(new_personality) == -1) {
			ERROR("could not ensure correct architecture: %s",
			      strerror(errno));
			return -1;
		}

		if (!elevated_privileges && lxc_attach_drop_privs(init_ctx)) {
			ERROR("could not drop privileges");
			return -1;
		}

		/* tell parent we are done setting up the container and wait
		 * until we have been put in the container's cgroup, if
		 * applicable */
		if (lxc_sync_barrier_parent(handler, LXC_SYNC_CONFIGURE))
			return -1;

		lxc_sync_fini(handler);

		if (my_args.argc) {
			execve(my_args.argv[0], my_args.argv, envp);
			SYSERROR("failed to exec '%s'", my_args.argv[0]);
			return -1;
		}

		uid = getuid();

		passwd = getpwuid(uid);
		if (!passwd) {
			SYSERROR("failed to get passwd "		\
				 "entry for uid '%d'", uid);
			return -1;
		}

		{
			char *const args[] = {
				passwd->pw_shell,
				NULL,
			};

			execve(args[0], args, envp);
			SYSERROR("failed to exec '%s'", args[0]);
			return -1;
		}

	}

	return 0;
}

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
#include <stdio.h>
#undef _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <libgen.h>
#include <getopt.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pwd.h>

#include "caps.h"
#include "log.h"
#include "namespace.h"
#include "cgroup.h"
#include "error.h"

lxc_log_define(lxc_unshare_ui, lxc);

void usage(char *cmd)
{
	fprintf(stderr, "%s <options> command [command_arguments]\n", basename(cmd));
	fprintf(stderr, "Options are:\n");
	fprintf(stderr, "\t -s flags: ORed list of flags to unshare:\n" \
			"\t           MOUNT, PID, UTSNAME, IPC, USER, NETWORK\n");
	fprintf(stderr, "\t -u <id> : new id to be set if -s USER is specified\n");
	_exit(1);
}

static uid_t lookup_user(const char *optarg)
{
	char name[sysconf(_SC_LOGIN_NAME_MAX)];
	uid_t uid = -1;
	struct passwd *pwent = NULL;

	if (!optarg || (optarg[0] == '\0'))
		return uid;

	if (sscanf(optarg, "%u", &uid) < 1) {
		/* not a uid -- perhaps a username */
		if (sscanf(optarg, "%s", name) < 1)
			return uid;

		pwent = getpwnam(name);
		if (!pwent) {
			ERROR("invalid username %s", name);
			return uid;
		}
		uid = pwent->pw_uid;
	} else {
		pwent = getpwuid(uid);
		if (!pwent) {
			ERROR("invalid uid %d", uid);
			uid = -1;
			return uid;
		}
	}
	return uid;
}


struct start_arg {
	char ***args;
	int *flags;
	uid_t *uid;
};

static int do_start(void *arg)
{
	struct start_arg *start_arg = arg;
	char **args = *start_arg->args;
	int flags = *start_arg->flags;
	uid_t uid = *start_arg->uid;

	if (flags & CLONE_NEWUSER && setuid(uid)) {
		ERROR("failed to set uid %d: %s", uid, strerror(errno));
		exit(1);
	}

	execvp(args[0], args);

	ERROR("failed to exec: '%s': %s", args[0], strerror(errno));
	return 1;
}

int main(int argc, char *argv[])
{
	int opt, status;
	int ret;
	char *namespaces = NULL;
	char **args;
	int flags = 0;
	uid_t uid = -1; /* valid only if (flags & CLONE_NEWUSER) */
	pid_t pid;

	struct start_arg start_arg = {
		.args = &args,
		.uid = &uid,
		.flags = &flags,
	};

	while ((opt = getopt(argc, argv, "s:u:h")) != -1) {
		switch (opt) {
		case 's':
			namespaces = optarg;
			break;
		case 'h':
			usage(argv[0]);
		case 'u':
			uid = lookup_user(optarg);
			if (uid == -1)
				return 1;
		}
	}

	if (argv[optind] == NULL) {
		ERROR("a command to execute in the new namespace is required");
		return 1;
	}

	args = &argv[optind];

	ret = lxc_caps_init();
	if (ret)
		return ret;

	ret = lxc_fill_namespace_flags(namespaces, &flags);
	if (ret)
		usage(argv[0]);

	if (!(flags & CLONE_NEWUSER) && uid != -1) {
		ERROR("-u <uid> needs -s USER option");
		return 1;
	}

	pid = lxc_clone(do_start, &start_arg, flags);
	if (pid < 0) {
		ERROR("failed to clone");
		return -1;
	}

	if (waitpid(pid, &status, 0) < 0) {
		ERROR("failed to wait for '%d'", pid);
		return -1;
	}

	return  lxc_error_set_and_log(pid, status);
}

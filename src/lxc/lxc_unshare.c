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
#include <sys/socket.h>
#include <netinet/in.h>

#include "caps.h"
#include "log.h"
#include "namespace.h"
#include "network.h"
#include "utils.h"
#include "cgroup.h"
#include "error.h"

lxc_log_define(lxc_unshare_ui, lxc);

struct my_iflist
{
  char *mi_ifname;
  struct my_iflist *mi_next;
};

void usage(char *cmd)
{
	fprintf(stderr, "%s <options> command [command_arguments]\n", basename(cmd));
	fprintf(stderr, "Options are:\n");
	fprintf(stderr, "\t -s flags   : ORed list of flags to unshare:\n" \
			"\t           MOUNT, PID, UTSNAME, IPC, USER, NETWORK\n");
	fprintf(stderr, "\t -u <id>      : new id to be set if -s USER is specified\n");
	fprintf(stderr, "\t -i <iface>   : Interface name to be moved into container (presumably with NETWORK unsharing set)\n");
	fprintf(stderr, "\t -H <hostname>: Set the hostname in the container\n");
	fprintf(stderr, "\t -D           : Daemonize (do not wait for container to exit)\n");
	fprintf(stderr, "\t -M           : reMount default fs inside container (/proc /dev/shm /dev/mqueue)\n");
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
        int want_default_mounts;
        const char *want_hostname;
};

static int do_start(void *arg)
{
	struct start_arg *start_arg = arg;
	char **args = *start_arg->args;
	int flags = *start_arg->flags;
	uid_t uid = *start_arg->uid;
	int want_default_mounts = start_arg->want_default_mounts;
	const char *want_hostname = start_arg->want_hostname;

	if ((flags & CLONE_NEWNS) && want_default_mounts)
		lxc_setup_fs();

	if ((flags & CLONE_NEWUTS) && want_hostname)
		if (sethostname(want_hostname, strlen(want_hostname)) < 0) {
			ERROR("failed to set hostname %s: %s", want_hostname, strerror(errno));
			exit(1);
		}

	// Setuid is useful even without a new user id space
	if ( uid >= 0 && setuid(uid)) {
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
	int daemonize = 0;
	uid_t uid = -1; /* valid only if (flags & CLONE_NEWUSER) */
	pid_t pid;
	struct my_iflist *tmpif, *my_iflist = NULL;
	struct start_arg start_arg = {
		.args = &args,
		.uid = &uid,
		.flags = &flags,
		.want_hostname = NULL,
		.want_default_mounts = 0,
	};

	while ((opt = getopt(argc, argv, "s:u:hH:i:DM")) != -1) {
		switch (opt) {
		case 's':
			namespaces = optarg;
			break;
		case 'i':
			if (!(tmpif = malloc(sizeof(*tmpif)))) {
				perror("malloc");
				exit(1);
			}
			tmpif->mi_ifname = optarg;
			tmpif->mi_next = my_iflist;
			my_iflist = tmpif;
			break;
		case 'D':
			daemonize = 1;
			break;
		case 'M':
			start_arg.want_default_mounts = 1;
			break;
		case 'H':
			start_arg.want_hostname = optarg;
			break;
		case 'h':
			usage(argv[0]);
			break;
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

	if (!(flags & CLONE_NEWNET) && my_iflist) {
		ERROR("-i <interfacename> needs -s NETWORK option");
		return 1;
	}

	if (!(flags & CLONE_NEWUTS) && start_arg.want_hostname) {
		ERROR("-H <hostname> needs -s UTSNAME option");
		return 1;
	}

	if (!(flags & CLONE_NEWNS) && start_arg.want_default_mounts) {
		ERROR("-M needs -s MOUNT option");
		return 1;
	}

	pid = lxc_clone(do_start, &start_arg, flags);
	if (pid < 0) {
		ERROR("failed to clone");
		return -1;
	}

	if (my_iflist) {
		for (tmpif = my_iflist; tmpif; tmpif = tmpif->mi_next) {
			if (lxc_netdev_move_by_name(tmpif->mi_ifname, pid) < 0)
				fprintf(stderr,"Could not move interface %s into container %d: %s\n", tmpif->mi_ifname, pid, strerror(errno));
		}
	}

	if (daemonize)
		exit(0);

	if (waitpid(pid, &status, 0) < 0) {
		ERROR("failed to wait for '%d'", pid);
		return -1;
	}

	return  lxc_error_set_and_log(pid, status);
}

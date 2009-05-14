/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2008
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
#include <stdio.h>
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

#include <lxc/lxc.h>

lxc_log_define(lxc_unshare, lxc);

void usage(char *cmd)
{
	fprintf(stderr, "%s <options> [command]\n", basename(cmd));
	fprintf(stderr, "Options are:\n");
	fprintf(stderr, "\t -f      : fork and unshare (automatic when unsharing the pids)\n");
	fprintf(stderr, "\t -s flags: Ored list of flags to unshare:\n" \
			"\t           MOUNT, PID, UTSNAME, IPC, USER, NETWORK\n");
	fprintf(stderr, "\t -u <id> : new id to be set if -s USER is specified\n");
	fprintf(stderr, "\t if -f or -s PID is specified, <command> is mandatory)\n");
	fprintf(stderr, "\t[-o <logfile>]    : path of the log file\n");
	fprintf(stderr, "\t[-l <logpriority>]: log level priority\n");
	_exit(1);
}

static uid_t lookup_user(const char *optarg)
{
	int bufflen = sysconf(_SC_GETPW_R_SIZE_MAX);
	char buff[bufflen];
	char name[sysconf(_SC_LOGIN_NAME_MAX)];
	uid_t uid = -1;
	struct passwd pwent;
	struct passwd *pent;

	if (!optarg || (optarg[0] == '\0'))
		return uid;

	if (sscanf(optarg, "%u", &uid) < 1) {
		/* not a uid -- perhaps a username */
		if (sscanf(optarg, "%s", name) < 1)
			return uid;

		if (getpwnam_r(name, &pwent, buff, bufflen, &pent) || !pent) {
			ERROR("invalid username %s", name);
			return uid;
		}
		uid = pent->pw_uid;
	} else {
		if (getpwuid_r(uid, &pwent, buff, bufflen, &pent) || !pent) {
			ERROR("invalid uid %d", uid);
			uid = -1;
			return uid;
		}
	}
	return uid;
}

static char *namespaces_list[] = {
	"MOUNT", "PID", "UTSNAME", "IPC",
	"USER", "NETWORK"
};
static int cloneflags_list[] = {
	CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWUTS, CLONE_NEWIPC,
	CLONE_NEWUSER, CLONE_NEWNET
};

static int lxc_namespace_2_cloneflag(char *namespace)
{
	int i, len;
	len = sizeof(namespaces_list)/sizeof(namespaces_list[0]);
	for (i = 0; i < len; i++)
		if (!strcmp(namespaces_list[i], namespace))
			return cloneflags_list[i];

	ERROR("invalid namespace name %s", namespace);
	return -1;
}

static int lxc_fill_namespace_flags(char *flaglist, long *flags)
{
	char *token, *saveptr = NULL;
	int aflag;

	if (!flaglist) {
		ERROR("need at least one namespace to unshare");
		return -1;
	}

	token = strtok_r(flaglist, "|", &saveptr);
	while (token) {

		aflag = lxc_namespace_2_cloneflag(token);
		if (aflag < 0)
			return -1;

		*flags |= aflag;

		token = strtok_r(NULL, "|", &saveptr);
	}
	return 0;
}

int main(int argc, char *argv[])
{
	int opt, status = 1, hastofork = 0;
	int ret;
	char *namespaces = NULL;
	char **args;
	const char *log_file = NULL, *log_priority = NULL;
	long flags = 0;
	uid_t uid = -1; /* valid only if (flags & CLONE_NEWUSER) */
	pid_t pid;

	while ((opt = getopt(argc, argv, "fs:u:o:l:")) != -1) {
		switch (opt) {
		case 's':
			namespaces = optarg;
			break;
		case 'u':
			uid = lookup_user(optarg);
			if (uid == -1)
				return 1;
		case 'f':
			hastofork = 1;
			break;
		case 'o':
			log_file = optarg;
			break;
		case 'l':
			log_priority = optarg;
			break;
		}
	}

	args = &argv[optind];

	if (lxc_log_init(log_file, log_priority, basename(argv[0])))
		return 1;

        ret = lxc_fill_namespace_flags(namespaces, &flags);
	if (ret)
		usage(argv[0]);

	if (!(flags & CLONE_NEWUSER) && uid != -1) {
		ERROR("-u <uid> need -s USER option");
		return 1;
	}

	if ((flags & CLONE_NEWPID) || hastofork) {

		if (!argv[optind] || !strlen(argv[optind]))
			usage(argv[0]);

		pid = fork_ns(flags);

		if (pid < 0) {
			ERROR("failed to fork into a new namespace: %s",
				strerror(errno));
			return 1;
		}

		if (!pid) {
			if (flags & CLONE_NEWUSER && setuid(uid)) {
				ERROR("failed to set uid %d: %s",
					uid, strerror(errno));
				exit(1);
			}

			execvp(args[0], args);
			ERROR("failed to exec: '%s': %s",
				argv[0], strerror(errno));
			exit(1);
		}
		
		if (waitpid(pid, &status, 0) < 0)
			ERROR("failed to wait for '%d'", pid);
		
		return status;
	}

	if (unshare_ns(flags)) {
		ERROR("failed to unshare the current process: %s",
			strerror(errno));
		return 1;
	}

	if (flags & CLONE_NEWUSER && setuid(uid)) {
		ERROR("failed to set uid %d: %s",
			uid, strerror(errno));
		return 1;
	}

	if (argv[optind] && strlen(argv[optind])) {
		execvp(args[0], args);
		ERROR("failed to exec: '%s': %s",
			argv[0], strerror(errno));
		return 1;
	}

	return 0;
}


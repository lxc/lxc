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
#include <fcntl.h>
#include <getopt.h>
#include <libgen.h>
#include <pwd.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "arguments.h"
#include "caps.h"
#include "list.h"
#include "log.h"
#include "namespace.h"
#include "utils.h"

lxc_log_define(lxc_unshare, lxc);

struct start_arg {
	char *const *args;
	int flags;
	uid_t uid;
	bool setuid;
	int want_default_mounts;
	int wait_fd;
	const char *want_hostname;
};

static int my_parser(struct lxc_arguments *args, int c, char *arg);
static inline int sethostname_including_android(const char *name, size_t len);
static int get_namespace_flags(char *namespaces);
static bool lookup_user(const char *optarg, uid_t *uid);
static int mount_fs(const char *source, const char *target, const char *type);
static void lxc_setup_fs(void);
static int do_start(void *arg);
static void free_ifname_list(void);

static struct lxc_list ifnames;

static const struct option my_longopts[] = {
	{"namespaces", required_argument, 0, 's'},
	{"user", required_argument, 0, 'u'},
	{"hostname", required_argument, 0, 'H'},
	{"ifname", required_argument, 0, 'i'},
	{"daemon", no_argument, 0, 'd'},
	{"remount", no_argument, 0, 'M'},
	LXC_COMMON_OPTIONS
};

static struct lxc_arguments my_args = {
	.progname     = "lxc-unshare",
	.help         = "\
-s NAMESPACES COMMAND\n\
\n\
lxc-unshare run a COMMAND in a new set of NAMESPACES\n\
\n\
Options :\n\
  -s, --namespaces=FLAGS\n\
                    ORed list of flags to unshare:\n\
                    MOUNT, PID, UTSNAME, IPC, USER, NETWORK\n\
  -u, --user=USERID\n\
                    new id to be set if -s USER is specified\n\
  -H, --hostname=HOSTNAME\n\
                    Set the hostname in the container\n\
  -i, --ifname=IFNAME\n\
                    Interface name to be moved into container (presumably with NETWORK unsharing set)\n\
  -d, --daemon      Daemonize (do not wait for container to exit)\n\
  -M, --remount     Remount default fs inside container (/proc /dev/shm /dev/mqueue)\n\
",
	.options      = my_longopts,
	.parser       = my_parser,
	.checker      = NULL,
	.log_priority = "ERROR",
	.log_file     = "none",
	.daemonize    = 0,
	.pidfile      = NULL,
};

static int my_parser(struct lxc_arguments *args, int c, char *arg)
{
	struct lxc_list *tmplist;

	switch (c) {
	case 's':
		args->flags = get_namespace_flags(arg);
		if (args->flags < 0)
			return -1;
		break;
	case 'u':
		if (!lookup_user(arg, &args->uid))
			return -1;

		args->setuid = true;
		break;
	case 'H':
		args->want_hostname = arg;
		break;
	case 'i':
		tmplist = malloc(sizeof(*tmplist));
		if (!tmplist) {
			SYSERROR("Failed to alloc lxc list");
			free_ifname_list();
			return -1;
		}

		lxc_list_add_elem(tmplist, arg);
		lxc_list_add_tail(&ifnames, tmplist);
		break;
	case 'd':
		args->daemonize = 1;
		break;
	case 'M':
		args->want_default_mounts = 1;
		break;
	}
	return 0;
}

/* Define sethostname() if missing from the C library also workaround some
 * quirky with having this defined in multiple places.
 */
static inline int sethostname_including_android(const char *name, size_t len)
{
#ifndef HAVE_SETHOSTNAME
#ifdef __NR_sethostname
	return syscall(__NR_sethostname, name, len);
#else
	errno = ENOSYS;
	return -1;
#endif
#else
	return sethostname(name, len);
#endif
}

static int get_namespace_flags(char *namespaces)
{
	int flags = 0;

	if (lxc_namespace_2_std_identifiers(namespaces) < 0)
		return -1;

	if (lxc_fill_namespace_flags(namespaces, &flags) < 0)
		return -1;

	return flags;
}

static bool lookup_user(const char *optarg, uid_t *uid)
{
	char name[MAXPATHLEN];
	struct passwd pwent;
	struct passwd *pwentp = NULL;
	char *buf;
	size_t bufsize;
	int ret;

	if (!optarg || (optarg[0] == '\0'))
		return false;

	bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (bufsize == -1)
		bufsize = 1024;

	buf = malloc(bufsize);
	if (!buf)
		return false;

	if (sscanf(optarg, "%u", uid) < 1) {
		/* not a uid -- perhaps a username */
		if (sscanf(optarg, "%s", name) < 1) {
			free(buf);
			return false;
		}

		ret = getpwnam_r(name, &pwent, buf, bufsize, &pwentp);
		if (!pwentp) {
			if (ret == 0)
				SYSERROR("Could not find matched password record");

			SYSERROR("Invalid username \"%s\"", name);
			free(buf);
			return false;
		}

		*uid = pwent.pw_uid;
	} else {
		ret = getpwuid_r(*uid, &pwent, buf, bufsize, &pwentp);
		if (!pwentp) {
			if (ret == 0)
				SYSERROR("Could not find matched password record");

			SYSERROR("Invalid uid : %u", *uid);
			free(buf);
			return false;
		}
	}

	free(buf);
	return true;
}

static int mount_fs(const char *source, const char *target, const char *type)
{
	/* the umount may fail */
	if (umount(target) < 0)

	if (mount(source, target, type, 0, NULL) < 0)
		return -1;

	return 0;
}

static void lxc_setup_fs(void)
{
	(void)mount_fs("proc", "/proc", "proc");

	/* if /dev has been populated by us, /dev/shm does not exist */
	if (access("/dev/shm", F_OK))
		(void)mkdir("/dev/shm", 0777);

	/* if we can't mount /dev/shm, continue anyway */
	(void)mount_fs("shmfs", "/dev/shm", "tmpfs");

	/* If we were able to mount /dev/shm, then /dev exists */
	/* Sure, but it's read-only per config :) */
	if (access("/dev/mqueue", F_OK))
		(void)mkdir("/dev/mqueue", 0666);

	/* continue even without posix message queue support */
	(void)mount_fs("mqueue", "/dev/mqueue", "mqueue");
}

static int do_start(void *arg)
{
	int ret;
	uint64_t wait_val;
	struct start_arg *start_arg = arg;
	char *const *args = start_arg->args;
	const char *want_hostname = start_arg->want_hostname;

	if (start_arg->setuid) {
		/* waiting until uid maps is set */
		ret = lxc_read_nointr(start_arg->wait_fd, &wait_val, sizeof(wait_val));
		if (ret == -1) {
			SYSERROR("Failed to read eventfd");
			close(start_arg->wait_fd);
			_exit(EXIT_FAILURE);
		}
	}

	if ((start_arg->flags & CLONE_NEWNS) && start_arg->want_default_mounts)
		lxc_setup_fs();

	if ((start_arg->flags & CLONE_NEWUTS) && want_hostname)
		if (sethostname_including_android(want_hostname, strlen(want_hostname)) < 0) {
			SYSERROR("Failed to set hostname %s", want_hostname);
			_exit(EXIT_FAILURE);
		}

	/* Setuid is useful even without a new user id space. */
	if (start_arg->setuid && setuid(start_arg->uid)) {
		SYSERROR("Failed to set uid %d", start_arg->uid);
		_exit(EXIT_FAILURE);
	}

	execvp(args[0], args);

	SYSERROR("Failed to exec: '%s'", args[0]);
	return 1;
}

static void free_ifname_list(void)
{
	struct lxc_list *iterator, *next;

	lxc_list_for_each_safe (iterator, &ifnames, next) {
		lxc_list_del(iterator);
		free(iterator);
	}
}

int main(int argc, char *argv[])
{
	int ret;
	pid_t pid;
	struct lxc_log log;
	struct start_arg start_arg;

	lxc_list_init(&ifnames);

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

	if (lxc_log_init(&log)) {
		free_ifname_list();
		exit(EXIT_FAILURE);
	}

	if (!*my_args.argv) {
		ERROR("A command to execute in the new namespace is required");
		free_ifname_list();
		exit(EXIT_FAILURE);
	}

	if (my_args.flags == 0) {
		ERROR("A namespace to execute command is required");
		free_ifname_list();
		exit(EXIT_FAILURE);
	}

	if (!(my_args.flags & CLONE_NEWNET) && lxc_list_len(&ifnames) > 0) {
		ERROR("-i <interfacename> needs -s NETWORK option");
		free_ifname_list();
		exit(EXIT_FAILURE);
	}

	if (!(my_args.flags & CLONE_NEWUTS) && my_args.want_hostname) {
		ERROR("-H <hostname> needs -s UTSNAME option");
		free_ifname_list();
		exit(EXIT_FAILURE);
	}

	if (!(my_args.flags & CLONE_NEWNS) && my_args.want_default_mounts) {
		ERROR("-M needs -s MOUNT option");
		free_ifname_list();
		exit(EXIT_FAILURE);
	}

	if (my_args.setuid) {
		start_arg.wait_fd = eventfd(0, EFD_CLOEXEC);
		if (start_arg.wait_fd < 0) {
			SYSERROR("Failed to create eventfd");
			free_ifname_list();
			exit(EXIT_FAILURE);
		}
	}

	/* set start arguments for lxc_clone from lxc_arguments */
	start_arg.args = my_args.argv;
	start_arg.uid = my_args.uid;	/* valid only if (flags & CLONE_NEWUSER) */
	start_arg.setuid = my_args.setuid;
	start_arg.flags = my_args.flags;
	start_arg.want_hostname = my_args.want_hostname;
	start_arg.want_default_mounts = my_args.want_default_mounts;

	pid = lxc_clone(do_start, &start_arg, my_args.flags);
	if (pid < 0) {
		ERROR("Failed to clone");
		free_ifname_list();
		exit(EXIT_FAILURE);
	}

	if (my_args.setuid) {
		uint64_t wait_val = 1;
		/* enough space to accommodate uids */
		char *umap = (char *)alloca(100);

		/* create new uid mapping using current UID and the one
		 * specified as parameter
		 */
		ret = snprintf(umap, 100, "%d %d 1\n" , my_args.uid, getuid());
		if (ret < 0 || ret >= 100) {
			ERROR("snprintf is failed");
			free_ifname_list();
			close(start_arg.wait_fd);
			exit(EXIT_FAILURE);
		}

		ret = write_id_mapping(ID_TYPE_UID, pid, umap, strlen(umap));
		if (ret < 0) {
			ERROR("Failed to map uid");
			free_ifname_list();
			close(start_arg.wait_fd);
			exit(EXIT_FAILURE);
		}

		ret = lxc_write_nointr(start_arg.wait_fd, &wait_val, sizeof(wait_val));
		if (ret < 0) {
			SYSERROR("Failed to write eventfd");
			free_ifname_list();
			close(start_arg.wait_fd);
			exit(EXIT_FAILURE);
		}
	}

	if (lxc_list_len(&ifnames) > 0) {
		struct lxc_list *iterator;
		char* ifname;
		pid_t pid;

		lxc_list_for_each(iterator, &ifnames) {
			ifname = iterator->elem;
			if (!ifname)
				continue;

			pid = fork();
			if (pid < 0) {
				SYSERROR("Failed to move network device \"%s\" to network namespace",
				         ifname);
				continue;
			}

			if (pid == 0) {
				char buf[256];

				ret = snprintf(buf, 256, "%d", pid);
				if (ret < 0 || ret >= 256)
					_exit(EXIT_FAILURE);

				execlp("ip", "ip", "link", "set", "dev", ifname, "netns", buf, (char *)NULL);
				_exit(EXIT_FAILURE);
			}

			if (wait_for_pid(pid) != 0)
				SYSERROR("Could not move interface \"%s\" into container %d",
				         ifname, pid);
		}

		free_ifname_list();
	}

	if (my_args.daemonize)
		exit(EXIT_SUCCESS);

	if (wait_for_pid(pid) != 0) {
		SYSERROR("Failed to wait for '%d'", pid);
		exit(EXIT_FAILURE);
	}

	/* Call exit() directly on this function because it retuns an exit code. */
	exit(EXIT_SUCCESS);
}

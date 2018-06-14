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
#include "config.h"

#include <stdio.h>
#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <netinet/in.h>
#include <pwd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "caps.h"
#include "cgroup.h"
#include "error.h"
#include "log.h"
#include "namespace.h"
#include "network.h"
#include "utils.h"

struct my_iflist
{
	char *mi_ifname;
	struct my_iflist *mi_next;
};

static void usage(char *cmd)
{
	fprintf(stderr, "%s <options> command [command_arguments]\n", basename(cmd));
	fprintf(stderr, "Options are:\n");
	fprintf(stderr, "\t -s flags   : ORed list of flags to unshare:\n" \
			"\t           MOUNT, PID, UTSNAME, IPC, USER, NETWORK\n");
	fprintf(stderr, "\t -u <id>      : new id to be set if -s USER is specified\n");
	fprintf(stderr, "\t -i <iface>   : Interface name to be moved into container (presumably with NETWORK unsharing set)\n");
	fprintf(stderr, "\t -H <hostname>: Set the hostname in the container\n");
	fprintf(stderr, "\t -d           : Daemonize (do not wait for container to exit)\n");
	fprintf(stderr, "\t -M           : Remount default fs inside container (/proc /dev/shm /dev/mqueue)\n");
	_exit(EXIT_SUCCESS);
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
				fprintf(stderr, "could not find matched password record\n");

			fprintf(stderr, "invalid username %s\n", name);
			free(buf);
			return false;
		}
		*uid = pwent.pw_uid;
	} else {
		ret = getpwuid_r(*uid, &pwent, buf, bufsize, &pwentp);
		if (!pwentp) {
			if (ret == 0)
				fprintf(stderr, "could not find matched password record\n");

			fprintf(stderr, "invalid uid %u\n", *uid);
			free(buf);
			return false;
		}
	}

	free(buf);
	return true;
}

struct start_arg {
	char ***args;
	int *flags;
	uid_t *uid;
	bool setuid;
	int want_default_mounts;
	int wait_fd;
	const char *want_hostname;
};

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
	char **args = *start_arg->args;
	int flags = *start_arg->flags;
	uid_t uid = *start_arg->uid;
	int want_default_mounts = start_arg->want_default_mounts;
	const char *want_hostname = start_arg->want_hostname;
	int wait_fd = start_arg->wait_fd;

	if (start_arg->setuid) {
		/* waiting until uid maps is set */
		ret = read(wait_fd, &wait_val, sizeof(wait_val));
		if (ret == -1) {
			close(wait_fd);
			fprintf(stderr, "read eventfd failed\n");
			exit(EXIT_FAILURE);
		}
	}

	if ((flags & CLONE_NEWNS) && want_default_mounts)
		lxc_setup_fs();

	if ((flags & CLONE_NEWUTS) && want_hostname)
		if (sethostname(want_hostname, strlen(want_hostname)) < 0) {
			fprintf(stderr, "failed to set hostname %s: %s\n", want_hostname, strerror(errno));
			exit(EXIT_FAILURE);
		}

	// Setuid is useful even without a new user id space
	if (start_arg->setuid && setuid(uid)) {
		fprintf(stderr, "failed to set uid %d: %s\n", uid, strerror(errno));
		exit(EXIT_FAILURE);
	}

	execvp(args[0], args);

	fprintf(stderr, "failed to exec: '%s': %s\n", args[0], strerror(errno));
	return 1;
}

int main(int argc, char *argv[])
{
	char *del;
	char **it, **args;
	int opt, status;
	int ret;
	char *namespaces = NULL;
	int flags = 0, daemonize = 0;
	uid_t uid = 0; /* valid only if (flags & CLONE_NEWUSER) */
	pid_t pid;
	uint64_t wait_val = 1;
	struct my_iflist *tmpif, *my_iflist = NULL;
	struct start_arg start_arg = {
		.args = &args,
		.uid = &uid,
		.setuid = false,
		.flags = &flags,
		.want_hostname = NULL,
		.want_default_mounts = 0,
	};

	while ((opt = getopt(argc, argv, "s:u:hH:i:dM")) != -1) {
		switch (opt) {
		case 's':
			namespaces = optarg;
			break;
		case 'i':
			if (!(tmpif = malloc(sizeof(*tmpif)))) {
				perror("malloc");
				exit(EXIT_FAILURE);
			}
			tmpif->mi_ifname = optarg;
			tmpif->mi_next = my_iflist;
			my_iflist = tmpif;
			break;
		case 'd':
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
			if (!lookup_user(optarg, &uid))
				exit(EXIT_FAILURE);
			start_arg.setuid = true;
		}
	}

	if (argv[optind] == NULL) {
		fprintf(stderr, "a command to execute in the new namespace is required\n");
		exit(EXIT_FAILURE);
	}

	args = &argv[optind];

	ret = lxc_caps_init();
	if (ret)
		exit(EXIT_FAILURE);

	/* The identifiers for namespaces used with lxc-unshare as given on the
	 * manpage do not align with the standard identifiers. This affects
	 * network, mount, and uts namespaces. The standard identifiers are:
	 * "mnt", "uts", and "net" whereas lxc-unshare uses "MOUNT", "UTSNAME",
	 * and "NETWORK". So let's use some cheap memmove()s to replace them by
	 * their standard identifiers. Let's illustrate this with an example:
	 * Assume the string:
	 *
	 *	"IPC|MOUNT|PID"
	 *
	 * then we memmove()
	 *
	 *	dest: del + 1 == OUNT|PID
	 *	src:  del + 3 == NT|PID
	 */
	if (!namespaces)
		usage(argv[0]);

	while ((del = strstr(namespaces, "MOUNT")))
		memmove(del + 1, del + 3, strlen(del) - 2);

	for (it = (char *[]){"NETWORK", "UTSNAME", NULL}; it && *it; it++)
		while ((del = strstr(namespaces, *it)))
			memmove(del + 3, del + 7, strlen(del) - 6);

	ret = lxc_fill_namespace_flags(namespaces, &flags);
	if (ret)
		usage(argv[0]);

	if (!(flags & CLONE_NEWNET) && my_iflist) {
		fprintf(stderr, "-i <interfacename> needs -s NETWORK option\n");
		exit(EXIT_FAILURE);
	}

	if (!(flags & CLONE_NEWUTS) && start_arg.want_hostname) {
		fprintf(stderr, "-H <hostname> needs -s UTSNAME option\n");
		exit(EXIT_FAILURE);
	}

	if (!(flags & CLONE_NEWNS) && start_arg.want_default_mounts) {
		fprintf(stderr, "-M needs -s MOUNT option\n");
		exit(EXIT_FAILURE);
	}

	if (start_arg.setuid) {
		start_arg.wait_fd = eventfd(0, EFD_CLOEXEC);
		if (start_arg.wait_fd < 0) {
			fprintf(stderr, "failed to create eventfd\n");
			exit(EXIT_FAILURE);
		}
	}

	pid = lxc_clone(do_start, &start_arg, flags);
	if (pid < 0) {
		fprintf(stderr, "failed to clone\n");
		exit(EXIT_FAILURE);
	}

	if (start_arg.setuid) {
		/* enough space to accommodate uids */
		char *umap = (char *)alloca(100);

		/* create new uid mapping using current UID and the one
		 * specified as parameter
		 */
		ret = snprintf(umap, 100, "%d %d 1\n" , *(start_arg.uid), getuid());
		if (ret < 0 || ret >= 100) {
			close(start_arg.wait_fd);
			fprintf(stderr, "snprintf failed");
			exit(EXIT_FAILURE);
		}

		ret = write_id_mapping(ID_TYPE_UID, pid, umap, strlen(umap));
		if (ret < 0) {
			close(start_arg.wait_fd);
			fprintf(stderr, "uid mapping failed\n");
			exit(EXIT_FAILURE);
		}

		ret = write(start_arg.wait_fd, &wait_val, sizeof(wait_val));
		if (ret < 0) {
			close(start_arg.wait_fd);
			fprintf(stderr, "write to eventfd failed\n");
			exit(EXIT_FAILURE);
		}
	}

	if (my_iflist) {
		for (tmpif = my_iflist; tmpif; tmpif = tmpif->mi_next) {
			if (lxc_netdev_move_by_name(tmpif->mi_ifname, pid, NULL) < 0)
				fprintf(stderr,"Could not move interface %s into container %d: %s\n", tmpif->mi_ifname, pid, strerror(errno));
		}
	}

	if (daemonize)
		exit(EXIT_SUCCESS);

	if (waitpid(pid, &status, 0) < 0) {
		fprintf(stderr, "failed to wait for '%d'\n", pid);
		exit(EXIT_FAILURE);
	}

	/* Call exit() directly on this function because it retuns an exit code. */
	exit(lxc_error_set_and_log(pid, status));
}

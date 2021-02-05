/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <libgen.h>
#include <pwd.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "compiler.h"
#include "conf.h"
#include "config.h"
#include "list.h"
#include "log.h"
#include "macro.h"
#include "memory_utils.h"
#include "file_utils.h"
#include "string_utils.h"
#include "syscall_wrappers.h"
#include "utils.h"

__hidden extern int lxc_log_fd;

static void usage(const char *name)
{
	printf("usage: %s [-h] [-m <uid-maps>] [-s] -- [command [arg ..]]\n", name);
	printf("\n");
	printf("  -h            this message\n");
	printf("\n");
	printf("  -m <uid-maps> uid maps to use\n");
	printf("\n");
	printf("  -s:           map self\n");
	printf("  uid-maps: [u|g|b]:ns_id:host_id:range\n");
	printf("            [u|g|b]: map user id, group id, or both\n");
	printf("            ns_id: the base id in the new namespace\n");
	printf("            host_id: the base id in the parent namespace\n");
	printf("            range: how many ids to map\n");
	printf("  Note: This program uses newuidmap(2) and newgidmap(2).\n");
	printf("        As such, /etc/subuid and /etc/subgid must grant the\n");
	printf("        calling user permission to use the mapped ranges\n");
}

static void opentty(const char *tty, int which)
{
	int fd, flags, ret;

	if (tty[0] == '\0')
		return;

	fd = open(tty, O_RDWR | O_NONBLOCK);
	if (fd < 0) {
		CMD_SYSINFO("Failed to open tty");
		return;
	}

	flags = fcntl(fd, F_GETFL);
	flags &= ~O_NONBLOCK;
	ret = fcntl(fd, F_SETFL, flags);
	if (ret < 0) {
		CMD_SYSINFO("Failed to remove O_NONBLOCK from file descriptor %d", fd);
		close(fd);
		return;
	}

	close(which);
	if (fd != which) {
		(void)dup2(fd, which);
		close(fd);
	}
}
/* Code copy end */

static int do_child(void *vargv)
{
	int ret;
	char **argv = (char **)vargv;

	if (!lxc_drop_groups() && errno != EPERM)
		return -1;

	/* Assume we want to become root */
	if (!lxc_switch_uid_gid(0, 0))
		return -1;

	ret = unshare(CLONE_NEWNS);
	if (ret < 0) {
		CMD_SYSERROR("Failed to unshare mount namespace");
		return -1;
	}

	if (detect_shared_rootfs()) {
		ret = mount(NULL, "/", NULL, MS_SLAVE | MS_REC, NULL);
		if (ret < 0) {
			CMD_SYSINFO("Failed to recursively turn root mount tree into dependent mount");
			return -1;
		}
	}

	execvp(argv[0], argv);
	CMD_SYSERROR("Failed to execute \"%s\"", argv[0]);
	return -1;
}

static struct lxc_list active_map;

static int add_map_entry(long host_id, long ns_id, long range, int which)
{
	struct lxc_list *tmp = NULL;
	struct id_map *newmap;

	newmap = malloc(sizeof(*newmap));
	if (!newmap)
		return -1;

	newmap->hostid = host_id;
	newmap->nsid = ns_id;
	newmap->range = range;
	newmap->idtype = which;
	tmp = malloc(sizeof(*tmp));
	if (!tmp) {
		free(newmap);
		return -1;
	}

	tmp->elem = newmap;
	lxc_list_add_tail(&active_map, tmp);
	return 0;
}

/*
 * Given a string like "b:0:100000:10", map both uids and gids 0-10 to 100000
 * to 100010
 */
static int parse_map(char *map)
{
	int i, ret, idtype;
	long host_id, ns_id, range;
	char which;
	char types[2] = {'u', 'g'};

	if (!map)
		return -1;

	ret = sscanf(map, "%c:%ld:%ld:%ld", &which, &ns_id, &host_id, &range);
	if (ret != 4)
		return -1;

	if (which != 'b' && which != 'u' && which != 'g')
		return -1;

	for (i = 0; i < 2; i++) {
		if (which != types[i] && which != 'b')
			continue;

		if (types[i] == 'u')
			idtype = ID_TYPE_UID;
		else
			idtype = ID_TYPE_GID;

		ret = add_map_entry(host_id, ns_id, range, idtype);
		if (ret < 0)
			return ret;
	}

	return 0;
}

/*
 * This is called if the user did not pass any uid ranges in through -m flags.
 * It's called once to get the default uid map, and once for the default gid
 * map.
 * Go through /etc/subuids and /etc/subgids to find this user's allowed map. We
 * only use the first one for each of uid and gid, because otherwise we're not
 * sure which entries the user wanted.
 */
static int read_default_map(char *fnam, int which, char *user)
{
	__do_free char *line = NULL;
	__do_fclose FILE *fin = NULL;
	size_t len;
	char *p1, *p2;
	unsigned long ul1, ul2;
	int ret = -1;
	size_t sz = 0;

	fin = fopen(fnam, "re");
	if (!fin)
		return -1;

	len = strlen(user);
	while (getline(&line, &sz, fin) != -1) {
		if (sz <= len || strncmp(line, user, len) != 0 || line[len] != ':')
			continue;

		p1 = strchr(line, ':');
		if (!p1)
			continue;

		p2 = strchr(p1 + 1, ':');
		if (!p2)
			continue;

		line[strlen(line) - 1] = '\0';
		*p2 = '\0';

		ret = lxc_safe_ulong(p1 + 1, &ul1);
		if (ret < 0)
			break;

		ret = lxc_safe_ulong(p2 + 1, &ul2);
		if (ret < 0)
			break;

		ret = add_map_entry(ul1, 0, ul2, which);
		break;
	}

	return ret;
}

static int find_default_map(void)
{
	__do_free char *buf = NULL;
	size_t bufsize;
	struct passwd pwent;
	int ret = -1;
	struct passwd *pwentp = NULL;

	bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (bufsize == -1)
		bufsize = 1024;

	buf = malloc(bufsize);
	if (!buf)
		return -1;

	ret = getpwuid_r(getuid(), &pwent, buf, bufsize, &pwentp);
	if (!pwentp) {
		if (ret == 0)
			CMD_SYSERROR("Failed to find matched password record");

		CMD_SYSERROR("Failed to get password record for uid %d", getuid());
		return -1;
	}

	ret = read_default_map(subuidfile, ID_TYPE_UID, pwent.pw_name);
	if (ret < 0)
		return -1;

	ret = read_default_map(subgidfile, ID_TYPE_GID, pwent.pw_name);
	if (ret < 0)
		return -1;

	return 0;
}

static bool is_in_ns_range(long id, struct id_map *map)
{
	if (id < map->nsid)
		return false;
	if (id >= map->nsid + map->range)
		return false;
	return true;
}

static bool do_map_self(void)
{
	struct id_map *map;
	long nsuid = 0, nsgid = 0;
	struct lxc_list *tmp = NULL;
	int ret;

	lxc_list_for_each(tmp, &active_map) {
		map = tmp->elem;
		if (map->idtype == ID_TYPE_UID) {
			if (is_in_ns_range(nsuid, map))
				nsuid += map->range;
		} else {
			if (is_in_ns_range(nsgid, map))
				nsgid += map->range;
		}
	}

	ret = add_map_entry(getgid(), nsgid, 1, ID_TYPE_GID);
	if (ret < 0)
		return false;
	ret = add_map_entry(getuid(), nsuid, 1, ID_TYPE_UID);
	if (ret < 0)
		return false;
	return true;
}

int main(int argc, char *argv[])
{
	int c, pid, ret, status;
	char buf[1];
	int pipe_fds1[2], /* child tells parent it has unshared */
	    pipe_fds2[2]; /* parent tells child it is mapped and may proceed */
	unsigned long flags = CLONE_NEWUSER | CLONE_NEWNS;
	char ttyname0[256] = {0}, ttyname1[256] = {0}, ttyname2[256] = {0};
	char *default_args[] = {"/bin/sh", NULL};
	bool map_self = false;

	lxc_log_fd = STDERR_FILENO;

	if (isatty(STDIN_FILENO)) {
		ret = readlink("/proc/self/fd/0", ttyname0, sizeof(ttyname0));
		if (ret < 0) {
			CMD_SYSERROR("Failed to open stdin");
			_exit(EXIT_FAILURE);
		}

		ret = readlink("/proc/self/fd/1", ttyname1, sizeof(ttyname1));
		if (ret < 0) {
			CMD_SYSINFO("Failed to open stdout. Continuing");
			ttyname1[0] = '\0';
		}

		ret = readlink("/proc/self/fd/2", ttyname2, sizeof(ttyname2));
		if (ret < 0) {
			CMD_SYSINFO("Failed to open stderr. Continuing");
			ttyname2[0] = '\0';
		}
	}

	lxc_list_init(&active_map);

	while ((c = getopt(argc, argv, "m:hs")) != EOF) {
		switch (c) {
		case 'm':
			ret = parse_map(optarg);
			if (ret < 0) {
				usage(argv[0]);
				_exit(EXIT_FAILURE);
			}
			break;
		case 'h':
			usage(argv[0]);
			_exit(EXIT_SUCCESS);
		case 's':
			map_self = true;
			break;
		default:
			usage(argv[0]);
			_exit(EXIT_FAILURE);
		}
	};

	if (lxc_list_empty(&active_map)) {
		ret = find_default_map();
		if (ret < 0) {
			fprintf(stderr, "Failed to find subuid or subgid allocation\n");
			_exit(EXIT_FAILURE);
		}
	}

	// Do we want to support map-self with no other allocations?
	// If so we should move this above the previous block.
	if (map_self) {
		if (!do_map_self()) {
			fprintf(stderr, "Failed mapping own uid\n");
			_exit(EXIT_FAILURE);
		}
	}

	argv = &argv[optind];
	argc = argc - optind;
	if (argc < 1)
		argv = default_args;

	ret = pipe2(pipe_fds1, O_CLOEXEC);
	if (ret < 0) {
		CMD_SYSERROR("Failed to open new pipe");
		_exit(EXIT_FAILURE);
	}

	ret = pipe2(pipe_fds2, O_CLOEXEC);
	if (ret < 0) {
		CMD_SYSERROR("Failed to open new pipe");
		close(pipe_fds1[0]);
		close(pipe_fds1[1]);
		_exit(EXIT_FAILURE);
	}

	pid = fork();
	if (pid < 0) {
		close(pipe_fds1[0]);
		close(pipe_fds1[1]);
		close(pipe_fds2[0]);
		close(pipe_fds2[1]);
		_exit(EXIT_FAILURE);
	}

	if (pid == 0) {
		close(pipe_fds1[0]);
		close(pipe_fds2[1]);

		opentty(ttyname0, STDIN_FILENO);
		opentty(ttyname1, STDOUT_FILENO);
		opentty(ttyname2, STDERR_FILENO);

		ret = unshare(flags);
		if (ret < 0) {
			CMD_SYSERROR("Failed to unshare mount and user namespace");
			close(pipe_fds1[1]);
			close(pipe_fds2[0]);
			_exit(EXIT_FAILURE);
		}

		buf[0] = '1';
		ret = lxc_write_nointr(pipe_fds1[1], buf, 1);
		if (ret != 1) {
			CMD_SYSERROR("Failed to write to pipe file descriptor %d",
				     pipe_fds1[1]);
			close(pipe_fds1[1]);
			close(pipe_fds2[0]);
			_exit(EXIT_FAILURE);
		}

		ret = lxc_read_nointr(pipe_fds2[0], buf, 1);
		if (ret != 1) {
			CMD_SYSERROR("Failed to read from pipe file descriptor %d",
				     pipe_fds2[0]);
			close(pipe_fds1[1]);
			close(pipe_fds2[0]);
			_exit(EXIT_FAILURE);
		}

		close(pipe_fds1[1]);
		close(pipe_fds2[0]);

		if (buf[0] != '1') {
			fprintf(stderr, "Received unexpected value from parent process\n");
			_exit(EXIT_FAILURE);
		}

		ret = do_child((void *)argv);
		if (ret < 0)
			_exit(EXIT_FAILURE);

		_exit(EXIT_SUCCESS);
	}

	close(pipe_fds1[1]);
	close(pipe_fds2[0]);

	ret = lxc_read_nointr(pipe_fds1[0], buf, 1);
	if (ret <= 0) {
		CMD_SYSERROR("Failed to read from pipe file descriptor %d", pipe_fds1[0]);
		_exit(EXIT_FAILURE);
	}

	buf[0] = '1';

	ret = lxc_map_ids(&active_map, pid);
	if (ret < 0)
		fprintf(stderr, "Failed to write id mapping for child process\n");

	ret = lxc_write_nointr(pipe_fds2[1], buf, 1);
	if (ret < 0) {
		CMD_SYSERROR("Failed to write to pipe file descriptor %d", pipe_fds2[1]);
		_exit(EXIT_FAILURE);
	}

	ret = waitpid(pid, &status, __WALL);
	if (ret < 0) {
		CMD_SYSERROR("Failed to wait on child process");
		_exit(EXIT_FAILURE);
	}

	_exit(WEXITSTATUS(status));
}

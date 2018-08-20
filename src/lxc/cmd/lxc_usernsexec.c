/*
 * (C) Copyright IBM Corp. 2008
 * (C) Copyright Canonical, Inc 2010-2013
 *
 * Authors:
 * Serge Hallyn <serge.hallyn@ubuntu.com>
 * (Once upon a time, this was based on nsexec from the IBM
 *  container tools)
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
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>
#include <sys/syscall.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <libgen.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <sched.h>
#include <pwd.h>
#include <grp.h>

#include "conf.h"
#include "list.h"
#include "log.h"
#include "namespace.h"
#include "utils.h"

#ifndef MS_REC
#define MS_REC 16384
#endif

#ifndef MS_SLAVE
#define MS_SLAVE (1 << 19)
#endif

extern int lxc_log_fd;

int unshare(int flags);

static void usage(const char *name)
{
	printf("usage: %s [-h] [-m <uid-maps>] -- [command [arg ..]]\n", name);
	printf("\n");
	printf("  -h            this message\n");
	printf("\n");
	printf("  -m <uid-maps> uid maps to use\n");
	printf("\n");
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
		CMD_SYSERROR("Failed to open tty");
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

	/* Assume we want to become root */
	ret = setgid(0);
	if (ret < 0) {
		CMD_SYSERROR("Failed to set gid to");
		return -1;
	}

	ret = setuid(0);
	if (ret < 0) {
		CMD_SYSERROR("Failed to set uid to 0");
		return -1;
	}

	ret = setgroups(0, NULL);
	if (ret < 0) {
		CMD_SYSERROR("Failed to clear supplementary groups");
		return -1;
	}

	ret = unshare(CLONE_NEWNS);
	if (ret < 0) {
		CMD_SYSERROR("Failed to unshare mount namespace");
		return -1;
	}

	if (detect_shared_rootfs()) {
		ret = mount(NULL, "/", NULL, MS_SLAVE | MS_REC, NULL);
		if (ret < 0) {
			CMD_SYSINFO("Failed to make \"/\" rslave");
			return -1;
		}
	}

	execvp(argv[0], argv);
	CMD_SYSERROR("Failed to execute \"%s\"", argv[0]);
	return -1;
}

static struct lxc_list active_map;

/*
 * Given a string like "b:0:100000:10", map both uids and gids 0-10 to 100000
 * to 100010
 */
static int parse_map(char *map)
{
	int i, ret;
	long host_id, ns_id, range;
	char which;
	struct id_map *newmap;
	char types[2] = {'u', 'g'};
	struct lxc_list *tmp = NULL;

	if (!map)
		return -EINVAL;

	ret = sscanf(map, "%c:%ld:%ld:%ld", &which, &ns_id, &host_id, &range);
	if (ret != 4)
		return -EINVAL;

	if (which != 'b' && which != 'u' && which != 'g')
		return -EINVAL;

	for (i = 0; i < 2; i++) {
		if (which != types[i] && which != 'b')
			continue;

		newmap = malloc(sizeof(*newmap));
		if (!newmap)
			return -1;

		newmap->hostid = host_id;
		newmap->nsid = ns_id;
		newmap->range = range;

		if (types[i] == 'u')
			newmap->idtype = ID_TYPE_UID;
		else
			newmap->idtype = ID_TYPE_GID;

		tmp = malloc(sizeof(*tmp));
		if (!tmp) {
			free(newmap);
			return -1;
		}

		tmp->elem = newmap;
		lxc_list_add_tail(&active_map, tmp);
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
static int read_default_map(char *fnam, int which, char *username)
{
	char *p1, *p2;
	FILE *fin;
	struct id_map *newmap;
	size_t sz = 0;
	char *line = NULL;
	struct lxc_list *tmp = NULL;

	fin = fopen(fnam, "r");
	if (!fin)
		return -1;

	while (getline(&line, &sz, fin) != -1) {
		if (sz <= strlen(username) ||
		    strncmp(line, username, strlen(username)) != 0 ||
		    line[strlen(username)] != ':')
			continue;

		p1 = strchr(line, ':');
		if (!p1)
			continue;

		p2 = strchr(p1 + 1, ':');
		if (!p2)
			continue;

		newmap = malloc(sizeof(*newmap));
		if (!newmap) {
			fclose(fin);
			free(line);
			return -1;
		}

		newmap->hostid = atol(p1 + 1);
		newmap->range = atol(p2 + 1);
		newmap->nsid = 0;
		newmap->idtype = which;

		tmp = malloc(sizeof(*tmp));
		if (!tmp) {
			fclose(fin);
			free(line);
			free(newmap);
			return -1;
		}

		tmp->elem = newmap;
		lxc_list_add_tail(&active_map, tmp);
		break;
	}

	free(line);
	fclose(fin);

	return 0;
}

static int find_default_map(void)
{
	size_t bufsize;
	char *buf;
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
		ret = -1;
		goto out;
	}

	ret = read_default_map(subuidfile, ID_TYPE_UID, pwent.pw_name);
	if (ret < 0)
		goto out;

	ret = read_default_map(subgidfile, ID_TYPE_GID, pwent.pw_name);
	if (ret < 0)
		goto out;

	ret = 0;

out:
	free(buf);

	return ret;
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

	while ((c = getopt(argc, argv, "m:h")) != EOF) {
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
	if (ret <= 0)
		CMD_SYSERROR("Failed to read from pipe file descriptor %d", pipe_fds1[0]);

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

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
#include "namespace.h"
#include "utils.h"

#ifndef MS_REC
#define MS_REC 16384
#endif

#ifndef MS_SLAVE
#define MS_SLAVE (1<<19)
#endif

int unshare(int flags);

static void usage(const char *name)
{
	printf("usage: %s [-h] [-m <uid-maps>] -- [command [arg ..]]\n", name);
	printf("\n");
	printf("  -h		this message\n");
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
	exit(1);
}

static void opentty(const char * tty, int which) {
	int fd, flags;

	if (tty[0] == '\0')
		return;

	fd = open(tty, O_RDWR | O_NONBLOCK);
	if (fd == -1) {
		printf("WARN: could not reopen tty: %s\n", strerror(errno));
		return;
	}

	flags = fcntl(fd, F_GETFL);
	flags &= ~O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags) < 0) {
		printf("WARN: could not set fd flags: %s\n", strerror(errno));
		return;
	}

	close(which);
	if (fd != which) {
		dup2(fd, which);
		close(fd);
	}
}
// Code copy end

static int do_child(void *vargv)
{
	char **argv = (char **)vargv;

	// Assume we want to become root
	if (setgid(0) < 0) {
		perror("setgid");
		return -1;
	}
	if (setuid(0) < 0) {
		perror("setuid");
		return -1;
	}
	if (setgroups(0, NULL) < 0) {
		perror("setgroups");
		return -1;
	}
	if (unshare(CLONE_NEWNS) < 0) {
		perror("unshare CLONE_NEWNS");
		return -1;
	}
	if (detect_shared_rootfs()) {
		if (mount(NULL, "/", NULL, MS_SLAVE|MS_REC, NULL)) {
			printf("Failed to make / rslave");
			return -1;
		}
	}
	execvp(argv[0], argv);
	perror("execvpe");
	return -1;
}

static struct lxc_list active_map;

/*
 * given a string like "b:0:100000:10", map both uids and gids
 * 0-10 to 100000 to 100010
 */
static int parse_map(char *map)
{
	struct id_map *newmap;
	struct lxc_list *tmp = NULL;
	int ret;
	int i;
	char types[2] = {'u', 'g'};
	char which;
	long host_id, ns_id, range;

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
 * This is called if the user did not pass any uid ranges in
 * through -m flags.  It's called once to get the default uid
 * map, and once for the default gid map.
 * Go through /etc/subuids and /etc/subgids to find this user's
 * allowed map.  We only use the first one for each of uid and
 * gid, because otherwise we're not sure which entries the user
 * wanted.
 */
static int read_default_map(char *fnam, int which, char *username)
{
	FILE *fin;
	char *line = NULL;
	size_t sz = 0;
	struct id_map *newmap;
	struct lxc_list *tmp = NULL;
	char *p1, *p2;

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
		p2 = strchr(p1+1, ':');
		if (!p2)
			continue;
		newmap = malloc(sizeof(*newmap));
		if (!newmap)  {
			fclose(fin);
			free(line);
			return -1;
		}
		newmap->hostid = atol(p1+1);
		newmap->range = atol(p2+1);
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
	struct passwd *p = getpwuid(getuid());
	if (!p)
		return -1;
	if (read_default_map(subuidfile, ID_TYPE_UID, p->pw_name) < 0)
		return -1;
	if (read_default_map(subgidfile, ID_TYPE_GID, p->pw_name) < 0)
		return -1;
    return 0;
}

int main(int argc, char *argv[])
{
	int c;
	unsigned long flags = CLONE_NEWUSER | CLONE_NEWNS;
	char ttyname0[256], ttyname1[256], ttyname2[256];
	int status;
	int ret;
	int pid;
	char *default_args[] = {"/bin/sh", NULL};
	char buf[1];
	int pipe1[2],  // child tells parent it has unshared
	    pipe2[2];  // parent tells child it is mapped and may proceed

	memset(ttyname0, '\0', sizeof(ttyname0));
	memset(ttyname1, '\0', sizeof(ttyname1));
	memset(ttyname2, '\0', sizeof(ttyname2));
	if (isatty(0)) {
		ret = readlink("/proc/self/fd/0", ttyname0, sizeof(ttyname0));
		if (ret < 0) {
			perror("unable to open stdin.");
			exit(1);
		}
		ret = readlink("/proc/self/fd/1", ttyname1, sizeof(ttyname1));
		if (ret < 0) {
			printf("Warning: unable to open stdout, continuing.");
			memset(ttyname1, '\0', sizeof(ttyname1));
		}
		ret = readlink("/proc/self/fd/2", ttyname2, sizeof(ttyname2));
		if (ret < 0) {
			printf("Warning: unable to open stderr, continuing.");
			memset(ttyname2, '\0', sizeof(ttyname2));
		}
	}

	lxc_list_init(&active_map);

	while ((c = getopt(argc, argv, "m:h")) != EOF) {
		switch (c) {
			case 'm': if (parse_map(optarg)) usage(argv[0]); break;
			case 'h':
			default:
				  usage(argv[0]);
		}
	};

	if (lxc_list_empty(&active_map)) {
		if (find_default_map()) {
			fprintf(stderr, "You have no allocated subuids or subgids\n");
			exit(1);
		}
	}

	argv = &argv[optind];
	argc = argc - optind;
	if (argc < 1) {
		argv = default_args;
		argc = 1;
	}

	if (pipe(pipe1) < 0 || pipe(pipe2) < 0) {
		perror("pipe");
		exit(1);
	}
	if ((pid = fork()) == 0) {
		// Child.

		close(pipe1[0]);
		close(pipe2[1]);
		opentty(ttyname0, 0);
		opentty(ttyname1, 1);
		opentty(ttyname2, 2);

		ret = unshare(flags);
		if (ret < 0) {
			perror("unshare");
			return 1;
		}
		buf[0] = '1';
		if (write(pipe1[1], buf, 1) < 1) {
			perror("write pipe");
			exit(1);
		}
		if (read(pipe2[0], buf, 1) < 1) {
			perror("read pipe");
			exit(1);
		}
		if (buf[0] != '1') {
			fprintf(stderr, "parent had an error, child exiting\n");
			exit(1);
		}

		close(pipe1[1]);
		close(pipe2[0]);
		return do_child((void*)argv);
	}

	close(pipe1[1]);
	close(pipe2[0]);
	if (read(pipe1[0], buf, 1) < 1) {
		perror("read pipe");
		exit(1);
	}

	buf[0] = '1';

	if (lxc_map_ids(&active_map, pid)) {
		fprintf(stderr, "error mapping child\n");
		ret = 0;
	}
	if (write(pipe2[1], buf, 1) < 0) {
		perror("write to pipe");
		exit(1);
	}

	if ((ret = waitpid(pid, &status, __WALL)) < 0) {
		printf("waitpid() returns %d, errno %d\n", ret, errno);
		exit(1);
	}

	exit(WEXITSTATUS(status));
}

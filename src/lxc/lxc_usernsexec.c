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
#include <sys/wait.h>
#include <sched.h>
#include <pwd.h>
#include <grp.h>

#include "config.h"
#include "namespace.h"
#include "utils.h"

int unshare(int flags);

static void usage(const char *name)
{
	printf("usage: %s [-h] [-c] [-mnuUip] [-P <pid-file>]"
			"[command [arg ..]]\n", name);
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

static void opentty(const char * tty) {
	int i, fd, flags;

	fd = open(tty, O_RDWR | O_NONBLOCK);
	if (fd == -1) {
		printf("WARN: could not reopen tty: %s", strerror(errno));
		return;
	}

	flags = fcntl(fd, F_GETFL);
	flags &= ~O_NONBLOCK;
	fcntl(fd, F_SETFL, flags);

	for (i = 0; i < fd; i++)
		close(i);
	for (i = 0; i < 3; i++)
		if (fd != i)
			dup2(fd, i);
	if (fd >= 3)
		close(fd);
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
	execvp(argv[0], argv);
	perror("execvpe");
	return -1;
}

struct id_map {
	char which; // b or u or g
	long host_id, ns_id, range;
	struct id_map *next;
};

static struct id_map default_map = {
	.which = 'b',
	.host_id = 100000,
	.ns_id = 0,
	.range = 10000,
};
static struct id_map *active_map = &default_map;

/*
 * given a string like "b:0:100000:10", map both uids and gids
 * 0-10 to 100000 to 100010
 */
static int parse_map(char *map)
{
	struct id_map *newmap;
    int ret;

	if (!map)
		return -1;
	newmap = malloc(sizeof(*newmap));
	if (!newmap)
		return -1;
	ret = sscanf(map, "%c:%ld:%ld:%ld", &newmap->which, &newmap->ns_id, &newmap->host_id, &newmap->range);
	if (ret != 4)
		goto out_free_map;
	if (newmap->which != 'b' && newmap->which != 'u' && newmap->which != 'g')
		goto out_free_map;
	if (active_map != &default_map)
		newmap->next = active_map;
	else
		newmap->next = NULL;
	active_map = newmap;
	return 0;

out_free_map:
	free(newmap);
	return -1;
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
static int read_default_map(char *fnam, char which, char *username)
{
	FILE *fin;
	char *line = NULL;
	size_t sz = 0;
	struct id_map *newmap;
	char *p1, *p2;

	fin = fopen(fnam, "r");
	if (!fin)
		return -1;
	while (getline(&line, &sz, fin) != -1) {
		if (sz <= strlen(username) ||
		    strncmp(line, username, strlen(username)) != 0 ||
		    line[strlen(username)] != ':')
			continue;
		p1 = index(line, ':');
		if (!p1)
			continue;
		p2 = index(p1+1, ':');
		if (!p2)
			continue;
		newmap = malloc(sizeof(*newmap));
		if (!newmap)  {
			fclose(fin);
			free(line);
			return -1;
		}
		newmap->host_id = atol(p1+1);
		newmap->range = atol(p2+1);
		newmap->ns_id = 0;
		newmap->which = which;
		if (active_map != &default_map)
			newmap->next = active_map;
		else
			newmap->next = NULL;
		active_map = newmap;
		break;
	}

	if (line)
		free(line);
	fclose(fin);
	return 0;
}

#define subuidfile "/etc/subuid"
#define subgidfile "/etc/subgid"
static int find_default_map(void)
{
	struct passwd *p = getpwuid(getuid());
	if (!p)
		return -1;
	if (read_default_map(subuidfile, 'u', p->pw_name) < 0)
		return -1;
	if (read_default_map(subgidfile, 'g', p->pw_name) < 0)
		return -1;
    return 0;
}

static int run_cmd(char **argv)
{
    int status;
	pid_t pid = fork();

	if (pid < 0)
		return pid;
	if (pid == 0) {
		execvp(argv[0], argv);
		perror("exec failed");
		exit(1);
	}
	if (waitpid(pid, &status, __WALL) < 0) {
        perror("waitpid");
		return -1;
	}

	return WEXITSTATUS(status);
}

static int map_child_uids(int pid, struct id_map *map)
{
	char **uidargs = NULL, **gidargs = NULL;
	char **newuidargs = NULL, **newgidargs = NULL;
	int i, nuargs = 2, ngargs = 2, ret = -1;
	struct id_map *m;

	uidargs = malloc(3 * sizeof(*uidargs));
	if (uidargs == NULL)
		return -1;
	gidargs = malloc(3 * sizeof(*gidargs));
	if (gidargs == NULL) {
		free(uidargs);
		return -1;
	}
	uidargs[0] = malloc(10);
	gidargs[0] = malloc(10);
	uidargs[1] = malloc(21);
	gidargs[1] = malloc(21);
	uidargs[2] = NULL;
	gidargs[2] = NULL;
	if (!uidargs[0] || !uidargs[1] || !gidargs[0] || !gidargs[1])
		goto out;
	sprintf(uidargs[0], "newuidmap");
	sprintf(gidargs[0], "newgidmap");
	sprintf(uidargs[1], "%d", pid);
	sprintf(gidargs[1], "%d", pid);
	for (m=map; m; m = m->next) {
		if (m->which == 'b' || m->which == 'u') {
			nuargs += 3;
			newuidargs = realloc(uidargs, (nuargs+1) * sizeof(*uidargs));
			if (!newuidargs)
				goto out;
			uidargs = newuidargs;
			uidargs[nuargs - 3] = malloc(21);
			uidargs[nuargs - 2] = malloc(21);
			uidargs[nuargs - 1] = malloc(21);
			if (!uidargs[nuargs-3] || !uidargs[nuargs-2] || !uidargs[nuargs-1])
				goto out;
			sprintf(uidargs[nuargs - 3], "%ld", m->ns_id);
			sprintf(uidargs[nuargs - 2], "%ld", m->host_id);
			sprintf(uidargs[nuargs - 1], "%ld", m->range);
			uidargs[nuargs] = NULL;
		}
		if (m->which == 'b' || m->which == 'g') {
			ngargs += 3;
			newgidargs = realloc(gidargs, (ngargs+1) * sizeof(*gidargs));
			if (!newgidargs)
				goto out;
			gidargs = newgidargs;
			gidargs[ngargs - 3] = malloc(21);
			gidargs[ngargs - 2] = malloc(21);
			gidargs[ngargs - 1] = malloc(21);
			if (!gidargs[ngargs-3] || !gidargs[ngargs-2] || !gidargs[ngargs-1])
				goto out;
			sprintf(gidargs[ngargs - 3], "%ld", m->ns_id);
			sprintf(gidargs[ngargs - 2], "%ld", m->host_id);
			sprintf(gidargs[ngargs - 1], "%ld", m->range);
			gidargs[ngargs] = NULL;
		}
	}

	ret = -2;
	// exec newuidmap
	if (nuargs > 2 && run_cmd(uidargs) != 0) {
		fprintf(stderr, "Error mapping uids\n");
		goto out;
	}
	// exec newgidmap
	if (ngargs > 2 && run_cmd(gidargs) != 0) {
		fprintf(stderr, "Error mapping gids\n");
		goto out;
	}
	ret = 0;

out:
	for (i=0; i<nuargs; i++)
		free(uidargs[i]);
	for (i=0; i<ngargs; i++)
		free(gidargs[i]);
	free(uidargs);
	free(gidargs);

	return ret;
}

int main(int argc, char *argv[])
{
	int c;
	unsigned long flags = CLONE_NEWUSER | CLONE_NEWNS;
	char ttyname[256];
	int status;
	int ret;
	int pid;
	char *default_args[] = {"/bin/sh", NULL};
	char buf[1];
	int pipe1[2],  // child tells parent it has unshared
	    pipe2[2];  // parent tells child it is mapped and may proceed

	memset(ttyname, '\0', sizeof(ttyname));
	ret = readlink("/proc/self/fd/0", ttyname, sizeof(ttyname));
	if (ret < 0) {
		perror("readlink on fd 0");
		exit(1);
	}

	while ((c = getopt(argc, argv, "m:h")) != EOF) {
		switch (c) {
			case 'm': if (parse_map(optarg)) usage(argv[0]); break;
			case 'h':
			default:
				  usage(argv[0]);
		}
	};

	if (active_map == &default_map) {
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
		opentty(ttyname);

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
	if (map_child_uids(pid, active_map)) {
		fprintf(stderr, "error mapping child\n");
		ret = 0;
	}
	if (write(pipe2[1], buf, 1) < 0) {
		perror("write to pipe");
		exit(1);
	}

	if ((ret = waitpid(pid, &status, __WALL)) < 0) {
		printf("waitpid() returns %d, errno %d\n", ret, errno);
		exit(ret);
	}

	exit(WEXITSTATUS(status));
}

/*
 *
 * Copyright © 2013 Serge Hallyn <serge.hallyn@ubuntu.com>.
 * Copyright © 2013 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include "config.h"

#include <stdio.h>
#include <libgen.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <fcntl.h>

#include <lxc/lxccontainer.h>

#include "lxc.h"
#include "log.h"
#include "bdev.h"
#include "arguments.h"
#include "utils.h"

lxc_log_define(lxc_snapshot_ui, lxc);

static char *newname;
static char *snapshot;

#define DO_SNAP 0
#define DO_LIST 1
#define DO_RESTORE 2
#define DO_DESTROY 3
static int action;
static int print_comments;
static char *commentfile;

static int do_snapshot(struct lxc_container *c)
{
	int ret;

	ret = c->snapshot(c, commentfile);
	if (ret < 0) {
		ERROR("Error creating a snapshot");
		return -1;
	}

	INFO("Created snapshot snap%d", ret);
	return 0;
}

static void print_file(char *path)
{
	if (!path)
		return;
	FILE *f = fopen(path, "r");
	char *line = NULL;
	size_t sz = 0;
	if (!f)
		return;
	while (getline(&line, &sz, f) != -1) {
		printf("%s", line);
	}
	if (line)
		free(line);
	fclose(f);
}

static int do_list_snapshots(struct lxc_container *c)
{
	struct lxc_snapshot *s;
	int i, n;

	n = c->snapshot_list(c, &s);
	if (n < 0) {
		ERROR("Error listing snapshots");
		return -1;
	}
	if (n == 0) {
		printf("No snapshots\n");
		return 0;
	}
	for (i=0; i<n; i++) {
		printf("%s (%s) %s\n", s[i].name, s[i].lxcpath, s[i].timestamp);
		if (print_comments)
			print_file(s[i].comment_pathname);
		s[i].free(&s[i]);
	}
	free(s);
	return 0;
}

static int do_restore_snapshots(struct lxc_container *c)
{
	if (c->snapshot_restore(c, snapshot, newname))
		return 0;

	ERROR("Error restoring snapshot %s", snapshot);
	return -1;
}

static int do_destroy_snapshots(struct lxc_container *c)
{
	if (c->snapshot_destroy(c, snapshot))
		return 0;

	ERROR("Error destroying snapshot %s", snapshot);
	return -1;
}

static int my_parser(struct lxc_arguments* args, int c, char* arg)
{
	switch (c) {
	case 'L': action = DO_LIST; break;
	case 'r': snapshot = arg; action = DO_RESTORE; break;
	case 'd': snapshot = arg; action = DO_DESTROY; break;
	case 'c': commentfile = arg; break;
	case 'C': print_comments = true; break;
	}
	return 0;
}

static const struct option my_longopts[] = {
	{"list", no_argument, 0, 'L'},
	{"restore", required_argument, 0, 'r'},
	{"destroy", required_argument, 0, 'd'},
	{"comment", required_argument, 0, 'c'},
	{"showcomments", no_argument, 0, 'C'},
	LXC_COMMON_OPTIONS
};


static struct lxc_arguments my_args = {
	.progname = "lxc-snapshot",
	.help     = "\
--name=NAME [-P lxcpath] [-L [-C]] [-c commentfile] [-r snapname [newname]]\n\
\n\
lxc-snapshot snapshots a container\n\
\n\
Options :\n\
  -n, --name=NAME   NAME for name of the container\n\
  -L, --list          list snapshots\n\
  -C, --showcomments  show snapshot comments in list\n\
  -c, --comment=file  add file as a comment\n\
  -r, --restore=name  restore snapshot name, i.e. 'snap0'\n\
  -d, --destroy=name  destroy snapshot name, i.e. 'snap0'\n",
	.options  = my_longopts,
	.parser   = my_parser,
	.checker  = NULL,
};

/*
 * lxc-snapshot -P lxcpath -n container
 * lxc-snapshot -P lxcpath -n container -l
 * lxc-snapshot -P lxcpath -n container -r snap3 recovered_1
 */

int main(int argc, char *argv[])
{
	struct lxc_container *c;
	int ret = 0;

	if (lxc_arguments_parse(&my_args, argc, argv))
		exit(1);

	if (!my_args.log_file)
		my_args.log_file = "none";

	if (my_args.argc > 1) {
		ERROR("Too many arguments");
		exit(1);
	}
	if (my_args.argc == 1)
		newname = my_args.argv[0];

	if (lxc_log_init(my_args.name, my_args.log_file, my_args.log_priority,
			 my_args.progname, my_args.quiet, my_args.lxcpath[0]))
		exit(1);
	lxc_log_options_no_override();

	if (geteuid()) {
		if (access(my_args.lxcpath[0], O_RDWR) < 0) {
			fprintf(stderr, "You lack access to %s\n", my_args.lxcpath[0]);
			exit(1);
		}
	}

	c = lxc_container_new(my_args.name, my_args.lxcpath[0]);
	if (!c) {
		fprintf(stderr, "System error loading container\n");
		exit(1);
	}

	if (!c->may_control(c)) {
		fprintf(stderr, "Insufficent privileges to control %s\n", my_args.name);
		lxc_container_put(c);
		exit(1);
	}

	switch(action) {
	case DO_SNAP:
		ret = do_snapshot(c);
		break;
	case DO_LIST:
		ret = do_list_snapshots(c);
		break;
	case DO_RESTORE:
		ret = do_restore_snapshots(c);
		break;
	case DO_DESTROY:
		ret = do_destroy_snapshots(c);
		break;
	}

	lxc_container_put(c);

	if (ret == 0)
		exit(EXIT_SUCCESS);
	exit(EXIT_FAILURE);
}

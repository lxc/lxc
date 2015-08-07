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

#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdint.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <lxc/lxccontainer.h>

#include "log.h"
#include "confile.h"
#include "arguments.h"
#include "lxc.h"
#include "conf.h"
#include "state.h"

lxc_log_define(lxc_clone_ui, lxc);

static int my_parser(struct lxc_arguments *args, int c, char *arg);

static const struct option my_longopts[] = {
	{ "newname", required_argument, 0, 'N'},
	{ "newpath", required_argument, 0, 'p'},
	{ "rename", no_argument, 0, 'R'},
	{ "snapshot", no_argument, 0, 's'},
	{ "backingstore", required_argument, 0, 'B'},
	{ "fssize", required_argument, 0, 'L'},
	{ "keepname", no_argument, 0, 'K'},
	{ "keepmac", no_argument, 0, 'M'},
	LXC_COMMON_OPTIONS
};

static struct lxc_arguments my_args = {
	.progname = "lxc-clone",
	.help = "\
--name=NAME [-P lxcpath] -N newname [-p newpath] [-B backingstorage] [-s] [-K] [-M] [-L size [unit]]\n\
\n\
lxc-lcone clone a container\n\
\n\
Options :\n\
  -n, --name=NAME           NAME of the container\n\
  -N, --newname=NEWNAME     NEWNAME for the restored container\n\
  -p, --newpath=NEWPATH     NEWPATH for the container to be stored\n\
  -R, --rename		    rename container\n\
  -s, --snapshot	    create snapshot instead of clone\n\
  -B, --backingstorage=TYPE backingstorage type for the container\n\
  -L, --fssize		    size of the new block device for block device containers\n\
  -K, --keepname	    keep the hostname of the original container\n\
  -M, --keepmac		    keep the MAC address of the original container\n",
	.options = my_longopts,
	.parser = my_parser,
	.checker = NULL,
};

static int do_clone(struct lxc_container *c, char *newname, char *newpath,
		    int flags, char *bdevtype, uint64_t fssize, char **args);
static int do_clone_rename(struct lxc_container *c, char *newname);
static uint64_t get_fssize(char *s);

int main(int argc, char *argv[])
{
	struct lxc_container *c;
	int flags = 0;
	int ret;

	if (lxc_arguments_parse(&my_args, argc, argv))
		exit(EXIT_FAILURE);

	if (!my_args.log_file)
		my_args.log_file = "none";

	if (lxc_log_init(my_args.name, my_args.log_file, my_args.log_priority,
			 my_args.progname, my_args.quiet, my_args.lxcpath[0]))
		exit(EXIT_FAILURE);
	lxc_log_options_no_override();

	if (geteuid()) {
		if (access(my_args.lxcpath[0], O_RDWR) < 0) {
			fprintf(stderr, "You lack access to %s\n",
				my_args.lxcpath[0]);
			exit(EXIT_FAILURE);
		}
	}

	if (!my_args.newname) {
		printf("Error: You must provide a NEWNAME for the clone.\n");
		exit(EXIT_FAILURE);
	}

	if (my_args.task == SNAP)
		flags |= LXC_CLONE_SNAPSHOT;
	if (my_args.keepname)
		flags |= LXC_CLONE_KEEPNAME;
	if (my_args.keepmac)
		flags |= LXC_CLONE_KEEPMACADDR;

	c = lxc_container_new(my_args.name, my_args.lxcpath[0]);
	if (!c)
		exit(EXIT_FAILURE);

	if (!c->may_control(c)) {
		fprintf(stderr, "Insufficent privileges to control %s\n",
			c->name);
		lxc_container_put(c);
		exit(EXIT_FAILURE);
	}

	if (!c->is_defined(c)) {
		fprintf(stderr, "Error: container %s is not defined\n",
			c->name);
		lxc_container_put(c);
		exit(EXIT_FAILURE);
	}

	if (my_args.task == RENAME) {
		ret = do_clone_rename(c, my_args.newname);
	} else {
		ret = do_clone(c, my_args.newname, my_args.newpath, flags,
			       my_args.bdevtype, my_args.fssize, &argv[optind]);
	}

	lxc_container_put(c);

	if (ret == 0)
		exit(EXIT_SUCCESS);
	exit(EXIT_FAILURE);
}

static int my_parser(struct lxc_arguments *args, int c, char *arg)
{
	switch (c) {
	case 'N':
		args->newname = arg;
		break;
	case 'p':
		args->newpath = arg;
		break;
	case 'R':
		args->task = RENAME;
		break;
	case 's':
		args->task = SNAP;
		break;
	case 'B':
		args->bdevtype = arg;
		break;
	case 'L':
		args->fssize = get_fssize(optarg);
		break;
	case 'K':
		args->keepname = 1;
		break;
	case 'M':
		args->keepmac = 1;
		break;
	}

	return 0;
}

static int do_clone_rename(struct lxc_container *c, char *newname)
{
	bool ret;

	ret = c->rename(c, newname);
	if (!ret) {
		ERROR("Error: Renaming container %s to %s failed\n", c->name,
		      my_args.newname);
		return -1;
	}

	INFO("Renamed container %s to %s\n", c->name, newname);

	return 0;
}

static int do_clone(struct lxc_container *c, char *newname, char *newpath,
		    int flags, char *bdevtype, uint64_t fssize, char **args)
{
	struct lxc_container *clone;

	clone = c->clone(c, newname, newpath, flags, bdevtype, NULL, fssize,
			 args);
	if (clone == NULL) {
		fprintf(stderr, "clone failed\n");
		return -1;
	}

	INFO("Created container %s as %s of %s\n", newname,
	     my_args.task ? "snapshot" : "copy", c->name);

	lxc_container_put(clone);

	return 0;
}

/* we pass fssize in bytes */
static uint64_t get_fssize(char *s)
{
	uint64_t ret;
	char *end;

	ret = strtoull(s, &end, 0);
	if (end == s) {
		fprintf(stderr, "Invalid blockdev size '%s', using default size\n", s);
		return 0;
	}
	while (isblank(*end))
		end++;
	if (*end == '\0') {
		ret *= 1024ULL * 1024ULL; // MB by default
	} else if (*end == 'b' || *end == 'B') {
		ret *= 1ULL;
	} else if (*end == 'k' || *end == 'K') {
		ret *= 1024ULL;
	} else if (*end == 'm' || *end == 'M') {
		ret *= 1024ULL * 1024ULL;
	} else if (*end == 'g' || *end == 'G') {
		ret *= 1024ULL * 1024ULL * 1024ULL;
	} else if (*end == 't' || *end == 'T') {
		ret *= 1024ULL * 1024ULL * 1024ULL * 1024ULL;
	} else {
		fprintf(stderr, "Invalid blockdev unit size '%c' in '%s', " "using default size\n", *end, s);
		return 0;
	}

	return ret;
}


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
#include <sys/wait.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>

#include "log.h"
#include "config.h"
#include "lxc.h"
#include "conf.h"
#include "state.h"
#include <lxc/lxccontainer.h>

lxc_log_define(lxc_clone, lxc);

static unsigned long get_fssize(char *s)
{
       unsigned long ret;
       char *end;

       ret = strtoul(s, &end, 0);
       if (end == s)
               return 0;
       while (isblank(*end))
               end++;
       if (!(*end))
               return ret;
       if (*end == 'g' || *end == 'G')
               ret *= 1000000000;
       else if (*end == 'm' || *end == 'M')
               ret *= 1000000;
       else if (*end == 'k' || *end == 'K')
               ret *= 1000;
       return ret;
}

void usage(const char *me)
{
	printf("Usage: %s [-s] [-B backingstore] [-L size] [-K] [-M] [-H]\n", me);
	printf("          [-p lxcpath] [-P newlxcpath] orig new\n");
	printf("\n");
	printf("  -s: snapshot rather than copy\n");
	printf("  -B: use specified new backingstore.  Default is the same as\n");
	printf("      the original.  Options include btrfs, lvm, overlayfs, \n");
	printf("      dir and loop\n");
	printf("  -L: for blockdev-backed backingstore, use specified size\n");
	printf("  -K: Keep name - do not change the container name\n");
	printf("  -M: Keep macaddr - do not choose a random new mac address\n");
	printf("  -H: copy Hooks - copy mount hooks into container directory\n");
	printf("      and substitute container names and lxcpaths\n");
	printf("  -p: use container orig from custom lxcpath\n");
	printf("  -P: create container new in custom lxcpath\n");
	exit(1);
}

static struct option options[] = {
	{ "snapshot", no_argument, 0, 's'},
	{ "backingstore", required_argument, 0, 'B'},
	{ "size", required_argument, 0, 'L'},
	{ "orig", required_argument, 0, 'o'},
	{ "new", required_argument, 0, 'n'},
	{ "vgname", required_argument, 0, 'v'},
	{ "keepname", no_argument, 0, 'K'},
	{ "keepmac", no_argument, 0, 'M'},
	{ "copyhooks", no_argument, 0, 'H'},  // should this be default?
	{ "lxcpath", required_argument, 0, 'p'},
	{ "newpath", required_argument, 0, 'P'},
	{ "fstype", required_argument, 0, 't'},
	{ "help", no_argument, 0, 'h'},
	{ 0, 0, 0, 0 },
};

int main(int argc, char *argv[])
{
	struct lxc_container *c1 = NULL, *c2 = NULL;
	int snapshot = 0, keepname = 0, keepmac = 0, copyhooks = 0;
	int flags = 0, option_index;
	long newsize = 0;
	char *bdevtype = NULL, *lxcpath = NULL, *newpath = NULL, *fstype = NULL;
	char *orig = NULL, *new = NULL, *vgname = NULL;
	char **args = NULL;
	int c;

	if (argc < 3)
		usage(argv[0]);

	while (1) {
		c = getopt_long(argc, argv, "sB:L:o:n:v:KMHp:P:t:h", options, &option_index);
		if (c == -1)
			break;
		switch (c) {
		case 's': snapshot = 1; break;
		case 'B': bdevtype = optarg; break;
		case 'L': newsize = get_fssize(optarg); break;
		case 'o': orig = optarg; break;
		case 'n': new = optarg; break;
		case 'v': vgname = optarg; break;
		case 'K': keepname = 1; break;
		case 'M': keepmac = 1; break;
		case 'H': copyhooks = 1; break;
		case 'p': lxcpath = optarg; break;
		case 'P': newpath = optarg; break;
		case 't': fstype = optarg; break;
		case 'h': usage(argv[0]);
		default: break;
		}
	}
    if (optind < argc && !orig)
		orig = argv[optind++];
    if (optind < argc && !new)
		new = argv[optind++];
	if (optind < argc)
		/* arguments for the clone hook */
		args = &argv[optind];
	if (!new || !orig) {
		printf("Error: you must provide orig and new names\n");
		usage(argv[0]);
	}

	if (snapshot)  flags |= LXC_CLONE_SNAPSHOT;
	if (keepname)  flags |= LXC_CLONE_KEEPNAME;
	if (keepmac)   flags |= LXC_CLONE_KEEPMACADDR;
	if (copyhooks) flags |= LXC_CLONE_COPYHOOKS;

	// vgname and fstype could be supported by sending them through the
	// bdevdata.  However, they currently are not yet.  I'm not convinced
	// they are worthwhile.
	if (vgname) {
		printf("Error: vgname not supported\n");
		usage(argv[0]);
	}
	if (fstype) {
		printf("Error: fstype not supported\n");
		usage(argv[0]);
	}

	c1 = lxc_container_new(orig, lxcpath);
	if (!c1)
		exit(1);

	if (!c1->may_control(c1)) {
		fprintf(stderr, "Insufficent privileges to control %s\n", orig);
		lxc_container_put(c1);
		return -1;
	}

	if (!c1->is_defined(c1)) {
		fprintf(stderr, "Error: container %s is not defined\n", orig);
		lxc_container_put(c1);
		exit(1);
	}
	c2 = c1->clone(c1, new, newpath, flags, bdevtype, NULL, newsize, args);
	if (c2 == NULL) {
		lxc_container_put(c1);
		fprintf(stderr, "clone failed\n");
		exit(1);
	}
	printf("Created container %s as %s of %s\n", new,
		snapshot ? "snapshot" : "copy", orig);
	lxc_container_put(c1);
	lxc_container_put(c2);
	return(0);
}

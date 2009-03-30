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
#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <libgen.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>

#include <lxc/lxc.h>
#include "confile.h"

void usage(char *cmd)
{
	fprintf(stderr, "%s <command>\n", basename(cmd));
	fprintf(stderr, "\t -n <name>      : name of the container\n");
	fprintf(stderr, "\t [-f <confile>] : path of the configuration file\n");
	_exit(1);
}

int main(int argc, char *argv[])
{
	char *name = NULL, *file = NULL;
	static char **args;
	char path[MAXPATHLEN];
	int opt;
	int nbargs = 0;
	int autodestroy = 0;
	int ret = 1;
	struct lxc_conf lxc_conf;

	while ((opt = getopt(argc, argv, "f:n:")) != -1) {
		switch (opt) {
		case 'n':
			name = optarg;
			break;
		case 'f':
			file = optarg;
			break;
		}

		nbargs++;
	}

	if (!name || !argv[optind] || !strlen(argv[optind]))
		usage(argv[0]);

	argc -= nbargs;
	
	if (lxc_conf_init(&lxc_conf)) {
		fprintf(stderr, "failed to initialize the configuration\n");
		goto out;
	}

	if (file && lxc_config_read(file, &lxc_conf)) {
		fprintf(stderr, "invalid configuration file\n");
		goto out;
	}

	snprintf(path, MAXPATHLEN, LXCPATH "/%s", name);
	if (access(path, R_OK)) {
		if (lxc_create(name, &lxc_conf)) {
			fprintf(stderr, "failed to create the container '%s'\n", name);
			goto out;
		}
		autodestroy = 1;
	}

	/* lxc-init --mount-procfs -- .... */
	args = malloc((argc + 3)*sizeof(*args));
	if (!args) {
		fprintf(stderr, "failed to allocate memory for '%s'\n", name);
		goto out;
	}

	nbargs = 0;
	args[nbargs++] = LXCLIBEXECDIR "/lxc-init";
	args[nbargs++] = "--mount-procfs";
	args[nbargs++] = "--";

	for (opt = 0; opt < argc; opt++)
		args[nbargs++] = argv[optind++];

	ret = lxc_start(name, args);
	if (ret) {
		fprintf(stderr, "%s\n", lxc_strerror(ret));
		goto out;
	}

	ret = 0;
out:
	if (autodestroy) {
		if (lxc_destroy(name)) {
			fprintf(stderr, "failed to destroy '%s'\n", name);
			ret = 1;
		}
	}

	return ret;
}


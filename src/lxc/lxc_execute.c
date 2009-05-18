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

lxc_log_define(lxc_execute, lxc);

void usage(char *cmd)
{
	fprintf(stderr, "%s <command>\n", basename(cmd));
	fprintf(stderr, "\t -n <name>      : name of the container\n");
	fprintf(stderr, "\t [-f <confile>] : path of the configuration file\n");
	fprintf(stderr, "\t[-o <logfile>]    : path of the log file\n");
	fprintf(stderr, "\t[-l <logpriority>]: log level priority\n");
	fprintf(stderr, "\t[-q ]             : be quiet\n");
	_exit(1);
}

int main(int argc, char *argv[])
{
	const char *name = NULL, *file = NULL;
	const char *log_file = NULL, *log_priority = NULL;
	static char **args;
	char path[MAXPATHLEN];
	int opt;
	int nbargs = 0;
	int autodestroy = 0;
	int ret = 1;
	int quiet = 0;
	struct lxc_conf lxc_conf;

	while ((opt = getopt(argc, argv, "f:n:o:l:q")) != -1) {
		switch (opt) {
		case 'n':
			name = optarg;
			break;
		case 'f':
			file = optarg;
			break;
		case 'o':
			log_file = optarg;
			break;
		case 'l':
			log_priority = optarg;
			break;
		case 'q':
			quiet = 1;
			break;
		}

		nbargs++;
	}

	if (!name || !argv[optind] || !strlen(argv[optind]))
		usage(argv[0]);

	argc -= nbargs;
	
	if (lxc_log_init(log_file, log_priority, basename(argv[0]), quiet))
		goto out;

	if (lxc_conf_init(&lxc_conf))
		goto out;

	if (file && lxc_config_read(file, &lxc_conf))
		goto out;

	snprintf(path, MAXPATHLEN, LXCPATH "/%s", name);
	if (access(path, R_OK)) {
		if (lxc_create(name, &lxc_conf))
			goto out;
		autodestroy = 1;
	}

	/* lxc-init --mount-procfs -- .... */
	args = malloc((argc + 3)*sizeof(*args));
	if (!args) {
		ERROR("failed to allocate memory for '%s'", name);
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
		ERROR("failed to start '%s'", name);
		goto out;
	}

	ret = 0;
out:
	if (autodestroy) {
		if (lxc_destroy(name)) {
			ERROR("failed to destroy '%s'", name);
			ret = 1;
		}
	}

	return ret;
}


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

#define _GNU_SOURCE
#include <lxc/lxccontainer.h>

#include <stdio.h>
#include <libgen.h>
#include <unistd.h>
#include <sys/types.h>

#include "lxc.h"
#include "log.h"
#include "arguments.h"
#include "utils.h"

lxc_log_define(lxc_destroy_ui, lxc);

static int my_parser(struct lxc_arguments* args, int c, char* arg);

static const struct option my_longopts[] = {
	{"force", no_argument, 0, 'f'},
	{"snapshots", no_argument, 0, 's'},
	LXC_COMMON_OPTIONS
};

static struct lxc_arguments my_args = {
	.progname = "lxc-destroy",
	.help     = "\
--name=NAME [-f] [-P lxcpath]\n\
\n\
lxc-destroy destroys a container with the identifier NAME\n\
\n\
Options :\n\
  -n, --name=NAME   NAME of the container\n\
  -s, --snapshots   destroy including all snapshots\n\
  -f, --force       wait for the container to shut down\n",
	.options  = my_longopts,
	.parser   = my_parser,
	.checker  = NULL,
	.task     = DESTROY,
};

static int do_destroy(struct lxc_container *c);
static int do_destroy_with_snapshots(struct lxc_container *c);

int main(int argc, char *argv[])
{
	struct lxc_container *c;
	int ret;

	if (lxc_arguments_parse(&my_args, argc, argv))
		exit(EXIT_FAILURE);

	if (!my_args.log_file)
		my_args.log_file = "none";

	if (lxc_log_init(my_args.name, my_args.log_file, my_args.log_priority,
			 my_args.progname, my_args.quiet, my_args.lxcpath[0]))
		exit(EXIT_FAILURE);
	lxc_log_options_no_override();

	c = lxc_container_new(my_args.name, my_args.lxcpath[0]);
	if (!c) {
		fprintf(stderr, "System error loading container\n");
		exit(EXIT_FAILURE);
	}

	if (!c->may_control(c)) {
		fprintf(stderr, "Insufficent privileges to control %s\n", my_args.name);
		lxc_container_put(c);
		exit(EXIT_FAILURE);
	}

	if (!c->is_defined(c)) {
		fprintf(stderr, "Container is not defined\n");
		lxc_container_put(c);
		exit(EXIT_FAILURE);
	}

	if (c->is_running(c)) {
		if (!my_args.force) {
			fprintf(stderr, "%s is running\n", my_args.name);
			lxc_container_put(c);
			exit(EXIT_FAILURE);
		}
		c->stop(c);
	}

	if (my_args.task == SNAP) {
		ret = do_destroy_with_snapshots(c);
	} else {
		ret = do_destroy(c);
	}

	lxc_container_put(c);

	if (ret == 0)
		exit(EXIT_SUCCESS);
	exit(EXIT_FAILURE);
}

static int my_parser(struct lxc_arguments *args, int c, char *arg)
{
	switch (c) {
	case 'f': args->force = 1; break;
	case 's': args->task = SNAP; break;
	}
	return 0;
}

static int do_destroy(struct lxc_container *c)
{
	if (!c->destroy(c)) {
		fprintf(stderr, "Destroying %s failed\n", my_args.name);
		return -1;
	}

	printf("Destroyed container %s\n", my_args.name);

	return 0;
}

static int do_destroy_with_snapshots(struct lxc_container *c)
{
	struct lxc_container *c1;
	struct stat fbuf;
	bool bret = false;
	char path[MAXPATHLEN];
	char *buf = NULL;
	char *lxcpath = NULL;
	char *lxcname = NULL;
	char *scratch = NULL;
	int fd;
	int ret;
	int counter = 0;

	/* Destroy snapshots created with lxc-clone listed in lxc-snapshots. */
	ret = snprintf(path, MAXPATHLEN, "%s/%s/lxc_snapshots", c->config_path, c->name);
	if (ret < 0 || ret >= MAXPATHLEN)
		return -1;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		ret = fstat(fd, &fbuf);
		if (ret < 0) {
			close(fd);
			return -1;
		}

		/* Make sure that the string is \0 terminated. */
		buf = calloc(fbuf.st_size + 1, sizeof(char));
		if (!buf) {
			SYSERROR("failed to allocate memory");
			close(fd);
			return -1;
		}

		ret = read(fd, buf, fbuf.st_size);
		if (ret < 0) {
			ERROR("could not read %s", path);
			close(fd);
			free(buf);
			return -1;
		}
		close(fd);

		while ((lxcpath = strtok_r(!counter ? buf : NULL, "\n", &scratch))) {
			if (!(lxcname = strtok_r(NULL, "\n", &scratch)))
				break;
			c1 = lxc_container_new(lxcname, lxcpath);
			if (!c1) {
				counter++;
				continue;
			}
			if (!c1->destroy(c1)) {
				fprintf(stderr, "Destroying snapshot %s of %s failed\n", lxcname, my_args.name);
				lxc_container_put(c1);
				free(buf);
				return -1;
			}
			lxc_container_put(c1);
			counter++;
		}
		free(buf);
	}

	/* Destroy snapshots located in the containers snap/ folder. */
	ret = snprintf(path, MAXPATHLEN, "%s/%s/snaps", c->config_path, c->name);
	if (ret < 0 || ret >= MAXPATHLEN)
		return -1;

	if (dir_exists(path))
		bret = c->destroy_with_snapshots(c);
	else
		bret = c->destroy(c);

	if (!bret) {
		fprintf(stderr, "Destroying %s failed\n", my_args.name);
		return -1;
	}

	printf("Destroyed container %s including snapshots \n", my_args.name);

	return 0;
}


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
#include <fcntl.h>
#include <libgen.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <lxc/lxccontainer.h>

#include "arguments.h"
#include "log.h"
#include "utils.h"

lxc_log_define(lxc_destroy, lxc);

static int my_parser(struct lxc_arguments *args, int c, char *arg);

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
  -f, --force       wait for the container to shut down\n\
  --rcfile=FILE     Load configuration file FILE\n",
	.options  = my_longopts,
	.parser   = my_parser,
	.checker  = NULL,
	.task     = DESTROY,
};

static bool do_destroy(struct lxc_container *c);
static bool do_destroy_with_snapshots(struct lxc_container *c);

int main(int argc, char *argv[])
{
	struct lxc_container *c;
	struct lxc_log log;
	bool bret;

	if (lxc_arguments_parse(&my_args, argc, argv))
		exit(EXIT_FAILURE);

	/* Only create log if explicitly instructed */
	if (my_args.log_file || my_args.log_priority) {
		log.name = my_args.name;
		log.file = my_args.log_file;
		log.level = my_args.log_priority;
		log.prefix = my_args.progname;
		log.quiet = my_args.quiet;
		log.lxcpath = my_args.lxcpath[0];

		if (lxc_log_init(&log))
			exit(EXIT_FAILURE);
	}

	c = lxc_container_new(my_args.name, my_args.lxcpath[0]);
	if (!c) {
		ERROR("System error loading container");
		exit(EXIT_FAILURE);
	}

	if (my_args.rcfile) {
		c->clear_config(c);

		if (!c->load_config(c, my_args.rcfile)) {
			ERROR("Failed to load rcfile");
			lxc_container_put(c);
			exit(EXIT_FAILURE);
		}

		c->configfile = strdup(my_args.rcfile);
		if (!c->configfile) {
			ERROR("Out of memory setting new config filename");
			lxc_container_put(c);
			exit(EXIT_FAILURE);
		}
	}

	if (!c->may_control(c)) {
		ERROR("Insufficent privileges to control %s", my_args.name);
		lxc_container_put(c);
		exit(EXIT_FAILURE);
	}

	if (!c->is_defined(c)) {
		ERROR("Container is not defined");
		lxc_container_put(c);
		exit(EXIT_FAILURE);
	}

	if (my_args.task == SNAP) {
		bret = do_destroy_with_snapshots(c);
		if (bret)
			ERROR("Destroyed container %s including snapshots", my_args.name);
	} else {
		bret = do_destroy(c);
		if (bret)
			ERROR("Destroyed container %s", my_args.name);
	}

	lxc_container_put(c);

	if (bret)
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

static bool do_destroy(struct lxc_container *c)
{
	bool bret = true;
	char path[MAXPATHLEN];

	/* First check whether the container has dependent clones or snapshots. */
	int ret = snprintf(path, MAXPATHLEN, "%s/%s/lxc_snapshots", c->config_path, c->name);
	if (ret < 0 || ret >= MAXPATHLEN)
		return false;

	if (file_exists(path)) {
		ERROR("Destroying %s failed: %s has clones", c->name, c->name);
		return false;
	}

	ret = snprintf(path, MAXPATHLEN, "%s/%s/snaps", c->config_path, c->name);
	if (ret < 0 || ret >= MAXPATHLEN)
		return false;

	if (rmdir(path) < 0 && errno != ENOENT) {
		ERROR("Destroying %s failed: %s has snapshots", c->name, c->name);
		return false;
	}

	if (c->is_running(c)) {
		if (!my_args.force) {
			ERROR("%s is running", my_args.name);
			return false;
		}

		/* If the container was ephemeral it will be removed on shutdown. */
		c->stop(c);
	}

	/* If the container was ephemeral we have already removed it when we
	 * stopped it. */
	if (c->is_defined(c)) {
		char buf[256];

		ret = c->get_config_item(c, "lxc.ephemeral", buf, 256);
		if (ret > 0 && strcmp(buf, "0") == 0) {
			bret = c->destroy(c);
		}
	}

	if (!bret) {
		ERROR("Destroying %s failed", my_args.name);
		return false;
	}

	return true;
}

static bool do_destroy_with_snapshots(struct lxc_container *c)
{
	struct lxc_container *c1;
	struct stat fbuf;
	bool bret = false;
	char path[MAXPATHLEN];
	char *buf = NULL;
	char *lxcpath = NULL;
	char *lxcname = NULL;
	int fd;
	int ret;
	ssize_t bytes;

	/* Destroy clones. */
	ret = snprintf(path, MAXPATHLEN, "%s/%s/lxc_snapshots", c->config_path, c->name);
	if (ret < 0 || ret >= MAXPATHLEN)
		return false;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		ret = fstat(fd, &fbuf);
		if (ret < 0) {
			close(fd);
			return false;
		}

		/* Make sure that the string is \0 terminated. */
		buf = calloc(fbuf.st_size + 1, sizeof(char));
		if (!buf) {
			ERROR("Failed to allocate memory");
			close(fd);
			return false;
		}

		bytes = lxc_read_nointr(fd, buf, fbuf.st_size);
		close(fd);
		if (bytes != (ssize_t)fbuf.st_size) {
			ERROR("Could not read %s", path);
			free(buf);
			return false;
		}

		lxc_iterate_parts(lxcpath, buf, "\n") {
			c1 = lxc_container_new(lxcname, lxcpath);
			if (!c1)
				continue;

			/* We do not destroy recursively. If a clone of a clone
			 * has clones or snapshots the user should remove it
			 * explicitly. */
			if (!do_destroy(c1)) {
				lxc_container_put(c1);
				free(buf);
				return false;
			}

			lxc_container_put(c1);
		}
		free(buf);
	}

	/* Destroy snapshots located in the containers snap/ folder. */
	ret = snprintf(path, MAXPATHLEN, "%s/%s/snaps", c->config_path, c->name);
	if (ret < 0 || ret >= MAXPATHLEN)
		return false;

	if (rmdir(path) < 0 && errno != ENOENT)
		bret = c->destroy_with_snapshots(c);
	else
		bret = do_destroy(c);

	return bret;
}

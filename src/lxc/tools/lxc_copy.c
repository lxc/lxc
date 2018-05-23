/*
 *
 * Copyright © 2015 Christian Brauner <christian.brauner@mailbox.org>.
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
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <lxc/lxccontainer.h>

#include "arguments.h"
#include "tool_utils.h"

#ifndef HAVE_GETSUBOPT
#include "include/getsubopt.h"
#endif

enum mnttype {
	LXC_MNT_BIND,
	LXC_MNT_OVL,
};

struct mnts {
	enum mnttype mnt_type;
	char *src;
	char *dest;
	char *options;
	char *upper;
	char *workdir;
	char *lower;
};

static unsigned int mnt_table_size = 0;
static struct mnts *mnt_table = NULL;

static int my_parser(struct lxc_arguments *args, int c, char *arg);

static const struct option my_longopts[] = {
	{ "newname", required_argument, 0, 'N'},
	{ "newpath", required_argument, 0, 'p'},
	{ "rename", no_argument, 0, 'R'},
	{ "snapshot", no_argument, 0, 's'},
	{ "foreground", no_argument, 0, 'F'},
	{ "daemon", no_argument, 0, 'd'},
	{ "ephemeral", no_argument, 0, 'e'},
	{ "mount", required_argument, 0, 'm'},
	{ "backingstorage", required_argument, 0, 'B'},
	{ "fssize", required_argument, 0, 'L'},
	{ "keepdata", no_argument, 0, 'D'},
	{ "keepname", no_argument, 0, 'K'},
	{ "keepmac", no_argument, 0, 'M'},
	{ "tmpfs", no_argument, 0, 't'},
	LXC_COMMON_OPTIONS
};

/* mount keys */
static char *const keys[] = {
	[LXC_MNT_BIND] = "bind",
	[LXC_MNT_OVL] = "overlay",
	NULL
};

static struct lxc_arguments my_args = {
	.progname = "lxc-copy",
	.help = "\n\
--name=NAME [-P lxcpath] -N newname [-p newpath] [-B backingstorage] [-s] [-K] [-M] [-L size [unit]] -- hook options\n\
--name=NAME [-P lxcpath] [-N newname] [-p newpath] [-B backingstorage] -e [-d] [-D] [-K] [-M] [-m {bind,overlay}=/src:/dest] -- hook options\n\
--name=NAME [-P lxcpath] -N newname -R\n\
\n\
lxc-copy clone a container\n\
\n\
Options :\n\
  -n, --name=NAME           NAME of the container\n\
  -N, --newname=NEWNAME     NEWNAME for the restored container\n\
  -p, --newpath=NEWPATH     NEWPATH for the container to be stored\n\
  -R, --rename              rename container\n\
  -s, --snapshot            create snapshot instead of clone\n\
  -F, --foreground          start with current tty attached to /dev/console\n\
  -d, --daemon              daemonize the container (default)\n\
  -e, --ephemeral           start ephemeral container\n\
  -m, --mount               directory to mount into container, either \n\
                            {bind,overlay}=/src-path or {bind,overlay}=/src-path:/dst-path\n\
  -B, --backingstorage=TYPE backingstorage type for the container\n\
  -t, --tmpfs               place ephemeral container on a tmpfs\n\
                            (WARNING: On reboot all changes made to the container will be lost.)\n\
  -L, --fssize              size of the new block device for block device containers\n\
  -D, --keedata             pass together with -e start a persistent snapshot \n\
  -K, --keepname            keep the hostname of the original container\n\
  --  hook options          arguments passed to the hook program\n\
  -M, --keepmac             keep the MAC address of the original container\n\
  --rcfile=FILE             Load configuration file FILE\n",
	.options = my_longopts,
	.parser = my_parser,
	.task = CLONE,
	.daemonize = 1,
	.quiet = false,
	.tmpfs = false,
};

static struct mnts *add_mnt(struct mnts **mnts, unsigned int *num,
			    enum mnttype type);
static int mk_rand_ovl_dirs(struct mnts *mnts, unsigned int num,
			    struct lxc_arguments *arg);
static char *construct_path(char *path, bool as_prefix);
static char *set_mnt_entry(struct mnts *m);
static int do_clone(struct lxc_container *c, char *newname, char *newpath,
		    int flags, char *bdevtype, uint64_t fssize, enum task task,
		    char **args);
static int do_clone_ephemeral(struct lxc_container *c,
			      struct lxc_arguments *arg, char **args,
			      int flags);
static int do_clone_rename(struct lxc_container *c, char *newname);
static int do_clone_task(struct lxc_container *c, enum task task, int flags,
			 char **args);
static void free_mnts(void);
static uint64_t get_fssize(char *s);

/* Place an ephemeral container started with -e flag on a tmpfs. Restrictions
 * are that you cannot request the data to be kept while placing the container
 * on a tmpfs and that either overlay storage driver must be used.
 */
static char *mount_tmpfs(const char *oldname, const char *newname,
			 const char *path, struct lxc_arguments *arg);
static int parse_mntsubopts(char *subopts, char *const *keys,
			    char *mntparameters);
static int parse_bind_mnt(char *mntstring, enum mnttype type);
static int parse_ovl_mnt(char *mntstring, enum mnttype type);

int main(int argc, char *argv[])
{
	struct lxc_container *c;
	struct lxc_log log;
	int flags = 0;
	int ret = EXIT_FAILURE;

	if (lxc_arguments_parse(&my_args, argc, argv))
		exit(ret);

	/* Only create log if explicitly instructed */
	if (my_args.log_file || my_args.log_priority) {
		log.name = my_args.name;
		log.file = my_args.log_file;
		log.level = my_args.log_priority;
		log.prefix = my_args.progname;
		log.quiet = my_args.quiet;
		log.lxcpath = my_args.lxcpath[0];

		if (lxc_log_init(&log))
			exit(ret);
	}

	if (geteuid()) {
		if (access(my_args.lxcpath[0], O_RDONLY) < 0) {
			if (!my_args.quiet)
				fprintf(stderr, "You lack access to %s\n", my_args.lxcpath[0]);
			exit(ret);
		}
	}

	if (!my_args.newname && !(my_args.task == DESTROY)) {
		if (!my_args.quiet)
			printf("Error: You must provide a NEWNAME for the clone.\n");
		exit(ret);
	}

	if (my_args.task == SNAP || my_args.task == DESTROY)
		flags |= LXC_CLONE_SNAPSHOT;
	if (my_args.keepname)
		flags |= LXC_CLONE_KEEPNAME;
	if (my_args.keepmac)
		flags |= LXC_CLONE_KEEPMACADDR;

	if (!my_args.newpath)
		my_args.newpath = (char *)my_args.lxcpath[0];

	c = lxc_container_new(my_args.name, my_args.lxcpath[0]);
	if (!c)
		exit(ret);

	if (my_args.rcfile) {
		c->clear_config(c);
		if (!c->load_config(c, my_args.rcfile)) {
			fprintf(stderr, "Failed to load rcfile\n");
			goto out;
		}
		c->configfile = strdup(my_args.rcfile);
		if (!c->configfile) {
			fprintf(stderr, "Out of memory setting new config filename\n");
			goto out;
		}
	}

	if (!c->may_control(c)) {
		if (!my_args.quiet)
			fprintf(stderr, "Insufficent privileges to control %s\n", c->name);
		goto out;
	}

	if (!c->is_defined(c)) {
		if (!my_args.quiet)
			fprintf(stderr, "Error: container %s is not defined\n", c->name);
		goto out;
	}

	ret = do_clone_task(c, my_args.task, flags, &argv[optind]);

out:
	lxc_container_put(c);

	if (ret == 0)
		exit(EXIT_SUCCESS);
	exit(EXIT_FAILURE);
}

static struct mnts *add_mnt(struct mnts **mnts, unsigned int *num, enum mnttype type)
{
	struct mnts *m, *n;

	n = realloc(*mnts, (*num + 1) * sizeof(struct mnts));
	if (!n)
		return NULL;

	*mnts = n;
	m = *mnts + *num;
	(*num)++;

	*m = (struct mnts) {.mnt_type = type};

	return m;
}

static int mk_rand_ovl_dirs(struct mnts *mnts, unsigned int num, struct lxc_arguments *arg)
{
	char upperdir[TOOL_MAXPATHLEN];
	char workdir[TOOL_MAXPATHLEN];
	unsigned int i;
	int ret;
	struct mnts *m = NULL;

	for (i = 0, m = mnts; i < num; i++, m++) {
		if (m->mnt_type == LXC_MNT_OVL) {
			ret = snprintf(upperdir, TOOL_MAXPATHLEN, "%s/%s/delta#XXXXXX",
					arg->newpath, arg->newname);
			if (ret < 0 || ret >= TOOL_MAXPATHLEN)
				return -1;
			if (!mkdtemp(upperdir))
				return -1;
			m->upper = strdup(upperdir);
			if (!m->upper)
				return -1;
		}

		if (m->mnt_type == LXC_MNT_OVL) {
			ret = snprintf(workdir, TOOL_MAXPATHLEN, "%s/%s/work#XXXXXX",
					arg->newpath, arg->newname);
			if (ret < 0 || ret >= TOOL_MAXPATHLEN)
				return -1;
			if (!mkdtemp(workdir))
				return -1;
			m->workdir = strdup(workdir);
			if (!m->workdir)
				return -1;
		}
	}

	return 0;
}

static char *construct_path(char *path, bool as_prefix)
{
	char **components = NULL;
	char *cleanpath = NULL;

	components = lxc_normalize_path(path);
	if (!components)
		return NULL;

	cleanpath = lxc_string_join("/", (const char **)components, as_prefix);
	lxc_free_array((void **)components, free);

	return cleanpath;
}

static char *set_mnt_entry(struct mnts *m)
{
	char *mntentry = NULL;
	int ret = 0;
	size_t len = 0;

	if (m->mnt_type == LXC_MNT_OVL) {
		len = strlen("  overlay lowerdir=,upperdir=,workdir=,create=dir") +
		      2 * strlen(m->src) + strlen(m->dest) + strlen(m->upper) +
		      strlen(m->workdir) + 1;

		mntentry = malloc(len);
		if (!mntentry)
			goto err;

		ret = snprintf(mntentry, len, "%s %s overlay lowerdir=%s,upperdir=%s,workdir=%s,create=dir",
				m->src, m->dest, m->src, m->upper, m->workdir);
		if (ret < 0 || (size_t)ret >= len)
			goto err;
	} else if (m->mnt_type == LXC_MNT_BIND) {
		len = strlen("  none bind,optional,, 0 0") +
		      strlen(is_dir(m->src) ? "create=dir" : "create=file") +
		      strlen(m->src) + strlen(m->dest) + strlen(m->options) + 1;

		mntentry = malloc(len);
		if (!mntentry)
			goto err;

		ret = snprintf(mntentry, len, "%s %s none bind,optional,%s,%s 0 0",
				m->src,	m->dest, m->options,
				is_dir(m->src) ? "create=dir" : "create=file");
		if (ret < 0 || (size_t)ret >= len)
			goto err;
	}

	return mntentry;

err:
	free(mntentry);
	return NULL;
}

static int do_clone(struct lxc_container *c, char *newname, char *newpath,
		    int flags, char *bdevtype, uint64_t fssize, enum task task,
		    char **args)
{
	struct lxc_container *clone;

	clone = c->clone(c, newname, newpath, flags, bdevtype, NULL, fssize,
			 args);
	if (!clone) {
		if (!my_args.quiet)
			fprintf(stderr, "clone failed\n");
		return -1;
	}

	lxc_container_put(clone);

	return 0;
}

static int do_clone_ephemeral(struct lxc_container *c,
		struct lxc_arguments *arg, char **args, int flags)
{
	char *premount;
	char randname[TOOL_MAXPATHLEN];
	unsigned int i;
	int ret = 0;
	bool bret = true, started = false;
	char *tmp_buf = randname;
	struct lxc_container *clone;
	lxc_attach_options_t attach_options = LXC_ATTACH_OPTIONS_DEFAULT;
	attach_options.env_policy = LXC_ATTACH_CLEAR_ENV;

	if (!arg->newname) {
		ret = snprintf(randname, TOOL_MAXPATHLEN, "%s/%s_XXXXXX", arg->newpath, arg->name);
		if (ret < 0 || ret >= TOOL_MAXPATHLEN)
			return -1;
		if (!mkdtemp(randname))
			return -1;
		if (chmod(randname, 0770) < 0) {
			(void)remove(randname);
			return -1;
		}
		arg->newname = randname + strlen(arg->newpath) + 1;
	}

	clone = c->clone(c, arg->newname, arg->newpath, flags,
			 arg->bdevtype, NULL, arg->fssize, args);
	if (!clone)
		return -1;

	if (arg->tmpfs) {
		premount = mount_tmpfs(arg->name, arg->newname, arg->newpath, arg);
		if (!premount)
			goto destroy_and_put;

		bret = clone->set_config_item(clone, "lxc.hook.pre-mount", premount);
		free(premount);
		if (!bret)
			goto destroy_and_put;
	}

	if (!arg->keepdata)
		if (!clone->set_config_item(clone, "lxc.ephemeral", "1"))
			goto destroy_and_put;

	/* allocate and create random upper- and workdirs for overlay mounts */
	if (mk_rand_ovl_dirs(mnt_table, mnt_table_size, arg) < 0)
		goto destroy_and_put;

	/* allocate and set mount entries */
	struct mnts *n = NULL;
	for (i = 0, n = mnt_table; i < mnt_table_size; i++, n++) {
		char *mntentry = NULL;
		mntentry = set_mnt_entry(n);
		if (!mntentry)
			goto destroy_and_put;
		bret = clone->set_config_item(clone, "lxc.mount.entry", mntentry);
		free(mntentry);
		if (!bret)
			goto destroy_and_put;
	}

	if (!clone->save_config(clone, NULL))
		goto destroy_and_put;

	if (!my_args.quiet)
		printf("Created %s as clone of %s\n", arg->newname, arg->name);

	if (arg->tmpfs && !my_args.quiet)
		printf("Container is placed on tmpfs.\nRebooting will cause "
		       "all changes made to it to be lost!\n");

	if (!arg->daemonize && arg->argc) {
		clone->want_daemonize(clone, true);
		arg->daemonize = 1;
	} else if (!arg->daemonize) {
		clone->want_daemonize(clone, false);
	}

	started = clone->start(clone, 0, NULL);
	if (!started)
		goto destroy_and_put;

	if (arg->daemonize && arg->argc) {
		ret = clone->attach_run_wait(clone, &attach_options, arg->argv[0], (const char *const *)arg->argv);
		if (ret < 0)
			goto destroy_and_put;
		clone->shutdown(clone, -1);
	}

	free_mnts();
	lxc_container_put(clone);
	return 0;

destroy_and_put:
	if (started)
		clone->shutdown(clone, -1);
	ret = clone->get_config_item(clone, "lxc.ephemeral", tmp_buf, TOOL_MAXPATHLEN);
	if (ret > 0 && strcmp(tmp_buf, "0"))
		clone->destroy(clone);
	free_mnts();
	lxc_container_put(clone);
	return -1;
}

static int do_clone_rename(struct lxc_container *c, char *newname)
{
	if (!c->rename(c, newname)) {
		fprintf(stderr, "Error: Renaming container %s to %s failed\n", c->name, newname);
		return -1;
	}

	return 0;
}

static int do_clone_task(struct lxc_container *c, enum task task, int flags,
			 char **args)
{
	int ret = 0;

	switch (task) {
	case DESTROY:
		ret = do_clone_ephemeral(c, &my_args, args, flags);
		break;
	case RENAME:
		ret = do_clone_rename(c, my_args.newname);
		break;
	default:
		ret = do_clone(c, my_args.newname, my_args.newpath, flags,
			       my_args.bdevtype, my_args.fssize, my_args.task,
			       args);
		break;
	}

	return ret;
}

static void free_mnts()
{
	unsigned int i;
	struct mnts *n = NULL;

	for (i = 0, n = mnt_table; i < mnt_table_size; i++, n++) {
		free(n->src);
		free(n->dest);
		free(n->options);
		free(n->upper);
		free(n->workdir);
	}
	free(mnt_table);
	mnt_table = NULL;
	mnt_table_size = 0;
}

/* we pass fssize in bytes */
static uint64_t get_fssize(char *s)
{
	uint64_t ret;
	char *end;

	ret = strtoull(s, &end, 0);
	if (end == s) {
		if (!my_args.quiet)
			fprintf(stderr, "Invalid blockdev size '%s', using default size\n", s);
		return 0;
	}
	while (isblank(*end))
		end++;
	if (*end == '\0') {
		ret *= 1024ULL * 1024ULL; /* MB by default */
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
		if (!my_args.quiet)
			fprintf(stderr, "Invalid blockdev unit size '%c' in '%s', " "using default size\n", *end, s);
		return 0;
	}

	return ret;
}

static int my_parser(struct lxc_arguments *args, int c, char *arg)
{
	char *subopts = NULL;
	char *mntparameters = NULL;
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
	case 'F':
		args->daemonize = 0;
		break;
	case 'd':
		args->daemonize = 1;
		break;
	case 'e':
		args->task = DESTROY;
		break;
	case 'm':
		subopts = optarg;
		if (parse_mntsubopts(subopts, keys, mntparameters) < 0)
			return -1;
		break;
	case 'B':
		if (strcmp(arg, "overlay") == 0)
			arg = "overlayfs";
		args->bdevtype = arg;
		break;
	case 't':
		args->tmpfs = true;
		break;
	case 'L':
		args->fssize = get_fssize(optarg);
		break;
	case 'D':
		args->keepdata = 1;
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

static int parse_bind_mnt(char *mntstring, enum mnttype type)
{
	int len = 0;
	char **mntarray = NULL;
	struct mnts *m = NULL;

	m = add_mnt(&mnt_table, &mnt_table_size, type);
	if (!m)
		goto err;

	mntarray = lxc_string_split(mntstring, ':');
	if (!mntarray)
		goto err;

	m->src = construct_path(mntarray[0], true);
	if (!m->src)
		goto err;

	len = lxc_array_len((void **)mntarray);
	if (len == 1) { /* bind=src */
		m->dest = construct_path(mntarray[0], false);
	} else if (len == 2) { /* bind=src:option or bind=src:dest */
		if (strncmp(mntarray[1], "rw", strlen(mntarray[1])) == 0)
			m->options = strdup("rw");

		if (strncmp(mntarray[1], "ro", strlen(mntarray[1])) == 0)
			m->options = strdup("ro");

		if (m->options)
			m->dest = construct_path(mntarray[0], false);
		else
			m->dest = construct_path(mntarray[1], false);
	} else if (len == 3) { /* bind=src:dest:option */
			m->dest = construct_path(mntarray[1], false);
			m->options = strdup(mntarray[2]);
	} else {
		printf("Excess elements in mount specification\n");
	}

	if (!m->dest)
		goto err;

	if (!m->options)
		m->options = strdup("rw");

	if (!m->options || (strncmp(m->options, "rw", strlen(m->options)) &&
			    strncmp(m->options, "ro", strlen(m->options))))
		goto err;

	lxc_free_array((void **)mntarray, free);
	return 0;

err:
	free_mnts();
	lxc_free_array((void **)mntarray, free);
	return -1;
}

static int parse_mntsubopts(char *subopts, char *const *keys, char *mntparameters)
{
	while (*subopts != '\0') {
		switch (getsubopt(&subopts, keys, &mntparameters)) {
		case LXC_MNT_BIND:
			if (parse_bind_mnt(mntparameters, LXC_MNT_BIND) < 0)
				return -1;
			break;
		case LXC_MNT_OVL:
			if (parse_ovl_mnt(mntparameters, LXC_MNT_OVL) < 0)
				return -1;
			break;
		default:
			break;
		}
	}
	return 0;
}

static int parse_ovl_mnt(char *mntstring, enum mnttype type)
{
	int len = 0;
	char **mntarray = NULL;
	struct mnts *m;

	m = add_mnt(&mnt_table, &mnt_table_size, type);
	if (!m)
		goto err;

	mntarray = lxc_string_split(mntstring, ':');
	if (!mntarray)
		goto err;

	m->src = construct_path(mntarray[0], true);
	if (!m->src)
		goto err;

	len = lxc_array_len((void **)mntarray);
	if (len == 1) /* overlay=src */
		m->dest = construct_path(mntarray[0], false);
	else if (len == 2) /* overlay=src:dest */
		m->dest = construct_path(mntarray[1], false);
	else
		printf("Excess elements in mount specification\n");

	if (!m->dest)
		goto err;

	lxc_free_array((void **)mntarray, free);
	return 0;

err:
	free_mnts();
	lxc_free_array((void **)mntarray, free);
	return -1;
}

/* For ephemeral snapshots backed by the overlay filesystem, this function
 * mounts a fresh tmpfs over the containers directory if the user requests it.
 * Because we mount a fresh tmpfs over the directory of the container the
 * updated /etc/hostname file created during the clone residing in the upperdir
 * (currently named "delta0" by default) will be hidden. Hence, if the user
 * requests that the old name is not to be kept for the clone, we recreate this
 * file on the tmpfs. This should be all that is required to restore the exact
 * behaviour we would get with a normal clone.
 */
static char *mount_tmpfs(const char *oldname, const char *newname,
			 const char *path, struct lxc_arguments *arg)
{
	int ret, fd;
	size_t len;
	char *premount = NULL;
	FILE *fp = NULL;

	if (arg->tmpfs && arg->keepdata) {
		fprintf(stderr, "%s\n",
			"A container can only be placed on a tmpfs when the "
			"overlay storage driver is used");
		goto err_free;
	}

	if (arg->tmpfs && !arg->bdevtype) {
		arg->bdevtype = "overlayfs";
	} else if (arg->tmpfs && arg->bdevtype &&
		   strcmp(arg->bdevtype, "overlayfs") != 0) {
		fprintf(stderr, "%s\n",
			"A container can only be placed on a tmpfs when the "
			"overlay storage driver is used");
		goto err_free;
	}

	len = strlen(path) + strlen(newname) + strlen("pre-start-XXXXXX") + /* //\0 */ 3;
	premount = malloc(len);
	if (!premount)
		goto err_free;

	ret = snprintf(premount, len, "%s/%s/pre-start-XXXXXX", path, newname);
	if (ret < 0 || (size_t)ret >= len)
		goto err_free;

	fd = mkstemp(premount);
	if (fd < 0)
		goto err_free;

	if (fcntl(fd, F_SETFD, FD_CLOEXEC)) {
		fprintf(stderr, "Failed to set close-on-exec on file descriptor.\n");
		goto err_close;
	}

	if (chmod(premount, 0755) < 0)
		goto err_close;

	fp = fdopen(fd, "r+");
	if (!fp)
		goto err_close;
	fd = -1;

	ret = fprintf(fp, "#! /bin/sh\n"
			  "mount -n -t tmpfs -o mode=0755 none %s/%s\n",
		      path, newname);
	if (ret < 0)
		goto err_close;

	if (!arg->keepname) {
		ret = fprintf(fp, "mkdir -p %s/%s/delta0/etc\n"
				  "echo %s > %s/%s/delta0/etc/hostname\n",
			      path, newname, newname, path, newname);
		if (ret < 0)
			goto err_close;
	}

	fclose(fp);
	return premount;

err_close:
	if (fd > 0)
		close(fd);
	else if (fp)
		fclose(fp);
err_free:
	free(premount);
	return NULL;
}

/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2008
 *
 * Authors:
 * Daniel Lezcano <daniel.lezcano at free.fr>
 * Michel Normand <normand at fr.ibm.com>
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

#ifndef __LXC_ARGUMENTS_H
#define __LXC_ARGUMENTS_H

#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

struct lxc_arguments;

typedef int (*lxc_arguments_parser_t) (struct lxc_arguments *, int, char*);
typedef int (*lxc_arguments_checker_t) (const struct lxc_arguments *);

struct lxc_arguments {
	const char *help;
	void(*helpfn)(const struct lxc_arguments *);
	const char *progname;
	const struct option* options;
	lxc_arguments_parser_t parser;
	lxc_arguments_checker_t checker;

	const char *name;
	char *log_file;
	char *log_priority;
	int quiet;
	int daemonize;
	const char *rcfile;
	const char *console;
	const char *console_log;
	const char *pidfile;
	const char **lxcpath;
	int lxcpath_cnt;
	/* set to 0 to accept only 1 lxcpath, -1 for unlimited */
	int lxcpath_additional;

	/* for lxc-start */
	const char *share_ns[32]; // size must be greater than LXC_NS_MAX

	/* for lxc-console */
	int ttynum;
	char escape;

	/* for lxc-wait */
	char *states;
	long timeout;

	/* for lxc-autostart */
	int shutdown;

	/* for lxc-stop */
	int hardstop;
	int nokill;
	int nolock;
	int nowait;
	int reboot;

	/* for lxc-destroy */
	int force;

	/* close fds from parent? */
	int close_all_fds;

	/* lxc-create */
	char *bdevtype, *configfile, *template;
	char *fstype;
	uint64_t fssize;
	char *lvname, *vgname, *thinpool;
	char *rbdname, *rbdpool;
	char *zfsroot, *lowerdir, *dir;

	/* lxc-execute */
	uid_t uid;
	gid_t gid;

	/* auto-start */
	int all;
	int ignore_auto;
	int list;
	char *groups; /* also used by lxc-ls */

	/* lxc-snapshot and lxc-copy */
	enum task {
		CLONE,
		DESTROY,
		LIST,
		RESTORE,
		SNAP,
		RENAME,
	} task;
	int print_comments;
	char *commentfile;
	char *newname;
	char *newpath;
	char *snapname;
	int keepdata;
	int keepname;
	int keepmac;

	/* lxc-ls */
	char *ls_fancy_format;
	char *ls_filter;
	unsigned int ls_nesting; /* maximum allowed nesting level */
	bool ls_active;
	bool ls_fancy;
	bool ls_frozen;
	bool ls_line;
	bool ls_running;
	bool ls_stopped;

	/* lxc-copy */
	bool tmpfs;

	/* remaining arguments */
	char *const *argv;
	int argc;

	/* private arguments */
	void *data;
};

#define LXC_COMMON_OPTIONS \
	{"name", required_argument, 0, 'n'}, \
	{"help", no_argument, 0, 'h'}, \
	{"usage", no_argument,	0, OPT_USAGE}, \
	{"version", no_argument,	0, OPT_VERSION}, \
	{"quiet", no_argument,	0, 'q'}, \
	{"logfile", required_argument, 0, 'o'}, \
	{"logpriority", required_argument, 0, 'l'}, \
	{"lxcpath", required_argument, 0, 'P'}, \
	{0, 0, 0, 0}

/* option keys for long only options */
#define	OPT_USAGE 0x1000
#define	OPT_VERSION OPT_USAGE-1

extern int lxc_arguments_parse(struct lxc_arguments *args,
			       int argc, char *const argv[]);

extern int lxc_arguments_str_to_int(struct lxc_arguments *args, const char *str);

extern const char *lxc_strerror(int errnum);

#define lxc_error(arg, fmt, args...) if (!(arg)->quiet)			\
	fprintf(stderr, "%s: " fmt "\n", (arg)->progname,  ## args)

#endif

/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2008
 *
 * Authors:
 * Daniel Lezcano <dlezcano at fr.ibm.com>
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */
#ifndef __arguments_h
#define __arguments_h

#include <getopt.h>

struct lxc_arguments;

typedef int (*lxc_arguments_parser_t) (struct lxc_arguments *, int, char*);
typedef int (*lxc_arguments_checker_t) (const struct lxc_arguments *);

struct lxc_arguments {
	const char *help;
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

	/* for lxc-checkpoint/restart */
	const char *statefile;
	int statefd;
	int flags;

	/* for lxc-console */
	int ttynum;
	char escape;

	/* for lxc-wait */
	char *states;

	/* remaining arguments */
	char *const *argv;
	int argc;
};

#define LXC_COMMON_OPTIONS \
	{"name", required_argument, 0, 'n'}, \
	{"help", no_argument, 0, 'h'}, \
	{"usage", no_argument,	0, OPT_USAGE}, \
	{"quiet", no_argument,	0, 'q'}, \
	{"logfile", required_argument, 0, 'o'}, \
	{"logpriority", required_argument, 0, 'l'}, \
	{0, 0, 0, 0}

/* option keys for long only options */
#define	OPT_USAGE 0x1000

extern int lxc_arguments_parse(struct lxc_arguments *args,
			       int argc, char *const argv[]);

extern char **lxc_arguments_dup(const char *file, struct lxc_arguments *args);
extern int lxc_arguments_str_to_int(struct lxc_arguments *args, const char *str);

extern const char *lxc_strerror(int errnum);

#define lxc_error(arg, fmt, args...) if (!(arg)->quiet)			\
	fprintf(stderr, "%s: " fmt "\n", (arg)->progname,  ## args)

#endif

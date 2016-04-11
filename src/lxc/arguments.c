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
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <ctype.h>		/* for isprint() */
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "arguments.h"
#include "utils.h"
#include "version.h"

/*---------------------------------------------------------------------------*/
static int build_shortopts(const struct option *a_options,
			   char *a_shortopts, size_t a_size)
{
	const struct option *opt;
	size_t i = 0;

	if (!a_options || !a_shortopts || !a_size)
		return -1;

	for (opt = a_options; opt->name; opt++) {

		if (!isascii(opt->val))
			continue;

		if (i < a_size)
			a_shortopts[i++] = opt->val;
		else
			goto is2big;

		if (opt->has_arg == no_argument)
			continue;

		if (i < a_size)
			a_shortopts[i++] = ':';
		else
			goto is2big;

		if (opt->has_arg == required_argument)
			continue;

		if (i < a_size)
			a_shortopts[i++] = ':';
		else
			goto is2big;
	}

	if (i < a_size)
		a_shortopts[i] = '\0';
	else
		goto is2big;

	return 0;

      is2big:
	errno = E2BIG;
	return -1;
}

/*---------------------------------------------------------------------------*/
static void print_usage(const struct option longopts[],
			const struct lxc_arguments *a_args)

{
	int i;
	const struct option *opt;

	fprintf(stderr, "Usage: %s ", a_args->progname);

	for (opt = longopts, i = 1; opt->name; opt++, i++) {
		int j;
		char *uppername = strdup(opt->name);

		if (!uppername)
			exit(-ENOMEM);

		for (j = 0; uppername[j]; j++)
			uppername[j] = toupper(uppername[j]);

		fprintf(stderr, "[");

		if (isprint(opt->val))
			fprintf(stderr, "-%c|", opt->val);

		fprintf(stderr, "--%s", opt->name);

		if (opt->has_arg == required_argument)
			fprintf(stderr, "=%s", uppername);

		if (opt->has_arg == optional_argument)
			fprintf(stderr, "[=%s]", uppername);

		fprintf(stderr, "] ");

		if (!(i % 4))
			fprintf(stderr, "\n\t");

		free(uppername);
	}

	fprintf(stderr, "\n");
	exit(0);
}

static void print_version() {
	printf("%s\n", LXC_VERSION);
	exit(0);
}

static void print_help(const struct lxc_arguments *args, int code)
{
	fprintf(stderr, "\
Usage: %s %s\
\n\
Common options :\n\
  -o, --logfile=FILE               Output log to FILE instead of stderr\n\
  -l, --logpriority=LEVEL          Set log priority to LEVEL\n\
  -q, --quiet                      Don't produce any output\n\
  -P, --lxcpath=PATH               Use specified container path\n\
  -?, --help                       Give this help list\n\
      --usage                      Give a short usage message\n\
      --version                    Print the version number\n\
\n\
Mandatory or optional arguments to long options are also mandatory or optional\n\
for any corresponding short options.\n\
\n\
See the %s man page for further information.\n\n",
	args->progname, args->help, args->progname);

	if (args->helpfn)
		args->helpfn(args);
	exit(code);
}

static int lxc_arguments_lxcpath_add(struct lxc_arguments *args,
				     const char *lxcpath)
{
	if (args->lxcpath_additional != -1 &&
	    args->lxcpath_cnt > args->lxcpath_additional) {
		fprintf(stderr, "This command only accepts %d -P,--lxcpath arguments\n",
			args->lxcpath_additional + 1);
		exit(EXIT_FAILURE);
	}

	args->lxcpath = realloc(args->lxcpath, (args->lxcpath_cnt + 1) *
				 sizeof(args->lxcpath[0]));
	if (args->lxcpath == NULL) {
		lxc_error(args, "no memory");
		return -ENOMEM;
	}
	args->lxcpath[args->lxcpath_cnt++] = lxcpath;
	return 0;
}

extern int lxc_arguments_parse(struct lxc_arguments *args,
			       int argc, char * const argv[])
{
	char shortopts[256];
	int  ret = 0;

	ret = build_shortopts(args->options, shortopts, sizeof(shortopts));
	if (ret < 0) {
		lxc_error(args, "build_shortopts() failed : %s",
			  strerror(errno));
		return ret;
	}

	while (1)  {
		int c, index = 0;

		c = getopt_long(argc, argv, shortopts, args->options, &index);
		if (c == -1)
			break;
		switch (c) {
		case 'n': 	args->name = optarg; break;
		case 'o':	args->log_file = optarg; break;
		case 'l':	args->log_priority = optarg; break;
		case 'q':	args->quiet = 1; break;
		case 'P':
			remove_trailing_slashes(optarg);
			ret = lxc_arguments_lxcpath_add(args, optarg);
			if (ret < 0)
				return ret;
			break;
		case OPT_USAGE: print_usage(args->options, args);
		case OPT_VERSION: print_version();
		case '?':	print_help(args, 1);
		case 'h': 	print_help(args, 0);
		default:
			if (args->parser) {
				ret = args->parser(args, c, optarg);
				if (ret)
					goto error;
			}
		}
	}

	/*
	 * Reclaim the remaining command arguments
	 */
	args->argv = &argv[optind];
	args->argc = argc - optind;

	/* If no lxcpaths were given, use default */
	if (!args->lxcpath_cnt) {
		ret = lxc_arguments_lxcpath_add(args, lxc_global_config_value("lxc.lxcpath"));
		if (ret < 0)
			return ret;
	}

	/* Check the command options */

	if (!args->name && strcmp(args->progname, "lxc-autostart") != 0) {
		lxc_error(args, "missing container name, use --name option");
		return -1;
	}

	if (args->checker)
		ret = args->checker(args);
error:
	if (ret)
		lxc_error(args, "could not parse command line");
	return ret;
}

int lxc_arguments_str_to_int(struct lxc_arguments *args, const char *str)
{
	long val;
	char *endptr;

	errno = 0;
	val = strtol(str, &endptr, 10);
	if (errno) {
		lxc_error(args, "invalid statefd '%s' : %m", str);
		return -1;
	}

	if (*endptr) {
		lxc_error(args, "invalid digit for statefd '%s'", str);
		return -1;
	}

	return (int)val;
}

/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <libgen.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <lxc/lxccontainer.h>
#include <lxc/version.h>

#include "compiler.h"
#include "config.h"
#include "initutils.h"
#include "memory_utils.h"
#include "parse.h"
#include "string_utils.h"

/* option keys for long only options */
#define OPT_USAGE 0x1000
#define OPT_VERSION (OPT_USAGE - 1)

#define QUOTE(macro) #macro
#define QUOTEVAL(macro) QUOTE(macro)

static struct option long_options[] = {
	    { "name",        required_argument, 0, 'n'         },
	    { "help",        no_argument,       0, 'h'         },
	    { "usage",       no_argument,       0, OPT_USAGE   },
	    { "version",     no_argument,       0, OPT_VERSION },
	    { "quiet",       no_argument,       0, 'q'         },
	    { "lxcpath",     required_argument, 0, 'P'         },
	    { 0,             0,                 0, 0           }
	};
static const char short_options[] = "n:hqo:l:P:";

struct arguments {
	const struct option *options;
	const char *shortopts;

	const char *name;
	bool quiet;
	const char *lxcpath;

	/* remaining arguments */
	char *const *argv;
	int argc;
};

static struct arguments my_args = {
	.options   = long_options,
	.shortopts = short_options
};

__noreturn static void print_usage_exit(const struct option longopts[])

{
	fprintf(stderr, "Usage: lxc-init [-n|--name=NAME] [-h|--help] [--usage] [--version]\n\
		[-q|--quiet] [-P|--lxcpath=LXCPATH]\n");
	exit(EXIT_SUCCESS);
}

__noreturn static void print_version_exit(void)
{
	printf("%s\n", LXC_VERSION);
	exit(EXIT_SUCCESS);
}

static void print_help(void)
{
	fprintf(stderr, "\
Usage: lxc-init --name=NAME -- COMMAND\n\
\n\
  lxc-init start a COMMAND as PID 2 inside a container\n\
\n\
Options :\n\
  -n, --name=NAME                  NAME of the container\n\
  -q, --quiet                      Don't produce any output\n\
  -P, --lxcpath=PATH               Use specified container path\n\
  -?, --help                       Give this help list\n\
      --usage                      Give a short usage message\n\
      --version                    Print the version number\n\
\n\
Mandatory or optional arguments to long options are also mandatory or optional\n\
for any corresponding short options.\n\
\n\
See the lxc-init man page for further information.\n\n");
}

static int arguments_parse(struct arguments *args, int argc,
			   char *const argv[])
{
	for (;;) {
		int c;
		int index = 0;

		c = getopt_long(argc, argv, args->shortopts, args->options, &index);
		if (c == -1)
			break;
		switch (c) {
		case 'n':
			args->name = optarg;
			break;
		case 'o':
			break;
		case 'l':
			break;
		case 'q':
			args->quiet = true;
			break;
		case 'P':
			remove_trailing_slashes(optarg);
			args->lxcpath = optarg;
			break;
		case OPT_USAGE:
			print_usage_exit(args->options);
		case OPT_VERSION:
			print_version_exit();
		case '?':
			print_help();
			exit(EXIT_FAILURE);
		case 'h':
			print_help();
			exit(EXIT_SUCCESS);
		}
	}

	/*
	 * Reclaim the remaining command arguments
	 */
	args->argv = &argv[optind];
	args->argc = argc - optind;

	/* If no lxcpath was given, use default */
	if (!args->lxcpath)
		args->lxcpath = lxc_global_config_value("lxc.lxcpath");

	/* Check the command options */
	if (!args->name) {
		if (!args->quiet)
			fprintf(stderr, "lxc-init: missing container name, use --name option\n");
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	if (arguments_parse(&my_args, argc, argv))
		exit(EXIT_FAILURE);

	if (!my_args.argc) {
		if (my_args.quiet)
			fprintf(stderr, "Please specify a command to execute\n");
		exit(EXIT_FAILURE);
	}

	lxc_container_init(my_args.argc, my_args.argv, my_args.quiet);
}

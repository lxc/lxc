/*
 * lxc: linux Container library
 *
 * Copyright © 2014 Oracle.
 *
 * Authors:
 * Dwight Engen <dwight.engen@oracle.com>
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

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <lxc/lxccontainer.h>

#include "arguments.h"
#include "log.h"
#include "lxc.h"
#include "mainloop.h"
#include "utils.h"

lxc_log_define(lxc_top_ui, lxc);

#define USER_HZ   100
#define ESC       "\033"
#define TERMCLEAR ESC "[H" ESC "[J"
#define TERMNORM  ESC "[0m"
#define TERMBOLD  ESC "[1m"
#define TERMRVRS  ESC "[7m"

struct stats {
	uint64_t mem_used;
	uint64_t mem_limit;
	uint64_t kmem_used;
	uint64_t kmem_limit;
	uint64_t cpu_use_nanos;
	uint64_t cpu_use_user;
	uint64_t cpu_use_sys;
	uint64_t blkio;
};

struct ct {
	struct lxc_container *c;
	struct stats *stats;
};

static int delay = 3;
static char sort_by = 'n';
static int sort_reverse = 0;

static struct termios oldtios;
static struct ct *ct = NULL;
static int ct_alloc_cnt = 0;

static int my_parser(struct lxc_arguments* args, int c, char* arg)
{
	switch (c) {
	case 'd': delay = atoi(arg); break;
	case 's': sort_by = arg[0]; break;
	case 'r': sort_reverse = 1; break;
	}
	return 0;
}

static const struct option my_longopts[] = {
	{"delay",   required_argument, 0, 'd'},
	{"sort",    required_argument, 0, 's'},
	{"reverse", no_argument,       0, 'r'},
	LXC_COMMON_OPTIONS
};

static struct lxc_arguments my_args = {
	.progname = "lxc-top",
	.help     = "\
[--name=NAME]\n\
\n\
lxc-top monitors the state of the active containers\n\
\n\
Options :\n\
  -d, --delay     delay in seconds between refreshes (default: 3.0)\n\
  -s, --sort      sort by [n,c,b,m] (default: n) where\n\
                  n = Name\n\
                  c = CPU use\n\
                  b = Block I/O use\n\
                  m = Memory use\n\
                  k = Kernel memory use\n\
  -r, --reverse   sort in reverse (descending) order\n",
	.name     = ".*",
	.options  = my_longopts,
	.parser   = my_parser,
	.checker  = NULL,
	.lxcpath_additional = -1,
};

static void stdin_tios_restore(void)
{
	tcsetattr(0, TCSAFLUSH, &oldtios);
	fprintf(stderr, "\n");
}

static int stdin_tios_setup(void)
{
	struct termios newtios;

	if (!isatty(0)) {
		ERROR("stdin is not a tty");
		return -1;
	}

	if (tcgetattr(0, &oldtios)) {
		SYSERROR("failed to get current terminal settings");
		return -1;
	}

	newtios = oldtios;

	/* turn off echo and line buffering */
	newtios.c_iflag &= ~IGNBRK;
	newtios.c_iflag &= BRKINT;
	newtios.c_lflag &= ~(ECHO|ICANON);
	newtios.c_cc[VMIN] = 1;
	newtios.c_cc[VTIME] = 0;

	if (tcsetattr(0, TCSAFLUSH, &newtios)) {
		ERROR("failed to set new terminal settings");
		return -1;
	}

	return 0;
}

static int stdin_tios_rows(void)
{
	struct winsize wsz;
	if (isatty(0) && ioctl(0, TIOCGWINSZ, &wsz) == 0)
		return wsz.ws_row;
	return 25;
}

static int stdin_handler(int fd, uint32_t events, void *data,
			 struct lxc_epoll_descr *descr)
{
	char *in_char = data;

	if (events & EPOLLIN) {
		int rc;

		rc = read(fd, in_char, sizeof(*in_char));
		if (rc <= 0)
			*in_char = '\0';
	}

	if (events & EPOLLHUP)
		*in_char = 'q';
	return 1;
}

static void sig_handler(int sig)
{
	exit(EXIT_SUCCESS);
}

static void size_humanize(unsigned long long val, char *buf, size_t bufsz)
{
	if (val > 1 << 30) {
		snprintf(buf, bufsz, "%u.%2.2u GB",
			    (int)(val >> 30),
			    (int)(val & ((1 << 30) - 1)) / 10737419);
	} else if (val > 1 << 20) {
		int x = val + 5243;  /* for rounding */
		snprintf(buf, bufsz, "%u.%2.2u MB",
			    x >> 20, ((x & ((1 << 20) - 1)) * 100) >> 20);
	} else if (val > 1 << 10) {
		int x = val + 5;  /* for rounding */
		snprintf(buf, bufsz, "%u.%2.2u KB",
			    x >> 10, ((x & ((1 << 10) - 1)) * 100) >> 10);
	} else {
		snprintf(buf, bufsz, "%3u.00   ", (int)val);
	}
}

static uint64_t stat_get_int(struct lxc_container *c, const char *item)
{
	char buf[80];
	int len;
	uint64_t val;

	len = c->get_cgroup_item(c, item, buf, sizeof(buf));
	if (len <= 0) {
		ERROR("unable to read cgroup item %s", item);
		return 0;
	}

	val = strtoull(buf, NULL, 0);
	return val;
}

static uint64_t stat_match_get_int(struct lxc_container *c, const char *item,
				   const char *match, int column)
{
	char buf[4096];
	int i,j,len;
	uint64_t val = 0;
	char **lines, **cols;
	size_t matchlen;

	len = c->get_cgroup_item(c, item, buf, sizeof(buf));
	if (len <= 0) {
		ERROR("unable to read cgroup item %s", item);
		goto out;
	}

	lines = lxc_string_split_and_trim(buf, '\n');
	if (!lines)
		goto out;

	matchlen = strlen(match);
	for (i = 0; lines[i]; i++) {
		if (strncmp(lines[i], match, matchlen) == 0) {
			cols = lxc_string_split_and_trim(lines[i], ' ');
			if (!cols)
				goto err1;
			for (j = 0; cols[j]; j++) {
				if (j == column) {
					val = strtoull(cols[j], NULL, 0);
					break;
				}
			}
			lxc_free_array((void **)cols, free);
			break;
		}
	}
err1:
	lxc_free_array((void **)lines, free);
out:
	return val;
}

static void stats_get(struct lxc_container *c, struct ct *ct, struct stats *total)
{
	ct->c = c;
	ct->stats->mem_used      = stat_get_int(c, "memory.usage_in_bytes");
	ct->stats->mem_limit     = stat_get_int(c, "memory.limit_in_bytes");
	ct->stats->kmem_used     = stat_get_int(c, "memory.kmem.usage_in_bytes");
	ct->stats->kmem_limit    = stat_get_int(c, "memory.kmem.limit_in_bytes");
	ct->stats->cpu_use_nanos = stat_get_int(c, "cpuacct.usage");
	ct->stats->cpu_use_user  = stat_match_get_int(c, "cpuacct.stat", "user", 1);
	ct->stats->cpu_use_sys   = stat_match_get_int(c, "cpuacct.stat", "system", 1);
	ct->stats->blkio         = stat_match_get_int(c, "blkio.throttle.io_service_bytes", "Total", 1);

	if (total) {
		total->mem_used      = total->mem_used      + ct->stats->mem_used;
		total->mem_limit     = total->mem_limit     + ct->stats->mem_limit;
		total->kmem_used     = total->kmem_used     + ct->stats->kmem_used;
		total->kmem_limit    = total->kmem_limit    + ct->stats->kmem_limit;
		total->cpu_use_nanos = total->cpu_use_nanos + ct->stats->cpu_use_nanos;
		total->cpu_use_user  = total->cpu_use_user  + ct->stats->cpu_use_user;
		total->cpu_use_sys   = total->cpu_use_sys   + ct->stats->cpu_use_sys;
		total->blkio         = total->blkio         + ct->stats->blkio;
	}
}

static void stats_print_header(struct stats *stats)
{
	printf(TERMRVRS TERMBOLD);
	printf("%-18s %12s %12s %12s %14s %10s", "Container", "CPU",  "CPU",  "CPU",  "BlkIO", "Mem");
	if (stats->kmem_used > 0)
		printf(" %10s", "KMem");
	printf("\n");

	printf("%-18s %12s %12s %12s %14s %10s", "Name",      "Used", "Sys",  "User", "Total", "Used");
	if (stats->kmem_used > 0)
		printf(" %10s", "Used");
	printf("\n");
	printf(TERMNORM);
}

static void stats_print(const char *name, const struct stats *stats,
			const struct stats *total)
{
	char blkio_str[20];
	char mem_used_str[20];
	char kmem_used_str[20];

	size_humanize(stats->blkio, blkio_str, sizeof(blkio_str));
	size_humanize(stats->mem_used, mem_used_str, sizeof(mem_used_str));

	printf("%-18.18s %12.2f %12.2f %12.2f %14s %10s",
	       name,
	       (float)stats->cpu_use_nanos / 1000000000,
	       (float)stats->cpu_use_sys  / USER_HZ,
	       (float)stats->cpu_use_user / USER_HZ,
	       blkio_str,
	       mem_used_str);
	if (total->kmem_used > 0) {
		size_humanize(stats->kmem_used, kmem_used_str, sizeof(kmem_used_str));
		printf(" %10s", kmem_used_str);
	}
}

static int cmp_name(const void *sct1, const void *sct2)
{
	const struct ct *ct1 = sct1;
	const struct ct *ct2 = sct2;

	if (sort_reverse)
		return strcmp(ct2->c->name, ct1->c->name);
	return strcmp(ct1->c->name, ct2->c->name);
}

static int cmp_cpuuse(const void *sct1, const void *sct2)
{
	const struct ct *ct1 = sct1;
	const struct ct *ct2 = sct2;

	if (sort_reverse)
		return ct2->stats->cpu_use_nanos < ct1->stats->cpu_use_nanos;
	return ct1->stats->cpu_use_nanos < ct2->stats->cpu_use_nanos;
}

static int cmp_blkio(const void *sct1, const void *sct2)
{
	const struct ct *ct1 = sct1;
	const struct ct *ct2 = sct2;

	if (sort_reverse)
		return ct2->stats->blkio < ct1->stats->blkio;
	return ct1->stats->blkio < ct2->stats->blkio;
}

static int cmp_memory(const void *sct1, const void *sct2)
{
	const struct ct *ct1 = sct1;
	const struct ct *ct2 = sct2;

	if (sort_reverse)
		return ct2->stats->mem_used < ct1->stats->mem_used;
	return ct1->stats->mem_used < ct2->stats->mem_used;
}

static int cmp_kmemory(const void *sct1, const void *sct2)
{
	const struct ct *ct1 = sct1;
	const struct ct *ct2 = sct2;

	if (sort_reverse)
		return ct2->stats->kmem_used < ct1->stats->kmem_used;
	return ct1->stats->kmem_used < ct2->stats->kmem_used;
}

static void ct_sort(int active)
{
	int (*cmp_func)(const void *, const void *);

	switch(sort_by) {
	default:
	case 'n': cmp_func = cmp_name; break;
	case 'c': cmp_func = cmp_cpuuse; break;
	case 'b': cmp_func = cmp_blkio; break;
	case 'm': cmp_func = cmp_memory; break;
	case 'k': cmp_func = cmp_kmemory; break;
	}
	qsort(ct, active, sizeof(*ct), (int (*)(const void *,const void *))cmp_func);
}

static void ct_free(void)
{
	int i;

	for (i = 0; i < ct_alloc_cnt; i++) {
		if (ct[i].c) {
			lxc_container_put(ct[i].c);
			ct[i].c = NULL;
		}
		free(ct[i].stats);
		ct[i].stats = NULL;
	}
}

static void ct_realloc(int active_cnt)
{
	int i;

	if (active_cnt > ct_alloc_cnt) {
		ct_free();
		ct = realloc(ct, sizeof(*ct) * active_cnt);
		if (!ct) {
			ERROR("cannot alloc mem");
			exit(EXIT_FAILURE);
		}
		for (i = 0; i < active_cnt; i++) {
			ct[i].stats = malloc(sizeof(*ct[0].stats));
			if (!ct[i].stats) {
				ERROR("cannot alloc mem");
				exit(EXIT_FAILURE);
			}
		}
		ct_alloc_cnt = active_cnt;
	}
}

int main(int argc, char *argv[])
{
	struct lxc_epoll_descr descr;
	int ret, ct_print_cnt;
	char in_char;

	ret = EXIT_FAILURE;
	if (lxc_arguments_parse(&my_args, argc, argv))
		goto out;

	ct_print_cnt = stdin_tios_rows() - 3; /* 3 -> header and total */
	if (stdin_tios_setup() < 0) {
		ERROR("failed to setup terminal");
		goto out;
	}

	/* ensure the terminal gets restored */
	atexit(stdin_tios_restore);
	signal(SIGINT, sig_handler);
	signal(SIGQUIT, sig_handler);

	if (lxc_mainloop_open(&descr)) {
		ERROR("failed to create mainloop");
		goto out;
	}

	ret = lxc_mainloop_add_handler(&descr, 0, stdin_handler, &in_char);
	if (ret) {
		ERROR("failed to add stdin handler");
		ret = EXIT_FAILURE;
		goto err1;
	}

	for(;;) {
		struct lxc_container **active;
		int i, active_cnt;
		struct stats total;
		char total_name[30];

		active_cnt = list_active_containers(my_args.lxcpath[0], NULL, &active);
		ct_realloc(active_cnt);

		memset(&total, 0, sizeof(total));
		for (i = 0; i < active_cnt; i++)
			stats_get(active[i], &ct[i], &total);

		ct_sort(active_cnt);

		printf(TERMCLEAR);
		stats_print_header(&total);
		for (i = 0; i < active_cnt && i < ct_print_cnt; i++) {
			stats_print(ct[i].c->name, ct[i].stats, &total);
			printf("\n");
		}
		sprintf(total_name, "TOTAL %d of %d", i, active_cnt);
		stats_print(total_name, &total, &total);
		fflush(stdout);

		for (i = 0; i < active_cnt; i++) {
			lxc_container_put(ct[i].c);
			ct[i].c = NULL;
		}

		in_char = '\0';
		ret = lxc_mainloop(&descr, 1000 * delay);
		if (ret != 0 || in_char == 'q')
			break;
		switch(in_char) {
		case 'r':
			sort_reverse ^= 1;
			break;
		case 'n':
		case 'c':
		case 'b':
		case 'm':
		case 'k':
			if (sort_by == in_char)
				sort_reverse ^= 1;
			else
				sort_reverse = 0;
			sort_by = in_char;
		}
	}
	ret = EXIT_SUCCESS;

err1:
	lxc_mainloop_close(&descr);
out:
	return ret;
}

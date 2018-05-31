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

#define _GNU_SOURCE
#define __STDC_FORMAT_MACROS /* Required for PRIu64 to work. */
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/time.h>

#include <lxc/lxccontainer.h>

#include "arguments.h"
#include "tool_utils.h"

#define USER_HZ   100
#define ESC       "\033"
#define TERMCLEAR ESC "[H" ESC "[J"
#define TERMNORM  ESC "[0m"
#define TERMBOLD  ESC "[1m"
#define TERMRVRS  ESC "[7m"

struct blkio_stats {
	uint64_t read;
	uint64_t write;
	uint64_t total;
};

struct stats {
	uint64_t mem_used;
	uint64_t mem_limit;
	uint64_t memsw_used;
	uint64_t memsw_limit;
	uint64_t kmem_used;
	uint64_t kmem_limit;
	uint64_t cpu_use_nanos;
	uint64_t cpu_use_user;
	uint64_t cpu_use_sys;
	struct blkio_stats io_service_bytes;
	struct blkio_stats io_serviced;
};

struct ct {
	struct lxc_container *c;
	struct stats *stats;
};

static int batch = 0;
static int delay_set = 0;
static int delay = 3;
static char sort_by = 'n';
static int sort_reverse = 0;
static struct termios oldtios;
static struct ct *ct = NULL;
static int ct_alloc_cnt = 0;

static int my_parser(struct lxc_arguments* args, int c, char* arg)
{
	switch (c) {
	case 'd':
		delay_set = 1;
		if (lxc_safe_int(arg, &delay) < 0)
			return -1;
		break;
	case 'b':
		batch=1;
		break;
	case 's':
		sort_by = arg[0];
		break;
	case 'r':
		sort_reverse = 1;
		break;
	}
	return 0;
}

static const struct option my_longopts[] = {
	{"delay",   required_argument, 0, 'd'},
	{"batch",   no_argument,       0, 'b'},
	{"sort",    required_argument, 0, 's'},
	{"reverse", no_argument,       0, 'r'},
	LXC_COMMON_OPTIONS
};

static struct lxc_arguments my_args = {
	.progname = "lxc-top",
	.help     = "\
\n\
\n\
lxc-top monitors the state of the active containers\n\
\n\
Options :\n\
  -d, --delay     delay in seconds between refreshes (default: 3.0)\n\
  -b, --batch     output designed to capture to a file\n\
  -s, --sort      sort by [n,c,b,m] (default: n) where\n\
                  n = Name\n\
                  c = CPU use\n\
                  b = Block I/O use\n\
                  m = Memory use\n\
                  s = Memory + Swap use\n\
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
		fprintf(stderr, "stdin is not a tty\n");
		return -1;
	}

	if (tcgetattr(0, &oldtios)) {
		fprintf(stderr, "failed to get current terminal settings\n");
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
		fprintf(stderr, "failed to set new terminal settings\n");
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

static void sig_handler(int sig)
{
	exit(EXIT_SUCCESS);
}

static void size_humanize(unsigned long long val, char *buf, size_t bufsz)
{
	int ret;

	if (val > 1 << 30) {
		ret = snprintf(buf, bufsz, "%u.%2.2u GiB",
			    (unsigned int)(val >> 30),
			    (unsigned int)(val & ((1 << 30) - 1)) / 10737419);
	} else if (val > 1 << 20) {
		unsigned int x = val + 5243;  /* for rounding */
		ret = snprintf(buf, bufsz, "%u.%2.2u MiB",
			    x >> 20, ((x & ((1 << 20) - 1)) * 100) >> 20);
	} else if (val > 1 << 10) {
		unsigned int x = val + 5;  /* for rounding */
		ret = snprintf(buf, bufsz, "%u.%2.2u KiB",
			    x >> 10, ((x & ((1 << 10) - 1)) * 100) >> 10);
	} else {
		ret = snprintf(buf, bufsz, "%3u.00   ", (unsigned int)val);
	}

	if (ret < 0 || (size_t)ret >= bufsz)
		fprintf(stderr, "Failed to create string\n");
}

static uint64_t stat_get_int(struct lxc_container *c, const char *item)
{
	char buf[80];
	int len;
	uint64_t val;

	len = c->get_cgroup_item(c, item, buf, sizeof(buf));
	if (len <= 0) {
		fprintf(stderr, "unable to read cgroup item %s\n", item);
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
		fprintf(stderr, "unable to read cgroup item %s\n", item);
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

/*
examples:
	blkio.throttle.io_serviced
	8:0 Read 4259
	8:0 Write 835
	8:0 Sync 292
	8:0 Async 4802
	8:0 Total 5094
	Total 5094

	blkio.throttle.io_service_bytes
	8:0 Read 110309376
	8:0 Write 39018496
	8:0 Sync 2818048
	8:0 Async 146509824
	8:0 Total 149327872
	Total 149327872
*/
static void stat_get_blk_stats(struct lxc_container *c, const char *item,
			      struct blkio_stats *stats) {
	char buf[4096];
	int i, len;
	char **lines, **cols;

	len = c->get_cgroup_item(c, item, buf, sizeof(buf));
	if (len <= 0 || (size_t)len >= sizeof(buf)) {
		fprintf(stderr, "unable to read cgroup item %s\n", item);
		return;
	}

	lines = lxc_string_split_and_trim(buf, '\n');
	if (!lines)
		return;

	memset(stats, 0, sizeof(struct blkio_stats));
	for (i = 0; lines[i]; i++) {
		cols = lxc_string_split_and_trim(lines[i], ' ');
		if (!cols)
			goto out;
		if (strcmp(cols[1], "Read") == 0)
			stats->read += strtoull(cols[2], NULL, 0);
		else if (strcmp(cols[1], "Write") == 0)
			stats->write += strtoull(cols[2], NULL, 0);
		if (strcmp(cols[0], "Total") == 0)
			stats->total = strtoull(cols[1], NULL, 0);

		lxc_free_array((void **)cols, free);
	}
out:
	lxc_free_array((void **)lines, free);
	return;
}

static void stats_get(struct lxc_container *c, struct ct *ct, struct stats *total)
{
	ct->c = c;
	ct->stats->mem_used      = stat_get_int(c, "memory.usage_in_bytes");
	ct->stats->mem_limit     = stat_get_int(c, "memory.limit_in_bytes");
	ct->stats->memsw_used    = stat_get_int(c, "memory.memsw.usage_in_bytes");
	ct->stats->memsw_limit   = stat_get_int(c, "memory.memsw.limit_in_bytes");
	ct->stats->kmem_used     = stat_get_int(c, "memory.kmem.usage_in_bytes");
	ct->stats->kmem_limit    = stat_get_int(c, "memory.kmem.limit_in_bytes");
	ct->stats->cpu_use_nanos = stat_get_int(c, "cpuacct.usage");
	ct->stats->cpu_use_user  = stat_match_get_int(c, "cpuacct.stat", "user", 1);
	ct->stats->cpu_use_sys   = stat_match_get_int(c, "cpuacct.stat", "system", 1);
	stat_get_blk_stats(c, "blkio.throttle.io_service_bytes", &ct->stats->io_service_bytes);
	stat_get_blk_stats(c, "blkio.throttle.io_serviced", &ct->stats->io_serviced);

	if (total) {
		total->mem_used      = total->mem_used      + ct->stats->mem_used;
		total->mem_limit     = total->mem_limit     + ct->stats->mem_limit;
		total->memsw_used    = total->memsw_used    + ct->stats->memsw_used;
		total->memsw_limit   = total->memsw_limit   + ct->stats->memsw_limit;
		total->kmem_used     = total->kmem_used     + ct->stats->kmem_used;
		total->kmem_limit    = total->kmem_limit    + ct->stats->kmem_limit;
		total->cpu_use_nanos = total->cpu_use_nanos + ct->stats->cpu_use_nanos;
		total->cpu_use_user  = total->cpu_use_user  + ct->stats->cpu_use_user;
		total->cpu_use_sys   = total->cpu_use_sys   + ct->stats->cpu_use_sys;
		total->io_service_bytes.total += ct->stats->io_service_bytes.total;
		total->io_service_bytes.read += ct->stats->io_service_bytes.read;
		total->io_service_bytes.write += ct->stats->io_service_bytes.write;
	}
}

static void stats_print_header(struct stats *stats)
{
	printf(TERMRVRS TERMBOLD);
	printf("%-18s %12s %12s %12s %36s %10s", "Container", "CPU",  "CPU",  "CPU",  "BlkIO", "Mem");
	if (stats->memsw_used > 0)
		printf(" %10s", "MemSw");
	if (stats->kmem_used > 0)
		printf(" %10s", "KMem");
	printf("\n");

	printf("%-18s %12s %12s %12s %36s %10s", "Name",      "Used", "Sys",  "User", "Total(Read/Write)", "Used");
	if (stats->memsw_used > 0)
		printf(" %10s", "Used");
	if (stats->kmem_used > 0)
		printf(" %10s", "Used");
	printf("\n");
	printf(TERMNORM);
}

static void stats_print(const char *name, const struct stats *stats,
			const struct stats *total)
{
	char iosb_str[63];
	char iosb_total_str[20];
	char iosb_read_str[20];
	char iosb_write_str[20];
	char mem_used_str[20];
	char memsw_used_str[20];
	char kmem_used_str[20];
	struct timeval time_val;
	unsigned long long time_ms;
	int ret;

	if (!batch) {
		size_humanize(stats->io_service_bytes.total, iosb_total_str, sizeof(iosb_total_str));
		size_humanize(stats->io_service_bytes.read, iosb_read_str, sizeof(iosb_read_str));
		size_humanize(stats->io_service_bytes.write, iosb_write_str, sizeof(iosb_write_str));
		size_humanize(stats->mem_used, mem_used_str, sizeof(mem_used_str));

		ret = snprintf(iosb_str, sizeof(iosb_str), "%s(%s/%s)", iosb_total_str, iosb_read_str, iosb_write_str);
		if (ret < 0 || (size_t)ret >= sizeof(iosb_str))
			printf("snprintf'd too many characters: %d\n", ret);

		printf("%-18.18s %12.2f %12.2f %12.2f %36s %10s",
		       name,
		       (float)stats->cpu_use_nanos / 1000000000,
		       (float)stats->cpu_use_sys  / USER_HZ,
		       (float)stats->cpu_use_user / USER_HZ,
		       iosb_str,
		       mem_used_str);

		if (total->memsw_used > 0) {
			size_humanize(stats->memsw_used, memsw_used_str, sizeof(memsw_used_str));
			printf(" %10s", memsw_used_str);
		}
		if (total->kmem_used > 0) {
			size_humanize(stats->kmem_used, kmem_used_str, sizeof(kmem_used_str));
			printf(" %10s", kmem_used_str);
		}
	} else {
		(void)gettimeofday(&time_val, NULL);
		time_ms = (unsigned long long) (time_val.tv_sec) * 1000 + (unsigned long long) (time_val.tv_usec) / 1000;
		printf("%" PRIu64 ",%s,%" PRIu64 ",%" PRIu64 ",%" PRIu64
		       ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64,
		       (uint64_t)time_ms, name, (uint64_t)stats->cpu_use_nanos,
		       (uint64_t)stats->cpu_use_sys,
		       (uint64_t)stats->cpu_use_user, (uint64_t)stats->io_service_bytes.total,
		       (uint64_t)stats->io_serviced.total, (uint64_t)stats->mem_used,
		       (uint64_t)stats->memsw_used, (uint64_t)stats->kmem_used);
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
		return ct2->stats->io_service_bytes.total < ct1->stats->io_service_bytes.total;
	return ct1->stats->io_service_bytes.total < ct2->stats->io_service_bytes.total;
}

static int cmp_memory(const void *sct1, const void *sct2)
{
	const struct ct *ct1 = sct1;
	const struct ct *ct2 = sct2;

	if (sort_reverse)
		return ct2->stats->mem_used < ct1->stats->mem_used;
	return ct1->stats->mem_used < ct2->stats->mem_used;
}

static int cmp_memorysw(const void *sct1, const void *sct2)
{
	const struct ct *ct1 = sct1;
	const struct ct *ct2 = sct2;

	if (sort_reverse)
		return ct2->stats->memsw_used < ct1->stats->memsw_used;
	return ct1->stats->memsw_used < ct2->stats->memsw_used;
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
	case 's': cmp_func = cmp_memorysw; break;
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
			fprintf(stderr, "cannot alloc mem\n");
			exit(EXIT_FAILURE);
		}
		for (i = 0; i < active_cnt; i++) {
			ct[i].stats = malloc(sizeof(*ct[0].stats));
			if (!ct[i].stats) {
				fprintf(stderr, "cannot alloc mem\n");
				exit(EXIT_FAILURE);
			}
		}
		ct_alloc_cnt = active_cnt;
	}
}

#define LXC_MAINLOOP_CONTINUE 0
#define LXC_MAINLOOP_CLOSE 1

struct lxc_epoll_descr {
	int epfd;
	struct lxc_list handlers;
};

typedef int (*lxc_mainloop_callback_t)(int fd, uint32_t event, void *data,
				       struct lxc_epoll_descr *descr);

struct mainloop_handler {
	lxc_mainloop_callback_t callback;
	int fd;
	void *data;
};

#define MAX_EVENTS 10

int lxc_mainloop(struct lxc_epoll_descr *descr, int timeout_ms)
{
	int i, nfds, ret;
	struct mainloop_handler *handler;
	struct epoll_event events[MAX_EVENTS];

	for (;;) {
		nfds = epoll_wait(descr->epfd, events, MAX_EVENTS, timeout_ms);
		if (nfds < 0) {
			if (errno == EINTR)
				continue;

			return -1;
		}

		for (i = 0; i < nfds; i++) {
			handler = events[i].data.ptr;

			/* If the handler returns a positive value, exit the
			 * mainloop.
			 */
			ret = handler->callback(handler->fd, events[i].events,
						handler->data, descr);
			if (ret == LXC_MAINLOOP_CLOSE)
				return 0;
		}

		if (nfds == 0)
			return 0;

		if (lxc_list_empty(&descr->handlers))
			return 0;
	}
}

int lxc_mainloop_open(struct lxc_epoll_descr *descr)
{
	/* hint value passed to epoll create */
	descr->epfd = epoll_create1(EPOLL_CLOEXEC);
	if (descr->epfd < 0)
		return -1;

	lxc_list_init(&descr->handlers);
	return 0;
}

int lxc_mainloop_add_handler(struct lxc_epoll_descr *descr, int fd,
			     lxc_mainloop_callback_t callback, void *data)
{
	struct epoll_event ev;
	struct mainloop_handler *handler;
	struct lxc_list *item;

	handler = malloc(sizeof(*handler));
	if (!handler)
		return -1;

	handler->callback = callback;
	handler->fd = fd;
	handler->data = data;

	ev.events = EPOLLIN;
	ev.data.ptr = handler;

	if (epoll_ctl(descr->epfd, EPOLL_CTL_ADD, fd, &ev) < 0)
		goto out_free_handler;

	item = malloc(sizeof(*item));
	if (!item)
		goto out_free_handler;

	item->elem = handler;
	lxc_list_add(&descr->handlers, item);
	return 0;

out_free_handler:
	free(handler);
	return -1;
}

int lxc_mainloop_close(struct lxc_epoll_descr *descr)
{
	struct lxc_list *iterator, *next;

	iterator = descr->handlers.next;
	while (iterator != &descr->handlers) {
		next = iterator->next;

		lxc_list_del(iterator);
		free(iterator->elem);
		free(iterator);
		iterator = next;
	}

	if (descr->epfd >= 0)
		return close(descr->epfd);

	return 0;
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
	return LXC_MAINLOOP_CLOSE;
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
		fprintf(stderr, "failed to setup terminal\n");
		goto out;
	}

	/* ensure the terminal gets restored */
	atexit(stdin_tios_restore);
	signal(SIGINT, sig_handler);
	signal(SIGQUIT, sig_handler);

	if (lxc_mainloop_open(&descr)) {
		fprintf(stderr, "failed to create mainloop\n");
		goto out;
	}

	ret = lxc_mainloop_add_handler(&descr, 0, stdin_handler, &in_char);
	if (ret) {
		fprintf(stderr, "failed to add stdin handler\n");
		ret = EXIT_FAILURE;
		goto err1;
	}

	if (batch && !delay_set) {
		delay = 300;
	}
        if (batch) {
		printf("time_ms,container,cpu_nanos,cpu_sys_userhz,cpu_user_userhz,blkio_bytes,blkio_iops,mem_used_bytes,memsw_used_bytes,kernel_mem_used_bytes\n");
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

		if (!batch) {
		  printf(TERMCLEAR);
		  stats_print_header(&total);
		}
		for (i = 0; i < active_cnt && i < ct_print_cnt; i++) {
			stats_print(ct[i].c->name, ct[i].stats, &total);
			printf("\n");
		}
		if (!batch) {
			sprintf(total_name, "TOTAL %d of %d", i, active_cnt);
			stats_print(total_name, &total, &total);
		}
		fflush(stdout);

		for (i = 0; i < active_cnt; i++) {
			lxc_container_put(ct[i].c);
			ct[i].c = NULL;
		}

		in_char = '\0';
		if (!batch) {
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
			case 's':
			case 'k':
				if (sort_by == in_char)
					sort_reverse ^= 1;
				else
					sort_reverse = 0;
				sort_by = in_char;
			}
		} else {
			sleep(delay);
		}
	}
	ret = EXIT_SUCCESS;

err1:
	lxc_mainloop_close(&descr);
out:
	exit(ret);
}

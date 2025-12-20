/* SPDX-License-Identifier: LGPL-2.1+ */

#include "config.h"

#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <termios.h>
#include <unistd.h>

#include "lxc.h"

#include "arguments.h"
#include "mainloop.h"
#include "utils.h"

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

struct cpu_stats {
	uint64_t use_nanos;
	uint64_t use_user;
	uint64_t use_sys;
};

struct mem_stats {
	union {
		struct {
			uint64_t swap_used;
			uint64_t swap_limit;
		}; /* v2 only */
		struct {
			uint64_t memsw_used;
			uint64_t memsw_limit;
		}; /* v1 only */
	};
	uint64_t used;
	uint64_t limit;
	uint64_t kmem_used;
	uint64_t kmem_limit;
};

struct stats {
	struct mem_stats mem;
	struct cpu_stats cpu;
	struct blkio_stats io_service_bytes;
	struct blkio_stats io_serviced;
};

struct container_stats {
	struct lxc_container *c;
	struct stats *stats;
};

static int batch = 0;
static int delay_set = 0;
static int delay = 3;
static char sort_by = 'n';
static int sort_reverse = 0;
static struct termios oldtios;
static struct container_stats *container_stats = NULL;
static int ct_alloc_cnt = 0;
static long user_hz = 0;

static int my_parser(struct lxc_arguments *args, int c, char *arg)
{
	switch (c) {
	case 'd':
		delay_set = 1;
		if (lxc_safe_int(arg, &delay) < 0)
			return -1;
		break;
	case 'b':
		batch = 1;
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
	.log_priority = "ERROR",
	.log_file     = "none",
};

static void stdin_tios_restore(void)
{
	(void)tcsetattr(0, TCSAFLUSH, &oldtios);
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
		fprintf(stderr, "Failed to get current terminal settings\n");
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
		fprintf(stderr, "Failed to set new terminal settings\n");
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
static int cg1_get_blk_stats(struct lxc_container *c, const char *item,
			      struct blkio_stats *stats) {
	char buf[4096];
	int i, len;
	char **lines, **cols;
	int ret = -1;

	len = c->get_cgroup_item(c, item, buf, sizeof(buf));
	if (len <= 0 || (size_t)len >= sizeof(buf)) {
		return ret;
	}

	lines = lxc_string_split_and_trim(buf, '\n');
	if (!lines)
		return ret;

	memset(stats, 0, sizeof(struct blkio_stats));

	for (i = 0; lines[i]; i++) {
		cols = lxc_string_split_and_trim(lines[i], ' ');
		if (!cols)
			goto out;

		if (strncmp(cols[1], "Read", strlen(cols[1])) == 0)
			stats->read += strtoull(cols[2], NULL, 0);
		else if (strncmp(cols[1], "Write", strlen(cols[1])) == 0)
			stats->write += strtoull(cols[2], NULL, 0);

		if (strncmp(cols[0], "Total", strlen(cols[0])) == 0)
			stats->total = strtoull(cols[1], NULL, 0);

		lxc_free_array((void **)cols, free);
	}
	ret = 0;
out:
	lxc_free_array((void **)lines, free);
	return ret;
}

static int cg2_get_blk_stats(struct lxc_container *c, const char *item,
			      struct blkio_stats *stats) {
	char buf[4096];
	int i, j, len;
	char **lines, **cols;
	int ret = -1;

	len = c->get_cgroup_item(c, item, buf, sizeof(buf));
	if (len <= 0 || (size_t)len >= sizeof(buf)) {
		return ret;
	}

	lines = lxc_string_split_and_trim(buf, '\n');
	if (!lines)
		return ret;

	memset(stats, 0, sizeof(struct blkio_stats));

	for (i = 0; lines[i]; i++) {
		cols = lxc_string_split_and_trim(lines[i], ' ');
		if (!cols)
			goto out;

		for (j = 0; cols[j]; j++) {
			if (strncmp(cols[j], "rbytes=", 7) == 0) {
				stats->read += strtoull(&cols[j][7], NULL, 0);
			} else if (strncmp(cols[j], "wbytes=", 7) == 0) {
				stats->write += strtoull(&cols[j][7], NULL, 0);
			}
		}

		lxc_free_array((void **)cols, free);
	}
	stats->total = stats->read + stats->write;
	ret = 0;
out:
	lxc_free_array((void **)lines, free);
	return ret;
}

static int cg1_mem_stats(struct lxc_container *c, struct mem_stats *mem)
{
	mem->used        = stat_get_int(c, "memory.usage_in_bytes");
	mem->limit       = stat_get_int(c, "memory.limit_in_bytes");
	mem->memsw_used  = stat_get_int(c, "memory.memsw.usage_in_bytes");
	mem->memsw_limit = stat_get_int(c, "memory.memsw.limit_in_bytes");
	mem->kmem_used   = stat_get_int(c, "memory.kmem.usage_in_bytes");
	mem->kmem_limit  = stat_get_int(c, "memory.kmem.limit_in_bytes");
	return mem->used > 0 ? 0 : -1;
}

static int cg2_mem_stats(struct lxc_container *c, struct mem_stats *mem)
{
	mem->used          = stat_get_int(c, "memory.current");
	mem->limit         = stat_get_int(c, "memory.max");
	mem->swap_used     = stat_get_int(c, "memory.swap.current");
	mem->swap_limit    = stat_get_int(c, "memory.swap.max");
	mem->kmem_used     = stat_match_get_int(c, "memory.stat", "kernel", 1);
	/* does not exist in cgroup v2 */
	// mem->kmem_limit = 0;
	return mem->used > 0 ? 0 : -1;
}

static int cg1_cpu_stats(struct lxc_container *c, struct cpu_stats *cpu)
{
	cpu->use_nanos = stat_get_int(c, "cpuacct.usage");
	cpu->use_user  = stat_match_get_int(c, "cpuacct.stat", "user", 1);
	cpu->use_sys   = stat_match_get_int(c, "cpuacct.stat", "system", 1);
	return cpu->use_nanos > 0 ? 0 : -1;
}

static int cg2_cpu_stats(struct lxc_container *c, struct cpu_stats *cpu)
{
	/* convert microseconds to nanoseconds */
	cpu->use_nanos = stat_match_get_int(c, "cpu.stat", "usage_usec", 1) * 1000;

	cpu->use_user  = stat_match_get_int(c, "cpu.stat", "user_usec", 1) * user_hz / 1000000;
	cpu->use_sys   = stat_match_get_int(c, "cpu.stat", "system_usec", 1) * user_hz / 1000000;
	return cpu->use_nanos > 0 ? 0 : -1;
}

static void stats_get(struct lxc_container *c, struct container_stats *ct, struct stats *total)
{
	ct->c = c;
	if (cg1_mem_stats(c, &ct->stats->mem) < 0) {
		if (cg2_mem_stats(c, &ct->stats->mem) < 0) {
			fprintf(stderr, "Unable to read memory stats\n");
		}
	}
	if (cg1_cpu_stats(c, &ct->stats->cpu) < 0) {
		if (cg2_cpu_stats(c, &ct->stats->cpu) < 0) {
			fprintf(stderr, "Unable to read CPU stats\n");
		}
	}

	if (cg1_get_blk_stats(c, "blkio.throttle.io_service_bytes", &ct->stats->io_service_bytes) < 0) {
		if (cg2_get_blk_stats(c, "io.stat", &ct->stats->io_service_bytes) < 0) {
			fprintf(stderr, "Unable to read IO stats\n");
		}
	} else {
		/* only with cgroups v1 */
		cg1_get_blk_stats(c, "blkio.throttle.io_serviced", &ct->stats->io_serviced);
	}


	if (total) {
		total->mem.used       += ct->stats->mem.used;
		total->mem.limit      += ct->stats->mem.limit;
		total->mem.swap_used  += ct->stats->mem.swap_used;
		total->mem.swap_limit += ct->stats->mem.swap_limit;
		total->mem.kmem_used  += ct->stats->mem.kmem_used;
		total->mem.kmem_limit += ct->stats->mem.kmem_limit;

		total->cpu.use_nanos += ct->stats->cpu.use_nanos;
		total->cpu.use_user  += ct->stats->cpu.use_user;
		total->cpu.use_sys   += ct->stats->cpu.use_sys;

		total->io_service_bytes.total += ct->stats->io_service_bytes.total;
		total->io_service_bytes.read  += ct->stats->io_service_bytes.read;
		total->io_service_bytes.write += ct->stats->io_service_bytes.write;
	}
}

static void stats_print_header(struct stats *stats)
{
	printf(TERMRVRS TERMBOLD);
	printf("%-18s %12s %12s %12s %36s %10s", "Container", "CPU",  "CPU",  "CPU",  "BlkIO", "Mem");

	if (stats->mem.swap_used > 0)
		printf(" %10s", "MemSw");

	if (stats->mem.kmem_used > 0)
		printf(" %10s", "KMem");
	printf("\n");

	printf("%-18s %12s %12s %12s %36s %10s", "Name",      "Used", "Sys",  "User", "Total(Read/Write)", "Used");

	if (stats->mem.swap_used > 0)
		printf(" %10s", "Used");

	if (stats->mem.kmem_used > 0)
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
		size_humanize(stats->mem.used, mem_used_str, sizeof(mem_used_str));

		ret = snprintf(iosb_str, sizeof(iosb_str), "%s(%s/%s)", iosb_total_str, iosb_read_str, iosb_write_str);
		if (ret < 0 || (size_t)ret >= sizeof(iosb_str))
			printf("snprintf'd too many characters: %d\n", ret);

		printf("%-18.18s %12.2f %12.2f %12.2f %36s %10s",
		       name,
		       (float)stats->cpu.use_nanos / 1000000000,
		       (float)stats->cpu.use_sys  / user_hz,
		       (float)stats->cpu.use_user / user_hz,
		       iosb_str,
		       mem_used_str);

		if (total->mem.swap_used > 0) {
			size_humanize(stats->mem.swap_used, memsw_used_str, sizeof(memsw_used_str));
			printf(" %10s", memsw_used_str);
		}
		if (total->mem.kmem_used > 0) {
			size_humanize(stats->mem.kmem_used, kmem_used_str, sizeof(kmem_used_str));
			printf(" %10s", kmem_used_str);
		}
	} else {
		(void)gettimeofday(&time_val, NULL);
		time_ms = (unsigned long long) (time_val.tv_sec) * 1000 + (unsigned long long) (time_val.tv_usec) / 1000;
		printf("%" PRIu64 ",%s,%" PRIu64 ",%" PRIu64 ",%" PRIu64
		       ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64,
		       (uint64_t)time_ms, name, (uint64_t)stats->cpu.use_nanos,
		       (uint64_t)stats->cpu.use_sys,
		       (uint64_t)stats->cpu.use_user, (uint64_t)stats->io_service_bytes.total,
		       (uint64_t)stats->io_serviced.total, (uint64_t)stats->mem.used,
		       (uint64_t)stats->mem.swap_used, (uint64_t)stats->mem.kmem_used);
	}

}

static int cmp_name(const void *sct1, const void *sct2)
{
	const struct container_stats *ct1 = sct1;
	const struct container_stats *ct2 = sct2;

	if (sort_reverse)
		return strncmp(ct2->c->name, ct1->c->name, strlen(ct2->c->name));

	return strncmp(ct1->c->name, ct2->c->name, strlen(ct1->c->name));
}

static int cmp_cpuuse(const void *sct1, const void *sct2)
{
	const struct container_stats *ct1 = sct1;
	const struct container_stats *ct2 = sct2;

	if (sort_reverse)
		return ct2->stats->cpu.use_nanos < ct1->stats->cpu.use_nanos;

	return ct1->stats->cpu.use_nanos < ct2->stats->cpu.use_nanos;
}

static int cmp_blkio(const void *sct1, const void *sct2)
{
	const struct container_stats *ct1 = sct1;
	const struct container_stats *ct2 = sct2;

	if (sort_reverse)
		return ct2->stats->io_service_bytes.total < ct1->stats->io_service_bytes.total;

	return ct1->stats->io_service_bytes.total < ct2->stats->io_service_bytes.total;
}

static int cmp_memory(const void *sct1, const void *sct2)
{
	const struct container_stats *ct1 = sct1;
	const struct container_stats *ct2 = sct2;

	if (sort_reverse)
		return ct2->stats->mem.used < ct1->stats->mem.used;

	return ct1->stats->mem.used < ct2->stats->mem.used;
}

static int cmp_memorysw(const void *sct1, const void *sct2)
{
	const struct container_stats *ct1 = sct1;
	const struct container_stats *ct2 = sct2;

	if (sort_reverse)
		return ct2->stats->mem.swap_used < ct1->stats->mem.swap_used;

	return ct1->stats->mem.swap_used < ct2->stats->mem.swap_used;
}

static int cmp_kmemory(const void *sct1, const void *sct2)
{
	const struct container_stats *ct1 = sct1;
	const struct container_stats *ct2 = sct2;

	if (sort_reverse)
		return ct2->stats->mem.kmem_used < ct1->stats->mem.kmem_used;

	return ct1->stats->mem.kmem_used < ct2->stats->mem.kmem_used;
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

	qsort(container_stats, active, sizeof(*container_stats), (int (*)(const void *,const void *))cmp_func);
}

static void ct_free(void)
{
	int i;

	for (i = 0; i < ct_alloc_cnt; i++) {
		if (container_stats[i].c) {
			lxc_container_put(container_stats[i].c);
			container_stats[i].c = NULL;
		}

		free(container_stats[i].stats);
		container_stats[i].stats = NULL;
	}
}

static void ct_realloc(int active_cnt)
{
	if (active_cnt > ct_alloc_cnt) {
		int i;

		ct_free();

		container_stats = realloc(container_stats, sizeof(*container_stats) * active_cnt);
		if (!container_stats) {
			fprintf(stderr, "Cannot alloc mem\n");
			exit(EXIT_FAILURE);
		}

		for (i = 0; i < active_cnt; i++) {
			container_stats[i].stats = malloc(sizeof(*container_stats[0].stats));
			if (!container_stats[i].stats) {
				fprintf(stderr, "Cannot alloc mem\n");
				exit(EXIT_FAILURE);
			}
		}

		ct_alloc_cnt = active_cnt;
	}
}

static int stdin_handler(int fd, uint32_t events, void *data,
			 struct lxc_async_descr *descr)
{
	char *in_char = data;

	if (events & EPOLLIN) {
		int rc;

		rc = lxc_read_nointr(fd, in_char, sizeof(*in_char));
		if (rc <= 0)
			*in_char = '\0';
	}

	if (events & EPOLLHUP)
		*in_char = 'q';

	return LXC_MAINLOOP_CLOSE;
}

int __attribute__((weak, alias("lxc_top_main"))) main(int argc, char *argv[]);
int lxc_top_main(int argc, char *argv[])
{
	struct lxc_async_descr descr;
	int ret, ct_print_cnt;
	char in_char;

	ret = EXIT_FAILURE;

	if (lxc_arguments_parse(&my_args, argc, argv))
		goto out;

	ct_print_cnt = stdin_tios_rows() - 3; /* 3 -> header and total */
	if (stdin_tios_setup() < 0) {
		fprintf(stderr, "Failed to setup terminal\n");
		goto out;
	}

	/* ensure the terminal gets restored */
	atexit(stdin_tios_restore);
	signal(SIGINT, sig_handler);
	signal(SIGQUIT, sig_handler);

	user_hz = sysconf(_SC_CLK_TCK);
	if (user_hz == 0) {
		user_hz = 100;
	}

	if (lxc_mainloop_open(&descr)) {
		fprintf(stderr, "Failed to create mainloop\n");
		goto out;
	}

	ret = lxc_mainloop_add_handler(&descr, 0,
				       stdin_handler,
				       default_cleanup_handler,
				       &in_char, "stdin_handler");
	if (ret) {
		fprintf(stderr, "Failed to add stdin handler\n");
		ret = EXIT_FAILURE;
		goto err1;
	}

	if (batch && !delay_set)
		delay = 300;

        if (batch)
		printf("time_ms,container,cpu_nanos,cpu_sys_userhz,cpu_user_userhz,blkio_bytes,blkio_iops,mem_used_bytes,memsw_used_bytes,kernel_mem_used_bytes\n");

	for(;;) {
		struct lxc_container **active;
		int i, active_cnt;
		struct stats total;
		char total_name[30];

		active_cnt = list_active_containers(my_args.lxcpath[0], NULL, &active);
		ct_realloc(active_cnt);

		memset(&total, 0, sizeof(total));

		for (i = 0; i < active_cnt; i++)
			stats_get(active[i], &container_stats[i], &total);

		ct_sort(active_cnt);

		if (!batch) {
			printf(TERMCLEAR);
			stats_print_header(&total);
		}

		for (i = 0; i < active_cnt && ((i < ct_print_cnt) || batch); i++) {
			stats_print(container_stats[i].c->name, container_stats[i].stats, &total);
			printf("\n");
		}

		if (!batch) {
			sprintf(total_name, "TOTAL %d of %d", i, active_cnt);
			stats_print(total_name, &total, &total);
		}
		fflush(stdout);

		for (i = 0; i < active_cnt; i++) {
			lxc_container_put(container_stats[i].c);
			container_stats[i].c = NULL;
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

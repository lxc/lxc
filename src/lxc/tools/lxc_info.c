/* SPDX-License-Identifier: LGPL-2.1+ */

#include "config.h"

#include <libgen.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "lxc.h"

#include "arguments.h"
#include "log.h"
#include "utils.h"
#include "macro.h"

lxc_log_define(lxc_info, lxc);

static bool ips;
static bool state;
static bool pid;
static bool stats;
static bool humanize = true;
static char **key = NULL;
static int nr_keys = 0;
static int filter_count = 0;

static int my_parser(struct lxc_arguments *args, int c, char *arg)
{
	char **newk;

	switch (c) {
	case 'c':
		newk = realloc(key, (nr_keys + 1) * sizeof(key[0]));
		if (!newk)
			return -1;

		key = newk;
		key[nr_keys] = arg;
		nr_keys++;
		break;
	case 'i': ips = true; filter_count += 1; break;
	case 's': state = true; filter_count += 1; break;
	case 'p': pid = true; filter_count += 1; break;
	case 'S': stats = true; filter_count += 5; break;
	case 'H': humanize = false; break;
	}
	return 0;
}

static const struct option my_longopts[] = {
	{"config", required_argument, 0, 'c'},
	{"ips", no_argument, 0, 'i'},
	{"state", no_argument, 0, 's'},
	{"pid", no_argument, 0, 'p'},
	{"stats", no_argument, 0, 'S'},
	{"no-humanize", no_argument, 0, 'H'},
	LXC_COMMON_OPTIONS,
};

static struct lxc_arguments my_args = {
	.progname = "lxc-info",
	.help     = "\
--name=NAME\n\
\n\
lxc-info display some information about a container with the identifier NAME\n\
\n\
Options :\n\
  -n, --name=NAME       NAME of the container\n\
  -c, --config=KEY      show configuration variable KEY from running container\n\
  -i, --ips             shows the IP addresses\n\
  -p, --pid             shows the process id of the init container\n\
  -S, --stats           shows usage stats\n\
  -H, --no-humanize     shows stats as raw numbers, not humanized\n\
  -s, --state           shows the state of the container\n\
  --rcfile=FILE         Load configuration file FILE\n",
	.name     = NULL,
	.options  = my_longopts,
	.parser   = my_parser,
	.checker  = NULL,
	.log_priority = "ERROR",
	.log_file     = "none",
};

static void str_chomp(char *buf)
{
	char *ch;

	/* remove trailing whitespace from buf */
	for(ch = &buf[strlen(buf)-1];
	    ch >= buf && (*ch == '\t' || *ch == '\n' || *ch == ' ');
	    ch--)
		*ch = '\0';
}

static void size_humanize(unsigned long long val, char *buf, size_t bufsz)
{
	if (val > 1 << 30) {
		(void)snprintf(buf, bufsz, "%u.%2.2u GiB",
			       (unsigned int)(val >> 30),
			       (unsigned int)(val & ((1 << 30) - 1)) / 10737419);
	} else if (val > 1 << 20) {
		unsigned int x = val + 5243;  /* for rounding */
		(void)snprintf(buf, bufsz, "%u.%2.2u MiB", x >> 20,
			       ((x & ((1 << 20) - 1)) * 100) >> 20);
	} else if (val > 1 << 10) {
		unsigned int x = val + 5;  /* for rounding */
		(void)snprintf(buf, bufsz, "%u.%2.2u KiB", x >> 10,
			       ((x & ((1 << 10) - 1)) * 100) >> 10);
	} else {
		(void)snprintf(buf, bufsz, "%u bytes", (unsigned int)val);
	}
}

static unsigned long long str_size_humanize(char *iobuf, size_t iobufsz)
{
	unsigned long long val;
	char *end = NULL;

	val = strtoull(iobuf, &end, 0);
	if (humanize) {
		if (*end == '\0' || *end == '\n')
			size_humanize(val, iobuf, iobufsz);
		else
			*iobuf = '\0';
	}
	return val;
}

static void print_net_stats(struct lxc_container *c)
{
	int rc,netnr;
	unsigned long long rx_bytes = 0, tx_bytes = 0;
	char *ifname, *type;
	char path[PATH_MAX];
	char buf[256];

	for(netnr = 0; ;netnr++) {
		sprintf(buf, "lxc.net.%d.type", netnr);

		type = c->get_running_config_item(c, buf);
		if (!type)
			break;

		if (!strcmp(type, "veth")) {
			sprintf(buf, "lxc.net.%d.veth.pair", netnr);
		} else {
			sprintf(buf, "lxc.net.%d.link", netnr);
		}
		free(type);

		ifname = c->get_running_config_item(c, buf);
		if (!ifname)
			return;

		printf("%-15s %s\n", "Link:", ifname);
		fflush(stdout);

		/* XXX: tx and rx are reversed from the host vs container
		 * perspective, print them from the container perspective
		 */
		rc = snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/rx_bytes", ifname);
		if (rc < 0 || (size_t)rc >= sizeof(path))
			return;

		rc = lxc_read_from_file(path, buf, sizeof(buf));
		if (rc > 0) {
			buf[rc - 1] = '\0';
			str_chomp(buf);
			rx_bytes = str_size_humanize(buf, sizeof(buf));
			printf("%-15s %s\n", " TX bytes:", buf);
			fflush(stdout);
		}

		rc = snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/tx_bytes", ifname);
		if (rc < 0 || (size_t)rc >= sizeof(path))
			return;

		rc = lxc_read_from_file(path, buf, sizeof(buf));
		if (rc > 0) {
			buf[rc - 1] = '\0';
			str_chomp(buf);
			tx_bytes = str_size_humanize(buf, sizeof(buf));
			printf("%-15s %s\n", " RX bytes:", buf);
			fflush(stdout);
		}

		sprintf(buf, "%llu", rx_bytes + tx_bytes);
		str_size_humanize(buf, sizeof(buf));
		printf("%-15s %s\n", " Total bytes:", buf);
		fflush(stdout);
		free(ifname);
	}
}

static int cg2_stat_iter(struct lxc_container *c, const char *file, void *cookie,
		int (*iter)(char *key, char *val, void *cookie))
{
	char *fileptr, *lineptr, *line, *metric, *value;
	char buf[4096];
	int ret;

	ret = c->get_cgroup_item(c, file, buf, sizeof(buf));
	if (ret < 0)
		return ret;

	if ((size_t)ret >= sizeof(buf)) {
		fprintf(stderr, "Internal buffer too small to read '%s'\n", file);
		return -EMSGSIZE;
	}

	for (line = strtok_r(buf, "\n", &fileptr); line; line = strtok_r(NULL, "\n", &fileptr)) {
		metric = strtok_r(line, " ", &lineptr);
		if (!metric)
			goto err;

		value = strtok_r(NULL, " ", &lineptr);
		if (!value)
			goto err;

		ret = iter(metric, value, cookie);
		if (ret)
			return ret;
	}

	return 0;

err:	fprintf(stderr, "Unexpected syntax of memory.stat\n");
	return -EIO;
}

static int cg1_cpu_usage(struct lxc_container *c, char *usage)
{
	char buf[64];
	int ret;

	ret = c->get_cgroup_item(c, "cpuacct.usage", buf, sizeof(buf));
	if (ret > 0 && (size_t)ret < sizeof(buf)) {
		str_chomp(buf);
		strcpy(usage, buf);
		return 0;
	}

	return ret;
}

static int cg2_cpu_usage_iter(char *metric, char *value, void *cookie)
{
	if (strcmp(metric, "usage_usec"))
		return 0;

	strcpy(cookie, value);
	strcat(cookie, "000");
	return 1;
}

static int cg2_cpu_usage(struct lxc_container *c, char *usage)
{
	int ret;

	ret = cg2_stat_iter(c, "cpu.stat", usage, cg2_cpu_usage_iter);
	return ret == 1 ? 0 : ret ?: -ESRCH;
}

static int search_array(const char *array[], const char *needle, size_t size)
{
	size_t i;

	for (i = 0; i < size; i++)
		if (!strcmp(array[i], needle))
			return 1;
	return 0;
}

struct cg2_mem_usage_s {
	unsigned long long user, kernel;
};

static int cg2_mem_usage_iter(char *metric, char *value, void *cookie)
{
	const char *kernel_fields[] = { "kernel_stack", "pagetables", "sock", "slab" };
	const char *user_fields[] = { "anon", "file" };
	struct cg2_mem_usage_s *usage = cookie;
	unsigned long long numvalue;
	char *end;

	numvalue = strtoull(value, &end, 10);
	if (numvalue == ULLONG_MAX || *end) {
		fprintf(stderr, "Unexpected syntax of memory.stat\n");
		return -EIO;
	}

	if (search_array(kernel_fields, metric, ARRAY_SIZE(kernel_fields)))
		usage->kernel += numvalue;
	else if (search_array(user_fields, metric, ARRAY_SIZE(user_fields)))
		usage->user += numvalue;
	return 0;
}

static int cg2_mem_usage(struct lxc_container *c, char *user, char *kernel)
{
	struct cg2_mem_usage_s usage = { 0 };
	int ret;

	ret = cg2_stat_iter(c, "memory.stat", &usage, cg2_mem_usage_iter);
	if (ret < 0)
		return ret;

	sprintf(kernel, "%llu", usage.kernel);
	sprintf(user, "%llu", usage.user);

	return 0;

}

static int cg1_mem_usage(struct lxc_container *c, char *user, char *kernel)
{
	struct {
		const char *file;
		char *target;
	} lxstat[] = {
		{ "memory.usage_in_bytes", user },
		{ "memory.kmem.usage_in_bytes", kernel },
	};
	int ret, i, match = 0;
	char buf[64];

	for (i = 0; i < (int)ARRAY_SIZE(lxstat); i++) {
		ret = c->get_cgroup_item(c, lxstat[i].file, buf, sizeof(buf));
		if (ret > 0 && (size_t)ret < sizeof(buf)) {
			str_chomp(buf);
			strcpy(lxstat[i].target, buf);
			match++;
		}
	}

	return match == ARRAY_SIZE(lxstat) ? 0 : -ESRCH;
}

static void print_stats(struct lxc_container *c)
{
	int ret;
	char buf[4096];
	char *user = buf;
	char *kernel = buf + sizeof(buf) / 2;

	if (!cg1_cpu_usage(c, buf) || !cg2_cpu_usage(c, buf)) {
		if (humanize) {
			float seconds = strtof(buf, NULL) / 1000000000.0;
			printf("%-15s %.2f seconds\n", "CPU use:", seconds);
		} else {
			printf("%-15s %s\n", "CPU use:", buf);
		}
		fflush(stdout);
	}

	ret = c->get_cgroup_item(c, "blkio.throttle.io_service_bytes", buf, sizeof(buf));
	if (ret > 0 && (size_t)ret < sizeof(buf)) {
		char *ch;

		/* put ch on last "Total" line */
		str_chomp(buf);
		for(ch = &buf[strlen(buf)-1]; ch > buf && *ch != '\n'; ch--)
			;
		if (*ch == '\n')
			ch++;

		if (strncmp(ch, "Total", 5) == 0) {
			ch += 6;
			memmove(buf, ch, strlen(ch)+1);
			str_size_humanize(buf, sizeof(buf));
			printf("%-15s %s\n", "BlkIO use:", buf);
		}
		fflush(stdout);
	}

	if (!cg1_mem_usage(c, user, kernel) || !cg2_mem_usage(c, user, kernel)) {
		str_size_humanize(user, sizeof(buf) / 2 - 1);
		printf("%-15s %s\n", "Memory use:", user);
		str_size_humanize(kernel, sizeof(buf) / 2 - 1);
		printf("%-15s %s\n", "KMem use:", kernel);
		fflush(stdout);
	}
}

static void print_info_msg_int(const char *k, int value)
{
	if (humanize)
		printf("%-15s %d\n", k, value);
	else {
		if (filter_count == 1)
			printf("%d\n", value);
		else
			printf("%-15s %d\n", k, value);
	}
	fflush(stdout);
}

static void print_info_msg_str(const char *k, const char *value)
{
	if (humanize)
		printf("%-15s %s\n", k, value);
	else {
		if (filter_count == 1)
			printf("%s\n", value);
		else
			printf("%-15s %s\n", k, value);
	}
	fflush(stdout);
}

static int print_info(const char *name, const char *lxcpath)
{
	int i;
	struct lxc_container *c;

	c = lxc_container_new(name, lxcpath);
	if (!c) {
		fprintf(stderr, "Failure to retrieve information on %s:%s\n", lxcpath ? lxcpath : "null",
				name ? name : "null");
		return -1;
	}

	if (my_args.rcfile) {
		c->clear_config(c);

		if (!c->load_config(c, my_args.rcfile)) {
			fprintf(stderr, "Failed to load rcfile\n");
			lxc_container_put(c);
			return -1;
		}

		c->configfile = strdup(my_args.rcfile);
		if (!c->configfile) {
			fprintf(stderr, "Out of memory setting new config filename\n");
			lxc_container_put(c);
			return -1;
		}
	}

	if (!c->may_control(c)) {
		fprintf(stderr, "Insufficent privileges to control %s\n", c->name);
		lxc_container_put(c);
		return -1;
	}

	if (!c->is_running(c) && !c->is_defined(c)) {
		fprintf(stderr, "%s doesn't exist\n", c->name);
		lxc_container_put(c);
		return -1;
	}

	if (!state && !pid && !ips && !stats && nr_keys <= 0) {
		state = pid = ips = stats = true;
		print_info_msg_str("Name:", c->name);
	}

	if (state)
		print_info_msg_str("State:", c->state(c));

	if (c->is_running(c)) {
		if (pid) {
			pid_t initpid;

			initpid = c->init_pid(c);
			if (initpid >= 0)
				print_info_msg_int("PID:", initpid);
		}

		if (ips) {
			fflush(stdout);

			char **addresses = c->get_ips(c, NULL, NULL, 0);
			if (addresses) {
				char *address;
				i = 0;

				while (addresses[i]) {
					address = addresses[i];
					print_info_msg_str("IP:", address);
					i++;
				}
			}
		}
	}

	if (stats) {
		print_stats(c);
		print_net_stats(c);
	}

	for(i = 0; i < nr_keys; i++) {
		int len = c->get_config_item(c, key[i], NULL, 0);

		if (len > 0) {
			char *val = (char*) malloc(sizeof(char)*len + 1);

			if (c->get_config_item(c, key[i], val, len + 1) != len) {
				fprintf(stderr, "unable to read %s from configuration\n", key[i]);
			} else {
				if (!humanize && nr_keys == 1)
					printf("%s\n", val);
				else
					printf("%s = %s\n", key[i], val);
			}

			free(val);
		} else if (len == 0) {
			if (!humanize && nr_keys == 1)
				printf("\n");
			else
				printf("%s =\n", key[i]);
		} else {
			fprintf(stderr, "%s invalid\n", key[i]);
		}
		fflush(stdout);
	}

	lxc_container_put(c);
	return 0;
}

int __attribute__((weak, alias("lxc_info_main"))) main(int argc, char *argv[]);
int lxc_info_main(int argc, char *argv[])
{
	int ret = EXIT_FAILURE;
	struct lxc_log log;

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

	if (print_info(my_args.name, my_args.lxcpath[0]) == 0)
		ret = EXIT_SUCCESS;

	exit(ret);
}

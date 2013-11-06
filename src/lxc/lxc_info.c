/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2008
 *
 * Authors:
 * Daniel Lezcano <daniel.lezcano at free.fr>
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
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <regex.h>
#include <limits.h>
#include <libgen.h>
#include <sys/types.h>

#include <lxc/lxc.h>
#include <lxc/log.h>
#include <lxc/utils.h>
#include <lxc/lxccontainer.h>

#include "commands.h"
#include "arguments.h"

static bool ips;
static bool state;
static bool pid;
static bool stats;
static bool humanize = true;
static char *test_state = NULL;
static char **key = NULL;
static int keys = 0;

static int my_parser(struct lxc_arguments* args, int c, char* arg)
{
	switch (c) {
	case 'c':
		key = realloc(key, keys+1 * sizeof(key[0]));
		key[keys] = arg;
		keys++;
		break;
	case 'i': ips = true; break;
	case 's': state = true; break;
	case 'p': pid = true; break;
	case 'S': stats = true; break;
	case 'H': humanize = false; break;
	case 't': test_state = arg; break;
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
	{"state-is", required_argument, 0, 't'},
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
  -n, --name=NAME       NAME for name of the container\n\
  -c, --config=KEY      show configuration variable KEY from running container\n\
  -i, --ips             shows the IP addresses\n\
  -p, --pid             shows the process id of the init container\n\
  -S, --stats           shows usage stats\n\
  -H, --no-humanize     shows stats as raw numbers, not humanized\n\
  -s, --state           shows the state of the container\n\
  -t, --state-is=STATE  test if current state is STATE\n\
                        returns success if it matches, false otherwise\n",
	.name     = ".*",
	.options  = my_longopts,
	.parser   = my_parser,
	.checker  = NULL,
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
		snprintf(buf, bufsz, "%u.%2.2u GiB",
			    (int)(val >> 30),
			    (int)(val & ((1 << 30) - 1)) / 10737419);
	} else if (val > 1 << 20) {
		int x = val + 5243;  /* for rounding */
		snprintf(buf, bufsz, "%u.%2.2u MiB",
			    x >> 20, ((x & ((1 << 20) - 1)) * 100) >> 20);
	} else if (val > 1 << 10) {
		int x = val + 5;  /* for rounding */
		snprintf(buf, bufsz, "%u.%2.2u KiB",
			    x >> 10, ((x & ((1 << 10) - 1)) * 100) >> 10);
	} else {
		snprintf(buf, bufsz, "%u bytes", (int)val);
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

static void print_net_stats(const char *name, const char *lxcpath)
{
	int rc,netnr;
	unsigned long long rx_bytes = 0, tx_bytes = 0;
	char *ifname, *type;
	char path[PATH_MAX];
	char buf[256];

	for(netnr = 0; ;netnr++) {
		sprintf(buf, "lxc.network.%d.type", netnr);
		type = lxc_cmd_get_config_item(name, buf, lxcpath);
		if (!type)
			break;

		if (!strcmp(type, "veth")) {
			sprintf(buf, "lxc.network.%d.veth.pair", netnr);
		} else {
			sprintf(buf, "lxc.network.%d.link", netnr);
		}
		free(type);
		ifname = lxc_cmd_get_config_item(name, buf, lxcpath);
		if (!ifname)
			return;
		printf("%-15s %s\n", "Link:", ifname);

		/* XXX: tx and rx are reversed from the host vs container
		 * perspective, print them from the container perspective
		 */
		snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/rx_bytes", ifname);
		rc = lxc_read_from_file(path, buf, sizeof(buf));
		if (rc > 0) {
			str_chomp(buf);
			rx_bytes = str_size_humanize(buf, sizeof(buf));
			printf("%-15s %s\n", " TX bytes:", buf);
		}

		snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/tx_bytes", ifname);
		rc = lxc_read_from_file(path, buf, sizeof(buf));
		if (rc > 0) {
			str_chomp(buf);
			tx_bytes = str_size_humanize(buf, sizeof(buf));
			printf("%-15s %s\n", " RX bytes:", buf);
		}

		sprintf(buf, "%llu", rx_bytes + tx_bytes);
		str_size_humanize(buf, sizeof(buf));
		printf("%-15s %s\n", " Total bytes:", buf);
		free(ifname);
	}
}

static void print_stats(struct lxc_container *c)
{
	int i, ret;
	char buf[256];

	ret = c->get_cgroup_item(c, "cpuacct.usage", buf, sizeof(buf));
	if (ret > 0 && ret < sizeof(buf)) {
		str_chomp(buf);
		if (humanize) {
			float seconds = strtof(buf, NULL) / 1000000000.0;
			printf("%-15s %.2f seconds\n", "CPU use:", seconds);
		} else {
			printf("%-15s %s\n", "CPU use:", buf);
		}
	}

	ret = c->get_cgroup_item(c, "blkio.throttle.io_service_bytes", buf, sizeof(buf));
	if (ret > 0 && ret < sizeof(buf)) {
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
	}

	static const struct {
		const char *name;
		const char *file;
	} lxstat[] = {
		{ "Memory use:", "memory.usage_in_bytes" },
		{ "KMem use:",   "memory.kmem.usage_in_bytes" },
		{ NULL, NULL },
	};

	for (i = 0; lxstat[i].name; i++) {
		ret = c->get_cgroup_item(c, lxstat[i].file, buf, sizeof(buf));
		if (ret > 0 && ret < sizeof(buf)) {
			str_chomp(buf);
			str_size_humanize(buf, sizeof(buf));
			printf("%-15s %s\n", lxstat[i].name, buf);
		}
	}
}

static int print_info(const char *name, const char *lxcpath)
{
	int i;
	struct lxc_container *c;

	c = lxc_container_new(name, lxcpath);
	if (!c)
		return -1;

	if (!c->may_control(c)) {
		fprintf(stderr, "Insufficent privileges to control %s\n", c->name);
		lxc_container_put(c);
		return -1;
	}

	if (!state && !pid && !ips && !stats && keys <= 0)
		state = pid = ips = stats = true;

	printf("%-15s %s\n", "Name:", c->name);

	if (state || test_state) {
		if (test_state)
			return strcmp(c->state(c), test_state) != 0;

		printf("%-15s %s\n", "State:", c->state(c));
	}

	if (pid) {
		pid_t initpid;

		initpid = c->init_pid(c);
		if (initpid >= 0)
			printf("%-15s %d\n", "Pid:", initpid);
	}

	if (ips) {
		char **addresses = c->get_ips(c, NULL, NULL, 0);
		if (addresses) {
			char *address;
			i = 0;
			while (addresses[i]) {
				address = addresses[i];
				printf("%-15s %s\n", "IP:", address);
				i++;
			}
		}
	}

	if (stats) {
		print_stats(c);
		print_net_stats(name, lxcpath);
	}

	for(i = 0; i < keys; i++) {
		int len = c->get_config_item(c, key[i], NULL, 0);

		if (len >= 0) {
			char *val = (char*) malloc(sizeof(char)*len + 1);

			if (c->get_config_item(c, key[i], val, len + 1) != len) {
				fprintf(stderr, "unable to read %s from configuration\n", key[i]);
			} else {
				printf("%s = %s\n", key[i], val);
			}
			free(val);
		} else {
			fprintf(stderr, "%s unset or invalid\n", key[i]);
		}
	}

	lxc_container_put(c);
	return 0;
}

int main(int argc, char *argv[])
{
	int rc, i, len, ret = EXIT_FAILURE;
	char *regexp;
	regex_t preg;
	int ct_cnt;
	char **ct_name;
	bool printed;

	if (lxc_arguments_parse(&my_args, argc, argv))
		goto err1;

	if (!my_args.log_file)
		my_args.log_file = "none";

	if (lxc_log_init(my_args.name, my_args.log_file, my_args.log_priority,
			 my_args.progname, my_args.quiet, my_args.lxcpath[0]))
		goto err1;

	len = strlen(my_args.name) + 3;
	regexp = malloc(len + 3);
	if (!regexp) {
		fprintf(stderr, "failed to allocate memory");
		goto err1;
	}
	rc = snprintf(regexp, len, "^%s$", my_args.name);
	if (rc < 0 || rc >= len) {
		fprintf(stderr, "Name too long");
		goto err2;
	}

	if (regcomp(&preg, regexp, REG_NOSUB|REG_EXTENDED)) {
		fprintf(stderr, "failed to compile the regex '%s'", my_args.name);
		goto err2;
	}

	printed = false;
	ct_cnt = list_all_containers(my_args.lxcpath[0], &ct_name, NULL);
	if (ct_cnt < 0)
		goto err3;

	for (i = 0; i < ct_cnt; i++) {
		if (regexec(&preg, ct_name[i], 0, NULL, 0) == 0)
		{
			if (printed)
				printf("\n");
			print_info(ct_name[i], my_args.lxcpath[0]);
			printed = true;
		}
		free(ct_name[i]);
	}
	if (ct_name)
		free(ct_name);
	ret = EXIT_SUCCESS;

err3:
	regfree(&preg);
err2:
	free(regexp);
err1:
	return ret;
}

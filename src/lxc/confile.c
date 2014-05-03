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
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/utsname.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>

#include "parse.h"
#include "config.h"
#include "confile.h"
#include "utils.h"
#include "log.h"
#include "conf.h"
#include "network.h"
#include "lxcseccomp.h"

#if HAVE_SYS_PERSONALITY_H
#include <sys/personality.h>
#endif

lxc_log_define(lxc_confile, lxc);

static int config_personality(const char *, const char *, struct lxc_conf *);
static int config_pts(const char *, const char *, struct lxc_conf *);
static int config_tty(const char *, const char *, struct lxc_conf *);
static int config_ttydir(const char *, const char *, struct lxc_conf *);
static int config_kmsg(const char *, const char *, struct lxc_conf *);
static int config_lsm_aa_profile(const char *, const char *, struct lxc_conf *);
static int config_lsm_se_context(const char *, const char *, struct lxc_conf *);
static int config_cgroup(const char *, const char *, struct lxc_conf *);
static int config_idmap(const char *, const char *, struct lxc_conf *);
static int config_loglevel(const char *, const char *, struct lxc_conf *);
static int config_logfile(const char *, const char *, struct lxc_conf *);
static int config_mount(const char *, const char *, struct lxc_conf *);
static int config_rootfs(const char *, const char *, struct lxc_conf *);
static int config_rootfs_mount(const char *, const char *, struct lxc_conf *);
static int config_rootfs_options(const char *, const char *, struct lxc_conf *);
static int config_pivotdir(const char *, const char *, struct lxc_conf *);
static int config_utsname(const char *, const char *, struct lxc_conf *);
static int config_hook(const char *, const char *, struct lxc_conf *lxc_conf);
static int config_network_type(const char *, const char *, struct lxc_conf *);
static int config_network_flags(const char *, const char *, struct lxc_conf *);
static int config_network_link(const char *, const char *, struct lxc_conf *);
static int config_network_name(const char *, const char *, struct lxc_conf *);
static int config_network_veth_pair(const char *, const char *, struct lxc_conf *);
static int config_network_macvlan_mode(const char *, const char *, struct lxc_conf *);
static int config_network_hwaddr(const char *, const char *, struct lxc_conf *);
static int config_network_vlan_id(const char *, const char *, struct lxc_conf *);
static int config_network_mtu(const char *, const char *, struct lxc_conf *);
static int config_network_ipv4(const char *, const char *, struct lxc_conf *);
static int config_network_ipv4_gateway(const char *, const char *, struct lxc_conf *);
static int config_network_script_up(const char *, const char *, struct lxc_conf *);
static int config_network_script_down(const char *, const char *, struct lxc_conf *);
static int config_network_ipv6(const char *, const char *, struct lxc_conf *);
static int config_network_ipv6_gateway(const char *, const char *, struct lxc_conf *);
static int config_cap_drop(const char *, const char *, struct lxc_conf *);
static int config_cap_keep(const char *, const char *, struct lxc_conf *);
static int config_console(const char *, const char *, struct lxc_conf *);
static int config_seccomp(const char *, const char *, struct lxc_conf *);
static int config_includefile(const char *, const char *, struct lxc_conf *);
static int config_network_nic(const char *, const char *, struct lxc_conf *);
static int config_autodev(const char *, const char *, struct lxc_conf *);
static int config_haltsignal(const char *, const char *, struct lxc_conf *);
static int config_stopsignal(const char *, const char *, struct lxc_conf *);
static int config_start(const char *, const char *, struct lxc_conf *);
static int config_group(const char *, const char *, struct lxc_conf *);

static struct lxc_config_t config[] = {

	{ "lxc.arch",                 config_personality          },
	{ "lxc.pts",                  config_pts                  },
	{ "lxc.tty",                  config_tty                  },
	{ "lxc.devttydir",            config_ttydir               },
	{ "lxc.kmsg",                 config_kmsg                 },
	{ "lxc.aa_profile",           config_lsm_aa_profile       },
	{ "lxc.se_context",           config_lsm_se_context       },
	{ "lxc.cgroup",               config_cgroup               },
	{ "lxc.id_map",               config_idmap                },
	{ "lxc.loglevel",             config_loglevel             },
	{ "lxc.logfile",              config_logfile              },
	{ "lxc.mount",                config_mount                },
	{ "lxc.rootfs.mount",         config_rootfs_mount         },
	{ "lxc.rootfs.options",       config_rootfs_options       },
	{ "lxc.rootfs",               config_rootfs               },
	{ "lxc.pivotdir",             config_pivotdir             },
	{ "lxc.utsname",              config_utsname              },
	{ "lxc.hook.pre-start",       config_hook                 },
	{ "lxc.hook.pre-mount",       config_hook                 },
	{ "lxc.hook.mount",           config_hook                 },
	{ "lxc.hook.autodev",         config_hook                 },
	{ "lxc.hook.start",           config_hook                 },
	{ "lxc.hook.post-stop",       config_hook                 },
	{ "lxc.hook.clone",           config_hook                 },
	{ "lxc.network.type",         config_network_type         },
	{ "lxc.network.flags",        config_network_flags        },
	{ "lxc.network.link",         config_network_link         },
	{ "lxc.network.name",         config_network_name         },
	{ "lxc.network.macvlan.mode", config_network_macvlan_mode },
	{ "lxc.network.veth.pair",    config_network_veth_pair    },
	{ "lxc.network.script.up",    config_network_script_up    },
	{ "lxc.network.script.down",  config_network_script_down  },
	{ "lxc.network.hwaddr",       config_network_hwaddr       },
	{ "lxc.network.mtu",          config_network_mtu          },
	{ "lxc.network.vlan.id",      config_network_vlan_id      },
	{ "lxc.network.ipv4.gateway", config_network_ipv4_gateway },
	{ "lxc.network.ipv4",         config_network_ipv4         },
	{ "lxc.network.ipv6.gateway", config_network_ipv6_gateway },
	{ "lxc.network.ipv6",         config_network_ipv6         },
	/* config_network_nic must come after all other 'lxc.network.*' entries */
	{ "lxc.network.",             config_network_nic          },
	{ "lxc.cap.drop",             config_cap_drop             },
	{ "lxc.cap.keep",             config_cap_keep             },
	{ "lxc.console",              config_console              },
	{ "lxc.seccomp",              config_seccomp              },
	{ "lxc.include",              config_includefile          },
	{ "lxc.autodev",              config_autodev              },
	{ "lxc.haltsignal",           config_haltsignal           },
	{ "lxc.stopsignal",           config_stopsignal           },
	{ "lxc.start.auto",           config_start                },
	{ "lxc.start.delay",          config_start                },
	{ "lxc.start.order",          config_start                },
	{ "lxc.group",                config_group                },
};

struct signame {
	int num;
	const char *name;
};

static const struct signame signames[] = {
	{ SIGHUP,    "HUP" },
	{ SIGINT,    "INT" },
	{ SIGQUIT,   "QUIT" },
	{ SIGILL,    "ILL" },
	{ SIGABRT,   "ABRT" },
	{ SIGFPE,    "FPE" },
	{ SIGKILL,   "KILL" },
	{ SIGSEGV,   "SEGV" },
	{ SIGPIPE,   "PIPE" },
	{ SIGALRM,   "ALRM" },
	{ SIGTERM,   "TERM" },
	{ SIGUSR1,   "USR1" },
	{ SIGUSR2,   "USR2" },
	{ SIGCHLD,   "CHLD" },
	{ SIGCONT,   "CONT" },
	{ SIGSTOP,   "STOP" },
	{ SIGTSTP,   "TSTP" },
	{ SIGTTIN,   "TTIN" },
	{ SIGTTOU,   "TTOU" },
};

static const size_t config_size = sizeof(config)/sizeof(struct lxc_config_t);

extern struct lxc_config_t *lxc_getconfig(const char *key)
{
	int i;

	for (i = 0; i < config_size; i++)
		if (!strncmp(config[i].name, key,
			     strlen(config[i].name)))
			return &config[i];
	return NULL;
}

#define strprint(str, inlen, ...) \
	do { \
		len = snprintf(str, inlen, ##__VA_ARGS__); \
		if (len < 0) { SYSERROR("snprintf"); return -1; }; \
		fulllen += len; \
		if (inlen > 0) { \
			if (str) str += len; \
			inlen -= len; \
			if (inlen < 0) inlen = 0; \
		} \
	} while (0);

int lxc_listconfigs(char *retv, int inlen)
{
	int i, fulllen = 0, len;

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);
	for (i = 0; i < config_size; i++) {
		char *s = config[i].name;
		if (s[strlen(s)-1] == '.')
			continue;
		strprint(retv, inlen, "%s\n", s);
	}
	return fulllen;
}

static int config_string_item(char **conf_item, const char *value)
{
	char *new_value;

	if (!value || strlen(value) == 0) {
		if (*conf_item)
			free(*conf_item);
		*conf_item = NULL;
		return 0;
	}

	new_value = strdup(value);
	if (!new_value) {
		SYSERROR("failed to strdup '%s': %m", value);
		return -1;
	}

	if (*conf_item)
		free(*conf_item);
	*conf_item = new_value;
	return 0;
}

static int config_string_item_max(char **conf_item, const char *value,
				  size_t max)
{
	if (strlen(value) >= max) {
		ERROR("%s is too long (>= %lu)", value, (unsigned long)max);
		return -1;
	}

	return config_string_item(conf_item, value);
}

static int config_path_item(char **conf_item, const char *value)
{
	return config_string_item_max(conf_item, value, PATH_MAX);
}

/*
 * config entry is something like "lxc.network.0.ipv4"
 * the key 'lxc.network.' was found.  So we make sure next
 * comes an integer, find the right callback (by rewriting
 * the key), and call it.
 */
static int config_network_nic(const char *key, const char *value,
			       struct lxc_conf *lxc_conf)
{
	char *copy = strdup(key), *p;
	int ret = -1;
	struct lxc_config_t *config;

	if (!copy) {
		SYSERROR("failed to allocate memory");
		return -1;
	}
	/*
	 * ok we know that to get here we've got "lxc.network."
	 * and it isn't any of the other network entries.  So
	 * after the second . should come an integer (# of defined
	 * nic) followed by a valid entry.
	 */
	if (*(key+12) < '0' || *(key+12) > '9')
		goto out;
	p = index(key+12, '.');
	if (!p)
		goto out;
	strcpy(copy+12, p+1);
	config = lxc_getconfig(copy);
	if (!config) {
		ERROR("unknown key %s", key);
		goto out;
	}
	ret = config->cb(key, value, lxc_conf);

out:
	free(copy);
	return ret;
}

static int macvlan_mode(int *valuep, const char *value);

static int config_network_type(const char *key, const char *value,
			       struct lxc_conf *lxc_conf)
{
	struct lxc_list *network = &lxc_conf->network;
	struct lxc_netdev *netdev;
	struct lxc_list *list;

	if (!value || strlen(value) == 0)
		return lxc_clear_config_network(lxc_conf);

	netdev = malloc(sizeof(*netdev));
	if (!netdev) {
		SYSERROR("failed to allocate memory");
		return -1;
	}

	memset(netdev, 0, sizeof(*netdev));
	lxc_list_init(&netdev->ipv4);
	lxc_list_init(&netdev->ipv6);

	list = malloc(sizeof(*list));
	if (!list) {
		SYSERROR("failed to allocate memory");
		free(netdev);
		return -1;
	}

	lxc_list_init(list);
	list->elem = netdev;

	lxc_list_add_tail(network, list);

	if (!strcmp(value, "veth"))
		netdev->type = LXC_NET_VETH;
	else if (!strcmp(value, "macvlan")) {
		netdev->type = LXC_NET_MACVLAN;
		macvlan_mode(&netdev->priv.macvlan_attr.mode, "private");
	}
	else if (!strcmp(value, "vlan"))
		netdev->type = LXC_NET_VLAN;
	else if (!strcmp(value, "phys"))
		netdev->type = LXC_NET_PHYS;
	else if (!strcmp(value, "empty"))
		netdev->type = LXC_NET_EMPTY;
	else if (!strcmp(value, "none"))
		netdev->type = LXC_NET_NONE;
	else {
		ERROR("invalid network type %s", value);
		return -1;
	}
	return 0;
}

static int config_ip_prefix(struct in_addr *addr)
{
	if (IN_CLASSA(addr->s_addr))
		return 32 - IN_CLASSA_NSHIFT;
	if (IN_CLASSB(addr->s_addr))
		return 32 - IN_CLASSB_NSHIFT;
	if (IN_CLASSC(addr->s_addr))
		return 32 - IN_CLASSC_NSHIFT;

	return 0;
}

/*
 * if you have p="lxc.network.0.link", pass it p+12
 * to get back '0' (the index of the nic)
 */
static int get_network_netdev_idx(const char *key)
{
	int ret, idx;

	if (*key < '0' || *key > '9')
		return -1;
	ret = sscanf(key, "%d", &idx);
	if (ret != 1)
		return -1;
	return idx;
}

/*
 * if you have p="lxc.network.0", pass this p+12 and it will return
 * the netdev of the first configured nic
 */
static struct lxc_netdev *get_netdev_from_key(const char *key,
					      struct lxc_list *network)
{
	int i = 0, idx = get_network_netdev_idx(key);
	struct lxc_netdev *netdev = NULL;
	struct lxc_list *it;
	if (idx == -1)
		return NULL;
	lxc_list_for_each(it, network) {
		if (idx == i++) {
			netdev = it->elem;
			break;
		}
	}
	return netdev;
}

extern int lxc_list_nicconfigs(struct lxc_conf *c, const char *key,
			       char *retv, int inlen)
{
	struct lxc_netdev *netdev;
	int fulllen = 0, len;

	netdev = get_netdev_from_key(key+12, &c->network);
	if (!netdev)
		return -1;

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	strprint(retv, inlen, "script.up\n");
	strprint(retv, inlen, "script.down\n");
	if (netdev->type != LXC_NET_EMPTY) {
		strprint(retv, inlen, "flags\n");
		strprint(retv, inlen, "link\n");
		strprint(retv, inlen, "name\n");
		strprint(retv, inlen, "hwaddr\n");
		strprint(retv, inlen, "mtu\n");
		strprint(retv, inlen, "ipv6\n");
		strprint(retv, inlen, "ipv6_gateway\n");
		strprint(retv, inlen, "ipv4\n");
		strprint(retv, inlen, "ipv4_gateway\n");
	}
	switch(netdev->type) {
	case LXC_NET_VETH:
		strprint(retv, inlen, "veth.pair\n");
		break;
	case LXC_NET_MACVLAN:
		strprint(retv, inlen, "macvlan.mode\n");
		break;
	case LXC_NET_VLAN:
		strprint(retv, inlen, "vlan.id\n");
		break;
	case LXC_NET_PHYS:
		break;
	}
	return fulllen;
}

static struct lxc_netdev *network_netdev(const char *key, const char *value,
					 struct lxc_list *network)
{
	struct lxc_netdev *netdev = NULL;

	if (lxc_list_empty(network)) {
		ERROR("network is not created for '%s' = '%s' option",
		      key, value);
		return NULL;
	}

	if (get_network_netdev_idx(key+12) == -1)
		netdev = lxc_list_last_elem(network);
	else
		netdev = get_netdev_from_key(key+12, network);

	if (!netdev) {
		ERROR("no network device defined for '%s' = '%s' option",
		      key, value);
		return NULL;
	}

	return netdev;
}

static int network_ifname(char **valuep, const char *value)
{
	return config_string_item_max(valuep, value, IFNAMSIZ);
}

#ifndef MACVLAN_MODE_PRIVATE
#  define MACVLAN_MODE_PRIVATE 1
#endif

#ifndef MACVLAN_MODE_VEPA
#  define MACVLAN_MODE_VEPA 2
#endif

#ifndef MACVLAN_MODE_BRIDGE
#  define MACVLAN_MODE_BRIDGE 4
#endif

static int macvlan_mode(int *valuep, const char *value)
{
	struct mc_mode {
		char *name;
		int mode;
	} m[] = {
		{ "private", MACVLAN_MODE_PRIVATE },
		{ "vepa", MACVLAN_MODE_VEPA },
		{ "bridge", MACVLAN_MODE_BRIDGE },
	};

	int i;

	for (i = 0; i < sizeof(m)/sizeof(m[0]); i++) {
		if (strcmp(m[i].name, value))
			continue;

		*valuep = m[i].mode;
		return 0;
	}

	return -1;
}

static int rand_complete_hwaddr(char *hwaddr)
{
	const char hex[] = "0123456789abcdef";
	char *curs = hwaddr;

#ifndef HAVE_RAND_R
	randseed(true);
#else
	unsigned int seed=randseed(false);
#endif
	while (*curs != '\0')
	{
		if ( *curs == 'x' || *curs == 'X' ) {
			if (curs - hwaddr == 1) {
				//ensure address is unicast
#ifdef HAVE_RAND_R
				*curs = hex[rand_r(&seed) & 0x0E];
			} else {
				*curs = hex[rand_r(&seed) & 0x0F];
#else
				*curs = hex[rand() & 0x0E];
			} else {
				*curs = hex[rand() & 0x0F];
#endif
			}
		}
		curs++;
	}
	return 0;
}

static int config_network_flags(const char *key, const char *value,
				struct lxc_conf *lxc_conf)
{
	struct lxc_netdev *netdev;

	netdev = network_netdev(key, value, &lxc_conf->network);
	if (!netdev)
		return -1;

	netdev->flags |= IFF_UP;

	return 0;
}

static int config_network_link(const char *key, const char *value,
			       struct lxc_conf *lxc_conf)
{
	struct lxc_netdev *netdev;

	netdev = network_netdev(key, value, &lxc_conf->network);
	if (!netdev)
		return -1;

	return network_ifname(&netdev->link, value);
}

static int config_network_name(const char *key, const char *value,
			       struct lxc_conf *lxc_conf)
{
	struct lxc_netdev *netdev;

	netdev = network_netdev(key, value, &lxc_conf->network);
	if (!netdev)
		return -1;

	return network_ifname(&netdev->name, value);
}

static int config_network_veth_pair(const char *key, const char *value,
				    struct lxc_conf *lxc_conf)
{
	struct lxc_netdev *netdev;

	netdev = network_netdev(key, value, &lxc_conf->network);
	if (!netdev)
		return -1;

	return network_ifname(&netdev->priv.veth_attr.pair, value);
}

static int config_network_macvlan_mode(const char *key, const char *value,
				       struct lxc_conf *lxc_conf)
{
	struct lxc_netdev *netdev;

	netdev = network_netdev(key, value, &lxc_conf->network);
	if (!netdev)
		return -1;

	return macvlan_mode(&netdev->priv.macvlan_attr.mode, value);
}

static int config_network_hwaddr(const char *key, const char *value,
				 struct lxc_conf *lxc_conf)
{
	struct lxc_netdev *netdev;

	char *new_value = strdup(value);
	if (!new_value) {
		SYSERROR("failed to strdup '%s': %m", value);
		return -1;
	}
	rand_complete_hwaddr(new_value);

	netdev = network_netdev(key, new_value, &lxc_conf->network);
	if (!netdev) {
		free(new_value);
		return -1;
	};

	if (!new_value || strlen(new_value) == 0) {
		free(new_value);
		netdev->hwaddr = NULL;
		return 0;
	}

	netdev->hwaddr = new_value;
	return 0;
}

static int config_network_vlan_id(const char *key, const char *value,
			       struct lxc_conf *lxc_conf)
{
	struct lxc_netdev *netdev;

	netdev = network_netdev(key, value, &lxc_conf->network);
	if (!netdev)
		return -1;

	if (get_u16(&netdev->priv.vlan_attr.vid, value, 0))
		return -1;

	return 0;
}

static int config_network_mtu(const char *key, const char *value,
			      struct lxc_conf *lxc_conf)
{
	struct lxc_netdev *netdev;

	netdev = network_netdev(key, value, &lxc_conf->network);
	if (!netdev)
		return -1;

	return config_string_item(&netdev->mtu, value);
}

static int config_network_ipv4(const char *key, const char *value,
			       struct lxc_conf *lxc_conf)
{
	struct lxc_netdev *netdev;
	struct lxc_inetdev *inetdev;
	struct lxc_list *list;
	char *cursor, *slash, *addr = NULL, *bcast = NULL, *prefix = NULL;

	netdev = network_netdev(key, value, &lxc_conf->network);
	if (!netdev)
		return -1;

	inetdev = malloc(sizeof(*inetdev));
	if (!inetdev) {
		SYSERROR("failed to allocate ipv4 address");
		return -1;
	}
	memset(inetdev, 0, sizeof(*inetdev));

	list = malloc(sizeof(*list));
	if (!list) {
		SYSERROR("failed to allocate memory");
		free(inetdev);
		return -1;
	}

	lxc_list_init(list);
	list->elem = inetdev;

	addr = strdup(value);
	if (!addr) {
		ERROR("no address specified");
		free(inetdev);
		free(list);
		return -1;
	}

	cursor = strstr(addr, " ");
	if (cursor) {
		*cursor = '\0';
		bcast = cursor + 1;
	}

	slash = strstr(addr, "/");
	if (slash) {
		*slash = '\0';
		prefix = slash + 1;
	}

	if (!inet_pton(AF_INET, addr, &inetdev->addr)) {
		SYSERROR("invalid ipv4 address: %s", value);
		free(inetdev);
		free(addr);
		free(list);
		return -1;
	}

	if (bcast && !inet_pton(AF_INET, bcast, &inetdev->bcast)) {
		SYSERROR("invalid ipv4 broadcast address: %s", value);
		free(inetdev);
		free(list);
		free(addr);
		return -1;
	}

	/* no prefix specified, determine it from the network class */
	inetdev->prefix = prefix ? atoi(prefix) :
		config_ip_prefix(&inetdev->addr);

	/* if no broadcast address, let compute one from the
	 * prefix and address
	 */
	if (!bcast) {
		inetdev->bcast.s_addr = inetdev->addr.s_addr;
		inetdev->bcast.s_addr |=
			htonl(INADDR_BROADCAST >>  inetdev->prefix);
	}

	lxc_list_add_tail(&netdev->ipv4, list);

	free(addr);
	return 0;
}

static int config_network_ipv4_gateway(const char *key, const char *value,
			               struct lxc_conf *lxc_conf)
{
	struct lxc_netdev *netdev;
	struct in_addr *gw;

	netdev = network_netdev(key, value, &lxc_conf->network);
	if (!netdev)
		return -1;

	gw = malloc(sizeof(*gw));
	if (!gw) {
		SYSERROR("failed to allocate ipv4 gateway address");
		return -1;
	}

	if (!value) {
		ERROR("no ipv4 gateway address specified");
		free(gw);
		return -1;
	}

	if (!strcmp(value, "auto")) {
		free(gw);
		netdev->ipv4_gateway = NULL;
		netdev->ipv4_gateway_auto = true;
	} else {
		if (!inet_pton(AF_INET, value, gw)) {
			SYSERROR("invalid ipv4 gateway address: %s", value);
			free(gw);
			return -1;
		}

		netdev->ipv4_gateway = gw;
		netdev->ipv4_gateway_auto = false;
	}

	return 0;
}

static int config_network_ipv6(const char *key, const char *value,
			       struct lxc_conf *lxc_conf)
{
	struct lxc_netdev *netdev;
	struct lxc_inet6dev *inet6dev;
	struct lxc_list *list;
	char *slash,*valdup;
	char *netmask;

	netdev = network_netdev(key, value, &lxc_conf->network);
	if (!netdev)
		return -1;

	inet6dev = malloc(sizeof(*inet6dev));
	if (!inet6dev) {
		SYSERROR("failed to allocate ipv6 address");
		return -1;
	}
	memset(inet6dev, 0, sizeof(*inet6dev));

	list = malloc(sizeof(*list));
	if (!list) {
		SYSERROR("failed to allocate memory");
		free(inet6dev);
		return -1;
	}

	lxc_list_init(list);
	list->elem = inet6dev;

	valdup = strdup(value);
	if (!valdup) {
		ERROR("no address specified");
		free(list);
		free(inet6dev);
		return -1;
	}

	inet6dev->prefix = 64;
	slash = strstr(valdup, "/");
	if (slash) {
		*slash = '\0';
		netmask = slash + 1;
		inet6dev->prefix = atoi(netmask);
	}

	if (!inet_pton(AF_INET6, valdup, &inet6dev->addr)) {
		SYSERROR("invalid ipv6 address: %s", valdup);
		free(list);
		free(inet6dev);
		free(valdup);
		return -1;
	}

	lxc_list_add_tail(&netdev->ipv6, list);

	free(valdup);
	return 0;
}

static int config_network_ipv6_gateway(const char *key, const char *value,
			               struct lxc_conf *lxc_conf)
{
	struct lxc_netdev *netdev;

	netdev = network_netdev(key, value, &lxc_conf->network);
	if (!netdev)
		return -1;

	if (!value) {
		ERROR("no ipv6 gateway address specified");
		return -1;
	}

	if (!strcmp(value, "auto")) {
		netdev->ipv6_gateway = NULL;
		netdev->ipv6_gateway_auto = true;
	} else {
		struct in6_addr *gw;

		gw = malloc(sizeof(*gw));
		if (!gw) {
			SYSERROR("failed to allocate ipv6 gateway address");
			return -1;
		}

		if (!inet_pton(AF_INET6, value, gw)) {
			SYSERROR("invalid ipv6 gateway address: %s", value);
			free(gw);
			return -1;
		}

		netdev->ipv6_gateway = gw;
		netdev->ipv6_gateway_auto = false;
	}

	return 0;
}

static int config_network_script_up(const char *key, const char *value,
				    struct lxc_conf *lxc_conf)
{
	struct lxc_netdev *netdev;

	netdev = network_netdev(key, value, &lxc_conf->network);
	if (!netdev)
 		return -1;

	return config_string_item(&netdev->upscript, value);
}

static int config_network_script_down(const char *key, const char *value,
				      struct lxc_conf *lxc_conf)
{
	struct lxc_netdev *netdev;

	netdev = network_netdev(key, value, &lxc_conf->network);
	if (!netdev)
 		return -1;

	return config_string_item(&netdev->downscript, value);
}

static int add_hook(struct lxc_conf *lxc_conf, int which, char *hook)
{
	struct lxc_list *hooklist;

	hooklist = malloc(sizeof(*hooklist));
	if (!hooklist) {
		free(hook);
		return -1;
	}
	hooklist->elem = hook;
	lxc_list_add_tail(&lxc_conf->hooks[which], hooklist);
	return 0;
}

static int config_seccomp(const char *key, const char *value,
				 struct lxc_conf *lxc_conf)
{
	return config_path_item(&lxc_conf->seccomp, value);
}

static int config_hook(const char *key, const char *value,
				 struct lxc_conf *lxc_conf)
{
	char *copy;
	
	if (!value || strlen(value) == 0)
		return lxc_clear_hooks(lxc_conf, key);

	copy = strdup(value);
	if (!copy) {
		SYSERROR("failed to dup string '%s'", value);
		return -1;
	}
	if (strcmp(key, "lxc.hook.pre-start") == 0)
		return add_hook(lxc_conf, LXCHOOK_PRESTART, copy);
	else if (strcmp(key, "lxc.hook.pre-mount") == 0)
		return add_hook(lxc_conf, LXCHOOK_PREMOUNT, copy);
	else if (strcmp(key, "lxc.hook.autodev") == 0)
		return add_hook(lxc_conf, LXCHOOK_AUTODEV, copy);
	else if (strcmp(key, "lxc.hook.mount") == 0)
		return add_hook(lxc_conf, LXCHOOK_MOUNT, copy);
	else if (strcmp(key, "lxc.hook.start") == 0)
		return add_hook(lxc_conf, LXCHOOK_START, copy);
	else if (strcmp(key, "lxc.hook.post-stop") == 0)
		return add_hook(lxc_conf, LXCHOOK_POSTSTOP, copy);
	else if (strcmp(key, "lxc.hook.clone") == 0)
		return add_hook(lxc_conf, LXCHOOK_CLONE, copy);
	SYSERROR("Unknown key: %s", key);
	free(copy);
	return -1;
}

static int config_personality(const char *key, const char *value,
			      struct lxc_conf *lxc_conf)
{
	signed long personality = lxc_config_parse_arch(value);

	if (personality >= 0)
		lxc_conf->personality = personality;
	else
		WARN("unsupported personality '%s'", value);

	return 0;
}

static int config_pts(const char *key, const char *value,
		      struct lxc_conf *lxc_conf)
{
	int maxpts = atoi(value);

	lxc_conf->pts = maxpts;

	return 0;
}

static int config_start(const char *key, const char *value,
		      struct lxc_conf *lxc_conf)
{
	if(strcmp(key, "lxc.start.auto") == 0) {
		lxc_conf->start_auto = atoi(value);
		return 0;
	}
	else if (strcmp(key, "lxc.start.delay") == 0) {
		lxc_conf->start_delay = atoi(value);
		return 0;
	}
	else if (strcmp(key, "lxc.start.order") == 0) {
		lxc_conf->start_order = atoi(value);
		return 0;
	}
	SYSERROR("Unknown key: %s", key);
	return -1;
}

static int config_group(const char *key, const char *value,
		      struct lxc_conf *lxc_conf)
{
	char *groups, *groupptr, *sptr, *token;
	struct lxc_list *grouplist;
	int ret = -1;

	if (!strlen(value))
		return lxc_clear_groups(lxc_conf);

	groups = strdup(value);
	if (!groups) {
		SYSERROR("failed to dup '%s'", value);
		return -1;
	}

	/* in case several groups are specified in a single line
	 * split these groups in a single element for the list */
	for (groupptr = groups;;groupptr = NULL) {
                token = strtok_r(groupptr, " \t", &sptr);
                if (!token) {
			ret = 0;
                        break;
		}

		grouplist = malloc(sizeof(*grouplist));
		if (!grouplist) {
			SYSERROR("failed to allocate groups list");
			break;
		}

		grouplist->elem = strdup(token);
		if (!grouplist->elem) {
			SYSERROR("failed to dup '%s'", token);
			free(grouplist);
			break;
		}

		lxc_list_add_tail(&lxc_conf->groups, grouplist);
        }

	free(groups);

	return ret;
}

static int config_tty(const char *key, const char *value,
		      struct lxc_conf *lxc_conf)
{
	int nbtty = atoi(value);

	lxc_conf->tty = nbtty;

	return 0;
}

static int config_ttydir(const char *key, const char *value,
			  struct lxc_conf *lxc_conf)
{
	return config_string_item_max(&lxc_conf->ttydir, value, NAME_MAX+1);
}

static int config_kmsg(const char *key, const char *value,
			  struct lxc_conf *lxc_conf)
{
	int v = atoi(value);

	lxc_conf->kmsg = v;

	return 0;
}

static int config_lsm_aa_profile(const char *key, const char *value,
				 struct lxc_conf *lxc_conf)
{
	return config_string_item(&lxc_conf->lsm_aa_profile, value);
}

static int config_lsm_se_context(const char *key, const char *value,
				 struct lxc_conf *lxc_conf)
{
	return config_string_item(&lxc_conf->lsm_se_context, value);
}

static int config_logfile(const char *key, const char *value,
			     struct lxc_conf *lxc_conf)
{
	int ret;

	// store these values in the lxc_conf, and then try to set for
	// actual current logging.
	ret = config_path_item(&lxc_conf->logfile, value);
	if (ret == 0)
		ret = lxc_log_set_file(lxc_conf->logfile);
	return ret;
}

static int config_loglevel(const char *key, const char *value,
			     struct lxc_conf *lxc_conf)
{
	int newlevel;

	if (!value || strlen(value) == 0)
		return 0;

	if (value[0] >= '0' && value[0] <= '9')
		newlevel = atoi(value);
	else
		newlevel = lxc_log_priority_to_int(value);
	// store these values in the lxc_conf, and then try to set for
	// actual current logging.
	lxc_conf->loglevel = newlevel;
	return lxc_log_set_level(newlevel);
}

static int config_autodev(const char *key, const char *value,
			  struct lxc_conf *lxc_conf)
{
	int v = atoi(value);

	lxc_conf->autodev = v;

	return 0;
}

static int sig_num(const char *sig)
{
	int n;
	char *endp = NULL;

	errno = 0;
	n = strtol(sig, &endp, 10);
	if (sig == endp || n < 0 || errno != 0)
		return -1;
	return n;
}

static int rt_sig_num(const char *signame)
{
	int sig_n = 0;
	int rtmax = 0;

	if (strncasecmp(signame, "max-", 4) == 0) {
		rtmax = 1;
	}
	signame += 4;
	if (!isdigit(*signame))
		return -1;
	sig_n = sig_num(signame);
	sig_n = rtmax ? SIGRTMAX - sig_n : SIGRTMIN + sig_n;
	if (sig_n > SIGRTMAX || sig_n < SIGRTMIN)
		return -1;
	return sig_n;
}

static const char *sig_name(int signum) {
	int n;

	for (n = 0; n < sizeof(signames) / sizeof((signames)[0]); n++) {
		if (n == signames[n].num)
			return signames[n].name;
	}
	return "";
}

static int sig_parse(const char *signame) {
	int n;

	if (isdigit(*signame)) {
		return sig_num(signame);
	} else if (strncasecmp(signame, "sig", 3) == 0) {
		signame += 3;
		if (strncasecmp(signame, "rt", 2) == 0)
			return rt_sig_num(signame + 2);
		for (n = 0; n < sizeof(signames) / sizeof((signames)[0]); n++) {
			if (strcasecmp (signames[n].name, signame) == 0)
				return signames[n].num;
		}
	}
	return -1;
}

static int config_haltsignal(const char *key, const char *value,
			     struct lxc_conf *lxc_conf)
{
	int sig_n = sig_parse(value);

	if (sig_n < 0)
		return -1;
	lxc_conf->haltsignal = sig_n;

	return 0;
}

static int config_stopsignal(const char *key, const char *value,
			  struct lxc_conf *lxc_conf)
{
	int sig_n = sig_parse(value);

	if (sig_n < 0)
		return -1;
	lxc_conf->stopsignal = sig_n;

	return 0;
}

static int config_cgroup(const char *key, const char *value,
			 struct lxc_conf *lxc_conf)
{
	char *token = "lxc.cgroup.";
	char *subkey;
	struct lxc_list *cglist = NULL;
	struct lxc_cgroup *cgelem = NULL;

	if (!value || strlen(value) == 0)
		return lxc_clear_cgroups(lxc_conf, key);

	subkey = strstr(key, token);

	if (!subkey)
		return -1;

	if (!strlen(subkey))
		return -1;

	if (strlen(subkey) == strlen(token))
		return -1;

	subkey += strlen(token);

	cglist = malloc(sizeof(*cglist));
	if (!cglist)
		goto out;

	cgelem = malloc(sizeof(*cgelem));
	if (!cgelem)
		goto out;
	memset(cgelem, 0, sizeof(*cgelem));

	cgelem->subsystem = strdup(subkey);
	cgelem->value = strdup(value);

	if (!cgelem->subsystem || !cgelem->value)
		goto out;

	cglist->elem = cgelem;

	lxc_list_add_tail(&lxc_conf->cgroup, cglist);

	return 0;

out:
	if (cglist)
		free(cglist);

	if (cgelem) {
		if (cgelem->subsystem)
			free(cgelem->subsystem);

		if (cgelem->value)
			free(cgelem->value);

		free(cgelem);
	}

	return -1;
}

static int config_idmap(const char *key, const char *value, struct lxc_conf *lxc_conf)
{
	char *token = "lxc.id_map";
	char *subkey;
	struct lxc_list *idmaplist = NULL;
	struct id_map *idmap = NULL;
	unsigned long hostid, nsid, range;
	char type;
	int ret;

	if (!value || strlen(value) == 0)
		return lxc_clear_idmaps(lxc_conf);

	subkey = strstr(key, token);

	if (!subkey)
		return -1;

	if (!strlen(subkey))
		return -1;

	idmaplist = malloc(sizeof(*idmaplist));
	if (!idmaplist)
		goto out;

	idmap = malloc(sizeof(*idmap));
	if (!idmap)
		goto out;
	memset(idmap, 0, sizeof(*idmap));

	ret = sscanf(value, "%c %lu %lu %lu", &type, &nsid, &hostid, &range);
	if (ret != 4)
		goto out;

	INFO("read uid map: type %c nsid %lu hostid %lu range %lu", type, nsid, hostid, range);
	if (type == 'u')
		idmap->idtype = ID_TYPE_UID;
	else if (type == 'g')
		idmap->idtype = ID_TYPE_GID;
	else
		goto out;

	idmap->hostid = hostid;
	idmap->nsid = nsid;
	idmap->range = range;

	idmaplist->elem = idmap;
	lxc_list_add_tail(&lxc_conf->id_map, idmaplist);

	return 0;

out:
	if (idmaplist)
		free(idmaplist);

	if (idmap) {
		free(idmap);
	}

	return -1;
}

static int config_fstab(const char *key, const char *value,
			struct lxc_conf *lxc_conf)
{
	return config_path_item(&lxc_conf->fstab, value);
}

static int config_mount_auto(const char *key, const char *value,
			     struct lxc_conf *lxc_conf)
{
	char *autos, *autoptr, *sptr, *token;
	static struct { const char *token; int mask; int flag; } allowed_auto_mounts[] = {
		{ "proc",               LXC_AUTO_PROC_MASK,      LXC_AUTO_PROC_MIXED         },
		{ "proc:mixed",         LXC_AUTO_PROC_MASK,      LXC_AUTO_PROC_MIXED         },
		{ "proc:rw",            LXC_AUTO_PROC_MASK,      LXC_AUTO_PROC_RW            },
		{ "sys",                LXC_AUTO_SYS_MASK,       LXC_AUTO_SYS_RO             },
		{ "sys:ro",             LXC_AUTO_SYS_MASK,       LXC_AUTO_SYS_RO             },
		{ "sys:rw",             LXC_AUTO_SYS_MASK,       LXC_AUTO_SYS_RW             },
		{ "cgroup",             LXC_AUTO_CGROUP_MASK,    LXC_AUTO_CGROUP_NOSPEC      },
		{ "cgroup:mixed",       LXC_AUTO_CGROUP_MASK,    LXC_AUTO_CGROUP_MIXED       },
		{ "cgroup:ro",          LXC_AUTO_CGROUP_MASK,    LXC_AUTO_CGROUP_RO          },
		{ "cgroup:rw",          LXC_AUTO_CGROUP_MASK,    LXC_AUTO_CGROUP_RW          },
		{ "cgroup-full",        LXC_AUTO_CGROUP_MASK,    LXC_AUTO_CGROUP_FULL_NOSPEC },
		{ "cgroup-full:mixed",  LXC_AUTO_CGROUP_MASK,    LXC_AUTO_CGROUP_FULL_MIXED  },
		{ "cgroup-full:ro",     LXC_AUTO_CGROUP_MASK,    LXC_AUTO_CGROUP_FULL_RO     },
		{ "cgroup-full:rw",     LXC_AUTO_CGROUP_MASK,    LXC_AUTO_CGROUP_FULL_RW     },
		/* NB: For adding anything that ist just a single on/off, but has
		 *     no options: keep mask and flag identical and just define the
		 *     enum value as an unused bit so far
		 */
		{ NULL, 0 }
	};
	int i;
	int ret = -1;

	if (!strlen(value))
		return -1;

	autos = strdup(value);
	if (!autos) {
		SYSERROR("failed to dup '%s'", value);
		return -1;
	}

	for (autoptr = autos; ; autoptr = NULL) {
                token = strtok_r(autoptr, " \t", &sptr);
                if (!token) {
			ret = 0;
                        break;
		}

		for (i = 0; allowed_auto_mounts[i].token; i++) {
			if (!strcmp(allowed_auto_mounts[i].token, token))
				break;
		}

		if (!allowed_auto_mounts[i].token) {
			ERROR("Invalid filesystem to automount: %s", token);
			break;
		}

		lxc_conf->auto_mounts &= ~allowed_auto_mounts[i].mask;
		lxc_conf->auto_mounts |= allowed_auto_mounts[i].flag;
        }

	free(autos);

	return ret;
}

static int config_mount(const char *key, const char *value,
			struct lxc_conf *lxc_conf)
{
	char *fstab_token = "lxc.mount";
	char *token = "lxc.mount.entry";
	char *auto_token = "lxc.mount.auto";
	char *subkey;
	char *mntelem;
	struct lxc_list *mntlist;

	if (!value || strlen(value) == 0)
		return lxc_clear_mount_entries(lxc_conf);

	subkey = strstr(key, token);

	if (!subkey) {
		subkey = strstr(key, auto_token);

		if (!subkey) {
			subkey = strstr(key, fstab_token);

			if (!subkey)
				return -1;

			return config_fstab(key, value, lxc_conf);
		}

		return config_mount_auto(key, value, lxc_conf);
	}

	if (!strlen(subkey))
		return -1;

	mntlist = malloc(sizeof(*mntlist));
	if (!mntlist)
		return -1;

	mntelem = strdup(value);
	if (!mntelem) {
		free(mntlist);
		return -1;
	}
	mntlist->elem = mntelem;

	lxc_list_add_tail(&lxc_conf->mount_list, mntlist);

	return 0;
}

static int config_cap_keep(const char *key, const char *value,
			   struct lxc_conf *lxc_conf)
{
	char *keepcaps, *keepptr, *sptr, *token;
	struct lxc_list *keeplist;
	int ret = -1;

	if (!strlen(value))
		return lxc_clear_config_keepcaps(lxc_conf);

	keepcaps = strdup(value);
	if (!keepcaps) {
		SYSERROR("failed to dup '%s'", value);
		return -1;
	}

	/* in case several capability keep is specified in a single line
	 * split these caps in a single element for the list */
	for (keepptr = keepcaps;;keepptr = NULL) {
                token = strtok_r(keepptr, " \t", &sptr);
                if (!token) {
			ret = 0;
                        break;
		}

		keeplist = malloc(sizeof(*keeplist));
		if (!keeplist) {
			SYSERROR("failed to allocate keepcap list");
			break;
		}

		keeplist->elem = strdup(token);
		if (!keeplist->elem) {
			SYSERROR("failed to dup '%s'", token);
			free(keeplist);
			break;
		}

		lxc_list_add_tail(&lxc_conf->keepcaps, keeplist);
        }

	free(keepcaps);

	return ret;
}

static int config_cap_drop(const char *key, const char *value,
			   struct lxc_conf *lxc_conf)
{
	char *dropcaps, *dropptr, *sptr, *token;
	struct lxc_list *droplist;
	int ret = -1;

	if (!strlen(value))
		return lxc_clear_config_caps(lxc_conf);

	dropcaps = strdup(value);
	if (!dropcaps) {
		SYSERROR("failed to dup '%s'", value);
		return -1;
	}

	/* in case several capability drop is specified in a single line
	 * split these caps in a single element for the list */
	for (dropptr = dropcaps;;dropptr = NULL) {
                token = strtok_r(dropptr, " \t", &sptr);
                if (!token) {
			ret = 0;
                        break;
		}

		droplist = malloc(sizeof(*droplist));
		if (!droplist) {
			SYSERROR("failed to allocate drop list");
			break;
		}

		droplist->elem = strdup(token);
		if (!droplist->elem) {
			SYSERROR("failed to dup '%s'", token);
			free(droplist);
			break;
		}

		lxc_list_add_tail(&lxc_conf->caps, droplist);
        }

	free(dropcaps);

	return ret;
}

static int config_console(const char *key, const char *value,
			  struct lxc_conf *lxc_conf)
{
	return config_path_item(&lxc_conf->console.path, value);
}

static int config_includefile(const char *key, const char *value,
			  struct lxc_conf *lxc_conf)
{
	return lxc_config_read(value, lxc_conf);
}

static int config_rootfs(const char *key, const char *value,
			 struct lxc_conf *lxc_conf)
{
	return config_path_item(&lxc_conf->rootfs.path, value);
}

static int config_rootfs_mount(const char *key, const char *value,
			       struct lxc_conf *lxc_conf)
{
	return config_path_item(&lxc_conf->rootfs.mount, value);
}

static int config_rootfs_options(const char *key, const char *value,
			       struct lxc_conf *lxc_conf)
{
	return config_string_item(&lxc_conf->rootfs.options, value);
}

static int config_pivotdir(const char *key, const char *value,
			   struct lxc_conf *lxc_conf)
{
	return config_path_item(&lxc_conf->rootfs.pivot, value);
}

static int config_utsname(const char *key, const char *value,
			  struct lxc_conf *lxc_conf)
{
	struct utsname *utsname;

	utsname = malloc(sizeof(*utsname));
	if (!utsname) {
		SYSERROR("failed to allocate memory");
		return -1;
	}

	if (strlen(value) >= sizeof(utsname->nodename)) {
		ERROR("node name '%s' is too long",
			      value);
		free(utsname);
		return -1;
	}

	strcpy(utsname->nodename, value);
	if (lxc_conf->utsname)
		free(lxc_conf->utsname);
	lxc_conf->utsname = utsname;

	return 0;
}

static int parse_line(char *buffer, void *data)
{
	struct lxc_config_t *config;
	char *line, *linep;
	char *dot;
	char *key;
	char *value;
	int ret = 0;

	if (lxc_is_line_empty(buffer))
		return 0;

	/* we have to dup the buffer otherwise, at the re-exec for
	 * reboot we modified the original string on the stack by
	 * replacing '=' by '\0' below
	 */
	linep = line = strdup(buffer);
	if (!line) {
		SYSERROR("failed to allocate memory for '%s'", buffer);
		return -1;
	}

	line += lxc_char_left_gc(line, strlen(line));

	/* martian option - ignoring it, the commented lines beginning by '#'
	 * fall in this case
	 */
	if (strncmp(line, "lxc.", 4))
		goto out;

	ret = -1;

	dot = strstr(line, "=");
	if (!dot) {
		ERROR("invalid configuration line: %s", line);
		goto out;
	}

	*dot = '\0';
	value = dot + 1;

	key = line;
	key[lxc_char_right_gc(key, strlen(key))] = '\0';

	value += lxc_char_left_gc(value, strlen(value));
	value[lxc_char_right_gc(value, strlen(value))] = '\0';

	config = lxc_getconfig(key);
	if (!config) {
		ERROR("unknown key %s", key);
		goto out;
	}

	ret = config->cb(key, value, data);

out:
	free(linep);
	return ret;
}

static int lxc_config_readline(char *buffer, struct lxc_conf *conf)
{
	return parse_line(buffer, conf);
}

int lxc_config_read(const char *file, struct lxc_conf *conf)
{
	if( access(file, R_OK) == -1 ) {
		return -1;
	}
	/* Catch only the top level config file name in the structure */
	if( ! conf->rcfile ) {
		conf->rcfile = strdup( file );
	}
	return lxc_file_for_each_line(file, parse_line, conf);
}

int lxc_config_define_add(struct lxc_list *defines, char* arg)
{
	struct lxc_list *dent;

	dent = malloc(sizeof(struct lxc_list));
	if (!dent)
		return -1;

	dent->elem = arg;
	lxc_list_add_tail(defines, dent);
	return 0;
}

int lxc_config_define_load(struct lxc_list *defines, struct lxc_conf *conf)
{
	struct lxc_list *it,*next;
	int ret = 0;

	lxc_list_for_each(it, defines) {
		ret = lxc_config_readline(it->elem, conf);
		if (ret)
			break;
	}

	lxc_list_for_each_safe(it, defines, next) {
		lxc_list_del(it);
		free(it);
	}

	return ret;
}

signed long lxc_config_parse_arch(const char *arch)
{
	#if HAVE_SYS_PERSONALITY_H
	struct per_name {
		char *name;
		unsigned long per;
	} pername[] = {
		{ "x86", PER_LINUX32 },
		{ "linux32", PER_LINUX32 },
		{ "i386", PER_LINUX32 },
		{ "i486", PER_LINUX32 },
		{ "i586", PER_LINUX32 },
		{ "i686", PER_LINUX32 },
		{ "athlon", PER_LINUX32 },
		{ "linux64", PER_LINUX },
		{ "x86_64", PER_LINUX },
		{ "amd64", PER_LINUX },
	};
	size_t len = sizeof(pername) / sizeof(pername[0]);

	int i;

	for (i = 0; i < len; i++) {
		if (!strcmp(pername[i].name, arch))
		    return pername[i].per;
	}
	#endif

	return -1;
}

int lxc_fill_elevated_privileges(char *flaglist, int *flags)
{
	char *token, *saveptr = NULL;
	int i, aflag;
	struct { const char *token; int flag; } all_privs[] = {
		{ "CGROUP",		LXC_ATTACH_MOVE_TO_CGROUP 	},
		{ "CAP",		LXC_ATTACH_DROP_CAPABILITIES 	},
		{ "LSM",		LXC_ATTACH_LSM_EXEC 		},
		{ NULL, 0 }
	};

	if (!flaglist) {
		/* for the sake of backward compatibility, drop all privileges
		   if none is specified */
		for (i = 0; all_privs[i].token; i++) {
	                *flags |= all_privs[i].flag;
		}
		return 0;
	}

	token = strtok_r(flaglist, "|", &saveptr);
	while (token) {
		aflag = -1;
		for (i = 0; all_privs[i].token; i++) {
			if (!strcmp(all_privs[i].token, token))
				aflag = all_privs[i].flag;
		}
		if (aflag < 0)
			return -1;

		*flags |= aflag;

		token = strtok_r(NULL, "|", &saveptr);
	}
	return 0;
}

static int lxc_get_conf_int(struct lxc_conf *c, char *retv, int inlen, int v)
{
	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);
	return snprintf(retv, inlen, "%d", v);
}

static int lxc_get_arch_entry(struct lxc_conf *c, char *retv, int inlen)
{
	int fulllen = 0;

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	#if HAVE_SYS_PERSONALITY_H
	int len = 0;

	switch(c->personality) {
	case PER_LINUX32: strprint(retv, inlen, "i686"); break;
	case PER_LINUX: strprint(retv, inlen, "x86_64"); break;
	default: break;
	}
	#endif

	return fulllen;
}

/*
 * If you ask for a specific cgroup value, i.e. lxc.cgroup.devices.list,
 * then just the value(s) will be printed.  Since there still could be
 * more than one, it is newline-separated.
 * (Maybe that's ambigous, since some values, i.e. devices.list, will
 * already have newlines?)
 * If you ask for 'lxc.cgroup", then all cgroup entries will be printed,
 * in 'lxc.cgroup.subsystem.key = value' format.
 */
static int lxc_get_cgroup_entry(struct lxc_conf *c, char *retv, int inlen,
				const char *key)
{
	int fulllen = 0, len;
	int all = 0;
	struct lxc_list *it;

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	if (strcmp(key, "all") == 0)
		all = 1;

	lxc_list_for_each(it, &c->cgroup) {
		struct lxc_cgroup *cg = it->elem;
		if (all) {
			strprint(retv, inlen, "lxc.cgroup.%s = %s\n", cg->subsystem, cg->value);
		} else if (strcmp(cg->subsystem, key) == 0) {
			strprint(retv, inlen, "%s\n", cg->value);
		}
	}
	return fulllen;
}

static int lxc_get_item_hooks(struct lxc_conf *c, char *retv, int inlen,
			      const char *key)
{
	char *subkey;
	int len, fulllen = 0, found = -1;
	struct lxc_list *it;
	int i;

	/* "lxc.hook.mount" */
	subkey = index(key, '.');
	if (subkey) subkey = index(subkey+1, '.');
	if (!subkey)
		return -1;
	subkey++;
	if (!*subkey)
		return -1;
	for (i=0; i<NUM_LXC_HOOKS; i++) {
		if (strcmp(lxchook_names[i], subkey) == 0) {
			found=i;
			break;
		}
	}
	if (found == -1)
		return -1;

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	lxc_list_for_each(it, &c->hooks[found]) {
		strprint(retv, inlen, "%s\n", (char *)it->elem);
	}
	return fulllen;
}

static int lxc_get_item_groups(struct lxc_conf *c, char *retv, int inlen)
{
	int len, fulllen = 0;
	struct lxc_list *it;

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	lxc_list_for_each(it, &c->groups) {
		strprint(retv, inlen, "%s\n", (char *)it->elem);
	}
	return fulllen;
}

static int lxc_get_item_cap_drop(struct lxc_conf *c, char *retv, int inlen)
{
	int len, fulllen = 0;
	struct lxc_list *it;

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	lxc_list_for_each(it, &c->caps) {
		strprint(retv, inlen, "%s\n", (char *)it->elem);
	}
	return fulllen;
}

static int lxc_get_item_cap_keep(struct lxc_conf *c, char *retv, int inlen)
{
	int len, fulllen = 0;
	struct lxc_list *it;

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	lxc_list_for_each(it, &c->keepcaps) {
		strprint(retv, inlen, "%s\n", (char *)it->elem);
	}
	return fulllen;
}

static int lxc_get_mount_entries(struct lxc_conf *c, char *retv, int inlen)
{
	int len, fulllen = 0;
	struct lxc_list *it;

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	lxc_list_for_each(it, &c->mount_list) {
		strprint(retv, inlen, "%s\n", (char *)it->elem);
	}
	return fulllen;
}

static int lxc_get_auto_mounts(struct lxc_conf *c, char *retv, int inlen)
{
	int len, fulllen = 0;
	const char *sep = "";

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	if (!(c->auto_mounts & LXC_AUTO_ALL_MASK))
		return 0;

	switch (c->auto_mounts & LXC_AUTO_PROC_MASK) {
		case LXC_AUTO_PROC_MIXED:         strprint(retv, inlen, "%sproc:mixed", sep);        sep = " "; break;
		case LXC_AUTO_PROC_RW:            strprint(retv, inlen, "%sproc:rw", sep);           sep = " "; break;
		default: break;
	}
	switch (c->auto_mounts & LXC_AUTO_SYS_MASK) {
		case LXC_AUTO_SYS_RO:             strprint(retv, inlen, "%ssys:ro", sep);            sep = " "; break;
		case LXC_AUTO_SYS_RW:             strprint(retv, inlen, "%ssys:rw", sep);            sep = " "; break;
		default: break;
	}
	switch (c->auto_mounts & LXC_AUTO_CGROUP_MASK) {
		case LXC_AUTO_CGROUP_NOSPEC:      strprint(retv, inlen, "%scgroup", sep);            sep = " "; break;
		case LXC_AUTO_CGROUP_MIXED:       strprint(retv, inlen, "%scgroup:mixed", sep);      sep = " "; break;
		case LXC_AUTO_CGROUP_RO:          strprint(retv, inlen, "%scgroup:ro", sep);         sep = " "; break;
		case LXC_AUTO_CGROUP_RW:          strprint(retv, inlen, "%scgroup:rw", sep);         sep = " "; break;
		case LXC_AUTO_CGROUP_FULL_NOSPEC: strprint(retv, inlen, "%scgroup-full", sep);       sep = " "; break;
		case LXC_AUTO_CGROUP_FULL_MIXED:  strprint(retv, inlen, "%scgroup-full:mixed", sep); sep = " "; break;
		case LXC_AUTO_CGROUP_FULL_RO:     strprint(retv, inlen, "%scgroup-full:ro", sep);    sep = " "; break;
		case LXC_AUTO_CGROUP_FULL_RW:     strprint(retv, inlen, "%scgroup-full:rw", sep);    sep = " "; break;
		default: break;
	}

	return fulllen;
}

/*
 * lxc.network.0.XXX, where XXX can be: name, type, link, flags, type,
 * macvlan.mode, veth.pair, vlan, ipv4, ipv6, script.up, hwaddr, mtu,
 * ipv4_gateway, ipv6_gateway.  ipvX_gateway can return 'auto' instead
 * of an address.  ipv4 and ipv6 return lists (newline-separated).
 * things like veth.pair return '' if invalid (i.e. if called for vlan
 * type).
 */
static int lxc_get_item_nic(struct lxc_conf *c, char *retv, int inlen,
			    const char *key)
{
	char *p1;
	int len, fulllen = 0;
	struct lxc_netdev *netdev;

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	p1 = index(key, '.');
	if (!p1 || *(p1+1) == '\0') return -1;
	p1++;

	netdev = get_netdev_from_key(key, &c->network);
	if (!netdev)
		return -1;
	if (strcmp(p1, "name") == 0) {
		if (netdev->name)
			strprint(retv, inlen, "%s", netdev->name);
	} else if (strcmp(p1, "type") == 0) {
		strprint(retv, inlen, "%s", lxc_net_type_to_str(netdev->type));
	} else if (strcmp(p1, "link") == 0) {
		if (netdev->link)
			strprint(retv, inlen, "%s", netdev->link);
	} else if (strcmp(p1, "flags") == 0) {
		if (netdev->flags & IFF_UP)
			strprint(retv, inlen, "up");
	} else if (strcmp(p1, "script.up") == 0) {
		if (netdev->upscript)
			strprint(retv, inlen, "%s", netdev->upscript);
	} else if (strcmp(p1, "script.down") == 0) {
		if (netdev->downscript)
			strprint(retv, inlen, "%s", netdev->downscript);
	} else if (strcmp(p1, "hwaddr") == 0) {
		if (netdev->hwaddr)
			strprint(retv, inlen, "%s", netdev->hwaddr);
	} else if (strcmp(p1, "mtu") == 0) {
		if (netdev->mtu)
			strprint(retv, inlen, "%s", netdev->mtu);
	} else if (strcmp(p1, "macvlan.mode") == 0) {
		if (netdev->type == LXC_NET_MACVLAN) {
			const char *mode;
			switch (netdev->priv.macvlan_attr.mode) {
			case MACVLAN_MODE_PRIVATE: mode = "private"; break;
			case MACVLAN_MODE_VEPA: mode = "vepa"; break;
			case MACVLAN_MODE_BRIDGE: mode = "bridge"; break;
			default: mode = "(invalid)"; break;
			}
			strprint(retv, inlen, "%s", mode);
		}
	} else if (strcmp(p1, "veth.pair") == 0) {
		if (netdev->type == LXC_NET_VETH) {
			strprint(retv, inlen, "%s",
				 netdev->priv.veth_attr.pair ?
				  netdev->priv.veth_attr.pair :
				  netdev->priv.veth_attr.veth1);
		}
	} else if (strcmp(p1, "vlan") == 0) {
		if (netdev->type == LXC_NET_VLAN) {
			strprint(retv, inlen, "%d", netdev->priv.vlan_attr.vid);
		}
	} else if (strcmp(p1, "ipv4_gateway") == 0) {
		if (netdev->ipv4_gateway_auto) {
			strprint(retv, inlen, "auto");
		} else if (netdev->ipv4_gateway) {
			char buf[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, netdev->ipv4_gateway, buf, sizeof(buf));
			strprint(retv, inlen, "%s", buf);
		}
	} else if (strcmp(p1, "ipv4") == 0) {
		struct lxc_list *it2;
		lxc_list_for_each(it2, &netdev->ipv4) {
			struct lxc_inetdev *i = it2->elem;
			char buf[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &i->addr, buf, sizeof(buf));
			strprint(retv, inlen, "%s\n", buf);
		}
	} else if (strcmp(p1, "ipv6_gateway") == 0) {
		if (netdev->ipv6_gateway_auto) {
			strprint(retv, inlen, "auto");
		} else if (netdev->ipv6_gateway) {
			char buf[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, netdev->ipv6_gateway, buf, sizeof(buf));
			strprint(retv, inlen, "%s", buf);
		}
	} else if (strcmp(p1, "ipv6") == 0) {
		struct lxc_list *it2;
		lxc_list_for_each(it2, &netdev->ipv6) {
			struct lxc_inetdev *i = it2->elem;
			char buf[INET_ADDRSTRLEN];
			inet_ntop(AF_INET6, &i->addr, buf, sizeof(buf));
			strprint(retv, inlen, "%s\n", buf);
		}
	}
	return fulllen;
}

static int lxc_get_item_network(struct lxc_conf *c, char *retv, int inlen)
{
	int len, fulllen = 0;
	struct lxc_list *it;

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	lxc_list_for_each(it, &c->network) {
		struct lxc_netdev *n = it->elem;
		const char *t = lxc_net_type_to_str(n->type);
		strprint(retv, inlen, "%s\n", t ? t : "(invalid)");
	}
	return fulllen;
}

int lxc_get_config_item(struct lxc_conf *c, const char *key, char *retv,
			int inlen)
{
	const char *v = NULL;

	if (strcmp(key, "lxc.mount.entry") == 0)
		return lxc_get_mount_entries(c, retv, inlen);
	else if (strcmp(key, "lxc.mount.auto") == 0)
		return lxc_get_auto_mounts(c, retv, inlen);
	else if (strcmp(key, "lxc.mount") == 0)
		v = c->fstab;
	else if (strcmp(key, "lxc.tty") == 0)
		return lxc_get_conf_int(c, retv, inlen, c->tty);
	else if (strcmp(key, "lxc.pts") == 0)
		return lxc_get_conf_int(c, retv, inlen, c->pts);
	else if (strcmp(key, "lxc.devttydir") == 0)
		v = c->ttydir;
	else if (strcmp(key, "lxc.arch") == 0)
		return lxc_get_arch_entry(c, retv, inlen);
	else if (strcmp(key, "lxc.aa_profile") == 0)
		v = c->lsm_aa_profile;
	else if (strcmp(key, "lxc.se_context") == 0)
		v = c->lsm_se_context;
	else if (strcmp(key, "lxc.logfile") == 0)
		v = lxc_log_get_file();
	else if (strcmp(key, "lxc.loglevel") == 0)
		v = lxc_log_priority_to_string(lxc_log_get_level());
	else if (strcmp(key, "lxc.cgroup") == 0) // all cgroup info
		return lxc_get_cgroup_entry(c, retv, inlen, "all");
	else if (strncmp(key, "lxc.cgroup.", 11) == 0) // specific cgroup info
		return lxc_get_cgroup_entry(c, retv, inlen, key + 11);
	else if (strcmp(key, "lxc.utsname") == 0)
		v = c->utsname ? c->utsname->nodename : NULL;
	else if (strcmp(key, "lxc.console") == 0)
		v = c->console.path;
	else if (strcmp(key, "lxc.rootfs.mount") == 0)
		v = c->rootfs.mount;
	else if (strcmp(key, "lxc.rootfs.options") == 0)
		v = c->rootfs.options;
	else if (strcmp(key, "lxc.rootfs") == 0)
		v = c->rootfs.path;
	else if (strcmp(key, "lxc.pivotdir") == 0)
		v = c->rootfs.pivot;
	else if (strcmp(key, "lxc.cap.drop") == 0)
		return lxc_get_item_cap_drop(c, retv, inlen);
	else if (strcmp(key, "lxc.cap.keep") == 0)
		return lxc_get_item_cap_keep(c, retv, inlen);
	else if (strncmp(key, "lxc.hook", 8) == 0)
		return lxc_get_item_hooks(c, retv, inlen, key);
	else if (strcmp(key, "lxc.network") == 0)
		return lxc_get_item_network(c, retv, inlen);
	else if (strncmp(key, "lxc.network.", 12) == 0)
		return lxc_get_item_nic(c, retv, inlen, key + 12);
	else if (strcmp(key, "lxc.start.auto") == 0)
		return lxc_get_conf_int(c, retv, inlen, c->start_auto);
	else if (strcmp(key, "lxc.start.delay") == 0)
		return lxc_get_conf_int(c, retv, inlen, c->start_delay);
	else if (strcmp(key, "lxc.start.order") == 0)
		return lxc_get_conf_int(c, retv, inlen, c->start_order);
	else if (strcmp(key, "lxc.group") == 0)
		return lxc_get_item_groups(c, retv, inlen);
	else if (strcmp(key, "lxc.seccomp") == 0)
		v = c->seccomp;
	else return -1;

	if (!v)
		return 0;
	if (retv && inlen >= strlen(v) + 1)
		strncpy(retv, v, strlen(v)+1);
	return strlen(v);
}

int lxc_clear_config_item(struct lxc_conf *c, const char *key)
{
	if (strcmp(key, "lxc.network") == 0)
		return lxc_clear_config_network(c);
	else if (strncmp(key, "lxc.network.", 12) == 0)
		return lxc_clear_nic(c, key + 12);
	else if (strcmp(key, "lxc.cap.drop") == 0)
		return lxc_clear_config_caps(c);
	else if (strcmp(key, "lxc.cap.keep") == 0)
		return lxc_clear_config_keepcaps(c);
	else if (strncmp(key, "lxc.cgroup", 10) == 0)
		return lxc_clear_cgroups(c, key);
	else if (strcmp(key, "lxc.mount.entries") == 0)
		return lxc_clear_mount_entries(c);
	else if (strcmp(key, "lxc.mount.auto") == 0)
		return lxc_clear_automounts(c);
	else if (strncmp(key, "lxc.hook", 8) == 0)
		return lxc_clear_hooks(c, key);
	else if (strncmp(key, "lxc.group", 9) == 0)
		return lxc_clear_groups(c);
	else if (strncmp(key, "lxc.seccomp", 11) == 0) {
		lxc_seccomp_free(c);
		return 0;
	}

	return -1;
}

/*
 * writing out a confile.
 */
void write_config(FILE *fout, struct lxc_conf *c)
{
	struct lxc_list *it;
	int i;

	if (c->fstab)
		fprintf(fout, "lxc.mount = %s\n", c->fstab);
	lxc_list_for_each(it, &c->mount_list) {
		fprintf(fout, "lxc.mount.entry = %s\n", (char *)it->elem);
	}
	if (c->auto_mounts & LXC_AUTO_ALL_MASK) {
		fprintf(fout, "lxc.mount.auto =");
		switch (c->auto_mounts & LXC_AUTO_PROC_MASK) {
			case LXC_AUTO_PROC_MIXED:         fprintf(fout, " proc:mixed");        break;
			case LXC_AUTO_PROC_RW:            fprintf(fout, " proc:rw");           break;
			default: break;
		}
		switch (c->auto_mounts & LXC_AUTO_SYS_MASK) {
			case LXC_AUTO_SYS_RO:             fprintf(fout, " sys:ro");            break;
			case LXC_AUTO_SYS_RW:             fprintf(fout, " sys:rw");            break;
			default: break;
		}
		switch (c->auto_mounts & LXC_AUTO_CGROUP_MASK) {
			case LXC_AUTO_CGROUP_NOSPEC:      fprintf(fout, " cgroup");            break;
			case LXC_AUTO_CGROUP_MIXED:       fprintf(fout, " cgroup:mixed");      break;
			case LXC_AUTO_CGROUP_RO:          fprintf(fout, " cgroup:ro");         break;
			case LXC_AUTO_CGROUP_RW:          fprintf(fout, " cgroup:rw");         break;
			case LXC_AUTO_CGROUP_FULL_NOSPEC: fprintf(fout, " cgroup-full");       break;
			case LXC_AUTO_CGROUP_FULL_MIXED:  fprintf(fout, " cgroup-full:mixed"); break;
			case LXC_AUTO_CGROUP_FULL_RO:     fprintf(fout, " cgroup-full:ro");    break;
			case LXC_AUTO_CGROUP_FULL_RW:     fprintf(fout, " cgroup-full:rw");    break;
			default: break;
		}
		fprintf(fout, "\n");
	}
	if (c->tty)
		fprintf(fout, "lxc.tty = %d\n", c->tty);
	if (c->pts)
		fprintf(fout, "lxc.pts = %d\n", c->pts);
	if (c->ttydir)
		fprintf(fout, "lxc.devttydir = %s\n", c->ttydir);
	if (c->haltsignal)
		fprintf(fout, "lxc.haltsignal = SIG%s\n", sig_name(c->haltsignal));
	if (c->stopsignal)
		fprintf(fout, "lxc.stopsignal = SIG%s\n", sig_name(c->stopsignal));
	#if HAVE_SYS_PERSONALITY_H
	switch(c->personality) {
	case PER_LINUX32: fprintf(fout, "lxc.arch = i686\n"); break;
	case PER_LINUX: fprintf(fout, "lxc.arch = x86_64\n"); break;
	default: break;
	}
	#endif
	if (c->lsm_aa_profile)
		fprintf(fout, "lxc.aa_profile = %s\n", c->lsm_aa_profile);
	if (c->lsm_se_context)
		fprintf(fout, "lxc.se_context = %s\n", c->lsm_se_context);
	if (c->seccomp)
		fprintf(fout, "lxc.seccomp = %s\n", c->seccomp);
	if (c->kmsg == 0)
		fprintf(fout, "lxc.kmsg = 0\n");
	if (c->autodev > 0)
		fprintf(fout, "lxc.autodev = 1\n");
	if (c->loglevel != LXC_LOG_PRIORITY_NOTSET)
		fprintf(fout, "lxc.loglevel = %s\n", lxc_log_priority_to_string(c->loglevel));
	if (c->logfile)
		fprintf(fout, "lxc.logfile = %s\n", c->logfile);
	lxc_list_for_each(it, &c->cgroup) {
		struct lxc_cgroup *cg = it->elem;
		fprintf(fout, "lxc.cgroup.%s = %s\n", cg->subsystem, cg->value);
	}
	if (c->utsname)
		fprintf(fout, "lxc.utsname = %s\n", c->utsname->nodename);
	lxc_list_for_each(it, &c->network) {
		struct lxc_netdev *n = it->elem;
		const char *t = lxc_net_type_to_str(n->type);
		struct lxc_list *it2;
		fprintf(fout, "lxc.network.type = %s\n", t ? t : "(invalid)");
		if (n->flags & IFF_UP)
			fprintf(fout, "lxc.network.flags = up\n");
		if (n->link)
			fprintf(fout, "lxc.network.link = %s\n", n->link);
		if (n->name)
			fprintf(fout, "lxc.network.name = %s\n", n->name);
		if (n->type == LXC_NET_MACVLAN) {
			const char *mode;
			switch (n->priv.macvlan_attr.mode) {
			case MACVLAN_MODE_PRIVATE: mode = "private"; break;
			case MACVLAN_MODE_VEPA: mode = "vepa"; break;
			case MACVLAN_MODE_BRIDGE: mode = "bridge"; break;
			default: mode = "(invalid)"; break;
			}
			fprintf(fout, "lxc.network.macvlan.mode = %s\n", mode);
		} else if (n->type == LXC_NET_VETH) {
			if (n->priv.veth_attr.pair)
				fprintf(fout, "lxc.network.veth.pair = %s\n",
					n->priv.veth_attr.pair);
		} else if (n->type == LXC_NET_VLAN) {
			fprintf(fout, "lxc.network.vlan.id = %d\n", n->priv.vlan_attr.vid);
		}
		if (n->upscript)
			fprintf(fout, "lxc.network.script.up = %s\n", n->upscript);
		if (n->downscript)
			fprintf(fout, "lxc.network.script.down = %s\n", n->downscript);
		if (n->hwaddr)
			fprintf(fout, "lxc.network.hwaddr = %s\n", n->hwaddr);
		if (n->mtu)
			fprintf(fout, "lxc.network.mtu = %s\n", n->mtu);
		if (n->ipv4_gateway_auto)
			fprintf(fout, "lxc.network.ipv4.gateway = auto\n");
		else if (n->ipv4_gateway) {
			char buf[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, n->ipv4_gateway, buf, sizeof(buf));
			fprintf(fout, "lxc.network.ipv4.gateway = %s\n", buf);
		}
		lxc_list_for_each(it2, &n->ipv4) {
			struct lxc_inetdev *i = it2->elem;
			char buf[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &i->addr, buf, sizeof(buf));
			fprintf(fout, "lxc.network.ipv4 = %s", buf);

			if (i->prefix)
				fprintf(fout, "/%d", i->prefix);

			if (i->bcast.s_addr != (i->addr.s_addr |
			    htonl(INADDR_BROADCAST >>  i->prefix))) {

				inet_ntop(AF_INET, &i->bcast, buf, sizeof(buf));
				fprintf(fout, " %s\n", buf);
			}
			else
				fprintf(fout, "\n");
		}
		if (n->ipv6_gateway_auto)
			fprintf(fout, "lxc.network.ipv6.gateway = auto\n");
		else if (n->ipv6_gateway) {
			char buf[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, n->ipv6_gateway, buf, sizeof(buf));
			fprintf(fout, "lxc.network.ipv6.gateway = %s\n", buf);
		}
		lxc_list_for_each(it2, &n->ipv6) {
			struct lxc_inet6dev *i = it2->elem;
			char buf[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, &i->addr, buf, sizeof(buf));
			if (i->prefix)
				fprintf(fout, "lxc.network.ipv6 = %s/%d\n",
					buf, i->prefix);
			else
				fprintf(fout, "lxc.network.ipv6 = %s\n", buf);
		}
	}
	lxc_list_for_each(it, &c->caps)
		fprintf(fout, "lxc.cap.drop = %s\n", (char *)it->elem);
	lxc_list_for_each(it, &c->keepcaps)
		fprintf(fout, "lxc.cap.keep = %s\n", (char *)it->elem);
	lxc_list_for_each(it, &c->id_map) {
		struct id_map *idmap = it->elem;
		fprintf(fout, "lxc.id_map = %c %lu %lu %lu\n",
			idmap->idtype == ID_TYPE_UID ? 'u' : 'g', idmap->nsid,
			idmap->hostid, idmap->range);
	}
	for (i=0; i<NUM_LXC_HOOKS; i++) {
		lxc_list_for_each(it, &c->hooks[i])
			fprintf(fout, "lxc.hook.%s = %s\n",
				lxchook_names[i], (char *)it->elem);
	}
	if (c->console.path)
		fprintf(fout, "lxc.console = %s\n", c->console.path);
	if (c->rootfs.path)
		fprintf(fout, "lxc.rootfs = %s\n", c->rootfs.path);
	if (c->rootfs.mount && strcmp(c->rootfs.mount, LXCROOTFSMOUNT) != 0)
		fprintf(fout, "lxc.rootfs.mount = %s\n", c->rootfs.mount);
	if (c->rootfs.options)
		fprintf(fout, "lxc.rootfs.options = %s\n", c->rootfs.options);
	if (c->rootfs.pivot)
		fprintf(fout, "lxc.pivotdir = %s\n", c->rootfs.pivot);
	if (c->start_auto)
		fprintf(fout, "lxc.start.auto = %d\n", c->start_auto);
	if (c->start_delay)
		fprintf(fout, "lxc.start.delay = %d\n", c->start_delay);
	if (c->start_order)
		fprintf(fout, "lxc.start.order = %d\n", c->start_order);
	lxc_list_for_each(it, &c->groups)
		fprintf(fout, "lxc.group = %s\n", (char *)it->elem);
}

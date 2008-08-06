/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2008
 *
 * Authors:
 * Daniel Lezcano <dlezcano at fr.ibm.com>
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/utsname.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>

#include <lxc.h>
#include <list.h>
#include <conf.h>
#include <log.h>


typedef int (*file_cb)(char* buffer, void *data);
typedef int (*config_cb)(char *value, struct lxc_conf *lxc_conf);

static int config_mount(char *, struct lxc_conf *);
static int config_chroot(char *, struct lxc_conf *);
static int config_utsname(char *, struct lxc_conf *);
static int config_network_type(char *, struct lxc_conf *);
static int config_network_flags(char *, struct lxc_conf *);
static int config_network_link(char *, struct lxc_conf *);
static int config_network_name(char *, struct lxc_conf *);
static int config_network_hwaddr(char *, struct lxc_conf *);
static int config_network_ipv4(char *, struct lxc_conf *);
static int config_network_ipv6(char *, struct lxc_conf *);

struct config {
	char *name;
	int type;
	config_cb cb;
};

enum { MOUNT, CHROOT, UTSNAME, NETTYPE, NETFLAGS, NETLINK, 
       NETNAME, NETHWADDR, NETIPV4, NETIPV6 };

struct config config[] = {
	{ "lxc.mount",             MOUNT,     config_mount           },
	{ "lxc.chroot",            CHROOT,    config_chroot          },
	{ "lxc.utsname",           UTSNAME,   config_utsname         },
	{ "lxc.network.type",      NETTYPE,   config_network_type    },
	{ "lxc.network.flags",     NETFLAGS,  config_network_flags   },
	{ "lxc.network.link",      NETLINK,   config_network_link    },
	{ "lxc.network.name",      NETNAME,   config_network_name    },
	{ "lxc.network.hwaddr",    NETHWADDR, config_network_hwaddr  },
	{ "lxc.network.ipv4",      NETIPV4,   config_network_ipv4    },
	{ "lxc.network.ipv6",      NETIPV6,   config_network_ipv6    },
};

static const size_t config_size = sizeof(config)/sizeof(struct config);

static struct config *getconfig(const char *key)
{
	int i;

	for (i = 0; i < config_size; i++)
		if (!strncmp(config[i].name, key, 
			     strlen(config[i].name)))
			return &config[i];
	return NULL;
}

static int is_line_empty(char *line)
{
	int i;
	size_t len = strlen(line);

	for (i = 0; i < len; i++)
		if (line[i] != ' ' && line[i] != '\t' && 
		    line[i] != '\n' && line[i] != '\r' &&
		    line[i] != '\f' && line[i] != '\0')
			return 0;
	return 1;
}

static int char_left_gc(char *buffer, size_t len)
{
	int i;
	for (i = 0; i < len; i++) {
		if (buffer[i] == ' ' ||
		    buffer[i] == '\t')
			continue;
		return i;
	}
	return 0;
}

static int char_right_gc(char *buffer, size_t len)
{
	int i;
	for (i = len - 1; i >= 0; i--) {
		if (buffer[i] == ' '  ||
		    buffer[i] == '\t' ||
		    buffer[i] == '\n' ||
		    buffer[i] == '\0')
			continue;
		return i + 1;
	}
	return 0;
}

static int config_network_type(char *value, struct lxc_conf *lxc_conf)
{
	struct list *networks = &lxc_conf->networks;
	struct network *network;
	struct netdev *netdev;
	struct list *list;
	struct list *ndlist;

	network = malloc(sizeof(*network));
	if (!network) {
		lxc_log_syserror("failed to allocate memory");
		return -1;
	}
	
	list_init(&network->netdev);

	netdev = malloc(sizeof(*netdev));
	if (!netdev) {
		lxc_log_syserror("failed to allocate memory");
		return -1;
	}

	list_init(&netdev->ipv4);
	list_init(&netdev->ipv6);
	list_init(&netdev->route4);
	list_init(&netdev->route6);

	ndlist = malloc(sizeof(*ndlist));
	if (!ndlist) {
		lxc_log_syserror("failed to allocate memory");
		return -1;
	}

	ndlist->elem = netdev;

	list_add(&network->netdev, ndlist);

	list = malloc(sizeof(*list));
	if (!list) {
		lxc_log_syserror("failed to allocate memory");
		return -1;
	}

	list_init(list);
	list->elem = network;

	list_add(networks, list);
	
	if (!strcmp(value, "veth"))
		network->type = VETH;
	else if (!strcmp(value, "macvlan"))
		network->type = MACVLAN;
	else if (!strcmp(value, "phys"))
		network->type = PHYS;
	else {
		lxc_log_error("invalid network type %s", value);
		return -1;
	}
	return 0;
}

static int config_network_flags(char *value, struct lxc_conf *lxc_conf)
{
	struct list *networks = &lxc_conf->networks;
	struct network *network;
	struct netdev *netdev;

	if (list_empty(networks)) {
		lxc_log_error("network is not created for '%s' option", value);
		return -1;
	}

	network = list_first_elem(networks);
	if (!network) {
		lxc_log_error("no network defined for '%s' option", value);
		return -1;
	}

	netdev = list_first_elem(&network->netdev);
	netdev->flags |= IFF_UP;
	return 0;
}

static int config_network_link(char *value, struct lxc_conf *lxc_conf)
{
	struct list *networks = &lxc_conf->networks;
	struct network *network;
	struct netdev *netdev;

	if (list_empty(networks)) {
		lxc_log_error("network is not created for %s", value);
		return -1;
	}

	network = list_first_elem(networks);
	if (!network) {
		lxc_log_error("no network defined for %s", value);
		return -1;
	}

	if (strlen(value) > IFNAMSIZ) {
		lxc_log_error("invalid interface name: %s", value);
		return -1;
	}

	netdev = list_first_elem(&network->netdev);
	netdev->ifname = strdup(value);
	return 0;
}

static int config_network_name(char *value, struct lxc_conf *lxc_conf)
{
	struct list *networks = &lxc_conf->networks;
	struct network *network;
	struct netdev *netdev;

	if (list_empty(networks)) {
		lxc_log_error("network is not created for %s", value);
		return -1;
	}

	network = list_first_elem(networks);
	if (!network) {
		lxc_log_error("no network defined for %s", value);
		return -1;
	}

	if (strlen(value) > IFNAMSIZ) {
		lxc_log_error("invalid interface name: %s", value);
		return -1;
	}

	netdev = list_first_elem(&network->netdev);
	netdev->newname = strdup(value);
	return 0;
}

static int config_network_hwaddr(char *value, struct lxc_conf *lxc_conf)
{
	struct list *networks = &lxc_conf->networks;
	struct network *network;
	struct netdev *netdev;

	if (list_empty(networks)) {
		lxc_log_error("network is not created for %s", value);
		return -1;
	}

	network = list_first_elem(networks);
	if (!network) {
		lxc_log_error("no network defined for %s", value);
		return -1;
	}

	netdev = list_first_elem(&network->netdev);
	netdev->hwaddr = strdup(value);
	return 0;
}

static int config_network_ipv4(char *value, struct lxc_conf *lxc_conf)
{
	struct list *networks = &lxc_conf->networks;
	struct network *network;
	struct inetdev *inetdev;
	struct netdev *netdev;
	struct list *list;
	char *cursor, *slash, *addr = NULL, *bcast = NULL, *prefix = NULL;

	if (list_empty(networks)) {
		lxc_log_error("network is not created for '%s'", value);
		return -1;
	}

	network = list_first_elem(networks);
	if (!network) {
		lxc_log_error("no network defined for '%s'", value);
		return -1;
	}

	netdev = list_first_elem(&network->netdev);
	if (!netdev) {
		lxc_log_error("no netdev defined for '%s'", value);
	}

	inetdev = malloc(sizeof(*inetdev));
	if (!inetdev) {
		lxc_log_syserror("failed to allocate ipv4 address");
		return -1;
	}
	memset(inetdev, 0, sizeof(*inetdev));

	list = malloc(sizeof(*list));
	if (!list) {
		lxc_log_syserror("failed to allocate memory");
		return -1;
	}

	list_init(list);
	list->elem = inetdev;

	addr = value;

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

	if (!addr) {
		lxc_log_error("no address specified");
		return -1;
	}

	if (!inet_pton(AF_INET, addr, &inetdev->addr)) {
		lxc_log_syserror("invalid ipv4 address: %s", value);
		return -1;
	}

	if (bcast)
		if (!inet_pton(AF_INET, bcast, &inetdev->bcast)) {
			lxc_log_syserror("invalid ipv4 address: %s", value);
			return -1;
		}

	if (prefix)
		inetdev->prefix = atoi(prefix);

	list_add(&netdev->ipv4, list);

	return 0;
}

static int config_network_ipv6(char *value, struct lxc_conf *lxc_conf)
{
	struct list *networks = &lxc_conf->networks;
	struct network *network;
	struct netdev *netdev;
	struct inet6dev *inet6dev;
	struct list *list;
	char *slash;
	char *netmask;

	if (list_empty(networks)) {
		lxc_log_error("network is not created for %s", value);
		return -1;
	}

	network = list_first_elem(networks);
	if (!network) {
		lxc_log_error("no network defined for %s", value);
		return -1;
	}

	inet6dev = malloc(sizeof(*inet6dev));
	if (!inet6dev) {
		lxc_log_syserror("failed to allocate ipv6 address");
		return -1;
	}
	memset(inet6dev, 0, sizeof(*inet6dev));

	list = malloc(sizeof(*list));
	if (!list) {
		lxc_log_syserror("failed to allocate memory");
		return -1;
	}

	list_init(list);
	list->elem = inet6dev;

	slash = strstr(value, "/");
	if (slash) {
		*slash = '\0';
		netmask = slash + 1;
		inet6dev->prefix = atoi(netmask);
	}

	if (!inet_pton(AF_INET6, value, &inet6dev->addr)) {
		lxc_log_syserror("invalid ipv6 address: %s", value);
		return -1;
	}


	netdev = list_first_elem(&network->netdev);
	list_add(&netdev->ipv6, list);

	return 0;
}

static int config_mount(char *value, struct lxc_conf *lxc_conf)
{
	if (strlen(value) >= MAXPATHLEN) {
		lxc_log_error("%s path is too long", value);
		return -1;
	}

	lxc_conf->fstab = strdup(value);
	if (!lxc_conf->fstab) {
		lxc_log_syserror("failed to duplicate string %s", value);
		return -1;
	}

	return 0;
}

static int config_chroot(char *value, struct lxc_conf *lxc_conf)
{
	if (strlen(value) >= MAXPATHLEN) {
		lxc_log_error("%s path is too long", value);
		return -1;
	}

	lxc_conf->chroot = strdup(value);
	if (!lxc_conf->chroot) {
		lxc_log_syserror("failed to duplicate string %s", value);
		return -1;
	}

	return 0;
}

static int config_utsname(char *value, struct lxc_conf *lxc_conf)
{
	struct utsname *utsname;

	utsname = malloc(sizeof(*utsname));
	if (!utsname) {
		lxc_log_syserror("failed to allocate memory");
		return -1;
	}

	if (strlen(value) >= sizeof(utsname->nodename)) {
		lxc_log_error("node name '%s' is too long", 
			      utsname->nodename);
		return -1;
	}

	strcpy(utsname->nodename, value);
	lxc_conf->utsname = utsname;

	return 0;
}

static int parse_line(char *buffer, void *data)
{
	struct config *config;
	char *dot;
	char *key;
	char *value;

	if (is_line_empty(buffer))
		return 0;

	buffer += char_left_gc(buffer, strlen(buffer));
	if (buffer[0] == '#')
		return 0;

	dot = strstr(buffer, "=");
	if (!dot) {
		lxc_log_error("invalid configuration line: %s", buffer);
		return -1;
	}
	
	*dot = '\0';
	value = dot + 1;

	key = buffer;
	key[char_right_gc(key, strlen(key))] = '\0';

	value += char_left_gc(value, strlen(value));
	value[char_right_gc(value, strlen(value))] = '\0';

	config = getconfig(key);
	if (!config) {
		lxc_log_error("unknow key %s", key);
		return -1;
	}

	return config->cb(value, data);
}

static int file_for_each_line(const char *file, file_cb callback, void *data)
{
	char buffer[MAXPATHLEN];
	size_t len = sizeof(buffer);
	FILE *f;
	int err = -1;

	f = fopen(file, "r");
	if (!f) {
		lxc_log_syserror("failed to open %s", file);
		return -1;
	}
	
	while (fgets(buffer, len, f))
		if (callback(buffer, data))
			goto out;
	err = 0;
out:
	fclose(f);	
	return err;
}

int config_read(const char *file, struct lxc_conf *conf)
{
	return file_for_each_line(file, parse_line, conf);
}

int config_init(struct lxc_conf *conf)
{
	conf->chroot = NULL;
	conf->fstab = NULL;
	conf->utsname = NULL;
	conf->cgroup = NULL;
	list_init(&conf->networks);
	return 0;
}

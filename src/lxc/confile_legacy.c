/*
 * lxc: linux Container library
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
#define __STDC_FORMAT_MACROS /* Required for PRIu64 to work. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <inttypes.h> /* Required for PRIu64 to work. */
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/utsname.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <time.h>
#include <dirent.h>
#include <syslog.h>

#include "bdev.h"
#include "parse.h"
#include "config.h"
#include "confile.h"
#include "confile_utils.h"
#include "confile_legacy.h"
#include "utils.h"
#include "log.h"
#include "conf.h"
#include "network.h"
#include "lxcseccomp.h"

#if HAVE_IFADDRS_H
#include <ifaddrs.h>
#else
#include <../include/ifaddrs.h>
#endif

lxc_log_define(lxc_confile_legacy, lxc);

/*
 * Config entry is something like "lxc.network.0.ipv4" the key 'lxc.network.'
 * was found.  So we make sure next comes an integer, find the right callback
 * (by rewriting the key), and call it.
 */
int set_config_network_legacy_nic(const char *key, const char *value,
				  struct lxc_conf *lxc_conf, void *data)
{
	char *copy = strdup(key), *p;
	int ret = -1;
	struct lxc_config_t *config;

	if (!copy) {
		SYSERROR("failed to allocate memory");
		return -1;
	}
	/*
	 * Ok we know that to get here we've got "lxc.network."
	 * and it isn't any of the other network entries.  So
	 * after the second . Should come an integer (# of defined
	 * nic) followed by a valid entry.
	 */
	if (*(key + 12) < '0' || *(key + 12) > '9')
		goto out;

	p = strchr(key + 12, '.');
	if (!p)
		goto out;

	strcpy(copy + 12, p + 1);
	config = lxc_getconfig(copy);
	if (!config) {
		ERROR("unknown key %s", key);
		goto out;
	}
	ret = config->set(key, value, lxc_conf, NULL);

out:
	free(copy);
	return ret;
}

static void lxc_remove_nic(struct lxc_list *it)
{
	struct lxc_netdev *netdev = it->elem;
	struct lxc_list *it2,*next;

	lxc_list_del(it);

	free(netdev->link);
	free(netdev->name);
	if (netdev->type == LXC_NET_VETH)
		free(netdev->priv.veth_attr.pair);
	free(netdev->upscript);
	free(netdev->downscript);
	free(netdev->hwaddr);
	free(netdev->mtu);
	free(netdev->ipv4_gateway);
	free(netdev->ipv6_gateway);
	lxc_list_for_each_safe(it2, &netdev->ipv4, next) {
		lxc_list_del(it2);
		free(it2->elem);
		free(it2);
	}
	lxc_list_for_each_safe(it2, &netdev->ipv6, next) {
		lxc_list_del(it2);
		free(it2->elem);
		free(it2);
	}
	free(netdev);
	free(it);
}

static int lxc_clear_config_network(struct lxc_conf *c)
{
	struct lxc_list *it,*next;
	lxc_list_for_each_safe(it, &c->network, next) {
		lxc_remove_nic(it);
	}
	return 0;
}

int set_config_network_legacy(const char *key, const char *value,
		       struct lxc_conf *lxc_conf, void *data)
{
	if (!lxc_config_value_empty(value)) {
		ERROR("lxc.network must not have a value");
		return -1;
	}

	return lxc_clear_config_network(lxc_conf);
}

int set_config_network_legacy_type(const char *key, const char *value,
				   struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_list *network = &lxc_conf->network;
	struct lxc_netdev *netdev, *prevnetdev;
	struct lxc_list *list;

	if (lxc_config_value_empty(value))
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

	/* We maintain a negative count for legacy networks. */
	netdev->idx = -1;
	if (!lxc_list_empty(network)) {
		prevnetdev = lxc_list_last_elem(network);
		netdev->idx = prevnetdev->idx;
		if (netdev->idx == INT_MIN) {
			ERROR("number of requested networks would underflow "
			      "counter");
			free(netdev);
			free(list);
			return -1;
		}
		netdev->idx--;
	}

	lxc_list_add_tail(network, list);

	if (!strcmp(value, "veth"))
		netdev->type = LXC_NET_VETH;
	else if (!strcmp(value, "macvlan")) {
		netdev->type = LXC_NET_MACVLAN;
		lxc_macvlan_mode_to_flag(&netdev->priv.macvlan_attr.mode, "private");
	} else if (!strcmp(value, "vlan"))
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

/*
 * If you have p="lxc.network.0.link", pass it p+12
 * to get back '0' (the index of the nic).
 */
static int get_network_netdev_idx(const char *key)
{
	int ret, idx;

	if (*key < '0' || *key > '9')
		return EINVAL;

	ret = sscanf(key, "%d", &idx);
	if (ret != 1)
		return EINVAL;

	/* Since we've implemented the new network parser legacy networks are
	 * recorded using a negative index starting from -1. To preserve the old
	 * behavior we need this function to return the appropriate negative
	 * index.
	 */
	return -(++idx);
}

/*
 * If you have p="lxc.network.0", pass this p+12 and it will return
 * the netdev of the first configured nic.
 */
static struct lxc_netdev *get_netdev_from_key(const char *key,
					      struct lxc_list *network)
{
	int idx;
	struct lxc_list *it;
	struct lxc_netdev *netdev = NULL;

	idx = get_network_netdev_idx(key);
	if (idx == EINVAL)
		return NULL;

	lxc_list_for_each(it, network) {
		netdev = it->elem;
		if (idx == netdev->idx)
			return netdev;
	}

	return NULL;
}

int lxc_list_nicconfigs_legacy(struct lxc_conf *c, const char *key, char *retv,
			       int inlen)
{
	struct lxc_netdev *netdev;
	int len;
	int fulllen = 0;

	netdev = get_netdev_from_key(key + 12, &c->network);
	if (!netdev)
		return -1;

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	strprint(retv, inlen, "type\n");
	strprint(retv, inlen, "script.up\n");
	strprint(retv, inlen, "script.down\n");
	if (netdev->type != LXC_NET_EMPTY) {
		strprint(retv, inlen, "flags\n");
		strprint(retv, inlen, "link\n");
		strprint(retv, inlen, "name\n");
		strprint(retv, inlen, "hwaddr\n");
		strprint(retv, inlen, "mtu\n");
		strprint(retv, inlen, "ipv6\n");
		strprint(retv, inlen, "ipv6.gateway\n");
		strprint(retv, inlen, "ipv4\n");
		strprint(retv, inlen, "ipv4.gateway\n");
	}

	switch (netdev->type) {
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
		ERROR("network is not created for '%s' = '%s' option", key,
		      value);
		return NULL;
	}

	if (get_network_netdev_idx(key + 12) == EINVAL)
		netdev = lxc_list_last_elem(network);
	else
		netdev = get_netdev_from_key(key + 12, network);

	if (!netdev) {
		ERROR("no network device defined for '%s' = '%s' option", key,
		      value);
		return NULL;
	}

	return netdev;
}

int set_config_network_legacy_flags(const char *key, const char *value,
				    struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_netdev *netdev;

	netdev = network_netdev(key, value, &lxc_conf->network);
	if (!netdev)
		return -1;

	netdev->flags |= IFF_UP;

	return 0;
}

static int create_matched_ifnames(const char *value, struct lxc_conf *lxc_conf,
			   struct lxc_netdev *netdev)
{
	struct ifaddrs *ifaddr, *ifa;
	int n;
	int ret = 0;
	const char *type_key = "lxc.network.type";
	const char *link_key = "lxc.network.link";
	const char *tmpvalue = "phys";

	if (getifaddrs(&ifaddr) == -1) {
		SYSERROR("Get network interfaces failed");
		return -1;
	}

	for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
		if (!ifa->ifa_addr)
			continue;
		if (ifa->ifa_addr->sa_family != AF_PACKET)
			continue;

		if (!strncmp(value, ifa->ifa_name, strlen(value) - 1)) {
			ret = set_config_network_legacy_type(type_key, tmpvalue,
							     lxc_conf, netdev);
			if (!ret) {
				ret = set_config_network_legacy_link(
				    link_key, ifa->ifa_name, lxc_conf, netdev);
				if (ret) {
					ERROR("failed to create matched ifnames");
					break;
				}
			} else {
				ERROR("failed to create matched ifnames");
				break;
			}
		}
	}

	freeifaddrs(ifaddr);
	ifaddr = NULL;

	return ret;
}

int set_config_network_legacy_link(const char *key, const char *value,
				   struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_netdev *netdev;
	struct lxc_list *it;
	int ret = 0;

	netdev = network_netdev(key, value, &lxc_conf->network);
	if (!netdev)
		return -1;

	if (value[strlen(value) - 1] == '+' && netdev->type == LXC_NET_PHYS) {
		/* Get the last network list and remove it. */
		it = lxc_conf->network.prev;
		if (((struct lxc_netdev *)(it->elem))->type != LXC_NET_PHYS) {
			ERROR("lxc config cannot support string pattern "
			      "matching for this link type");
			return -1;
		}

		lxc_list_del(it);
		free(it);
		ret = create_matched_ifnames(value, lxc_conf, NULL);
	} else {
		ret = network_ifname(&netdev->link, value);
	}

	return ret;
}

int set_config_network_legacy_name(const char *key, const char *value,
				   struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_netdev *netdev;

	netdev = network_netdev(key, value, &lxc_conf->network);
	if (!netdev)
		return -1;

	return network_ifname(&netdev->name, value);
}

int set_config_network_legacy_veth_pair(const char *key, const char *value,
					struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_netdev *netdev;

	netdev = network_netdev(key, value, &lxc_conf->network);
	if (!netdev)
		return -1;

	if (netdev->type != LXC_NET_VETH) {
		ERROR("Invalid veth pair for a non-veth netdev");
		return -1;
	}

	return network_ifname(&netdev->priv.veth_attr.pair, value);
}

int set_config_network_legacy_macvlan_mode(const char *key, const char *value,
					   struct lxc_conf *lxc_conf,
					   void *data)
{
	struct lxc_netdev *netdev;

	netdev = network_netdev(key, value, &lxc_conf->network);
	if (!netdev)
		return -1;

	if (netdev->type != LXC_NET_MACVLAN) {
		ERROR("Invalid macvlan.mode for a non-macvlan netdev");
		return -1;
	}

	return lxc_macvlan_mode_to_flag(&netdev->priv.macvlan_attr.mode, value);
}

int set_config_network_legacy_hwaddr(const char *key, const char *value,
				     struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_netdev *netdev;
	char *new_value;

	new_value = strdup(value);
	if (!new_value) {
		SYSERROR("failed to strdup \"%s\"", value);
		return -1;
	}
	rand_complete_hwaddr(new_value);

	netdev = network_netdev(key, new_value, &lxc_conf->network);
	if (!netdev) {
		free(new_value);
		return -1;
	};

	if (lxc_config_value_empty(new_value)) {
		free(new_value);
		netdev->hwaddr = NULL;
		return 0;
	}

	netdev->hwaddr = new_value;
	return 0;
}

int set_config_network_legacy_vlan_id(const char *key, const char *value,
				      struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_netdev *netdev;

	netdev = network_netdev(key, value, &lxc_conf->network);
	if (!netdev)
		return -1;

	if (netdev->type != LXC_NET_VLAN) {
		ERROR("Invalid vlan.id for a non-macvlan netdev");
		return -1;
	}

	if (get_u16(&netdev->priv.vlan_attr.vid, value, 0))
		return -1;

	return 0;
}

int set_config_network_legacy_mtu(const char *key, const char *value,
				  struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_netdev *netdev;

	netdev = network_netdev(key, value, &lxc_conf->network);
	if (!netdev)
		return -1;

	return set_config_string_item(&netdev->mtu, value);
}

int set_config_network_legacy_ipv4(const char *key, const char *value,
				   struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_netdev *netdev;
	struct lxc_inetdev *inetdev;
	struct lxc_list *list;
	char *cursor, *slash;
	char *addr = NULL, *bcast = NULL, *prefix = NULL;

	if (lxc_config_value_empty(value))
		return clr_config_network_legacy_item(key, lxc_conf, NULL);

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

	/* No prefix specified, determine it from the network class. */
	if (prefix) {
		if (lxc_safe_uint(prefix, &inetdev->prefix) < 0)
			return -1;
	} else {
		inetdev->prefix = config_ip_prefix(&inetdev->addr);
	}

	/* If no broadcast address, let compute one from the
	 * prefix and address.
	 */
	if (!bcast) {
		inetdev->bcast.s_addr = inetdev->addr.s_addr;
		inetdev->bcast.s_addr |=
		    htonl(INADDR_BROADCAST >> inetdev->prefix);
	}

	lxc_list_add_tail(&netdev->ipv4, list);

	free(addr);
	return 0;
}

int set_config_network_legacy_ipv4_gateway(const char *key, const char *value,
					   struct lxc_conf *lxc_conf,
					   void *data)
{
	struct lxc_netdev *netdev;

	netdev = network_netdev(key, value, &lxc_conf->network);
	if (!netdev)
		return -1;

	free(netdev->ipv4_gateway);

	if (lxc_config_value_empty(value)) {
		netdev->ipv4_gateway = NULL;
	} else if (!strcmp(value, "auto")) {
		netdev->ipv4_gateway = NULL;
		netdev->ipv4_gateway_auto = true;
	} else {
		struct in_addr *gw;

		gw = malloc(sizeof(*gw));
		if (!gw) {
			SYSERROR("failed to allocate ipv4 gateway address");
			return -1;
		}

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

int set_config_network_legacy_ipv6(const char *key, const char *value,
				   struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_netdev *netdev;
	struct lxc_inet6dev *inet6dev;
	struct lxc_list *list;
	char *slash, *valdup, *netmask;

	if (lxc_config_value_empty(value))
		return clr_config_network_legacy_item(key, lxc_conf, NULL);

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
		if (lxc_safe_uint(netmask, &inet6dev->prefix) < 0)
			return -1;
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

int set_config_network_legacy_ipv6_gateway(const char *key, const char *value,
					   struct lxc_conf *lxc_conf,
					   void *data)
{
	struct lxc_netdev *netdev;

	netdev = network_netdev(key, value, &lxc_conf->network);
	if (!netdev)
		return -1;

	free(netdev->ipv6_gateway);

	if (lxc_config_value_empty(value)) {
		netdev->ipv6_gateway = NULL;
	} else if (!strcmp(value, "auto")) {
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

int set_config_network_legacy_script_up(const char *key, const char *value,
					struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_netdev *netdev;

	netdev = network_netdev(key, value, &lxc_conf->network);
	if (!netdev)
		return -1;

	return set_config_string_item(&netdev->upscript, value);
}

int set_config_network_legacy_script_down(const char *key, const char *value,
					  struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_netdev *netdev;

	netdev = network_netdev(key, value, &lxc_conf->network);
	if (!netdev)
		return -1;

	return set_config_string_item(&netdev->downscript, value);
}

int get_config_network_legacy(const char *key, char *retv, int inlen,
			      struct lxc_conf *c, void *data)
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

/*
 * lxc.network.0.XXX, where XXX can be: name, type, link, flags, type,
 * macvlan.mode, veth.pair, vlan, ipv4, ipv6, script.up, hwaddr, mtu,
 * ipv4.gateway, ipv6.gateway.  ipvX.gateway can return 'auto' instead
 * of an address.  ipv4 and ipv6 return lists (newline-separated).
 * things like veth.pair return '' if invalid (i.e. if called for vlan
 * type).
 */
int get_config_network_legacy_item(const char *key, char *retv, int inlen,
				   struct lxc_conf *c, void *data)
{
	char *p1;
	int len, fulllen = 0;
	struct lxc_netdev *netdev;

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	if (!strncmp(key, "lxc.network.", 12))
		key += 12;
	else
		return -1;

	p1 = strchr(key, '.');
	if (!p1 || *(p1 + 1) == '\0')
		return -1;
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
			case MACVLAN_MODE_PRIVATE:
				mode = "private";
				break;
			case MACVLAN_MODE_VEPA:
				mode = "vepa";
				break;
			case MACVLAN_MODE_BRIDGE:
				mode = "bridge";
				break;
			case MACVLAN_MODE_PASSTHRU:
				mode = "passthru";
				break;
			default:
				mode = "(invalid)";
				break;
			}
			strprint(retv, inlen, "%s", mode);
		}
	} else if (strcmp(p1, "veth.pair") == 0) {
		if (netdev->type == LXC_NET_VETH) {
			strprint(retv, inlen, "%s",
				 netdev->priv.veth_attr.pair
				     ? netdev->priv.veth_attr.pair
				     : netdev->priv.veth_attr.veth1);
		}
	} else if (strcmp(p1, "vlan") == 0) {
		if (netdev->type == LXC_NET_VLAN) {
			strprint(retv, inlen, "%d", netdev->priv.vlan_attr.vid);
		}
	} else if (strcmp(p1, "ipv4.gateway") == 0) {
		if (netdev->ipv4_gateway_auto) {
			strprint(retv, inlen, "auto");
		} else if (netdev->ipv4_gateway) {
			char buf[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, netdev->ipv4_gateway, buf,
				  sizeof(buf));
			strprint(retv, inlen, "%s", buf);
		}
	} else if (strcmp(p1, "ipv4") == 0) {
		struct lxc_list *it2;
		lxc_list_for_each(it2, &netdev->ipv4) {
			struct lxc_inetdev *i = it2->elem;
			char buf[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &i->addr, buf, sizeof(buf));
			strprint(retv, inlen, "%s/%d\n", buf, i->prefix);
		}
	} else if (strcmp(p1, "ipv6.gateway") == 0) {
		if (netdev->ipv6_gateway_auto) {
			strprint(retv, inlen, "auto");
		} else if (netdev->ipv6_gateway) {
			char buf[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, netdev->ipv6_gateway, buf,
				  sizeof(buf));
			strprint(retv, inlen, "%s", buf);
		}
	} else if (strcmp(p1, "ipv6") == 0) {
		struct lxc_list *it2;
		lxc_list_for_each(it2, &netdev->ipv6) {
			struct lxc_inet6dev *i = it2->elem;
			char buf[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, &i->addr, buf, sizeof(buf));
			strprint(retv, inlen, "%s/%d\n", buf, i->prefix);
		}
	}
	return fulllen;
}

/* we get passed in something like '0', '0.ipv4' or '1.ipv6' */
static int lxc_clear_nic(struct lxc_conf *c, const char *key)
{
	char *p1;
	int idx;
	struct lxc_list *it = NULL;
	struct lxc_netdev *netdev = NULL;

	if (lxc_list_empty(&c->network)) {
		ERROR("network is not created for %s", key);
		return -1;
	}

	if ((idx = get_network_netdev_idx(key)) == EINVAL)
		netdev = lxc_list_last_elem(&c->network);
	else {
		lxc_list_for_each(it, &c->network) {
			netdev = it->elem;
			if (idx == netdev->idx)
				break;
			netdev = NULL;
		}
	}
	if (!netdev)
		return -1;

	p1 = strchr(key, '.');
	if (!p1 || *(p1+1) == '\0')
		p1 = NULL;

	if (!p1 && it) {
		lxc_remove_nic(it);
	} else if (strcmp(p1, ".ipv4") == 0) {
		struct lxc_list *it2,*next;
		lxc_list_for_each_safe(it2, &netdev->ipv4, next) {
			lxc_list_del(it2);
			free(it2->elem);
			free(it2);
		}
	} else if (strcmp(p1, ".ipv6") == 0) {
		struct lxc_list *it2,*next;
		lxc_list_for_each_safe(it2, &netdev->ipv6, next) {
			lxc_list_del(it2);
			free(it2->elem);
			free(it2);
		}
	}
	else return -1;

	return 0;
}

inline int clr_config_network_legacy_item(const char *key, struct lxc_conf *c,
					  void *data)
{
	return lxc_clear_nic(c, key + 12);
}

inline int clr_config_network_legacy(const char *key, struct lxc_conf *c, void *data)
{
	return lxc_clear_config_network(c);
}

inline int clr_config_lsm_aa_profile(const char *key, struct lxc_conf *c,
				     void *data)
{
	free(c->lsm_aa_profile);
	c->lsm_aa_profile = NULL;
	return 0;
}

inline int clr_config_lsm_aa_incomplete(const char *key, struct lxc_conf *c,
					void *data)
{
	c->lsm_aa_allow_incomplete = 0;
	return 0;
}

int get_config_lsm_aa_profile(const char *key, char *retv, int inlen,
			      struct lxc_conf *c, void *data)
{
	return lxc_get_conf_str(retv, inlen, c->lsm_aa_profile);
}

int get_config_lsm_aa_incomplete(const char *key, char *retv, int inlen,
				 struct lxc_conf *c, void *data)
{
	return lxc_get_conf_int(c, retv, inlen,
				c->lsm_aa_allow_incomplete);
}

int set_config_lsm_aa_profile(const char *key, const char *value,
			      struct lxc_conf *lxc_conf, void *data)
{
	return set_config_string_item(&lxc_conf->lsm_aa_profile, value);
}

int set_config_lsm_aa_incomplete(const char *key, const char *value,
				 struct lxc_conf *lxc_conf, void *data)
{
	/* Set config value to default. */
	if (lxc_config_value_empty(value)) {
		lxc_conf->lsm_aa_allow_incomplete = 0;
		return 0;
	}

	/* Parse new config value. */
	if (lxc_safe_uint(value, &lxc_conf->lsm_aa_allow_incomplete) < 0)
		return -1;

	if (lxc_conf->lsm_aa_allow_incomplete > 1) {
		ERROR("Wrong value for lxc.lsm_aa_allow_incomplete. Can only "
		      "be set to 0 or 1");
		return -1;
	}

	return 0;
}

int set_config_lsm_se_context(const char *key, const char *value,
			      struct lxc_conf *lxc_conf, void *data)
{
	return set_config_string_item(&lxc_conf->lsm_se_context, value);
}

int get_config_lsm_se_context(const char *key, char *retv, int inlen,
			      struct lxc_conf *c, void *data)
{
	return lxc_get_conf_str(retv, inlen, c->lsm_se_context);
}

inline int clr_config_lsm_se_context(const char *key, struct lxc_conf *c,
				     void *data)
{
	free(c->lsm_se_context);
	c->lsm_se_context = NULL;
	return 0;
}

extern int set_config_limit(const char *key, const char *value,
			    struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_list *iter;
	struct rlimit limit;
	unsigned long limit_value;
	struct lxc_list *limlist = NULL;
	struct lxc_limit *limelem = NULL;

	if (lxc_config_value_empty(value))
		return lxc_clear_limits(lxc_conf, key);

	if (strncmp(key, "lxc.limit.", sizeof("lxc.limit.") - 1) != 0)
		return -1;

	key += sizeof("lxc.limit.") - 1;

	/* soft limit comes first in the value */
	if (!parse_limit_value(&value, &limit_value))
		return -1;
	limit.rlim_cur = limit_value;

	/* skip spaces and a colon */
	while (isspace(*value))
		++value;

	if (*value == ':')
		++value;
	else if (*value) /* any other character is an error here */
		return -1;

	while (isspace(*value))
		++value;

	/* optional hard limit */
	if (*value) {
		if (!parse_limit_value(&value, &limit_value))
			return -1;
		limit.rlim_max = limit_value;

		/* check for trailing garbage */
		while (isspace(*value))
			++value;

		if (*value)
			return -1;
	} else {
		/* a single value sets both hard and soft limit */
		limit.rlim_max = limit.rlim_cur;
	}

	/* find existing list element */
	lxc_list_for_each(iter, &lxc_conf->limits)
	{
		limelem = iter->elem;
		if (!strcmp(key, limelem->resource)) {
			limelem->limit = limit;
			return 0;
		}
	}

	/* allocate list element */
	limlist = malloc(sizeof(*limlist));
	if (!limlist)
		goto out;

	limelem = malloc(sizeof(*limelem));
	if (!limelem)
		goto out;
	memset(limelem, 0, sizeof(*limelem));

	limelem->resource = strdup(key);
	if (!limelem->resource)
		goto out;
	limelem->limit = limit;

	limlist->elem = limelem;

	lxc_list_add_tail(&lxc_conf->limits, limlist);

	return 0;

out:
	free(limlist);
	if (limelem) {
		free(limelem->resource);
		free(limelem);
	}
	return -1;
}

/*
 * If you ask for a specific value, i.e. lxc.limit.nofile, then just the value
 * will be printed. If you ask for 'lxc.limit', then all limit entries will be
 * printed, in 'lxc.limit.resource = value' format.
 */
extern int get_config_limit(const char *key, char *retv, int inlen,
			    struct lxc_conf *c, void *data)
{
	int fulllen = 0, len;
	bool get_all = false;
	struct lxc_list *it;

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	if (!strcmp(key, "lxc.limit"))
		get_all = true;
	else if (strncmp(key, "lxc.limit.", 10) == 0)
		key += 10;
	else
		return -1;

	lxc_list_for_each(it, &c->limits) {
		char buf[LXC_NUMSTRLEN64 * 2 + 2]; /* 2 colon separated 64 bit
						      integers or the word
						      'unlimited' */
		int partlen;
		struct lxc_limit *lim = it->elem;

		if (lim->limit.rlim_cur == RLIM_INFINITY) {
			memcpy(buf, "unlimited", sizeof("unlimited"));
			partlen = sizeof("unlimited") - 1;
		} else {
			partlen = sprintf(buf, "%" PRIu64,
					  (uint64_t)lim->limit.rlim_cur);
		}
		if (lim->limit.rlim_cur != lim->limit.rlim_max) {
			if (lim->limit.rlim_max == RLIM_INFINITY) {
				memcpy(buf + partlen, ":unlimited",
				       sizeof(":unlimited"));
			} else {
				sprintf(buf + partlen, ":%" PRIu64,
					(uint64_t)lim->limit.rlim_max);
			}
		}

		if (get_all) {
			strprint(retv, inlen, "lxc.limit.%s = %s\n",
				 lim->resource, buf);
		} else if (strcmp(lim->resource, key) == 0) {
			strprint(retv, inlen, "%s", buf);
		}
	}

	return fulllen;
}

extern int clr_config_limit(const char *key, struct lxc_conf *c,
				   void *data)
{
	return lxc_clear_limits(c, key);
}

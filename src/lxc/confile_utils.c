/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <arpa/inet.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "conf.h"
#include "config.h"
#include "confile.h"
#include "confile_utils.h"
#include "error.h"
#include "list.h"
#include "lxc.h"
#include "log.h"
#include "lxccontainer.h"
#include "macro.h"
#include "memory_utils.h"
#include "network.h"
#include "parse.h"
#include "utils.h"

#ifndef HAVE_STRLCPY
#include "include/strlcpy.h"
#endif

lxc_log_define(confile_utils, lxc);

int parse_idmaps(const char *idmap, char *type, unsigned long *nsid,
		 unsigned long *hostid, unsigned long *range)
{
	__do_free char *dup = NULL;
	int ret = -1;
	unsigned long tmp_hostid, tmp_nsid, tmp_range;
	char tmp_type;
	char *window, *slide;

	/* Duplicate string. */
	dup = strdup(idmap);
	if (!dup)
		return ret_errno(ENOMEM);

	/* A prototypical idmap entry would be: "u 1000 1000000 65536" */

	/* align */
	slide = window = dup;
	/* skip whitespace */
	slide += strspn(slide, " \t\r");
	if (slide != window && *slide == '\0')
		return ret_errno(EINVAL);

	/* Validate type. */
	if (*slide != 'u' && *slide != 'g')
		return log_error_errno(-EINVAL, EINVAL, "Invalid id mapping type: %c", *slide);

	/* Assign type. */
	tmp_type = *slide;

	/* move beyond type */
	slide++;
	/* align */
	window = slide;
	/* Validate that only whitespace follows. */
	slide += strspn(slide, " \t\r");
	/* There must be whitespace. */
	if (slide == window)
		return ret_errno(EINVAL);

	/* Mark beginning of nsid. */
	window = slide;
	/* Validate that non-whitespace follows. */
	slide += strcspn(slide, " \t\r");
	/* There must be non-whitespace. */
	if (slide == window || *slide == '\0')
		return ret_errno(EINVAL);
	/* Mark end of nsid. */
	*slide = '\0';

	/* Parse nsid. */
	ret = lxc_safe_ulong(window, &tmp_nsid);
	if (ret < 0)
		return log_error_errno(ret, errno, "Failed to parse nsid: %s", window);

	/* Move beyond \0. */
	slide++;
	/* Validate that only whitespace follows. */
	slide += strspn(slide, " \t\r");
	/* If there was only one whitespace then we whiped it with our \0 above.
	 * So only ensure that we're not at the end of the string.
	 */
	if (*slide == '\0')
		return ret_errno(EINVAL);

	/* Mark beginning of hostid. */
	window = slide;
	/* Validate that non-whitespace follows. */
	slide += strcspn(slide, " \t\r");
	/* There must be non-whitespace. */
	if (slide == window || *slide == '\0')
		return ret_errno(EINVAL);
	/* Mark end of nsid. */
	*slide = '\0';

	/* Parse hostid. */
	ret = lxc_safe_ulong(window, &tmp_hostid);
	if (ret < 0)
		return log_error_errno(ret, errno, "Failed to parse hostid: %s", window);

	/* Move beyond \0. */
	slide++;
	/* Validate that only whitespace follows. */
	slide += strspn(slide, " \t\r");
	/* If there was only one whitespace then we whiped it with our \0 above.
	 * So only ensure that we're not at the end of the string.
	 */
	if (*slide == '\0')
		return ret_errno(EINVAL);

	/* Mark beginning of range. */
	window = slide;
	/* Validate that non-whitespace follows. */
	slide += strcspn(slide, " \t\r");
	/* There must be non-whitespace. */
	if (slide == window)
		return ret_errno(EINVAL);

	/* The range is the last valid entry we expect. So make sure that there
	 * is no trailing garbage and if there is, error out.
	 */
	if (*(slide + strspn(slide, " \t\r\n")) != '\0')
		return ret_errno(EINVAL);

	/* Mark end of range. */
	*slide = '\0';

	/* Parse range. */
	ret = lxc_safe_ulong(window, &tmp_range);
	if (ret < 0)
		return log_error_errno(ret, errno, "Failed to parse id mapping range: %s", window);

	*type	= tmp_type;
	*nsid	= tmp_nsid;
	*hostid = tmp_hostid;
	*range	= tmp_range;

	/* Yay, we survived. */
	return 0;
}

bool lxc_config_value_empty(const char *value)
{
	if (value && strlen(value) > 0)
		return false;

	return true;
}

struct lxc_netdev *lxc_network_add(struct lxc_list *networks, int idx, bool tail)
{
	__do_free struct lxc_list *newlist = NULL;
	__do_free struct lxc_netdev *netdev = NULL;

	/* network does not exist */
	netdev = malloc(sizeof(*netdev));
	if (!netdev)
		return ret_set_errno(NULL, ENOMEM);

	memset(netdev, 0, sizeof(*netdev));
	lxc_list_init(&netdev->ipv4);
	lxc_list_init(&netdev->ipv6);

	/* give network a unique index */
	netdev->idx = idx;

	/* prepare new list */
	newlist = malloc(sizeof(*newlist));
	if (!newlist)
		return ret_set_errno(NULL, ENOMEM);

	lxc_list_init(newlist);
	newlist->elem = netdev;

	if (tail)
		lxc_list_add_tail(networks, newlist);
	else
		lxc_list_add(networks, newlist);
	move_ptr(newlist);

	return move_ptr(netdev);
}

/* Takes care of finding the correct netdev struct in the networks list or
 * allocates a new one if it couldn't be found.
 */
struct lxc_netdev *lxc_get_netdev_by_idx(struct lxc_conf *conf,
					 unsigned int idx, bool allocate)
{
	struct lxc_netdev *netdev = NULL;
	struct lxc_list *networks = &conf->network;
	struct lxc_list *insert = networks;

	/* lookup network */
	if (!lxc_list_empty(networks)) {
		lxc_list_for_each(insert, networks) {
			netdev = insert->elem;
			if (netdev->idx == idx)
				return netdev;
			else if (netdev->idx > idx)
				break;
		}
	}

	if (!allocate)
		return ret_set_errno(NULL, EINVAL);

	return lxc_network_add(insert, idx, true);
}

void lxc_log_configured_netdevs(const struct lxc_conf *conf)
{
	struct lxc_netdev *netdev;
	struct lxc_list *it = (struct lxc_list *)&conf->network;;

	if (!lxc_log_trace())
		return;

	if (lxc_list_empty(it)) {
		TRACE("container has no networks configured");
		return;
	}

	lxc_list_for_each(it, &conf->network) {
		struct lxc_list *cur, *next;
		struct lxc_inetdev *inet4dev;
		struct lxc_inet6dev *inet6dev;
		char bufinet4[INET_ADDRSTRLEN], bufinet6[INET6_ADDRSTRLEN];

		netdev = it->elem;

		TRACE("index: %zd", netdev->idx);
		TRACE("ifindex: %d", netdev->ifindex);

		switch (netdev->type) {
		case LXC_NET_VETH:
			TRACE("type: veth");

			if (netdev->priv.veth_attr.pair[0] != '\0')
				TRACE("veth pair: %s",
				      netdev->priv.veth_attr.pair);

			if (netdev->priv.veth_attr.veth1[0] != '\0')
				TRACE("veth1 : %s",
				      netdev->priv.veth_attr.veth1);

			if (netdev->priv.veth_attr.ifindex > 0)
				TRACE("host side ifindex for veth device: %d",
				      netdev->priv.veth_attr.ifindex);
			break;
		case LXC_NET_MACVLAN:
			TRACE("type: macvlan");

			if (netdev->priv.macvlan_attr.mode > 0) {
				char *mode;

				mode = lxc_macvlan_flag_to_mode(
				    netdev->priv.macvlan_attr.mode);
				TRACE("macvlan mode: %s",
				      mode ? mode : "(invalid mode)");
			}
			break;
		case LXC_NET_IPVLAN:
			TRACE("type: ipvlan");

			char *mode;
			mode = lxc_ipvlan_flag_to_mode(netdev->priv.ipvlan_attr.mode);
			TRACE("ipvlan mode: %s", mode ? mode : "(invalid mode)");

			char *isolation;
			isolation = lxc_ipvlan_flag_to_isolation(netdev->priv.ipvlan_attr.isolation);
			TRACE("ipvlan isolation: %s", isolation ? isolation : "(invalid isolation)");
			break;
		case LXC_NET_VLAN:
			TRACE("type: vlan");
			TRACE("vlan id: %d", netdev->priv.vlan_attr.vid);
			break;
		case LXC_NET_PHYS:
			TRACE("type: phys");

			if (netdev->priv.phys_attr.ifindex > 0)
				TRACE("host side ifindex for phys device: %d",
				      netdev->priv.phys_attr.ifindex);
			break;
		case LXC_NET_EMPTY:
			TRACE("type: empty");
			break;
		case LXC_NET_NONE:
			TRACE("type: none");
			break;
		default:
			ERROR("Invalid network type %d", netdev->type);
			return;
		}

		if (netdev->type != LXC_NET_EMPTY) {
			TRACE("flags: %s",
			      netdev->flags == IFF_UP ? "up" : "none");

			if (netdev->link[0] != '\0')
				TRACE("link: %s", netdev->link);

			/* l2proxy only used when link is specified */
			if (netdev->link[0] != '\0')
				TRACE("l2proxy: %s", netdev->l2proxy ? "true" : "false");

			if (netdev->name[0] != '\0')
				TRACE("name: %s", netdev->name);

			if (netdev->hwaddr)
				TRACE("hwaddr: %s", netdev->hwaddr);

			if (netdev->mtu)
				TRACE("mtu: %s", netdev->mtu);

			if (netdev->upscript)
				TRACE("upscript: %s", netdev->upscript);

			if (netdev->downscript)
				TRACE("downscript: %s", netdev->downscript);

			TRACE("ipv4 gateway auto: %s",
			      netdev->ipv4_gateway_auto ? "true" : "false");

			TRACE("ipv4 gateway dev: %s",
			      netdev->ipv4_gateway_dev ? "true" : "false");

			if (netdev->ipv4_gateway) {
				inet_ntop(AF_INET, netdev->ipv4_gateway,
					  bufinet4, sizeof(bufinet4));
				TRACE("ipv4 gateway: %s", bufinet4);
			}

			lxc_list_for_each_safe(cur, &netdev->ipv4, next) {
				inet4dev = cur->elem;
				inet_ntop(AF_INET, &inet4dev->addr, bufinet4,
					  sizeof(bufinet4));
				TRACE("ipv4 addr: %s", bufinet4);
			}

			TRACE("ipv6 gateway auto: %s",
			      netdev->ipv6_gateway_auto ? "true" : "false");

			TRACE("ipv6 gateway dev: %s",
			      netdev->ipv6_gateway_dev ? "true" : "false");

			if (netdev->ipv6_gateway) {
				inet_ntop(AF_INET6, netdev->ipv6_gateway,
					  bufinet6, sizeof(bufinet6));
				TRACE("ipv6 gateway: %s", bufinet6);
			}

			lxc_list_for_each_safe(cur, &netdev->ipv6, next) {
				inet6dev = cur->elem;
				inet_ntop(AF_INET6, &inet6dev->addr, bufinet6,
					  sizeof(bufinet6));
				TRACE("ipv6 addr: %s", bufinet6);
			}

			if (netdev->type == LXC_NET_VETH) {
				lxc_list_for_each_safe(cur, &netdev->priv.veth_attr.ipv4_routes, next) {
					inet4dev = cur->elem;
					if (!inet_ntop(AF_INET, &inet4dev->addr, bufinet4, sizeof(bufinet4))) {
						ERROR("Invalid ipv4 veth route");
						return;
					}

					TRACE("ipv4 veth route: %s/%u", bufinet4, inet4dev->prefix);
				}

				lxc_list_for_each_safe(cur, &netdev->priv.veth_attr.ipv6_routes, next) {
					inet6dev = cur->elem;
					if (!inet_ntop(AF_INET6, &inet6dev->addr, bufinet6, sizeof(bufinet6))) {
						ERROR("Invalid ipv6 veth route");
						return;
					}

					TRACE("ipv6 veth route: %s/%u", bufinet6, inet6dev->prefix);
				}
			}
		}
	}
}

static void lxc_free_netdev(struct lxc_netdev *netdev)
{
	struct lxc_list *cur, *next;

	if (!netdev)
		return;

	free(netdev->upscript);
	free(netdev->downscript);
	free(netdev->hwaddr);
	free(netdev->mtu);

	free(netdev->ipv4_gateway);
	lxc_list_for_each_safe(cur, &netdev->ipv4, next) {
		lxc_list_del(cur);
		free(cur->elem);
		free(cur);
	}

	free(netdev->ipv6_gateway);
	lxc_list_for_each_safe(cur, &netdev->ipv6, next) {
		lxc_list_del(cur);
		free(cur->elem);
		free(cur);
	}

	if (netdev->type == LXC_NET_VETH) {
		lxc_list_for_each_safe(cur, &netdev->priv.veth_attr.ipv4_routes, next) {
			lxc_list_del(cur);
			free(cur->elem);
			free(cur);
		}

		lxc_list_for_each_safe(cur, &netdev->priv.veth_attr.ipv6_routes, next) {
			lxc_list_del(cur);
			free(cur->elem);
			free(cur);
		}
	}

	free(netdev);
}

define_cleanup_function(struct lxc_netdev *, lxc_free_netdev);

bool lxc_remove_nic_by_idx(struct lxc_conf *conf, unsigned int idx)
{
	call_cleaner(lxc_free_netdev) struct lxc_netdev *netdev = NULL;
	struct lxc_list *cur, *next;

	lxc_list_for_each_safe(cur, &conf->network, next) {
		netdev = cur->elem;
		if (netdev->idx != idx)
			continue;

		lxc_list_del(cur);
		free(cur);
		return true;
	}

	return false;
}

void lxc_free_networks(struct lxc_list *networks)
{
	struct lxc_list *cur, *next;

	lxc_list_for_each_safe (cur, networks, next) {
		struct lxc_netdev *netdev = cur->elem;
		netdev = cur->elem;
		lxc_free_netdev(netdev);
		free(cur);
	}

	/* prevent segfaults */
	lxc_list_init(networks);
}

static struct lxc_veth_mode {
	char *name;
	int mode;
} veth_mode[] = {
	{ "bridge", VETH_MODE_BRIDGE },
	{ "router", VETH_MODE_ROUTER },
};

int lxc_veth_mode_to_flag(int *mode, const char *value)
{
	for (size_t i = 0; i < sizeof(veth_mode) / sizeof(veth_mode[0]); i++) {
		if (strcmp(veth_mode[i].name, value) != 0)
			continue;

		*mode = veth_mode[i].mode;
		return 0;
	}

	return ret_errno(EINVAL);
}

char *lxc_veth_flag_to_mode(int mode)
{
	for (size_t i = 0; i < sizeof(veth_mode) / sizeof(veth_mode[0]); i++) {
		if (veth_mode[i].mode != mode)
			continue;

		return veth_mode[i].name;
	}

	return ret_set_errno(NULL, EINVAL);
}

static struct lxc_macvlan_mode {
	char *name;
	int mode;
} macvlan_mode[] = {
	{ "private",  MACVLAN_MODE_PRIVATE  },
	{ "vepa",     MACVLAN_MODE_VEPA     },
	{ "bridge",   MACVLAN_MODE_BRIDGE   },
	{ "passthru", MACVLAN_MODE_PASSTHRU },
};

int lxc_macvlan_mode_to_flag(int *mode, const char *value)
{
	for (size_t i = 0; i < sizeof(macvlan_mode) / sizeof(macvlan_mode[0]); i++) {
		if (strcmp(macvlan_mode[i].name, value))
			continue;

		*mode = macvlan_mode[i].mode;
		return 0;
	}

	return ret_errno(EINVAL);
}

char *lxc_macvlan_flag_to_mode(int mode)
{
	for (size_t i = 0; i < sizeof(macvlan_mode) / sizeof(macvlan_mode[0]); i++) {
		if (macvlan_mode[i].mode != mode)
			continue;

		return macvlan_mode[i].name;
	}

	return ret_set_errno(NULL, EINVAL);
}

static struct lxc_ipvlan_mode {
	char *name;
	int mode;
} ipvlan_mode[] = {
	{ "l3",  IPVLAN_MODE_L3  },
	{ "l3s", IPVLAN_MODE_L3S },
	{ "l2",  IPVLAN_MODE_L2  },
};

int lxc_ipvlan_mode_to_flag(int *mode, const char *value)
{
	for (size_t i = 0; i < sizeof(ipvlan_mode) / sizeof(ipvlan_mode[0]); i++) {
		if (strcmp(ipvlan_mode[i].name, value) != 0)
			continue;

		*mode = ipvlan_mode[i].mode;
		return 0;
	}

	return ret_errno(EINVAL);
}

char *lxc_ipvlan_flag_to_mode(int mode)
{
	for (size_t i = 0; i < sizeof(ipvlan_mode) / sizeof(ipvlan_mode[0]); i++) {
		if (ipvlan_mode[i].mode != mode)
			continue;

		return ipvlan_mode[i].name;
	}

	return ret_set_errno(NULL, EINVAL);
}

static struct lxc_ipvlan_isolation {
	char *name;
	int flag;
} ipvlan_isolation[] = {
	{ "bridge",  IPVLAN_ISOLATION_BRIDGE  },
	{ "private", IPVLAN_ISOLATION_PRIVATE },
	{ "vepa",    IPVLAN_ISOLATION_VEPA    },
};

int lxc_ipvlan_isolation_to_flag(int *flag, const char *value)
{
	for (size_t i = 0; i < sizeof(ipvlan_isolation) / sizeof(ipvlan_isolation[0]); i++) {
		if (strcmp(ipvlan_isolation[i].name, value) != 0)
			continue;

		*flag = ipvlan_isolation[i].flag;
		return 0;
	}

	return ret_errno(EINVAL);
}

char *lxc_ipvlan_flag_to_isolation(int flag)
{
	for (size_t i = 0; i < sizeof(ipvlan_isolation) / sizeof(ipvlan_isolation[0]); i++) {
		if (ipvlan_isolation[i].flag != flag)
			continue;

		return ipvlan_isolation[i].name;
	}

	return ret_set_errno(NULL, EINVAL);
}

int set_config_string_item(char **conf_item, const char *value)
{
	char *new_value;

	if (lxc_config_value_empty(value)) {
		free_disarm(*conf_item);
		return 0;
	}

	new_value = strdup(value);
	if (!new_value)
		return log_error_errno(-ENOMEM, ENOMEM, "Failed to duplicate string \"%s\"", value);

	free_move_ptr(*conf_item, new_value);
	return 0;
}

int set_config_string_item_max(char **conf_item, const char *value, size_t max)
{
	if (strlen(value) >= max)
		return log_error_errno(-ENAMETOOLONG, ENAMETOOLONG, "%s is too long (>= %lu)", value, (unsigned long)max);

	return set_config_string_item(conf_item, value);
}

int set_config_path_item(char **conf_item, const char *value)
{
	return set_config_string_item_max(conf_item, value, PATH_MAX);
}

int set_config_bool_item(bool *conf_item, const char *value, bool empty_conf_action)
{
	int ret;
	unsigned int val = 0;

	if (lxc_config_value_empty(value)) {
		*conf_item = empty_conf_action;
		return 0;
	}

	ret = lxc_safe_uint(value, &val);
	if (ret < 0)
		return ret;

	switch (val) {
	case 0:
		*conf_item = false;
		return 0;
	case 1:
		*conf_item = true;
		return 0;
	}

	return ret_errno(EINVAL);
}

int config_ip_prefix(struct in_addr *addr)
{
	if (IN_CLASSA(addr->s_addr))
		return 32 - IN_CLASSA_NSHIFT;

	if (IN_CLASSB(addr->s_addr))
		return 32 - IN_CLASSB_NSHIFT;

	if (IN_CLASSC(addr->s_addr))
		return 32 - IN_CLASSC_NSHIFT;

	return 0;
}

int network_ifname(char *valuep, const char *value, size_t size)
{
	size_t retlen;

	if (!valuep || !value)
		return ret_errno(EINVAL);

	retlen = strlcpy(valuep, value, size);
	if (retlen >= size)
		ERROR("Network device name \"%s\" is too long (>= %zu)", value, size);

	return 0;
}

bool lxc_config_net_is_hwaddr(const char *line)
{
	unsigned index;
	char tmp[7];

	if (strncmp(line, "lxc.net", 7) != 0)
		return false;

	if (strncmp(line, "lxc.net.hwaddr", 14) == 0)
		return true;

	if (strncmp(line, "lxc.network.hwaddr", 18) == 0)
		return true;

	if (sscanf(line, "lxc.net.%u.%6s", &index, tmp) == 2 ||
	    sscanf(line, "lxc.network.%u.%6s", &index, tmp) == 2)
		return strncmp(tmp, "hwaddr", 6) == 0;

	return false;
}

void rand_complete_hwaddr(char *hwaddr)
{
	const char hex[] = "0123456789abcdef";
	char *curs = hwaddr;
#ifdef HAVE_RAND_R
	unsigned int seed;

	seed = randseed(false);
#else

	(void)randseed(true);
#endif

	while (*curs != '\0' && *curs != '\n') {
		if (*curs == 'x' || *curs == 'X') {
			if (curs - hwaddr == 1) {
				/* ensure address is unicast */
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
}

bool new_hwaddr(char *hwaddr)
{
	int ret;
#ifdef HAVE_RAND_R
	unsigned int seed;

	seed = randseed(false);

	ret = snprintf(hwaddr, 18, "00:16:3e:%02x:%02x:%02x", rand_r(&seed) % 255,
		       rand_r(&seed) % 255, rand_r(&seed) % 255);
#else

	(void)randseed(true);

	ret = snprintf(hwaddr, 18, "00:16:3e:%02x:%02x:%02x", rand() % 255,
		       rand() % 255, rand() % 255);
#endif
	if (ret < 0 || ret >= 18) {
		return log_error_errno(false, EIO, "Failed to call snprintf()");
	}

	return true;
}

int lxc_get_conf_str(char *retv, int inlen, const char *value)
{
	size_t value_len;

	if (!value)
		return 0;

	value_len = strlen(value);
	if (retv && inlen >= value_len + 1)
		memcpy(retv, value, value_len + 1);

	return value_len;
}

int lxc_get_conf_bool(struct lxc_conf *c, char *retv, int inlen, bool v)
{
	int len;
	int fulllen = 0;

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	strprint(retv, inlen, "%d", v);

	return fulllen;
}

int lxc_get_conf_int(struct lxc_conf *c, char *retv, int inlen, int v)
{
	int len;
	int fulllen = 0;

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	strprint(retv, inlen, "%d", v);

	return fulllen;
}

int lxc_get_conf_size_t(struct lxc_conf *c, char *retv, int inlen, size_t v)
{
	int len;
	int fulllen = 0;

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	strprint(retv, inlen, "%zu", v);

	return fulllen;
}

int lxc_get_conf_uint64(struct lxc_conf *c, char *retv, int inlen, uint64_t v)
{
	int len;
	int fulllen = 0;

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	strprint(retv, inlen, "%"PRIu64, v);

	return fulllen;
}

static int lxc_container_name_to_pid(const char *lxcname_or_pid,
				     const char *lxcpath)
{
	int ret;
	signed long int pid;
	char *err = NULL;

	pid = strtol(lxcname_or_pid, &err, 10);
	if (*err != '\0' || pid < 1) {
		__put_lxc_container struct lxc_container *c = NULL;

		c = lxc_container_new(lxcname_or_pid, lxcpath);
		if (!c)
			return log_error_errno(-EINVAL, EINVAL, "\"%s\" is not a valid pid nor a container name", lxcname_or_pid);

		if (!c->may_control(c))
			return log_error_errno(-EPERM, EPERM, "Insufficient privileges to control container \"%s\"", c->name);

		pid = c->init_pid(c);
		if (pid < 1)
			return log_error_errno(-EINVAL, EINVAL, "Container \"%s\" is not running", c->name);

	}

	ret = kill(pid, 0);
	if (ret < 0)
		return log_error_errno(-errno, errno, "Failed to send signal to pid %d", (int)pid);

	return pid;
}

int lxc_inherit_namespace(const char *nsfd_path, const char *lxcpath,
			  const char *namespace)
{
	__do_free char *dup = NULL;
	int fd, pid;
	char *lastslash;

	if (nsfd_path[0] == '/') {
		return open(nsfd_path, O_RDONLY | O_CLOEXEC);
	}

	lastslash = strrchr(nsfd_path, '/');
	if (lastslash) {
		dup = strdup(nsfd_path);
		if (!dup)
			return ret_errno(ENOMEM);

		dup[lastslash - nsfd_path] = '\0';
		lxcpath = lastslash + 1;
		nsfd_path = lastslash + 1;
	}

	pid = lxc_container_name_to_pid(nsfd_path, lxcpath);
	if (pid < 0)
		return pid;

	fd = lxc_preserve_ns(pid, namespace);
	if (fd < 0)
		return -errno;

	return fd;
}

struct signame {
	int num;
	const char *name;
};

static const struct signame signames[] = {
	{ SIGHUP,    "HUP"    },
	{ SIGINT,    "INT"    },
	{ SIGQUIT,   "QUIT"   },
	{ SIGILL,    "ILL"    },
	{ SIGABRT,   "ABRT"   },
	{ SIGFPE,    "FPE"    },
	{ SIGKILL,   "KILL"   },
	{ SIGSEGV,   "SEGV"   },
	{ SIGPIPE,   "PIPE"   },
	{ SIGALRM,   "ALRM"   },
	{ SIGTERM,   "TERM"   },
	{ SIGUSR1,   "USR1"   },
	{ SIGUSR2,   "USR2"   },
	{ SIGCHLD,   "CHLD"   },
	{ SIGCONT,   "CONT"   },
	{ SIGSTOP,   "STOP"   },
	{ SIGTSTP,   "TSTP"   },
	{ SIGTTIN,   "TTIN"   },
	{ SIGTTOU,   "TTOU"   },
#ifdef SIGTRAP
	{ SIGTRAP,   "TRAP"   },
#endif
#ifdef SIGIOT
	{ SIGIOT,    "IOT"    },
#endif
#ifdef SIGEMT
	{ SIGEMT,    "EMT"    },
#endif
#ifdef SIGBUS
	{ SIGBUS,    "BUS"    },
#endif
#ifdef SIGSTKFLT
	{ SIGSTKFLT, "STKFLT" },
#endif
#ifdef SIGCLD
	{ SIGCLD,    "CLD"    },
#endif
#ifdef SIGURG
	{ SIGURG,    "URG"    },
#endif
#ifdef SIGXCPU
	{ SIGXCPU,   "XCPU"   },
#endif
#ifdef SIGXFSZ
	{ SIGXFSZ,   "XFSZ"   },
#endif
#ifdef SIGVTALRM
	{ SIGVTALRM, "VTALRM" },
#endif
#ifdef SIGPROF
	{ SIGPROF,   "PROF"   },
#endif
#ifdef SIGWINCH
	{ SIGWINCH,  "WINCH"  },
#endif
#ifdef SIGIO
	{ SIGIO,     "IO"     },
#endif
#ifdef SIGPOLL
	{ SIGPOLL,   "POLL"   },
#endif
#ifdef SIGINFO
	{ SIGINFO,   "INFO"   },
#endif
#ifdef SIGLOST
	{ SIGLOST,   "LOST"   },
#endif
#ifdef SIGPWR
	{ SIGPWR,    "PWR"    },
#endif
#ifdef SIGUNUSED
	{ SIGUNUSED, "UNUSED" },
#endif
#ifdef SIGSYS
	{ SIGSYS,    "SYS"    },
#endif
};

static int sig_num(const char *sig)
{
	int ret;
	unsigned int signum;

	ret = lxc_safe_uint(sig, &signum);
	if (ret < 0)
		return ret;

	return signum;
}

static int rt_sig_num(const char *signame)
{
	int rtmax = 0, sig_n = 0;

	if (strncasecmp(signame, "max-", 4) == 0)
		rtmax = 1;

	signame += 4;
	if (!isdigit(*signame))
		return ret_errno(EINVAL);

	sig_n = sig_num(signame);
	sig_n = rtmax ? SIGRTMAX - sig_n : SIGRTMIN + sig_n;
	if (sig_n > SIGRTMAX || sig_n < SIGRTMIN)
		return ret_errno(EINVAL);

	return sig_n;
}

int sig_parse(const char *signame)
{
	size_t n;

	if (isdigit(*signame)) {
		return sig_num(signame);
	} else if (strncasecmp(signame, "sig", 3) == 0) {
		signame += 3;
		if (strncasecmp(signame, "rt", 2) == 0)
			return rt_sig_num(signame + 2);

		for (n = 0; n < sizeof(signames) / sizeof((signames)[0]); n++)
			if (strcasecmp(signames[n].name, signame) == 0)
				return signames[n].num;
	}

	return ret_errno(EINVAL);
}

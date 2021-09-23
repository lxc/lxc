/* SPDX-License-Identifier: LGPL-2.1+ */

#include "config.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lxc.h"

#include "conf.h"
#include "confile.h"
#include "confile_utils.h"
#include "error.h"
#include "list.h"
#include "lxc.h"
#include "log.h"
#include "macro.h"
#include "memory_utils.h"
#include "network.h"
#include "parse.h"
#include "utils.h"

#if !HAVE_STRLCPY
#include "strlcpy.h"
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

static struct lxc_netdev *lxc_network_add(struct list_head *head, int idx, bool tail)
{
	__do_free struct lxc_netdev *netdev = NULL;

	/* network does not exist */
	netdev = zalloc(sizeof(*netdev));
	if (!netdev)
		return ret_set_errno(NULL, ENOMEM);

	INIT_LIST_HEAD(&netdev->ipv4_addresses);
	INIT_LIST_HEAD(&netdev->ipv6_addresses);

	/* give network a unique index */
	netdev->idx = idx;

	if (tail)
		list_add_tail(&netdev->head, head);
	else
		list_add(&netdev->head, head);

	return move_ptr(netdev);
}

/* Takes care of finding the correct netdev struct in the networks list or
 * allocates a new one if it couldn't be found.
 */
struct lxc_netdev *lxc_get_netdev_by_idx(struct lxc_conf *conf,
					 unsigned int idx, bool allocate)
{
	struct list_head *netdevs = &conf->netdevs;
	struct list_head *head = netdevs;
	struct lxc_netdev *netdev;

	/* lookup network */
	if (!list_empty(netdevs)) {
		list_for_each_entry(netdev, netdevs, head) {
			/* found network device */
			if (netdev->idx == idx)
				return netdev;

			if (netdev->idx > idx) {
				head = &netdev->head;
				break;
			}
		}
	}

	if (allocate)
		return lxc_network_add(head, idx, true);

	return NULL;
}

void lxc_log_configured_netdevs(const struct lxc_conf *conf)
{
	struct lxc_netdev *netdev;
	const struct list_head *netdevs = &conf->netdevs;

	if (!lxc_log_trace())
		return;

	if (list_empty(netdevs)) {
		TRACE("container has no networks configured");
		return;
	}

	list_for_each_entry(netdev, netdevs, head) {
		struct lxc_list *cur, *next;
		struct lxc_inetdev *inet4dev;
		struct lxc_inet6dev *inet6dev;
		char bufinet4[INET_ADDRSTRLEN], bufinet6[INET6_ADDRSTRLEN];

		TRACE("index: %zd", netdev->idx);
		TRACE("ifindex: %d", netdev->ifindex);

		switch (netdev->type) {
		case LXC_NET_VETH:
			TRACE("type: veth");
			TRACE("veth mode: %d", netdev->priv.veth_attr.mode);

			if (netdev->priv.veth_attr.pair[0] != '\0')
				TRACE("veth pair: %s",
				      netdev->priv.veth_attr.pair);

			if (netdev->priv.veth_attr.veth1[0] != '\0')
				TRACE("veth1 : %s",
				      netdev->priv.veth_attr.veth1);

			if (netdev->priv.veth_attr.ifindex > 0)
				TRACE("host side ifindex for veth device: %d",
				      netdev->priv.veth_attr.ifindex);

			if (netdev->priv.veth_attr.vlan_id_set)
				TRACE("veth vlan id: %d", netdev->priv.veth_attr.vlan_id);

			lxc_list_for_each_safe(cur, &netdev->priv.veth_attr.vlan_tagged_ids, next) {
				unsigned short vlan_tagged_id = PTR_TO_USHORT(cur->elem);
				TRACE("veth vlan tagged id: %u", vlan_tagged_id);
			}

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

			list_for_each_entry(inet4dev, &netdev->ipv4_addresses, head) {
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

			list_for_each_entry(inet6dev, &netdev->ipv6_addresses, head) {
				inet_ntop(AF_INET6, &inet6dev->addr, bufinet6,
					  sizeof(bufinet6));
				TRACE("ipv6 addr: %s", bufinet6);
			}

			if (netdev->type == LXC_NET_VETH) {
				list_for_each_entry(inet4dev, &netdev->priv.veth_attr.ipv4_routes, head) {
					if (!inet_ntop(AF_INET, &inet4dev->addr, bufinet4, sizeof(bufinet4))) {
						ERROR("Invalid ipv4 veth route");
						return;
					}

					TRACE("ipv4 veth route: %s/%u", bufinet4, inet4dev->prefix);
				}

				list_for_each_entry(inet6dev, &netdev->priv.veth_attr.ipv6_routes, head) {
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

void lxc_clear_netdev(struct lxc_netdev *netdev)
{
	struct lxc_list *cur, *next;
	struct list_head head;
	struct lxc_inetdev *inetdev, *ninetdev;
	struct lxc_inet6dev *inet6dev, *ninet6dev;
	ssize_t idx;

	if (!netdev)
		return;

	idx = netdev->idx;

	free_disarm(netdev->upscript);
	free_disarm(netdev->downscript);
	free_disarm(netdev->hwaddr);
	free_disarm(netdev->mtu);

	free_disarm(netdev->ipv4_gateway);
	list_for_each_entry_safe(inetdev, ninetdev, &netdev->ipv4_addresses, head) {
		list_del(&inetdev->head);
		free(inetdev);
	}

	free_disarm(netdev->ipv6_gateway);
	list_for_each_entry_safe(inet6dev, ninet6dev, &netdev->ipv6_addresses, head) {
		list_del(&inet6dev->head);
		free(inet6dev);
	}

	if (netdev->type == LXC_NET_VETH) {
		list_for_each_entry_safe(inetdev, ninetdev, &netdev->priv.veth_attr.ipv4_routes, head) {
			list_del(&inetdev->head);
			free(inetdev);
		}

		list_for_each_entry_safe(inet6dev, ninet6dev, &netdev->priv.veth_attr.ipv6_routes, head) {
			list_del(&inet6dev->head);
			free(inet6dev);
		}

		lxc_list_for_each_safe(cur, &netdev->priv.veth_attr.vlan_tagged_ids, next) {
			lxc_list_del(cur);
			free(cur);
		}
	}

	head = netdev->head;
	memset(netdev, 0, sizeof(struct lxc_netdev));
	netdev->head = head;
	INIT_LIST_HEAD(&netdev->ipv4_addresses);
	INIT_LIST_HEAD(&netdev->ipv6_addresses);
	netdev->type = -1;
	netdev->idx = idx;
}

static void lxc_free_netdev(struct lxc_netdev *netdev)
{
	if (netdev) {
		lxc_clear_netdev(netdev);
		free(netdev);
	}
}

bool lxc_remove_nic_by_idx(struct lxc_conf *conf, unsigned int idx)
{
	struct lxc_netdev *netdev;

	if (list_empty(&conf->netdevs))
		return false;

	list_for_each_entry(netdev, &conf->netdevs, head) {
		if (netdev->idx != idx)
			continue;

		list_del(&netdev->head);
		lxc_free_netdev(netdev);
		return true;
	}

	return false;
}

void lxc_free_networks(struct lxc_conf *conf)
{
	struct lxc_netdev *netdev, *n;

	if (list_empty(&conf->netdevs))
		return;

	list_for_each_entry_safe(netdev, n, &conf->netdevs, head) {
		list_del(&netdev->head);
		lxc_free_netdev(netdev);
	}

	/* prevent segfaults */
	INIT_LIST_HEAD(&conf->netdevs);
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
		if (!strequal(veth_mode[i].name, value))
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
		if (!strequal(macvlan_mode[i].name, value))
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
		if (!strequal(ipvlan_mode[i].name, value))
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
		if (!strequal(ipvlan_isolation[i].name, value))
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
	__do_free char *valdup = NULL;

	valdup = path_simplify(value);
	if (!valdup)
		return -ENOMEM;

	return set_config_string_item_max(conf_item, valdup, PATH_MAX);
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

	if (!strnequal(line, "lxc.net", 7))
		return false;

	if (strnequal(line, "lxc.net.hwaddr", 14))
		return true;

	if (strnequal(line, "lxc.network.hwaddr", 18))
		return true;

	if (sscanf(line, "lxc.net.%u.%6s", &index, tmp) == 2 ||
	    sscanf(line, "lxc.network.%u.%6s", &index, tmp) == 2)
		return strnequal(tmp, "hwaddr", 6);

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

	ret = strnprintf(hwaddr, 18, "00:16:3e:%02x:%02x:%02x", rand_r(&seed) % 255,
		       rand_r(&seed) % 255, rand_r(&seed) % 255);
#else

	(void)randseed(true);

	ret = strnprintf(hwaddr, 18, "00:16:3e:%02x:%02x:%02x", rand() % 255,
		       rand() % 255, rand() % 255);
#endif
	if (ret < 0)
		return log_error_errno(false, EIO, "Failed to call strnprintf()");

	return true;
}

int lxc_get_conf_str(char *retv, int inlen, const char *value)
{
	size_t value_len;

	if (!value)
		return 0;

	value_len = strlen(value);
	if (retv && (size_t)inlen >= value_len + 1)
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
	bool rtmax;
	int sig_n = 0;

	if (is_empty_string(signame))
		return ret_errno(EINVAL);

	if (strncasecmp(signame, "max-", STRLITERALLEN("max-")) == 0) {
		rtmax = true;
		signame += STRLITERALLEN("max-");
	} else if (strncasecmp(signame, "min+", STRLITERALLEN("min+")) == 0) {
		rtmax = false;
		signame += STRLITERALLEN("min+");
	} else {
		return ret_errno(EINVAL);
	}

	if (is_empty_string(signame) || !isdigit(*signame))
		return ret_errno(EINVAL);

	sig_n = sig_num(signame);
	if (sig_n < 0 || sig_n > SIGRTMAX - SIGRTMIN)
		return ret_errno(EINVAL);

	if (rtmax)
		sig_n = SIGRTMAX - sig_n;
	else
		sig_n = SIGRTMIN + sig_n;

	return sig_n;
}

int sig_parse(const char *signame)
{
	if (isdigit(*signame))
		return sig_num(signame);

	if (strncasecmp(signame, "sig", STRLITERALLEN("sig")) == 0) {
		signame += STRLITERALLEN("sig");
		if (strncasecmp(signame, "rt", STRLITERALLEN("rt")) == 0)
			return rt_sig_num(signame + STRLITERALLEN("rt"));

		for (size_t n = 0; n < ARRAY_SIZE(signames); n++)
			if (strcasecmp(signames[n].name, signame) == 0)
				return signames[n].num;
	}

	return ret_errno(EINVAL);
}

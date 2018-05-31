/* liblxcapi
 *
 * Copyright © 2017 Christian Brauner <christian.brauner@ubuntu.com>.
 * Copyright © 2017 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "conf.h"
#include "confile.h"
#include "confile_utils.h"
#include "error.h"
#include "list.h"
#include "log.h"
#include "lxccontainer.h"
#include "network.h"
#include "parse.h"
#include "utils.h"

lxc_log_define(lxc_confile_utils, lxc);

int parse_idmaps(const char *idmap, char *type, unsigned long *nsid,
		 unsigned long *hostid, unsigned long *range)
{
	int ret = -1;
	unsigned long tmp_hostid, tmp_nsid, tmp_range;
	char tmp_type;
	char *window, *slide;
	char *dup = NULL;

	/* Duplicate string. */
	dup = strdup(idmap);
	if (!dup)
		goto on_error;

	/* A prototypical idmap entry would be: "u 1000 1000000 65536" */

	/* align */
	slide = window = dup;
	/* skip whitespace */
	slide += strspn(slide, " \t\r");
	if (slide != window && *slide == '\0')
		goto on_error;

	/* Validate type. */
	if (*slide != 'u' && *slide != 'g') {
		ERROR("Invalid id mapping type: %c", *slide);
		goto on_error;
	}

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
		goto on_error;

	/* Mark beginning of nsid. */
	window = slide;
	/* Validate that non-whitespace follows. */
	slide += strcspn(slide, " \t\r");
	/* There must be non-whitespace. */
	if (slide == window || *slide == '\0')
		goto on_error;
	/* Mark end of nsid. */
	*slide = '\0';

	/* Parse nsid. */
	if (lxc_safe_ulong(window, &tmp_nsid) < 0) {
		ERROR("Failed to parse nsid: %s", window);
		goto on_error;
	}

	/* Move beyond \0. */
	slide++;
	/* Validate that only whitespace follows. */
	slide += strspn(slide, " \t\r");
	/* If there was only one whitespace then we whiped it with our \0 above.
	 * So only ensure that we're not at the end of the string.
	 */
	if (*slide == '\0')
		goto on_error;

	/* Mark beginning of hostid. */
	window = slide;
	/* Validate that non-whitespace follows. */
	slide += strcspn(slide, " \t\r");
	/* There must be non-whitespace. */
	if (slide == window || *slide == '\0')
		goto on_error;
	/* Mark end of nsid. */
	*slide = '\0';

	/* Parse hostid. */
	if (lxc_safe_ulong(window, &tmp_hostid) < 0) {
		ERROR("Failed to parse hostid: %s", window);
		goto on_error;
	}

	/* Move beyond \0. */
	slide++;
	/* Validate that only whitespace follows. */
	slide += strspn(slide, " \t\r");
	/* If there was only one whitespace then we whiped it with our \0 above.
	 * So only ensure that we're not at the end of the string.
	 */
	if (*slide == '\0')
		goto on_error;

	/* Mark beginning of range. */
	window = slide;
	/* Validate that non-whitespace follows. */
	slide += strcspn(slide, " \t\r");
	/* There must be non-whitespace. */
	if (slide == window)
		goto on_error;

	/* The range is the last valid entry we expect. So make sure that there
	 * is no trailing garbage and if there is, error out.
	 */
	if (*(slide + strspn(slide, " \t\r\n")) != '\0')
		goto on_error;
	/* Mark end of range. */
	*slide = '\0';

	/* Parse range. */
	if (lxc_safe_ulong(window, &tmp_range) < 0) {
		ERROR("Failed to parse id mapping range: %s", window);
		goto on_error;
	}

	*type = tmp_type;
	*nsid = tmp_nsid;
	*hostid = tmp_hostid;
	*range = tmp_range;

	/* Yay, we survived. */
	ret = 0;

on_error:
	free(dup);

	return ret;
}

bool lxc_config_value_empty(const char *value)
{
	if (value && strlen(value) > 0)
		return false;

	return true;
}

struct lxc_netdev *lxc_network_add(struct lxc_list *networks, int idx, bool tail)
{
	struct lxc_list *newlist;
	struct lxc_netdev *netdev = NULL;

	/* network does not exist */
	netdev = malloc(sizeof(*netdev));
	if (!netdev)
		return NULL;

	memset(netdev, 0, sizeof(*netdev));
	lxc_list_init(&netdev->ipv4);
	lxc_list_init(&netdev->ipv6);

	/* give network a unique index */
	netdev->idx = idx;

	/* prepare new list */
	newlist = malloc(sizeof(*newlist));
	if (!newlist) {
		free(netdev);
		return NULL;
	}

	lxc_list_init(newlist);
	newlist->elem = netdev;

	if (tail)
		lxc_list_add_tail(networks, newlist);
	else
		lxc_list_add(networks, newlist);
	return netdev;
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
		return NULL;

	return lxc_network_add(insert, idx, true);
}

void lxc_log_configured_netdevs(const struct lxc_conf *conf)
{
	struct lxc_netdev *netdev;
	struct lxc_list *it = (struct lxc_list *)&conf->network;;

	if ((conf->loglevel != LXC_LOG_LEVEL_TRACE) &&
	    (lxc_log_get_level() != LXC_LOG_LEVEL_TRACE))
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
				char *macvlan_mode;
				macvlan_mode = lxc_macvlan_flag_to_mode(
				    netdev->priv.macvlan_attr.mode);
				TRACE("macvlan mode: %s",
				      macvlan_mode ? macvlan_mode
						   : "(invalid mode)");
			}
			break;
		case LXC_NET_VLAN:
			TRACE("type: vlan");
			TRACE("vlan id: %d", netdev->priv.vlan_attr.vid);
			break;
		case LXC_NET_PHYS:
			TRACE("type: phys");
			if (netdev->priv.phys_attr.ifindex > 0) {
				TRACE("host side ifindex for phys device: %d",
				      netdev->priv.phys_attr.ifindex);
			}
			break;
		case LXC_NET_EMPTY:
			TRACE("type: empty");
			break;
		case LXC_NET_NONE:
			TRACE("type: none");
			break;
		default:
			ERROR("invalid network type %d", netdev->type);
			return;
		}

		if (netdev->type != LXC_NET_EMPTY) {
			TRACE("flags: %s",
			      netdev->flags == IFF_UP ? "up" : "none");
			if (netdev->link[0] != '\0')
				TRACE("link: %s", netdev->link);
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
		}
	}
}

static void lxc_free_netdev(struct lxc_netdev *netdev)
{
	struct lxc_list *cur, *next;

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

	free(netdev);
}

bool lxc_remove_nic_by_idx(struct lxc_conf *conf, unsigned int idx)
{
	struct lxc_list *cur, *next;
	struct lxc_netdev *netdev;
	bool found = false;

	lxc_list_for_each_safe(cur, &conf->network, next) {
		netdev = cur->elem;
		if (netdev->idx != idx)
			continue;

		lxc_list_del(cur);
		found = true;
		break;
	}

	if (!found)
		return false;

	lxc_free_netdev(netdev);
	free(cur);

	return true;
}

void lxc_free_networks(struct lxc_list *networks)
{
	struct lxc_list *cur, *next;
	struct lxc_netdev *netdev;

	lxc_list_for_each_safe(cur, networks, next) {
		netdev = cur->elem;
		lxc_free_netdev(netdev);
		free(cur);
	}

	/* prevent segfaults */
	lxc_list_init(networks);
}

static struct macvlan_mode {
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
	size_t i;

	for (i = 0; i < sizeof(macvlan_mode) / sizeof(macvlan_mode[0]); i++) {
		if (strcmp(macvlan_mode[i].name, value))
			continue;

		*mode = macvlan_mode[i].mode;
		return 0;
	}

	return -1;
}

char *lxc_macvlan_flag_to_mode(int mode)
{
	size_t i;

	for (i = 0; i < sizeof(macvlan_mode) / sizeof(macvlan_mode[0]); i++) {
		if (macvlan_mode[i].mode == mode)
			continue;

		return macvlan_mode[i].name;
	}

	return NULL;
}

int set_config_string_item(char **conf_item, const char *value)
{
	char *new_value;

	if (lxc_config_value_empty(value)) {
		free(*conf_item);
		*conf_item = NULL;
		return 0;
	}

	new_value = strdup(value);
	if (!new_value) {
		SYSERROR("failed to duplicate string \"%s\"", value);
		return -1;
	}

	free(*conf_item);
	*conf_item = new_value;
	return 0;
}

int set_config_string_item_max(char **conf_item, const char *value, size_t max)
{
	if (strlen(value) >= max) {
		ERROR("%s is too long (>= %lu)", value, (unsigned long)max);
		return -1;
	}

	return set_config_string_item(conf_item, value);
}

int set_config_path_item(char **conf_item, const char *value)
{
	return set_config_string_item_max(conf_item, value, PATH_MAX);
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

int network_ifname(char *valuep, const char *value)
{
	if (strlen(value) >= IFNAMSIZ) {
		ERROR("Network devie name \"%s\" is too long (>= %zu)", value,
		      (size_t)IFNAMSIZ);
	}

	strcpy(valuep, value);
	return 0;
}

int rand_complete_hwaddr(char *hwaddr)
{
	const char hex[] = "0123456789abcdef";
	char *curs = hwaddr;

#ifndef HAVE_RAND_R
	randseed(true);
#else
	unsigned int seed;

	seed = randseed(false);
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
	return 0;
}

bool lxc_config_net_hwaddr(const char *line)
{
	unsigned index;
	char tmp[7];

	if (strncmp(line, "lxc.net", 7) != 0)
		return false;
	if (strncmp(line, "lxc.net.hwaddr", 14) == 0)
		return true;
	if (strncmp(line, "lxc.network.hwaddr", 18) == 0)
		return true;
	if (sscanf(line, "lxc.net.%u.%6s", &index, tmp) == 2 || sscanf(line, "lxc.network.%u.%6s", &index, tmp) == 2)
		return strncmp(tmp, "hwaddr", 6) == 0;

	return false;
}

/*
 * If we find a lxc.net.[i].hwaddr or lxc.network.hwaddr in the original config
 * file, we expand it in the unexpanded_config, so that after a save_config we
 * store the hwaddr for re-use.
 * This is only called when reading the config file, not when executing a
 * lxc.include.
 * 'x' and 'X' are substituted in-place.
 */
void update_hwaddr(const char *line)
{
	char *p;

	line += lxc_char_left_gc(line, strlen(line));
	if (line[0] == '#')
		return;

	if (!lxc_config_net_hwaddr(line))
		return;

	/* Let config_net_hwaddr raise the error. */
	p = strchr(line, '=');
	if (!p)
		return;
	p++;

	while (isblank(*p))
		p++;

	if (!*p)
		return;

	rand_complete_hwaddr(p);
}

bool new_hwaddr(char *hwaddr)
{
	int ret;

	(void)randseed(true);

	ret = snprintf(hwaddr, 18, "00:16:3e:%02x:%02x:%02x", rand() % 255,
		       rand() % 255, rand() % 255);
	if (ret < 0 || ret >= 18) {
		SYSERROR("Failed to call snprintf().");
		return false;
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

	return strlen(value);
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

bool parse_limit_value(const char **value, rlim_t *res)
{
	char *endptr = NULL;

	if (strncmp(*value, "unlimited", sizeof("unlimited") - 1) == 0) {
		*res = RLIM_INFINITY;
		*value += sizeof("unlimited") - 1;
		return true;
	}

	errno = 0;
	*res = strtoull(*value, &endptr, 10);
	if (errno || !endptr)
		return false;
	*value = endptr;

	return true;
}

static int lxc_container_name_to_pid(const char *lxcname_or_pid,
				     const char *lxcpath)
{
	int ret;
	signed long int pid;
	char *err = NULL;

	pid = strtol(lxcname_or_pid, &err, 10);
	if (*err != '\0' || pid < 1) {
		struct lxc_container *c;

		c = lxc_container_new(lxcname_or_pid, lxcpath);
		if (!c) {
			ERROR("\"%s\" is not a valid pid nor a container name",
			      lxcname_or_pid);
			return -1;
		}

		if (!c->may_control(c)) {
			ERROR("Insufficient privileges to control container "
			      "\"%s\"", c->name);
			lxc_container_put(c);
			return -1;
		}

		pid = c->init_pid(c);
		if (pid < 1) {
			ERROR("Container \"%s\" is not running", c->name);
			lxc_container_put(c);
			return -1;
		}

		lxc_container_put(c);
	}

	ret = kill(pid, 0);
	if (ret < 0) {
		ERROR("%s - Failed to send signal to pid %d", strerror(errno),
		      (int)pid);
		return -EPERM;
	}

	return pid;
}

int lxc_inherit_namespace(const char *lxcname_or_pid, const char *lxcpath,
			  const char *namespace)
{
	int fd, pid;
	char *dup, *lastslash;

	lastslash = strrchr(lxcname_or_pid, '/');
	if (lastslash) {
		dup = strdup(lxcname_or_pid);
		if (!dup)
			return -ENOMEM;

		dup[lastslash - lxcname_or_pid] = '\0';
		pid = lxc_container_name_to_pid(lastslash + 1, dup);
		free(dup);
	} else {
		pid = lxc_container_name_to_pid(lxcname_or_pid, lxcpath);
	}

	if (pid < 0)
		return -EINVAL;

	fd = lxc_preserve_ns(pid, namespace);
	if (fd < 0)
		return -EINVAL;

	return fd;
}

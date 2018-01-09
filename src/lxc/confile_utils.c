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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "conf.h"
#include "confile.h"
#include "confile_utils.h"
#include "error.h"
#include "log.h"
#include "list.h"
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

struct lxc_netdev *lxc_find_netdev_by_idx(struct lxc_conf *conf,
					  unsigned int idx)
{
	struct lxc_netdev *netdev = NULL;
	struct lxc_list *networks = &conf->network;
	struct lxc_list *insert = networks;

	/* lookup network */
	if (lxc_list_empty(networks))
		return NULL;

	lxc_list_for_each(insert, networks) {
		netdev = insert->elem;
		if (netdev->idx >= idx)
			break;
	}

	/* network already exists */
	if (netdev->idx == idx)
		return netdev;

	return NULL;
}

/* Takes care of finding the correct netdev struct in the networks list or
 * allocates a new one if it couldn't be found.
 */
struct lxc_netdev *lxc_get_netdev_by_idx(struct lxc_conf *conf,
					 unsigned int idx)
{
	struct lxc_list *newlist;
	struct lxc_netdev *netdev = NULL;
	struct lxc_list *networks = &conf->network;
	struct lxc_list *insert = networks;

	/* lookup network */
	netdev = lxc_find_netdev_by_idx(conf, idx);
	if (netdev)
		return netdev;

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

	/* Insert will now point to the correct position to insert the new
	 * netdev.
	 */
	lxc_list_add_tail(insert, newlist);

	return netdev;
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
			break;
		case LXC_NET_VLAN:
			TRACE("type: vlan");
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

		TRACE("flags: %s", netdev->flags == IFF_UP ? "up" : "none");
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
	}
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

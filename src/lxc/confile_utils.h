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

#ifndef __LXC_CONFILE_UTILS_H
#define __LXC_CONFILE_UTILS_H

#include <stdbool.h>

#include "conf.h"
#include "confile_utils.h"

#define strprint(str, inlen, ...)                                       \
	do {                                                            \
		if (str)                                                \
			len = snprintf(str, inlen, ##__VA_ARGS__);      \
		else                                                    \
			len = snprintf((char *){""}, 0, ##__VA_ARGS__); \
		if (len < 0) {                                          \
			SYSERROR("failed to create string");            \
			return -1;                                      \
		};                                                      \
		fulllen += len;                                         \
		if (inlen > 0) {                                        \
			if (str)                                        \
				str += len;                             \
			inlen -= len;                                   \
			if (inlen < 0)                                  \
				inlen = 0;                              \
		}                                                       \
	} while (0);

extern int parse_idmaps(const char *idmap, char *type, unsigned long *nsid,
			unsigned long *hostid, unsigned long *range);

extern bool lxc_config_value_empty(const char *value);
extern struct lxc_netdev *lxc_find_netdev_by_idx(struct lxc_conf *conf,
						 unsigned int idx);
extern struct lxc_netdev *lxc_get_netdev_by_idx(struct lxc_conf *conf,
						unsigned int idx);
extern void lxc_log_configured_netdevs(const struct lxc_conf *conf);
extern int network_ifname(char *valuep, const char *value);

#endif /* __LXC_CONFILE_UTILS_H */

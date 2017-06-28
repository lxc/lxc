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

#ifndef __LXC_CONFILE_LEGACY_H
#define __LXC_CONFILE_LEGACY_H

#include <stdio.h>
#include <lxc/attach_options.h>
#include <stdbool.h>

struct lxc_conf;
struct lxc_list;

extern int set_config_network_legacy_type(const char *, const char *,
					  struct lxc_conf *, void *);
extern int set_config_network_legacy_flags(const char *, const char *,
					   struct lxc_conf *, void *);
extern int set_config_network_legacy_link(const char *, const char *,
					  struct lxc_conf *, void *);
extern int set_config_network_legacy_name(const char *, const char *,
					  struct lxc_conf *, void *);
extern int set_config_network_legacy_veth_pair(const char *, const char *,
					       struct lxc_conf *, void *);
extern int set_config_network_legacy_macvlan_mode(const char *, const char *,
						  struct lxc_conf *, void *);
extern int set_config_network_legacy_hwaddr(const char *, const char *,
					    struct lxc_conf *, void *);
extern int set_config_network_legacy_vlan_id(const char *, const char *,
					     struct lxc_conf *, void *);
extern int set_config_network_legacy_mtu(const char *, const char *,
					 struct lxc_conf *, void *);
extern int set_config_network_legacy_ipv4(const char *, const char *,
					  struct lxc_conf *, void *);
extern int set_config_network_legacy_ipv4_gateway(const char *, const char *,
						  struct lxc_conf *, void *);
extern int set_config_network_legacy_script_up(const char *, const char *,
					       struct lxc_conf *, void *);
extern int set_config_network_legacy_script_down(const char *, const char *,
						 struct lxc_conf *, void *);
extern int set_config_network_legacy_ipv6(const char *, const char *,
					  struct lxc_conf *, void *);
extern int set_config_network_legacy_ipv6_gateway(const char *, const char *,
						  struct lxc_conf *, void *);
extern int set_config_network_legacy_nic(const char *, const char *,
					 struct lxc_conf *, void *);
extern int get_config_network_legacy_item(const char *, char *, int,
					  struct lxc_conf *, void *);
extern int clr_config_network_legacy_item(const char *, struct lxc_conf *,
					  void *);

extern int lxc_list_nicconfigs_legacy(struct lxc_conf *c, const char *key,
				      char *retv, int inlen);
extern int lxc_listconfigs(char *retv, int inlen);

extern bool network_new_hwaddrs(struct lxc_conf *conf);

#define lxc_config_legacy_define(name)					\
	extern int set_config_##name(const char *, const char *,	\
			struct lxc_conf *, void *);			\
	extern int get_config_##name(const char *, char *, int,		\
			struct lxc_conf *, void *);			\
	extern int clr_config_##name(const char *, struct lxc_conf *,	\
			void *);

lxc_config_legacy_define(network_legacy);
lxc_config_legacy_define(lsm_aa_profile);
lxc_config_legacy_define(lsm_aa_incomplete);
lxc_config_legacy_define(lsm_se_context);
lxc_config_legacy_define(limit);

#endif /* __LXC_CONFILE_LEGACY_H */

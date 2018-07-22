/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2008
 *
 * Authors:
 * Daniel Lezcano <daniel.lezcano at free.fr>
 * Serge Hallyn <serge@hallyn.com>
 * Christian Brauner <christian.brauner@ubuntu.com>
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

#ifndef __LXC_CONFILE_H
#define __LXC_CONFILE_H

#include <stdbool.h>
#include <stdio.h>

#include <lxc/attach_options.h>
#include <lxc/lxccontainer.h>

struct lxc_conf;
struct lxc_list;

/* Callback prototype to set a configuration item.
 * Must be implemented when adding a new configuration key.
 */
typedef int (*config_set_cb)(const char *key, const char *value,
			     struct lxc_conf *conf, void *data);

/* Callback prototype to get a configuration item.
 * Must be implemented when adding a new configuration key.
 */
typedef int (*config_get_cb)(const char *key, char *value, int inlen,
			     struct lxc_conf *conf, void *data);

/* Callback prototype to clear a configuration item.
 * Must be implemented when adding a new configuration key.
 */
typedef int (*config_clr_cb)(const char *key, struct lxc_conf *conf,
			     void *data);

struct lxc_config_t {
	char *name;
	config_set_cb set;
	config_get_cb get;
	config_clr_cb clr;
};

struct new_config_item {
	char *key;
	char *val;
};

/* Get the jump table entry for the given configuration key. */
extern struct lxc_config_t *lxc_get_config(const char *key);

/* List all available config items. */
extern int lxc_list_config_items(char *retv, int inlen);

/* Given a configuration key namespace (e.g. lxc.apparmor) list all associated
 * subkeys for that namespace.
 * Must be implemented when adding a new configuration key.
 */
extern int lxc_list_subkeys(struct lxc_conf *conf, const char *key, char *retv,
			    int inlen);

/* List all configuration items associated with a given network. For example
 * pass "lxc.net.[i]" to retrieve all configuration items associated with
 * the network associated with index [i].
 */
extern int lxc_list_net(struct lxc_conf *c, const char *key, char *retv,
			int inlen);

extern int lxc_config_read(const char *file, struct lxc_conf *conf,
			   bool from_include);

extern int append_unexp_config_line(const char *line, struct lxc_conf *conf);

extern int lxc_config_define_add(struct lxc_list *defines, char* arg);

extern bool lxc_config_define_load(struct lxc_list *defines,
				   struct lxc_container *c);

extern void lxc_config_define_free(struct lxc_list *defines);

/* needed for lxc-attach */
extern signed long lxc_config_parse_arch(const char *arch);

extern int lxc_fill_elevated_privileges(char *flaglist, int *flags);

extern int lxc_clear_config_item(struct lxc_conf *c, const char *key);

extern int write_config(int fd, const struct lxc_conf *conf);

extern bool do_append_unexp_config_line(struct lxc_conf *conf, const char *key,
					const char *v);

/* These are used when cloning a container */
extern void clear_unexp_config_line(struct lxc_conf *conf, const char *key,
				    bool rm_subkeys);

extern bool clone_update_unexp_hooks(struct lxc_conf *conf, const char *oldpath,
				     const char *newpath, const char *oldname,
				     const char *newmame);

bool clone_update_unexp_ovl_paths(struct lxc_conf *conf, const char *oldpath,
				  const char *newpath, const char *oldname,
				  const char *newname, const char *ovldir);

extern bool network_new_hwaddrs(struct lxc_conf *conf);

#endif /* __LXC_CONFILE_H */

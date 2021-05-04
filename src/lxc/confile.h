/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_CONFILE_H
#define __LXC_CONFILE_H

#include <stdbool.h>
#include <stdio.h>

#include <lxc/attach_options.h>
#include <lxc/lxccontainer.h>

#include "compiler.h"

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

#define LXC_CONFIG_MEMBERS \
	char *name;        \
	bool strict;       \
	config_set_cb set; \
	config_get_cb get; \
	config_clr_cb clr

struct lxc_config_t {
	LXC_CONFIG_MEMBERS;
};

struct new_config_item {
	char *key;
	char *val;
};

/* Get the jump table entry for the given configuration key. */
__hidden extern struct lxc_config_t *lxc_get_config_exact(const char *key);

/* Get the jump table entry if entry name is a prefix of the given configuration key. */
__hidden extern struct lxc_config_t *lxc_get_config(const char *key);

/* List all available config items. */
__hidden extern int lxc_list_config_items(char *retv, int inlen)
__access_rw(1, 2);

/* Given a configuration key namespace (e.g. lxc.apparmor) list all associated
 * subkeys for that namespace.
 * Must be implemented when adding a new configuration key.
 */
__hidden extern int lxc_list_subkeys(struct lxc_conf *conf, const char *key, char *retv, int inlen)
    __access_rw(3, 4);

/* List all configuration items associated with a given network. For example
 * pass "lxc.net.[i]" to retrieve all configuration items associated with
 * the network associated with index [i].
 */
__hidden extern int lxc_list_net(struct lxc_conf *c, const char *key, char *retv, int inlen)
    __access_rw(3, 4);

__hidden extern int lxc_config_read(const char *file, struct lxc_conf *conf, bool from_include);

__hidden extern int append_unexp_config_line(const char *line, struct lxc_conf *conf);

__hidden extern int lxc_config_define_add(struct lxc_list *defines, char *arg);

__hidden extern bool lxc_config_define_load(struct lxc_list *defines, struct lxc_container *c);

__hidden extern void lxc_config_define_free(struct lxc_list *defines);

#define LXC_ARCH_UNCHANGED 0xffffffffL
/*
 * Parse personality of the container. Returns 0 if personality is valid,
 * negative errno otherwise.
 */
__hidden extern int lxc_config_parse_arch(const char *arch, signed long *persona);

__hidden extern int lxc_fill_elevated_privileges(char *flaglist, int *flags);

__hidden extern int lxc_clear_config_item(struct lxc_conf *c, const char *key);

__hidden extern int write_config(int fd, const struct lxc_conf *conf);

__hidden extern bool do_append_unexp_config_line(struct lxc_conf *conf, const char *key,
						 const char *v);

/* These are used when cloning a container */
__hidden extern void clear_unexp_config_line(struct lxc_conf *conf, const char *key, bool rm_subkeys);

__hidden extern bool clone_update_unexp_hooks(struct lxc_conf *conf, const char *oldpath,
					      const char *newpath, const char *oldname,
					      const char *newmame);

__hidden extern bool clone_update_unexp_ovl_paths(struct lxc_conf *conf, const char *oldpath,
						  const char *newpath, const char *oldname,
						  const char *newname, const char *ovldir);

__hidden extern bool network_new_hwaddrs(struct lxc_conf *conf);

__hidden extern int add_elem_to_mount_list(const char *value, struct lxc_conf *lxc_conf);

#endif /* __LXC_CONFILE_H */

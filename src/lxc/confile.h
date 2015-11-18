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

#ifndef __LXC_CONFILE_H
#define __LXC_CONFILE_H

#include <stdio.h>
#include <lxc/attach_options.h>
#include <stdbool.h>

struct lxc_conf;
struct lxc_list;

typedef int (*config_cb)(const char *, const char *, struct lxc_conf *);
struct lxc_config_t {
	char *name;
	config_cb cb;
};

extern struct lxc_config_t *lxc_getconfig(const char *key);
extern int lxc_list_nicconfigs(struct lxc_conf *c, const char *key, char *retv, int inlen);
extern int lxc_listconfigs(char *retv, int inlen);
extern int lxc_config_read(const char *file, struct lxc_conf *conf, bool from_include);
extern int append_unexp_config_line(const char *line, struct lxc_conf *conf);

extern int lxc_config_define_add(struct lxc_list *defines, char* arg);
extern int lxc_config_define_load(struct lxc_list *defines,
				  struct lxc_conf *conf);

/* needed for lxc-attach */
extern signed long lxc_config_parse_arch(const char *arch);
extern int lxc_fill_elevated_privileges(char *flaglist, int *flags);

extern int lxc_get_config_item(struct lxc_conf *c, const char *key, char *retv, int inlen);
extern int lxc_clear_config_item(struct lxc_conf *c, const char *key);
extern void write_config(FILE *fout, struct lxc_conf *c);

extern bool do_append_unexp_config_line(struct lxc_conf *conf, const char *key, const char *v);

/* These are used when cloning a container */
extern void clear_unexp_config_line(struct lxc_conf *conf, const char *key, bool rm_subkeys);
extern bool clone_update_unexp_hooks(struct lxc_conf *conf, const char *oldpath,
	const char *newpath, const char *oldname, const char *newmame);
bool clone_update_unexp_ovl_paths(struct lxc_conf *conf, const char *oldpath,
				  const char *newpath, const char *oldname,
				  const char *newname, const char *ovldir);
extern bool network_new_hwaddrs(struct lxc_conf *conf);
#endif

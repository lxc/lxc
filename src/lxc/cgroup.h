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

#ifndef __LXC_CGROUP_H
#define __LXC_CGROUP_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

struct lxc_handler;
struct lxc_conf;
struct lxc_list;

typedef enum {
	CGFS,
	CGMANAGER,
	CGFSNG,
} cgroup_driver_t;

struct cgroup_ops {
	const char *name;

	void *(*init)(const char *name);
	void (*destroy)(void *hdata, struct lxc_conf *conf);
	bool (*create)(void *hdata);
	bool (*enter)(void *hdata, pid_t pid);
	bool (*create_legacy)(void *hdata, pid_t pid);
	const char *(*get_cgroup)(void *hdata, const char *subsystem);
	const char *(*canonical_path)(void *hdata);
	bool (*escape)();
	int (*set)(const char *filename, const char *value, const char *name, const char *lxcpath);
	int (*get)(const char *filename, char *value, size_t len, const char *name, const char *lxcpath);
	bool (*unfreeze)(void *hdata);
	bool (*setup_limits)(void *hdata, struct lxc_list *cgroup_conf, bool with_devices);
	bool (*chown)(void *hdata, struct lxc_conf *conf);
	bool (*attach)(const char *name, const char *lxcpath, pid_t pid);
	bool (*mount_cgroup)(void *hdata, const char *root, int type);
	int (*nrtasks)(void *hdata);
	void (*disconnect)(void);
	cgroup_driver_t driver;
};

extern bool cgroup_attach(const char *name, const char *lxcpath, pid_t pid);
extern bool cgroup_mount(const char *root, struct lxc_handler *handler, int type);
extern void cgroup_destroy(struct lxc_handler *handler);
extern bool cgroup_init(struct lxc_handler *handler);
extern bool cgroup_create(struct lxc_handler *handler);
extern bool cgroup_setup_limits(struct lxc_handler *handler, bool with_devices);
extern bool cgroup_chown(struct lxc_handler *handler);
extern bool cgroup_enter(struct lxc_handler *handler);
extern void cgroup_cleanup(struct lxc_handler *handler);
extern bool cgroup_create_legacy(struct lxc_handler *handler);
extern int cgroup_nrtasks(struct lxc_handler *handler);
extern const char *cgroup_get_cgroup(struct lxc_handler *handler, const char *subsystem);
extern bool cgroup_escape();

/*
 * Currently, this call  only makes sense for privileged containers.
 */
extern const char *cgroup_canonical_path(struct lxc_handler *handler);
extern bool cgroup_unfreeze(struct lxc_handler *handler);
extern void cgroup_disconnect(void);
extern cgroup_driver_t cgroup_driver(void);

extern void prune_init_scope(char *cg);
extern bool is_crucial_cgroup_subsystem(const char *s);

#endif

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
        CGROUP_LAYOUT_UNKNOWN = -1,
        CGROUP_LAYOUT_LEGACY  =  0,
        CGROUP_LAYOUT_HYBRID  =  1,
        CGROUP_LAYOUT_UNIFIED =  2,
} cgroup_layout_t;

/* A descriptor for a mounted hierarchy
 *
 * @controllers
 * - legacy hierarchy
 *   Either NULL, or a null-terminated list of all the co-mounted controllers.
 * - unified hierarchy
 *   Either NULL, or a null-terminated list of all enabled controllers.
 *
 * @mountpoint
 * - The mountpoint we will use.
 * - legacy hierarchy
 *   It will be either /sys/fs/cgroup/controller or
 *   /sys/fs/cgroup/controllerlist.
 * - unified hierarchy
 *   It will either be /sys/fs/cgroup or /sys/fs/cgroup/<mountpoint-name>
 *   depending on whether this is a hybrid cgroup layout (mix of legacy and
 *   unified hierarchies) or a pure unified cgroup layout.
 *
 * @base_cgroup
 * - The cgroup under which the container cgroup path
 *   is created. This will be either the caller's cgroup (if not root), or
 *   init's cgroup (if root).
 *
 * @fullcgpath
 * - The full path to the containers cgroup.
 *
 * @version
 * - legacy hierarchy
 *   If the hierarchy is a legacy hierarchy this will be set to
 *   CGROUP_SUPER_MAGIC.
 * - unified hierarchy
 *   If the hierarchy is a legacy hierarchy this will be set to
 *   CGROUP2_SUPER_MAGIC.
 */
struct hierarchy {
	char **controllers;
	char *mountpoint;
	char *base_cgroup;
	char *fullcgpath;
	int version;
};

struct cgroup_ops {
	/* string constant */
	const char *driver;

	/* string constant */
	const char *version;

	/* What controllers is the container supposed to use. */
	char *cgroup_use;
	char *cgroup_pattern;
	char *container_cgroup;

	/* @hierarchies
	 * - A NULL-terminated array of struct hierarchy, one per legacy
	 *   hierarchy. No duplicates. First sufficient, writeable mounted
	 *   hierarchy wins.
	 */
	struct hierarchy **hierarchies;
	struct hierarchy *unified;

	/*
	 * @cgroup_layout
	 * - What cgroup layout the container is running with.
	 *   - CGROUP_LAYOUT_UNKNOWN
	 *     The cgroup layout could not be determined. This should be treated
	 *     as an error condition.
	 *   - CGROUP_LAYOUT_LEGACY
	 *     The container is running with all controllers mounted into legacy
	 *     cgroup hierarchies.
	 *   - CGROUP_LAYOUT_HYBRID
	 *     The container is running with at least one controller mounted
	 *     into a legacy cgroup hierarchy and a mountpoint for the unified
	 *     hierarchy. The unified hierarchy can be empty (no controllers
	 *     enabled) or non-empty (controllers enabled).
	 *   - CGROUP_LAYOUT_UNIFIED
	 *     The container is running on a pure unified cgroup hierarchy. The
	 *     unified hierarchy can be empty (no controllers enabled) or
	 *     non-empty (controllers enabled).
	 */
	cgroup_layout_t cgroup_layout;

	bool (*data_init)(struct cgroup_ops *ops);
	void (*destroy)(struct cgroup_ops *ops, struct lxc_handler *handler);
	bool (*create)(struct cgroup_ops *ops, struct lxc_handler *handler);
	bool (*enter)(struct cgroup_ops *ops, pid_t pid);
	const char *(*get_cgroup)(struct cgroup_ops *ops, const char *controller);
	bool (*escape)(const struct cgroup_ops *ops);
	int (*num_hierarchies)(struct cgroup_ops *ops);
	bool (*get_hierarchies)(struct cgroup_ops *ops, int n, char ***out);
	int (*set)(struct cgroup_ops *ops, const char *filename,
		   const char *value, const char *name, const char *lxcpath);
	int (*get)(struct cgroup_ops *ops, const char *filename, char *value,
		   size_t len, const char *name, const char *lxcpath);
	bool (*unfreeze)(struct cgroup_ops *ops);
	bool (*setup_limits)(struct cgroup_ops *ops, struct lxc_conf *conf,
			     bool with_devices);
	bool (*chown)(struct cgroup_ops *ops, struct lxc_conf *conf);
	bool (*attach)(struct cgroup_ops *ops, const char *name,
		       const char *lxcpath, pid_t pid);
	bool (*mount)(struct cgroup_ops *ops, struct lxc_handler *handler,
		      const char *root, int type);
	int (*nrtasks)(struct cgroup_ops *ops);
};

extern struct cgroup_ops *cgroup_init(struct lxc_handler *handler);
extern void cgroup_exit(struct cgroup_ops *ops);

extern void prune_init_scope(char *cg);
extern bool is_crucial_cgroup_subsystem(const char *s);

#endif

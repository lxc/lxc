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
#ifndef _ncgroup_h
#define _ncgroup_h
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

struct cgroup_hierarchy;
struct cgroup_meta_data;
struct cgroup_mount_point;

/*
 * cgroup_meta_data: the metadata about the cgroup infrastructure on this
 *                   host
 */
struct cgroup_meta_data {
	ptrdiff_t ref; /* simple refcount */
	struct cgroup_hierarchy **hierarchies;
	struct cgroup_mount_point **mount_points;
	int maximum_hierarchy;
};

/*
 * cgroup_hierarchy: describes a single cgroup hierarchy
 *                   (may have multiple mount points)
 */
struct cgroup_hierarchy {
	int index;
	bool used; /* false if the hierarchy should be ignored by lxc */
	char **subsystems;
	struct cgroup_mount_point *rw_absolute_mount_point;
	struct cgroup_mount_point *ro_absolute_mount_point;
	struct cgroup_mount_point **all_mount_points;
	size_t all_mount_point_capacity;
};

/*
 * cgroup_mount_point: a mount point to where a hierarchy
 *                     is mounted to
 */
struct cgroup_mount_point {
	struct cgroup_hierarchy *hierarchy;
	char *mount_point;
	char *mount_prefix;
	bool read_only;
};

/*
 * cgroup_process_info: describes the membership of a
 *                      process to the different cgroup
 *                      hierarchies
 */
struct cgroup_process_info {
	struct cgroup_process_info *next;
	struct cgroup_meta_data *meta_ref;
	struct cgroup_hierarchy *hierarchy;
	char *cgroup_path;
	char *cgroup_path_sub;
	char **created_paths;
	size_t created_paths_capacity;
	size_t created_paths_count;
	struct cgroup_mount_point *designated_mount_point;
};

/* meta data management:
 *    lxc_cgroup_load_meta  loads the meta data (using subsystem
 *                          whitelist from main lxc configuration)
 *    lxc_cgroup_load_meta2 does the same, but allows one to specify
 *                          a custom whitelist
 *    lxc_cgroup_get_meta   increments the refcount of a meta data
 *                          object
 *    lxc_cgroup_put_meta   decrements the refcount of a meta data
 *                          object, potentially destroying it
 */
extern struct cgroup_meta_data *lxc_cgroup_load_meta();
extern struct cgroup_meta_data *lxc_cgroup_load_meta2(const char **subsystem_whitelist);
extern struct cgroup_meta_data *lxc_cgroup_get_meta(struct cgroup_meta_data *meta_data);
extern struct cgroup_meta_data *lxc_cgroup_put_meta(struct cgroup_meta_data *meta_data);

/* find the hierarchy corresponding to a given subsystem */
extern struct cgroup_hierarchy *lxc_cgroup_find_hierarchy(struct cgroup_meta_data *meta_data, const char *subsystem);

/* find a mount point for a given hierarchy that has access to the cgroup in 'cgroup' and (if wanted) is writable */
extern struct cgroup_mount_point *lxc_cgroup_find_mount_point(struct cgroup_hierarchy *hierarchy, const char *group, bool should_be_writable);

/* all-in-one: find a mount point for a given hierarchy that has access to the cgroup and return the correct path within */
extern char *lxc_cgroup_find_abs_path(const char *subsystem, const char *group, bool should_be_writable, const char *suffix);

/* determine the cgroup membership of a given process */
extern struct cgroup_process_info *lxc_cgroup_process_info_get(pid_t pid, struct cgroup_meta_data *meta);
extern struct cgroup_process_info *lxc_cgroup_process_info_get_init(struct cgroup_meta_data *meta);
extern struct cgroup_process_info *lxc_cgroup_process_info_get_self(struct cgroup_meta_data *meta);

/* create a new cgroup */
extern struct cgroup_process_info *lxc_cgroup_create(const char *name, const char *path_pattern, struct cgroup_meta_data *meta_data, const char *sub_pattern);

/* get the cgroup membership of a given container */
extern struct cgroup_process_info *lxc_cgroup_get_container_info(const char *name, const char *lxcpath, struct cgroup_meta_data *meta_data);

/* move a processs to the cgroups specified by the membership */
extern int lxc_cgroup_enter(struct cgroup_process_info *info, pid_t pid, bool enter_sub);

/* free process membership information */
extern void lxc_cgroup_process_info_free(struct cgroup_process_info *info);
extern void lxc_cgroup_process_info_free_and_remove(struct cgroup_process_info *info);

struct lxc_handler;
extern char *lxc_cgroup_get_hierarchy_path_handler(const char *subsystem, struct lxc_handler *handler);
extern char *lxc_cgroup_get_hierarchy_path(const char *subsystem, const char *name, const char *lxcpath);
extern char *lxc_cgroup_get_hierarchy_abs_path_handler(const char *subsystem, struct lxc_handler *handler);
extern char *lxc_cgroup_get_hierarchy_abs_path(const char *subsystem, const char *name, const char *lxcpath);
extern int lxc_cgroup_set_handler(const char *filename, const char *value, struct lxc_handler *handler);
extern int lxc_cgroup_get_handler(const char *filename, char *value, size_t len, struct lxc_handler *handler);
extern int lxc_cgroup_set(const char *filename, const char *value, const char *name, const char *lxcpath);
extern int lxc_cgroup_get(const char *filename, char *value, size_t len, const char *name, const char *lxcpath);

/*
 * lxc_cgroup_path_get: Get the absolute pathname for a cgroup
 * file for a running container.
 *
 * @filename  : the file of interest (e.g. "freezer.state") or
 *              the subsystem name (e.g. "freezer") in which case
 *              the directory where the cgroup may be modified
 *              will be returned
 * @name      : name of container to connect to
 * @lxcpath   : the lxcpath in which the container is running
 * 
 * This is the exported function, which determines cgpath from the
 * lxc-start of the @name container running in @lxcpath.
 *
 * Returns path on success, NULL on error. The caller must free()
 * the returned path.
 */
extern char *lxc_cgroup_path_get(const char *subsystem, const char *name,
                                 const char *lxcpath);

struct lxc_list;
extern int lxc_setup_cgroup_without_devices(struct lxc_handler *h, struct lxc_list *cgroup_settings);
extern int lxc_setup_cgroup_devices(struct lxc_handler *h, struct lxc_list *cgroup_settings);

extern int lxc_cgroup_nrtasks_handler(struct lxc_handler *handler);

#endif

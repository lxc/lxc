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
#define _GNU_SOURCE
#include <stdio.h>
#undef _GNU_SOURCE
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/inotify.h>
#include <netinet/in.h>
#include <net/if.h>

#include "error.h"
#include "config.h"
#include "commands.h"
#include "list.h"
#include "conf.h"
#include "utils.h"

#include <lxc/log.h>
#include <lxc/cgroup.h>
#include <lxc/start.h>

#if IS_BIONIC
#include <../include/lxcmntent.h>
#else
#include <mntent.h>
#endif

#ifndef HAVE_GETLINE
#ifdef HAVE_FGETLN
#include <../include/getline.h>
#endif
#endif

lxc_log_define(lxc_cgroup, lxc);

static struct cgroup_process_info *lxc_cgroup_process_info_getx(const char *proc_pid_cgroup_str, struct cgroup_meta_data *meta);
static char **subsystems_from_mount_options(const char *mount_options, char **kernel_list);
static void lxc_cgroup_mount_point_free(struct cgroup_mount_point *mp);
static void lxc_cgroup_hierarchy_free(struct cgroup_hierarchy *h);
static bool is_valid_cgroup(const char *name);
static int create_or_remove_cgroup(bool remove, struct cgroup_mount_point *mp, const char *path);
static int create_cgroup(struct cgroup_mount_point *mp, const char *path);
static int remove_cgroup(struct cgroup_mount_point *mp, const char *path);
static char *cgroup_to_absolute_path(struct cgroup_mount_point *mp, const char *path, const char *suffix);
static struct cgroup_process_info *find_info_for_subsystem(struct cgroup_process_info *info, const char *subsystem);
static int do_cgroup_get(const char *cgroup_path, const char *sub_filename, char *value, size_t len);
static int do_cgroup_set(const char *cgroup_path, const char *sub_filename, const char *value);
static bool cgroup_devices_has_allow_or_deny(struct lxc_handler *h, char *v, bool for_allow);
static int do_setup_cgroup(struct lxc_handler *h, struct lxc_list *cgroup_settings, bool do_devices);
static int cgroup_recursive_task_count(const char *cgroup_path);
static int count_lines(const char *fn);
static int handle_clone_children(struct cgroup_mount_point *mp, char *cgroup_path);

struct cgroup_meta_data *lxc_cgroup_load_meta()
{
	const char *cgroup_use = NULL;
	char **cgroup_use_list = NULL;
	struct cgroup_meta_data *md = NULL;
	int saved_errno;

	errno = 0;
	cgroup_use = lxc_global_config_value("cgroup.use");
	if (!cgroup_use && errno != 0)
		return NULL;
	if (cgroup_use) {
		cgroup_use_list = lxc_string_split_and_trim(cgroup_use, ',');
		if (!cgroup_use_list)
			return NULL;
	}

	md = lxc_cgroup_load_meta2((const char **)cgroup_use_list);
	saved_errno = errno;
	lxc_free_array((void **)cgroup_use_list, free);
	errno = saved_errno;
	return md;
}

struct cgroup_meta_data *lxc_cgroup_load_meta2(const char **subsystem_whitelist)
{
	FILE *proc_cgroups = NULL;
	FILE *proc_self_cgroup = NULL;
	FILE *proc_self_mountinfo = NULL;
	bool all_kernel_subsystems = true;
	bool all_named_subsystems = false;
	struct cgroup_meta_data *meta_data = NULL;
	char **kernel_subsystems = NULL;
	size_t kernel_subsystems_count = 0;
	size_t kernel_subsystems_capacity = 0;
	size_t hierarchy_capacity = 0;
	size_t mount_point_capacity = 0;
	size_t mount_point_count = 0;
	char **tokens = NULL;
	size_t token_capacity = 0;
	char *line = NULL;
	size_t sz = 0;
	int r, saved_errno = 0;

	/* if the subsystem whitelist is not specified, include all
	 * hierarchies that contain kernel subsystems by default but
	 * no hierarchies that only contain named subsystems
	 *
	 * if it is specified, the specifier @all will select all
	 * hierarchies, @kernel will select all hierarchies with
	 * kernel subsystems and @named will select all named
	 * hierarchies
	 */
	all_kernel_subsystems = subsystem_whitelist ?
		(lxc_string_in_array("@kernel", subsystem_whitelist) || lxc_string_in_array("@all", subsystem_whitelist)) :
		true;
	all_named_subsystems = subsystem_whitelist ?
		(lxc_string_in_array("@named", subsystem_whitelist) || lxc_string_in_array("@all", subsystem_whitelist)) :
		false;

	meta_data = calloc(1, sizeof(struct cgroup_meta_data));
	if (!meta_data)
		return NULL;
	meta_data->ref = 1;

	/* Step 1: determine all kernel subsystems */
	proc_cgroups = fopen_cloexec("/proc/cgroups", "r");
	if (!proc_cgroups)
		goto out_error;

	while (getline(&line, &sz, proc_cgroups) != -1) {
		char *tab1;
		char *tab2;
		int hierarchy_number;

		if (line[0] == '#')
			continue;
		if (!line[0])
			continue;

		tab1 = strchr(line, '\t');
		if (!tab1)
			continue;  
		*tab1++ = '\0';
		tab2 = strchr(tab1, '\t');
		if (!tab2)
			continue;
		*tab2 = '\0';

		tab2 = NULL;
		hierarchy_number = strtoul(tab1, &tab2, 10);
		if (!tab2 || *tab2)
			continue;
		(void)hierarchy_number;

		r = lxc_grow_array((void ***)&kernel_subsystems, &kernel_subsystems_capacity, kernel_subsystems_count + 1, 12);
		if (r < 0)
			goto out_error;
		kernel_subsystems[kernel_subsystems_count] = strdup(line);
		if (!kernel_subsystems[kernel_subsystems_count])
			goto out_error;
		kernel_subsystems_count++;
	}

	fclose(proc_cgroups);
	proc_cgroups = NULL;

	/* Step 2: determine all hierarchies (by reading /proc/self/cgroup),
	 *         since mount points don't specify hierarchy number and
	 *         /proc/cgroups does not contain named hierarchies
	 */
	proc_self_cgroup = fopen_cloexec("/proc/self/cgroup", "r");
	/* if for some reason (because of setns() and pid namespace for example),
	 * /proc/self is not valid, we try /proc/1/cgroup... */
	if (!proc_self_cgroup)
		proc_self_cgroup = fopen_cloexec("/proc/1/cgroup", "r");
	if (!proc_self_cgroup)
		goto out_error;

	while (getline(&line, &sz, proc_self_cgroup) != -1) {
		/* file format: hierarchy:subsystems:group,
		 * we only extract hierarchy and subsystems
		 * here */
		char *colon1;
		char *colon2;
		int hierarchy_number;
		struct cgroup_hierarchy *h = NULL;
		char **p;

		if (!line[0])
			continue;

		colon1 = strchr(line, ':');
		if (!colon1)
			continue;  
		*colon1++ = '\0';
		colon2 = strchr(colon1, ':');
		if (!colon2)
			continue;
		*colon2 = '\0';

		colon2 = NULL;
		hierarchy_number = strtoul(line, &colon2, 10);
		if (!colon2 || *colon2)
			continue;

		if (hierarchy_number > meta_data->maximum_hierarchy) {
			/* lxc_grow_array will never shrink, so even if we find a lower
			* hierarchy number here, the array will never be smaller
			*/
			r = lxc_grow_array((void ***)&meta_data->hierarchies, &hierarchy_capacity, hierarchy_number + 1, 12);
			if (r < 0)
				goto out_error;

			meta_data->maximum_hierarchy = hierarchy_number;
		}

		/* this shouldn't happen, we had this already */
		if (meta_data->hierarchies[hierarchy_number])
			goto out_error;

		h = calloc(1, sizeof(struct cgroup_hierarchy));
		if (!h)
			goto out_error;

		meta_data->hierarchies[hierarchy_number] = h;

		h->index = hierarchy_number;
		h->subsystems = lxc_string_split_and_trim(colon1, ',');
		if (!h->subsystems)
			goto out_error;
		/* see if this hierarchy should be considered */
		if (!all_kernel_subsystems || !all_named_subsystems) {
			for (p = h->subsystems; *p; p++) {
				if (!strncmp(*p, "name=", 5)) {
					if (all_named_subsystems || (subsystem_whitelist && lxc_string_in_array(*p, subsystem_whitelist))) {
						h->used = true;
						break;
					}
				} else {
					if (all_kernel_subsystems || (subsystem_whitelist && lxc_string_in_array(*p, subsystem_whitelist))) {
						h->used = true;
						break;
					}
				}
			}
		} else {
			/* we want all hierarchy anyway */
			h->used = true;
		}
	}

	fclose(proc_self_cgroup);
	proc_self_cgroup = NULL;
	
	/* Step 3: determine all mount points of each hierarchy */
	proc_self_mountinfo = fopen_cloexec("/proc/self/mountinfo", "r");
	/* if for some reason (because of setns() and pid namespace for example),
	 * /proc/self is not valid, we try /proc/1/cgroup... */
	if (!proc_self_mountinfo)
		proc_self_mountinfo = fopen_cloexec("/proc/1/mountinfo", "r");
	if (!proc_self_mountinfo)
		goto out_error;

	while (getline(&line, &sz, proc_self_mountinfo) != -1) {
		char *token, *saveptr = NULL;
		size_t i, j, k;
		struct cgroup_mount_point *mount_point;
		struct cgroup_hierarchy *h;
		char **subsystems;

		if (line[0] && line[strlen(line) - 1] == '\n')
			line[strlen(line) - 1] = '\0';

		for (i = 0; (token = strtok_r(line, " ", &saveptr)); line = NULL) {
			r = lxc_grow_array((void ***)&tokens, &token_capacity, i + 1, 64);
			if (r < 0)
				goto out_error;
			tokens[i++] = token;
		}

		/* layout of /proc/self/mountinfo:
		 *      0: id
		 *      1: parent id
		 *      2: device major:minor
		 *      3: mount prefix
		 *      4: mount point 
		 *      5: per-mount options
		 *    [optional X]: additional data
		 *    X+7: "-"
		 *    X+8: type
		 *    X+9: source
		 *    X+10: per-superblock options
		 */
		for (j = 6; j < i && tokens[j]; j++)
			if (!strcmp(tokens[j], "-"))
				break;

		/* could not find separator */
		if (j >= i || !tokens[j])
			continue;
		/* there should be exactly three fields after
		 * the separator
		 */
		if (i != j + 4)
			continue;

		/* not a cgroup filesystem */
		if (strcmp(tokens[j + 1], "cgroup") != 0)
			continue;

		subsystems = subsystems_from_mount_options(tokens[j + 3], kernel_subsystems);
		if (!subsystems)
			goto out_error;

		h = NULL;
		for (k = 1; k <= meta_data->maximum_hierarchy; k++) {
			if (meta_data->hierarchies[k] &&
			    meta_data->hierarchies[k]->subsystems[0] &&
			    lxc_string_in_array(meta_data->hierarchies[k]->subsystems[0], (const char **)subsystems)) {
				/* TODO: we could also check if the lists really match completely,
				 *       just to have an additional sanity check */
				h = meta_data->hierarchies[k];
				break;
			}
		}
		lxc_free_array((void **)subsystems, free);

		r = lxc_grow_array((void ***)&meta_data->mount_points, &mount_point_capacity, mount_point_count + 1, 12);
		if (r < 0)
			goto out_error;

		/* create mount point object */
		mount_point = calloc(1, sizeof(*mount_point));
		if (!mount_point)
			goto out_error;

		meta_data->mount_points[mount_point_count++] = mount_point;

		mount_point->hierarchy = h;
		mount_point->mount_point = strdup(tokens[4]);
		mount_point->mount_prefix = strdup(tokens[3]);
		if (!mount_point->mount_point || !mount_point->mount_prefix)
			goto out_error;
		mount_point->read_only = !lxc_string_in_list("rw", tokens[5], ',');

		if (!strcmp(mount_point->mount_prefix, "/")) {
			if (mount_point->read_only) {
				if (!h->ro_absolute_mount_point)
					h->ro_absolute_mount_point = mount_point;
			} else {
				if (!h->rw_absolute_mount_point)
					h->rw_absolute_mount_point = mount_point;
			}
		}

		k = lxc_array_len((void **)h->all_mount_points);
		r = lxc_grow_array((void ***)&h->all_mount_points, &h->all_mount_point_capacity, k + 1, 4);
		if (r < 0)
			goto out_error;
		h->all_mount_points[k] = mount_point;
	}

	/* oops, we couldn't find anything */
	if (!meta_data->hierarchies || !meta_data->mount_points) {
		errno = EINVAL;
		goto out_error;
	}

	return meta_data;

out_error:
	saved_errno = errno;
	if (proc_cgroups)
		fclose(proc_cgroups);
	if (proc_self_cgroup)
		fclose(proc_self_cgroup);
	if (proc_self_mountinfo)
		fclose(proc_self_mountinfo);
	free(line);
	free(tokens);
	lxc_free_array((void **)kernel_subsystems, free);
	lxc_cgroup_put_meta(meta_data);
	errno = saved_errno;
	return NULL;
}

struct cgroup_meta_data *lxc_cgroup_get_meta(struct cgroup_meta_data *meta_data)
{
	meta_data->ref++;
	return meta_data;
}

struct cgroup_meta_data *lxc_cgroup_put_meta(struct cgroup_meta_data *meta_data)
{
	size_t i;
	if (!meta_data)
		return NULL;
	if (--meta_data->ref > 0)
		return meta_data;
	lxc_free_array((void **)meta_data->mount_points, (lxc_free_fn)lxc_cgroup_mount_point_free);
	if (meta_data->hierarchies) {
		for (i = 0; i <= meta_data->maximum_hierarchy; i++)
			lxc_cgroup_hierarchy_free(meta_data->hierarchies[i]);
	}
	free(meta_data->hierarchies);
	return NULL;
}

struct cgroup_hierarchy *lxc_cgroup_find_hierarchy(struct cgroup_meta_data *meta_data, const char *subsystem)
{
	size_t i;
	for (i = 0; i <= meta_data->maximum_hierarchy; i++) {
		struct cgroup_hierarchy *h = meta_data->hierarchies[i];
		if (h && lxc_string_in_array(subsystem, (const char **)h->subsystems))
			return h;
	}
	return NULL;
}

struct cgroup_mount_point *lxc_cgroup_find_mount_point(struct cgroup_hierarchy *hierarchy, const char *group, bool should_be_writable)
{
	struct cgroup_mount_point **mps;
	struct cgroup_mount_point *current_result = NULL;
	ssize_t quality = -1;

	/* trivial case */
	if (hierarchy->rw_absolute_mount_point)
		return hierarchy->rw_absolute_mount_point;
	if (!should_be_writable && hierarchy->ro_absolute_mount_point)
		return hierarchy->ro_absolute_mount_point;

	for (mps = hierarchy->all_mount_points; mps && *mps; mps++) {
		struct cgroup_mount_point *mp = *mps;
		size_t prefix_len = mp->mount_prefix ? strlen(mp->mount_prefix) : 0;

		if (prefix_len == 1 && mp->mount_prefix[0] == '/')
			prefix_len = 0;

		if (should_be_writable && mp->read_only)
			continue;

		if (!prefix_len ||
		    (strncmp(group, mp->mount_prefix, prefix_len) == 0 &&
		     (group[prefix_len] == '\0' || group[prefix_len] == '/'))) {
			/* search for the best quality match, i.e. the match with the
			 * shortest prefix where this group is still contained
			 */
			if (quality == -1 || prefix_len < quality) {
				current_result = mp;
				quality = prefix_len;
			}
		}
	}

	if (!current_result)
		errno = ENOENT;
	return current_result;
}

char *lxc_cgroup_find_abs_path(const char *subsystem, const char *group, bool should_be_writable, const char *suffix)
{
	struct cgroup_meta_data *meta_data;
	struct cgroup_hierarchy *h;
	struct cgroup_mount_point *mp;
	char *result;
	int saved_errno;

	meta_data = lxc_cgroup_load_meta();
	if (!meta_data)
		return NULL;

	h = lxc_cgroup_find_hierarchy(meta_data, subsystem);
	if (!h)
		goto out_error;

	mp = lxc_cgroup_find_mount_point(h, group, should_be_writable);
	if (!mp)
		goto out_error;

	result = cgroup_to_absolute_path(mp, group, suffix);
	if (!result)
		goto out_error;

	lxc_cgroup_put_meta(meta_data);
	return result;

out_error:
	saved_errno = errno;
	lxc_cgroup_put_meta(meta_data);
	errno = saved_errno;
	return NULL;
}

struct cgroup_process_info *lxc_cgroup_process_info_get(pid_t pid, struct cgroup_meta_data *meta)
{
	char pid_buf[32];
	snprintf(pid_buf, 32, "/proc/%lu/cgroup", (unsigned long)pid);
	return lxc_cgroup_process_info_getx(pid_buf, meta);
}

struct cgroup_process_info *lxc_cgroup_process_info_get_init(struct cgroup_meta_data *meta)
{
	return lxc_cgroup_process_info_get(1, meta);
}

struct cgroup_process_info *lxc_cgroup_process_info_get_self(struct cgroup_meta_data *meta)
{
	struct cgroup_process_info *i;
	i = lxc_cgroup_process_info_getx("/proc/self/cgroup", meta);
	if (!i)
		i = lxc_cgroup_process_info_get(getpid(), meta);
	return i;
}

/* create a new cgroup */
extern struct cgroup_process_info *lxc_cgroup_create(const char *name, const char *path_pattern, struct cgroup_meta_data *meta_data, const char *sub_pattern)
{
	char **cgroup_path_components;
	char **p = NULL;
	char *path_so_far = NULL;
	char **new_cgroup_paths = NULL;
	char **new_cgroup_paths_sub = NULL;
	struct cgroup_mount_point *mp;
	struct cgroup_hierarchy *h;
	struct cgroup_process_info *base_info = NULL;
	struct cgroup_process_info *info_ptr;
	int saved_errno;
	int r;
	unsigned suffix = 0;
	bool had_sub_pattern = false;
	size_t i;

	if (!is_valid_cgroup(name)) {
		ERROR("Invalid cgroup name: '%s'", name);
		errno = EINVAL;
		return NULL;
	}

	if (!strstr(path_pattern, "%n")) {
		ERROR("Invalid cgroup path pattern: '%s'; contains no %%n for specifying container name", path_pattern);
		errno = EINVAL;
		return NULL;
	}

	/* we will modify the result of this operation directly,
	 * so we don't have to copy the data structure
	 */
	base_info = (path_pattern[0] == '/') ?
		lxc_cgroup_process_info_get_init(meta_data) :
		lxc_cgroup_process_info_get_self(meta_data);
	if (!base_info)
		return NULL;

	new_cgroup_paths = calloc(meta_data->maximum_hierarchy + 1, sizeof(char *));
	if (!new_cgroup_paths)
		goto out_initial_error;

	new_cgroup_paths_sub = calloc(meta_data->maximum_hierarchy + 1, sizeof(char *));
	if (!new_cgroup_paths_sub)
		goto out_initial_error;

	/* find mount points we can use */
	for (info_ptr = base_info; info_ptr; info_ptr = info_ptr->next) {
		h = info_ptr->hierarchy;
		mp = lxc_cgroup_find_mount_point(h, info_ptr->cgroup_path, true);
		if (!mp) {
			ERROR("Could not find writable mount point for cgroup hierarchy %d while trying to create cgroup.", h->index);
			goto out_initial_error;
		}
		info_ptr->designated_mount_point = mp;

		if (handle_clone_children(mp, info_ptr->cgroup_path) < 0) {
			ERROR("Could not set clone_children to 1 for cpuset hierarchy in parent cgroup.");
			goto out_initial_error;
		}
	}

	/* normalize the path */
	cgroup_path_components = lxc_normalize_path(path_pattern);
	if (!cgroup_path_components)
		goto out_initial_error;

	/* go through the path components to see if we can create them */
	for (p = cgroup_path_components; *p || (sub_pattern && !had_sub_pattern); p++) {
		/* we only want to create the same component with -1, -2, etc.
		 * if the component contains the container name itself, otherwise
		 * it's not an error if it already exists
		 */
		char *p_eff = *p ? *p : (char *)sub_pattern;
		bool contains_name = strstr(p_eff, "%n");
		char *current_component = NULL;
		char *current_subpath = NULL;
		char *current_entire_path = NULL;
		char *parts[3];
		size_t j = 0;
		i = 0;

		/* if we are processing the subpattern, we want to make sure
		 * loop is ended the next time around
		 */
		if (!*p) {
			had_sub_pattern = true;
			p--;
		}

		goto find_name_on_this_level;
	
	cleanup_name_on_this_level:
		/* This is reached if we found a name clash.
		 * In that case, remove the cgroup from all previous hierarchies
		 */
		for (j = 0, info_ptr = base_info; j < i && info_ptr; info_ptr = info_ptr->next, j++) {
			r = remove_cgroup(info_ptr->designated_mount_point, info_ptr->created_paths[info_ptr->created_paths_count - 1]);
			if (r < 0)
				WARN("could not clean up cgroup we created when trying to create container");
			free(info_ptr->created_paths[info_ptr->created_paths_count - 1]);
			info_ptr->created_paths[--info_ptr->created_paths_count] = NULL;
		}
		if (current_component != current_subpath)
			free(current_subpath);
		if (current_component != p_eff)
			free(current_component);
		current_component = current_subpath = NULL;
		/* try again with another suffix */
		++suffix;
	
	find_name_on_this_level:
		/* determine name of the path component we should create */
		if (contains_name && suffix > 0) {
			char *buf = calloc(strlen(name) + 32, 1);
			if (!buf)
				goto out_initial_error;
			snprintf(buf, strlen(name) + 32, "%s-%u", name, suffix);
			current_component = lxc_string_replace("%n", buf, p_eff);
			free(buf);
		} else {
			current_component = contains_name ? lxc_string_replace("%n", name, p_eff) : p_eff;
		}
		parts[0] = path_so_far;
		parts[1] = current_component;
		parts[2] = NULL;
		current_subpath = path_so_far ? lxc_string_join("/", (const char **)parts, false) : current_component;

		/* Now go through each hierarchy and try to create the
		 * corresponding cgroup
		 */
		for (i = 0, info_ptr = base_info; info_ptr; info_ptr = info_ptr->next, i++) {
			char *parts2[3];
			current_entire_path = NULL;

			parts2[0] = !strcmp(info_ptr->cgroup_path, "/") ? "" : info_ptr->cgroup_path;
			parts2[1] = current_subpath;
			parts2[2] = NULL;
			current_entire_path = lxc_string_join("/", (const char **)parts2, false);

			if (!*p) {
				/* we are processing the subpath, so only update that one */
				free(new_cgroup_paths_sub[i]);
				new_cgroup_paths_sub[i] = strdup(current_entire_path);
				if (!new_cgroup_paths_sub[i])
					goto cleanup_from_error;
			} else {
				/* remember which path was used on this controller */
				free(new_cgroup_paths[i]);
				new_cgroup_paths[i] = strdup(current_entire_path);
				if (!new_cgroup_paths[i])
					goto cleanup_from_error;
			}

			r = create_cgroup(info_ptr->designated_mount_point, current_entire_path);
			if (r < 0 && errno == EEXIST && contains_name) {
				/* name clash => try new name with new suffix */
				free(current_entire_path);
				current_entire_path = NULL;
				goto cleanup_name_on_this_level;
			} else if (r < 0 && errno != EEXIST) {
				SYSERROR("Could not create cgroup %s", current_entire_path);
				goto cleanup_from_error;
			} else if (r == 0) {
				/* successfully created */
				r = lxc_grow_array((void ***)&info_ptr->created_paths, &info_ptr->created_paths_capacity, info_ptr->created_paths_count + 1, 8);
				if (r < 0)
					goto cleanup_from_error;
				info_ptr->created_paths[info_ptr->created_paths_count++] = current_entire_path;
			} else {
				/* if we didn't create the cgroup, then we have to make sure that
				 * further cgroups will be created properly
				 */
				if (handle_clone_children(mp, info_ptr->cgroup_path) < 0) {
					ERROR("Could not set clone_children to 1 for cpuset hierarchy in pre-existing cgroup.");
					goto cleanup_from_error;
				}

				/* already existed but path component of pattern didn't contain '%n',
				 * so this is not an error; but then we don't need current_entire_path
				 * anymore...
				 */
				free(current_entire_path);
				current_entire_path = NULL;
			}
		}

		/* save path so far */
		free(path_so_far);
		path_so_far = strdup(current_subpath);
		if (!path_so_far)
			goto cleanup_from_error;

		/* cleanup */
		if (current_component != current_subpath)
			free(current_subpath);
		if (current_component != p_eff)
			free(current_component);
		current_component = current_subpath = NULL;
		continue;
	
	cleanup_from_error:
		/* called if an error occured in the loop, so we
		 * do some additional cleanup here
		 */
		saved_errno = errno;
		if (current_component != current_subpath)
			free(current_subpath);
		if (current_component != p_eff)
			free(current_component);
		free(current_entire_path);
		errno = saved_errno;
		goto out_initial_error;
	}

	/* we're done, now update the paths */
	for (i = 0, info_ptr = base_info; info_ptr; info_ptr = info_ptr->next, i++) {
		free(info_ptr->cgroup_path);
		info_ptr->cgroup_path = new_cgroup_paths[i];
		info_ptr->cgroup_path_sub = new_cgroup_paths_sub[i];
	}
	/* don't use lxc_free_array since we used the array members
	 * to store them in our result...
	 */
	free(new_cgroup_paths);
	free(new_cgroup_paths_sub);
	free(path_so_far);
	lxc_free_array((void **)cgroup_path_components, free);
	return base_info;

out_initial_error:
	saved_errno = errno;
	free(path_so_far);
	lxc_cgroup_process_info_free_and_remove(base_info);
	lxc_free_array((void **)new_cgroup_paths, free);
	lxc_free_array((void **)new_cgroup_paths_sub, free);
	lxc_free_array((void **)cgroup_path_components, free);
	errno = saved_errno;
	return NULL;
}

/* get the cgroup membership of a given container */
struct cgroup_process_info *lxc_cgroup_get_container_info(const char *name, const char *lxcpath, struct cgroup_meta_data *meta_data)
{
	struct cgroup_process_info *result = NULL;
	int saved_errno = 0;
	size_t i;
	struct cgroup_process_info **cptr = &result;
	struct cgroup_process_info *entry = NULL;
	char *path = NULL;

	for (i = 0; i <= meta_data->maximum_hierarchy; i++) {
		struct cgroup_hierarchy *h = meta_data->hierarchies[i];
		if (!h || !h->used)
			continue;

		/* use the command interface to look for the cgroup */
		path = lxc_cmd_get_cgroup_path(name, lxcpath, h->subsystems[0]);
		if (!path)
			goto out_error;

		entry = calloc(1, sizeof(struct cgroup_process_info));
		if (!entry)
			goto out_error;
		entry->meta_ref = lxc_cgroup_get_meta(meta_data);
		entry->hierarchy = h;
		entry->cgroup_path = path;
		path = NULL;

		/* it is not an error if we don't find anything here,
		 * it is up to the caller to decide what to do in that
		 * case */
		entry->designated_mount_point = lxc_cgroup_find_mount_point(h, entry->cgroup_path, true);

		*cptr = entry;
		cptr = &entry->next;
		entry = NULL;
	}

	return result;
out_error:
	saved_errno = errno;
	free(path);
	lxc_cgroup_process_info_free(result);
	lxc_cgroup_process_info_free(entry);
	errno = saved_errno;
	return NULL;
}

/* move a processs to the cgroups specified by the membership */
int lxc_cgroup_enter(struct cgroup_process_info *info, pid_t pid, bool enter_sub)
{
	char pid_buf[32];
	char *cgroup_tasks_fn;
	int r;
	struct cgroup_process_info *info_ptr;

	snprintf(pid_buf, 32, "%lu", (unsigned long)pid);
	for (info_ptr = info; info_ptr; info_ptr = info_ptr->next) {
		char *cgroup_path = (enter_sub && info_ptr->cgroup_path_sub) ?
			info_ptr->cgroup_path_sub :
			info_ptr->cgroup_path;

		if (!info_ptr->designated_mount_point) {
			info_ptr->designated_mount_point = lxc_cgroup_find_mount_point(info_ptr->hierarchy, cgroup_path, true);
			if (!info_ptr->designated_mount_point) {
				SYSERROR("Could not add pid %lu to cgroup %s: internal error (couldn't find any writable mountpoint to cgroup filesystem)", (unsigned long)pid, cgroup_path);
				return -1;
			}
		}

		cgroup_tasks_fn = cgroup_to_absolute_path(info_ptr->designated_mount_point, cgroup_path, "/tasks");
		if (!cgroup_tasks_fn) {
			SYSERROR("Could not add pid %lu to cgroup %s: internal error", (unsigned long)pid, cgroup_path);
			return -1;
		}

		r = lxc_write_to_file(cgroup_tasks_fn, pid_buf, strlen(pid_buf), false);
		if (r < 0) {
			SYSERROR("Could not add pid %lu to cgroup %s: internal error", (unsigned long)pid, cgroup_path);
			return -1;
		}
	}

	return 0;
}

/* free process membership information */
void lxc_cgroup_process_info_free(struct cgroup_process_info *info)
{
	struct cgroup_process_info *next;
	if (!info)
		return;
	next = info->next;
	lxc_cgroup_put_meta(info->meta_ref);
	free(info->cgroup_path);
	free(info->cgroup_path_sub);
	lxc_free_array((void **)info->created_paths, free);
	free(info);
	lxc_cgroup_process_info_free(next);
}

/* free process membership information and remove cgroups that were created */
void lxc_cgroup_process_info_free_and_remove(struct cgroup_process_info *info)
{
	struct cgroup_process_info *next;
	char **pp;
	if (!info)
		return;
	next = info->next;
	for (pp = info->created_paths; pp && *pp; pp++);
	for ((void)(pp && --pp); info->created_paths && pp >= info->created_paths; --pp) {
		struct cgroup_mount_point *mp = info->designated_mount_point;
		if (!mp)
			mp = lxc_cgroup_find_mount_point(info->hierarchy, info->cgroup_path, true);
		if (mp)
			/* ignore return value here, perhaps we created the
			 * '/lxc' cgroup in this container but another container
			 * is still running (for example)
			 */
			(void)remove_cgroup(mp, *pp);
		free(*pp);
	}
	free(info->created_paths);
	lxc_cgroup_put_meta(info->meta_ref);
	free(info->cgroup_path);
	free(info->cgroup_path_sub);
	free(info);
	lxc_cgroup_process_info_free(next);
}

char *lxc_cgroup_get_hierarchy_path_handler(const char *subsystem, struct lxc_handler *handler)
{
	struct cgroup_process_info *info = find_info_for_subsystem(handler->cgroup, subsystem);
	if (!info)
		return NULL;
	return info->cgroup_path;
}

char *lxc_cgroup_get_hierarchy_path(const char *subsystem, const char *name, const char *lxcpath)
{
	return lxc_cmd_get_cgroup_path(name, lxcpath, subsystem);
}

char *lxc_cgroup_get_hierarchy_abs_path_handler(const char *subsystem, struct lxc_handler *handler)
{
	struct cgroup_mount_point *mp = NULL;
	struct cgroup_process_info *info = find_info_for_subsystem(handler->cgroup, subsystem);
	if (!info)
		return NULL;
	if (info->designated_mount_point) {
		mp = info->designated_mount_point; 
	} else {
		mp = lxc_cgroup_find_mount_point(info->hierarchy, info->cgroup_path, true);
		if (!mp)
			return NULL;
	}
	return cgroup_to_absolute_path(mp, info->cgroup_path, NULL);
}

char *lxc_cgroup_get_hierarchy_abs_path(const char *subsystem, const char *name, const char *lxcpath)
{
	struct cgroup_meta_data *meta;
	struct cgroup_process_info *base_info, *info;
	struct cgroup_mount_point *mp;
	char *result = NULL;
	int saved_errno;

	meta = lxc_cgroup_load_meta();
	if (!meta)
		return NULL;
	base_info = lxc_cgroup_get_container_info(name, lxcpath, meta);
	if (!base_info)
		return NULL;
	info = find_info_for_subsystem(base_info, subsystem);
	if (!info)
		return NULL;
	if (info->designated_mount_point) {
		mp = info->designated_mount_point; 
	} else {
		mp = lxc_cgroup_find_mount_point(info->hierarchy, info->cgroup_path, true);
		if (!mp)
			return NULL;
	}
	result = cgroup_to_absolute_path(mp, info->cgroup_path, NULL);
	saved_errno = errno;
	lxc_cgroup_process_info_free(base_info);
	lxc_cgroup_put_meta(meta);
	errno = saved_errno;
	return result;
}

int lxc_cgroup_set_handler(const char *filename, const char *value, struct lxc_handler *handler)
{
	char *subsystem = NULL, *p, *path;
	int ret = -1;

	subsystem = alloca(strlen(filename) + 1);
	strcpy(subsystem, filename);
	if ((p = index(subsystem, '.')) != NULL)
		*p = '\0';

	path = lxc_cgroup_get_hierarchy_abs_path_handler(subsystem, handler);
	if (path) {
		ret = do_cgroup_set(path, filename, value);
		free(path);
	}
	return ret;
}

int lxc_cgroup_get_handler(const char *filename, char *value, size_t len, struct lxc_handler *handler)
{
	char *subsystem = NULL, *p, *path;
	int ret = -1;

	subsystem = alloca(strlen(filename) + 1);
	strcpy(subsystem, filename);
	if ((p = index(subsystem, '.')) != NULL)
		*p = '\0';

	path = lxc_cgroup_get_hierarchy_abs_path_handler(subsystem, handler);
	if (path) {
		ret = do_cgroup_get(path, filename, value, len);
		free(path);
	}
	return ret;
}

int lxc_cgroup_set(const char *filename, const char *value, const char *name, const char *lxcpath)
{
	char *subsystem = NULL, *p, *path;
	int ret = -1;

	subsystem = alloca(strlen(filename) + 1);
	strcpy(subsystem, filename);
	if ((p = index(subsystem, '.')) != NULL)
		*p = '\0';

	path = lxc_cgroup_get_hierarchy_abs_path(subsystem, name, lxcpath);
	if (path) {
		ret = do_cgroup_set(path, filename, value);
		free(path);
	}
	return ret;
}

int lxc_cgroup_get(const char *filename, char *value, size_t len, const char *name, const char *lxcpath)
{
	char *subsystem = NULL, *p, *path;
	int ret = -1;

	subsystem = alloca(strlen(filename) + 1);
	strcpy(subsystem, filename);
	if ((p = index(subsystem, '.')) != NULL)
		*p = '\0';

	path = lxc_cgroup_get_hierarchy_abs_path(subsystem, name, lxcpath);
	if (path) {
		ret = do_cgroup_get(path, filename, value, len);
		free(path);
	}
	return ret;
}

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
char *lxc_cgroup_path_get(const char *filename, const char *name,
                          const char *lxcpath)
{
	char *subsystem = NULL, *longer_file = NULL, *p, *group, *path;

	subsystem = alloca(strlen(filename) + 1);
	strcpy(subsystem, filename);
	if ((p = index(subsystem, '.')) != NULL) {
		*p = '\0';
		longer_file = alloca(strlen(filename) + 2);
		longer_file[0] = '/';
		strcpy(longer_file + 1, filename);
	}

	group = lxc_cgroup_get_hierarchy_path(subsystem, name, lxcpath);
	if (!group)
		return NULL;

	path = lxc_cgroup_find_abs_path(subsystem, group, true, *p ? longer_file : NULL);
	free(group);
	return path;
}

int lxc_setup_cgroup_without_devices(struct lxc_handler *h, struct lxc_list *cgroup_settings)
{
	return do_setup_cgroup(h, cgroup_settings, false);
}

int lxc_setup_cgroup_devices(struct lxc_handler *h, struct lxc_list *cgroup_settings)
{
	return do_setup_cgroup(h, cgroup_settings, true);
}

int lxc_cgroup_nrtasks_handler(struct lxc_handler *handler)
{
	struct cgroup_process_info *info = handler->cgroup;
	struct cgroup_mount_point *mp = NULL;
	char *abs_path = NULL;
	int ret;

	if (!info) {
		errno = ENOENT;
		return -1;
	}

	if (info->designated_mount_point) {
		mp = info->designated_mount_point; 
	} else {
		mp = lxc_cgroup_find_mount_point(info->hierarchy, info->cgroup_path, false);
		if (!mp)
			return -1;
	}

	abs_path = cgroup_to_absolute_path(mp, info->cgroup_path, NULL);
	if (!abs_path)
		return -1;

	ret = cgroup_recursive_task_count(abs_path);
	free(abs_path);
	return ret;
}

struct cgroup_process_info *lxc_cgroup_process_info_getx(const char *proc_pid_cgroup_str, struct cgroup_meta_data *meta)
{
	struct cgroup_process_info *result = NULL;
	FILE *proc_pid_cgroup = NULL;
	char *line = NULL;
	size_t sz = 0;
	int saved_errno = 0;
	struct cgroup_process_info **cptr = &result;
	struct cgroup_process_info *entry = NULL;

	proc_pid_cgroup = fopen_cloexec(proc_pid_cgroup_str, "r");
	if (!proc_pid_cgroup)
		return NULL;

	while (getline(&line, &sz, proc_pid_cgroup) != -1) {
		/* file format: hierarchy:subsystems:group */
		char *colon1;
		char *colon2;
		char *endptr;
		int hierarchy_number;
		struct cgroup_hierarchy *h = NULL;

		if (!line[0])
			continue;

		if (line[strlen(line) - 1] == '\n')
			line[strlen(line) - 1] = '\0';

		colon1 = strchr(line, ':');
		if (!colon1)
			continue;  
		*colon1++ = '\0';
		colon2 = strchr(colon1, ':');
		if (!colon2)
			continue;
		*colon2++ = '\0';

		endptr = NULL;
		hierarchy_number = strtoul(line, &endptr, 10);
		if (!endptr || *endptr)
			continue;

		if (hierarchy_number > meta->maximum_hierarchy) {
			/* we encountered a hierarchy we didn't have before,
			 * so probably somebody remounted some stuff in the
			 * mean time...
			 */
			errno = EAGAIN;
			goto out_error;
		}

		h = meta->hierarchies[hierarchy_number];
		if (!h) {
			/* we encountered a hierarchy that was thought to be
			 * dead before, so probably somebody remounted some
			 * stuff in the mean time...
			 */
			errno = EAGAIN;
			goto out_error;
		}

		/* we are told that we should ignore this hierarchy */
		if (!h->used)
			continue;

		entry = calloc(1, sizeof(struct cgroup_process_info));
		if (!entry)
			goto out_error;

		entry->meta_ref = lxc_cgroup_get_meta(meta);
		entry->hierarchy = h;
		entry->cgroup_path = strdup(colon2);
		if (!entry->cgroup_path)
			goto out_error;

		*cptr = entry;
		cptr = &entry->next;
		entry = NULL;
	}

	fclose(proc_pid_cgroup);
	free(line);
	return result;

out_error:
	saved_errno = errno;
	if (proc_pid_cgroup)
		fclose(proc_pid_cgroup);
	lxc_cgroup_process_info_free(result);
	lxc_cgroup_process_info_free(entry);
	free(line);
	errno = saved_errno;
	return NULL;
}

char **subsystems_from_mount_options(const char *mount_options, char **kernel_list)
{
	char *token, *str, *saveptr = NULL;
	char **result = NULL;
	size_t result_capacity = 0;
	size_t result_count = 0;   
	int saved_errno;
	int r;

	str = alloca(strlen(mount_options)+1);
	strcpy(str, mount_options);
	for (; (token = strtok_r(str, ",", &saveptr)); str = NULL) {
		/* we have a subsystem if it's either in the list of
		 * subsystems provided by the kernel OR if it starts
		 * with name= for named hierarchies
		 */
		if (!strncmp(token, "name=", 5) || lxc_string_in_array(token, (const char **)kernel_list)) {
			r = lxc_grow_array((void ***)&result, &result_capacity, result_count + 1, 12);
			if (r < 0)
				goto out_free;
			result[result_count + 1] = NULL;
			result[result_count] = strdup(token);
			if (!result[result_count])
				goto out_free;
			result_count++;
		}
	}

	return result;

out_free:
	saved_errno = errno;
	lxc_free_array((void**)result, free);
	errno = saved_errno;
	return NULL;
}

void lxc_cgroup_mount_point_free(struct cgroup_mount_point *mp)
{
	if (!mp)
		return;
	free(mp->mount_point);
	free(mp->mount_prefix);
	free(mp);
}

void lxc_cgroup_hierarchy_free(struct cgroup_hierarchy *h)
{
	if (!h)
		return;
	lxc_free_array((void **)h->subsystems, free);
	free(h);
}

bool is_valid_cgroup(const char *name)
{
	const char *p;
	for (p = name; *p; p++) {
		if (*p < 32 || *p == 127 || *p == '/')
			return false;
	}
	return strcmp(name, ".") != 0 && strcmp(name, "..") != 0;
}

int create_or_remove_cgroup(bool do_remove, struct cgroup_mount_point *mp, const char *path)
{
	int r, saved_errno = 0;
	char *buf = cgroup_to_absolute_path(mp, path, NULL);
	if (!buf)
		return -1;

	/* create or remove directory */
	r = do_remove ?
		rmdir(buf) :
		mkdir(buf, 0777);
	saved_errno = errno;
	free(buf);
	errno = saved_errno;
	return r;
}

int create_cgroup(struct cgroup_mount_point *mp, const char *path)
{
	return create_or_remove_cgroup(false, mp, path);
}

int remove_cgroup(struct cgroup_mount_point *mp, const char *path)
{
	return create_or_remove_cgroup(true, mp, path);
}

char *cgroup_to_absolute_path(struct cgroup_mount_point *mp, const char *path, const char *suffix)
{
	/* first we have to make sure we subtract the mount point's prefix */
	char *prefix = mp->mount_prefix;
	char *buf;
	ssize_t len, rv;

	/* we want to make sure only absolute paths to cgroups are passed to us */
	if (path[0] != '/') {
		errno = EINVAL;
		return NULL;
	}

	if (prefix && !strcmp(prefix, "/"))
		prefix = NULL;

	/* prefix doesn't match */
	if (prefix && strncmp(prefix, path, strlen(prefix)) != 0) {
		errno = EINVAL;
		return NULL;
	}
	/* if prefix is /foo and path is /foobar */
	if (prefix && path[strlen(prefix)] != '/' && path[strlen(prefix)] != '\0') {
		errno = EINVAL;
		return NULL;
	}

	/* remove prefix from path */
	path += prefix ? strlen(prefix) : 0;

	len = strlen(mp->mount_point) + strlen(path) + (suffix ? strlen(suffix) : 0);
	buf = calloc(len + 1, 1);
	rv = snprintf(buf, len + 1, "%s%s%s", mp->mount_point, path, suffix ? suffix : "");
	if (rv > len) { 
		free(buf);
		errno = ENOMEM;
		return NULL; 
	}

	return buf;
}

struct cgroup_process_info *find_info_for_subsystem(struct cgroup_process_info *info, const char *subsystem)
{
	struct cgroup_process_info *info_ptr;
	for (info_ptr = info; info_ptr; info_ptr = info_ptr->next) {
		struct cgroup_hierarchy *h = info_ptr->hierarchy;
		if (lxc_string_in_array(subsystem, (const char **)h->subsystems))
			return info_ptr;
	}
	errno = ENOENT;
	return NULL;
}

int do_cgroup_get(const char *cgroup_path, const char *sub_filename, char *value, size_t len)
{
	const char *parts[3] = {
		cgroup_path,
		sub_filename,
		NULL
	};
	char *filename;
	int ret, saved_errno;

	filename = lxc_string_join("/", parts, false);
	if (!filename)
		return -1;

	ret = lxc_read_from_file(filename, value, len);
	saved_errno = errno;
	free(filename);
	errno = saved_errno;
	return ret;
}

int do_cgroup_set(const char *cgroup_path, const char *sub_filename, const char *value)
{
	const char *parts[3] = {
		cgroup_path,
		sub_filename,
		NULL
	};
	char *filename;
	int ret, saved_errno;

	filename = lxc_string_join("/", parts, false);
	if (!filename)
		return -1;

	ret = lxc_write_to_file(filename, value, strlen(value), false);
	saved_errno = errno;
	free(filename);
	errno = saved_errno;
	return ret;
}

int do_setup_cgroup(struct lxc_handler *h, struct lxc_list *cgroup_settings, bool do_devices)
{
	struct lxc_list *iterator;
	struct lxc_cgroup *cg;
	int ret = -1;

	if (lxc_list_empty(cgroup_settings))
		return 0;

	lxc_list_for_each(iterator, cgroup_settings) {
		cg = iterator->elem;

		if (do_devices == !strncmp("devices", cg->subsystem, 7)) {
			if (strcmp(cg->subsystem, "devices.deny") == 0 &&
					cgroup_devices_has_allow_or_deny(h, cg->value, false))
				continue;
			if (strcmp(cg->subsystem, "devices.allow") == 0 &&
					cgroup_devices_has_allow_or_deny(h, cg->value, true))
				continue;
			if (lxc_cgroup_set_handler(cg->subsystem, cg->value, h)) {
				ERROR("Error setting %s to %s for %s\n",
				      cg->subsystem, cg->value, h->name);
				goto out;
			}
		}

		DEBUG("cgroup '%s' set to '%s'", cg->subsystem, cg->value);
	}

	ret = 0;
	INFO("cgroup has been setup");
out:
	return ret;
}

bool cgroup_devices_has_allow_or_deny(struct lxc_handler *h, char *v, bool for_allow)
{
	char *path;
	FILE *devices_list;
	char *line = NULL; 
	size_t sz = 0;
	bool ret = !for_allow;
	const char *parts[3] = {
		NULL,
		"devices.list",
		NULL
	};

	// XXX FIXME if users could use something other than 'lxc.devices.deny = a'.
	// not sure they ever do, but they *could*
	// right now, I'm assuming they do NOT
	if (!for_allow && strcmp(v, "a") != 0 && strcmp(v, "a *:* rwm") != 0)
		return false;

	parts[0] = (const char *)lxc_cgroup_get_hierarchy_abs_path_handler("devices", h);
	if (!parts[0])
		return false;
	path = lxc_string_join("/", parts, false);
	if (!path) {
		free((void *)parts[0]);
		return false;
	}

	devices_list = fopen_cloexec(path, "r");
	if (!devices_list) {
		free(path);
		return false;
	}

	while (getline(&line, &sz, devices_list) != -1) {
		size_t len = strlen(line);
		if (len > 0 && line[len-1] == '\n')
			line[len-1] = '\0';
		if (strcmp(line, "a *:* rwm") == 0) {
			ret = for_allow;
			goto out;
		} else if (for_allow && strcmp(line, v) == 0) {
			ret = true;
			goto out;  
		}
	}

out:
	fclose(devices_list);
	free(line);
	free(path);
	return ret;
}

int cgroup_recursive_task_count(const char *cgroup_path)
{
	DIR *d;
	struct dirent *dent_buf;
	struct dirent *dent;
	ssize_t name_max;   
	int n = 0, r;

	/* see man readdir_r(3) */
	name_max = pathconf(cgroup_path, _PC_NAME_MAX);
	if (name_max <= 0)
		name_max = 255;
	dent_buf = malloc(offsetof(struct dirent, d_name) + name_max + 1);
	if (!dent_buf)
		return -1;

	d = opendir(cgroup_path);
	if (!d)
		return 0;

	while (readdir_r(d, dent_buf, &dent) == 0 && dent) {
		const char *parts[3] = {
			cgroup_path,
			dent->d_name,
			NULL
		};
		char *sub_path;
		struct stat st;

		if (!strcmp(dent->d_name, ".") || !strcmp(dent->d_name, ".."))
			continue;
		sub_path = lxc_string_join("/", parts, false);
		if (!sub_path) {
			closedir(d);
			free(dent_buf);
			return -1;
		}
		r = stat(sub_path, &st);
		if (r < 0) {
			closedir(d);
			free(dent_buf);
			free(sub_path);
			return -1;
		}
		if (S_ISDIR(st.st_mode)) {
			r = cgroup_recursive_task_count(sub_path);
			if (r >= 0)
				n += r;
		} else if (!strcmp(dent->d_name, "tasks")) {
			r = count_lines(sub_path);
			if (r >= 0)
				n += r;
		}
		free(sub_path);
	}
	closedir(d);
	free(dent_buf);

	return n;
}

int count_lines(const char *fn)  
{
	FILE *f;
	char *line = NULL;
	size_t sz = 0;
	int n = 0;

	f = fopen_cloexec(fn, "r");
	if (!f)
		return -1;

	while (getline(&line, &sz, f) != -1) {
		n++;
	}
	free(line);
	fclose(f);
	return n;
}

int handle_clone_children(struct cgroup_mount_point *mp, char *cgroup_path)
{
	int r, saved_errno = 0;
	/* if this is a cpuset hierarchy, we have to set cgroup.clone_children in
	 * the base cgroup, otherwise containers will start with an empty cpuset.mems
	 * and cpuset.cpus and then
	 */
	if (lxc_string_in_array("cpuset", (const char **)mp->hierarchy->subsystems)) {
		char *cc_path = cgroup_to_absolute_path(mp, cgroup_path, "/cgroup.clone_children");
		if (!cc_path)
			return -1;
		r = lxc_write_to_file(cc_path, "1", 1, false);
		saved_errno = errno;
		free(cc_path);
		errno = saved_errno;
		return r < 0 ? -1 : 0;
	}
	return 0;
}

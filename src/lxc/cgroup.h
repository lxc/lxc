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
#ifndef _cgroup_h
#define _cgroup_h
#include <stdbool.h>

/*
 * cgroup_desc: describe a container's cgroup membership
 */
struct cgroup_desc {
	char *mntpt; /* where this is mounted */
	char *subsystems; /* comma-separated list of subsystems, or NULL */
	char *curcgroup; /* task's current cgroup, full pathanme */
	char *realcgroup; /* the cgroup as known in /proc/self/cgroup */
	struct cgroup_desc *next;
};

struct lxc_handler;
extern void lxc_cgroup_destroy_desc(struct cgroup_desc *cgroups);
extern char *lxc_cgroup_path_get(const char *subsystem, const char *name,
			      const char *lxcpath);
extern int lxc_cgroup_nrtasks(struct lxc_handler *handler);
struct cgroup_desc *lxc_cgroup_path_create(const char *name);
extern int lxc_cgroup_enter(struct cgroup_desc *cgroups, pid_t pid);
extern int lxc_cgroup_attach(pid_t pid, const char *name, const char *lxcpath);
extern char *cgroup_path_get(const char *subsystem, const char *cgpath);
extern bool get_subsys_mount(char *dest, const char *subsystem);
extern bool is_in_subcgroup(int pid, const char *subsystem, struct cgroup_desc *d);
/*
 * Called by commands.c by a container's monitor to find out the
 * container's cgroup path in a specific subsystem
 */
extern char *cgroup_get_subsys_path(struct lxc_handler *handler, const char *subsys);
struct lxc_list;
extern int setup_cgroup(struct lxc_handler *h, struct lxc_list *cgroups);
extern int setup_cgroup_devices(struct lxc_handler *h, struct lxc_list *cgroups);
#endif

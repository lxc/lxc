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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */
#ifndef _cgroup_h
#define _cgroup_h

#define MAXPRIOLEN 24

struct lxc_handler;
extern int lxc_cgroup_destroy(const char *cgpath);
extern int lxc_cgroup_path_get(char **path, const char *subsystem, const char *name,
			      const char *lxcpath);
extern int lxc_cgroup_nrtasks(const char *cgpath);
extern char *lxc_cgroup_path_create(const char *lxcgroup, const char *name);
extern int lxc_cgroup_enter(const char *cgpath, pid_t pid);
extern int lxc_cgroup_attach(pid_t pid, const char *name, const char *lxcpath);
extern int cgroup_path_get(char **path, const char *subsystem, const char *cgpath);
extern int lxc_get_cgpath(const char **path, const char *subsystem, const char *name, const char *lxcpath);
#endif

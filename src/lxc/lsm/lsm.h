/*
 * lxc: linux Container library
 *
 * Copyright © 2013 Oracle.
 *
 * Authors:
 * Dwight Engen <dwight.engen@oracle.com>
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

#ifndef __lxc_lsm_h
#define __lxc_lsm_h

struct lxc_conf;

#include <sys/types.h>

struct lsm_drv {
	const char *name;

	int   (*enabled)(void);
	char *(*process_label_get)(pid_t pid);
	int   (*process_label_set)(const char *label, struct lxc_conf *conf,
				   int use_default, int on_exec);
};

#if HAVE_APPARMOR || HAVE_SELINUX
void        lsm_init(void);
int         lsm_enabled(void);
const char *lsm_name(void);
char       *lsm_process_label_get(pid_t pid);
int         lsm_process_label_set(const char *label, struct lxc_conf *conf,
		int use_default, int on_exec);
#else
static inline void        lsm_init(void) { }
static inline int         lsm_enabled(void) { return 0; }
static inline const char *lsm_name(void) { return "none"; }
static inline char       *lsm_process_label_get(pid_t pid) { return NULL; }
static inline int         lsm_process_label_set(const char *label,
		struct lxc_conf *conf, int use_default, int on_exec) { return 0; }
#endif

#endif

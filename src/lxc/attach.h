/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2008
 *
 * Authors:
 * Daniel Lezcano <dlezcano at fr.ibm.com>
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

#ifndef _attach_h
#define _attach_h

#include <sys/types.h>

struct lxc_proc_context_info {
	char *aa_profile;
	unsigned long personality;
	unsigned long long capability_mask;
};

extern struct lxc_proc_context_info *lxc_proc_get_context_info(pid_t pid);

extern int lxc_attach_to_ns(pid_t other_pid, int which);
extern int lxc_attach_remount_sys_proc();
extern int lxc_attach_drop_privs(struct lxc_proc_context_info *ctx);

extern char *lxc_attach_getpwshell(uid_t uid);

extern void lxc_attach_get_init_uidgid(uid_t* init_uid, gid_t* init_gid);

#endif

/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2009
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
#ifndef __LXC_NAMESPACE_H
#define __LXC_NAMESPACE_H

#include <sys/syscall.h>
#include <sched.h>

#include "config.h"

#ifndef CLONE_FS
#  define CLONE_FS                0x00000200
#endif
#ifndef CLONE_NEWNS
#  define CLONE_NEWNS             0x00020000
#endif
#ifndef CLONE_NEWCGROUP
#  define CLONE_NEWCGROUP         0x02000000
#endif
#ifndef CLONE_NEWUTS
#  define CLONE_NEWUTS            0x04000000
#endif
#ifndef CLONE_NEWIPC
#  define CLONE_NEWIPC            0x08000000
#endif
#ifndef CLONE_NEWUSER
#  define CLONE_NEWUSER           0x10000000
#endif
#ifndef CLONE_NEWPID
#  define CLONE_NEWPID            0x20000000
#endif
#ifndef CLONE_NEWNET
#  define CLONE_NEWNET            0x40000000
#endif

enum {
	LXC_NS_USER,
	LXC_NS_MNT,
	LXC_NS_PID,
	LXC_NS_UTS,
	LXC_NS_IPC,
	LXC_NS_NET,
	LXC_NS_CGROUP,
	LXC_NS_MAX
};

extern const struct ns_info {
	const char *proc_name;
	int clone_flag;
	const char *flag_name;
} ns_info[LXC_NS_MAX];

#if defined(__ia64__)
int __clone2(int (*__fn) (void *__arg), void *__child_stack_base,
             size_t __child_stack_size, int __flags, void *__arg, ...);
#else
int clone(int (*fn)(void *), void *child_stack,
	int flags, void *arg, ...
	/* pid_t *ptid, struct user_desc *tls, pid_t *ctid */ );
#endif

extern pid_t lxc_clone(int (*fn)(void *), void *arg, int flags);

extern int lxc_namespace_2_cloneflag(const char *namespace);
extern int lxc_namespace_2_ns_idx(const char *namespace);
extern int lxc_fill_namespace_flags(char *flaglist, int *flags);

#endif

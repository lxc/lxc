/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_NAMESPACE_H
#define __LXC_NAMESPACE_H

#include "config.h"

#include <sched.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "compiler.h"

typedef enum lxc_namespace_t {
	LXC_NS_USER	= 0,
	LXC_NS_MNT	= 1,
	LXC_NS_PID	= 2,
	LXC_NS_UTS	= 3,
	LXC_NS_IPC	= 4,
	LXC_NS_NET	= 5,
	LXC_NS_CGROUP	= 6,
	LXC_NS_TIME	= 7,
	LXC_NS_MAX	= 8
} lxc_namespace_t;

__hidden extern const struct ns_info {
#define MAX_NS_PROC_NAME 6
	const char proc_name[MAX_NS_PROC_NAME + 1];
	const char *proc_path;
	int clone_flag;
	const char *flag_name;
	const char *env_name;
} ns_info[LXC_NS_MAX];

__hidden extern int lxc_namespace_2_cloneflag(const char *namespace);
__hidden extern int lxc_namespace_2_ns_idx(const char *namespace);
__hidden extern int lxc_namespace_2_std_identifiers(char *namespaces);
__hidden extern int lxc_fill_namespace_flags(char *flaglist, int *flags);

#endif /* __LXC_NAMESPACE_H */

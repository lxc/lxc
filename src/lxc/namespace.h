/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_NAMESPACE_H
#define __LXC_NAMESPACE_H

#include <sched.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "compiler.h"

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

__hidden extern const struct ns_info {
	const char *proc_name;
	int clone_flag;
	const char *flag_name;
	const char *env_name;
} ns_info[LXC_NS_MAX];

__hidden extern int lxc_namespace_2_cloneflag(const char *namespace);
__hidden extern int lxc_namespace_2_ns_idx(const char *namespace);
__hidden extern int lxc_namespace_2_std_identifiers(char *namespaces);
__hidden extern int lxc_fill_namespace_flags(char *flaglist, int *flags);

#endif /* __LXC_NAMESPACE_H */

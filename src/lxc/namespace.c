/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"
#include "log.h"
#include "memory_utils.h"
#include "namespace.h"
#include "utils.h"

lxc_log_define(namespace, lxc);

/* Leave the user namespace at the first position in the array of structs so
 * that we always attach to it first when iterating over the struct and using
 * setns() to switch namespaces. This especially affects lxc_attach(): Suppose
 * you cloned a new user namespace and mount namespace as an unprivileged user
 * on the host and want to setns() to the mount namespace. This requires you to
 * attach to the user namespace first otherwise the kernel will fail this check:
 *
 *        if (!ns_capable(mnt_ns->user_ns, CAP_SYS_ADMIN) ||
 *            !ns_capable(current_user_ns(), CAP_SYS_CHROOT) ||
 *            !ns_capable(current_user_ns(), CAP_SYS_ADMIN))
 *            return -EPERM;
 *
 *    in
 *
 *        linux/fs/namespace.c:mntns_install().
 */
const struct ns_info ns_info[LXC_NS_MAX] = {
	[LXC_NS_USER]    = { "user",   "ns/user",   CLONE_NEWUSER,   "CLONE_NEWUSER",   "LXC_USER_NS"    },
	[LXC_NS_MNT]    =  { "mnt",    "ns/mnt",    CLONE_NEWNS,     "CLONE_NEWNS",     "LXC_MNT_NS"     },
	[LXC_NS_PID]    =  { "pid",    "ns/pid",    CLONE_NEWPID,    "CLONE_NEWPID",    "LXC_PID_NS"     },
	[LXC_NS_UTS]    =  { "uts",    "ns/uts",    CLONE_NEWUTS,    "CLONE_NEWUTS",    "LXC_UTS_NS"     },
	[LXC_NS_IPC]    =  { "ipc",    "ns/ipc",    CLONE_NEWIPC,    "CLONE_NEWIPC",    "LXC_IPC_NS"     },
	[LXC_NS_NET]    =  { "net",    "ns/net",    CLONE_NEWNET,    "CLONE_NEWNET",    "LXC_NET_NS"     },
	[LXC_NS_CGROUP] =  { "cgroup", "ns/cgroup", CLONE_NEWCGROUP, "CLONE_NEWCGROUP", "LXC_CGROUP_NS"  },
	[LXC_NS_TIME]	=  { "time",   "ns/time",   CLONE_NEWTIME,   "CLONE_NEWTIME",   "LXC_TIME_NS"    },
};

int lxc_namespace_2_cloneflag(const char *namespace)
{
	int i;

	for (i = 0; i < LXC_NS_MAX; i++)
		if (!strcasecmp(ns_info[i].proc_name, namespace))
			return ns_info[i].clone_flag;

	ERROR("Invalid namespace name \"%s\"", namespace);
	return -EINVAL;
}

int lxc_namespace_2_ns_idx(const char *namespace)
{
	for (int i = 0; i < LXC_NS_MAX; i++) {
		if (strequal(ns_info[i].proc_name, namespace))
			return i;
	}

	ERROR("Invalid namespace name \"%s\"", namespace);
	return -EINVAL;
}

extern int lxc_namespace_2_std_identifiers(char *namespaces)
{
	char **it;
	char *del;

	/* The identifiers for namespaces used with lxc-attach and lxc-unshare
	 * as given on the manpage do not align with the standard identifiers.
	 * This affects network, mount, and uts namespaces. The standard identifiers
	 * are: "mnt", "uts", and "net" whereas lxc-attach and lxc-unshare uses
	 * "MOUNT", "UTSNAME", and "NETWORK". So let's use some cheap memmove()s
	 * to replace them by their standard identifiers.
	 * Let's illustrate this with an example:
	 * Assume the string:
	 *
	 *	"IPC|MOUNT|PID"
	 *
	 * then we memmove()
	 *
	 *	dest: del + 1 == OUNT|PID
	 *	src:  del + 3 == NT|PID
	 */
	if (!namespaces)
		return -1;

	while ((del = strstr(namespaces, "MOUNT")))
		memmove(del + 1, del + 3, strlen(del) - 2);

	for (it = (char *[]){"NETWORK", "UTSNAME", NULL}; it && *it; it++)
		while ((del = strstr(namespaces, *it)))
			memmove(del + 3, del + 7, strlen(del) - 6);

	return 0;
}

int lxc_fill_namespace_flags(char *flaglist, int *flags)
{
	char *token;
	int aflag;

	if (!flaglist) {
		ERROR("At least one namespace is needed.");
		return -1;
	}

	lxc_iterate_parts(token, flaglist, "|") {
		aflag = lxc_namespace_2_cloneflag(token);
		if (aflag < 0)
			return -1;

		*flags |= aflag;
	}

	return 0;
}

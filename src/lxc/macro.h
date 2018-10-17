/* liblxcapi
 *
 * Copyright © 2018 Christian Brauner <christian.brauner@ubuntu.com>.
 * Copyright © 2018 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __LXC_MACRO_H
#define __LXC_MACRO_H

#include <asm/types.h>
#include <limits.h>
#include <linux/if_link.h>
#include <linux/loop.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/types.h>
#include <stdint.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* Define __S_ISTYPE if missing from the C library. */
#ifndef __S_ISTYPE
#define __S_ISTYPE(mode, mask) (((mode)&S_IFMT) == (mask))
#endif

/* capabilities */
#ifndef CAP_SYS_ADMIN
#define CAP_SYS_ADMIN 21
#endif

#ifndef CAP_SETFCAP
#define CAP_SETFCAP 31
#endif

#ifndef CAP_MAC_OVERRIDE
#define CAP_MAC_OVERRIDE 32
#endif

#ifndef CAP_MAC_ADMIN
#define CAP_MAC_ADMIN 33
#endif

#ifndef CAP_SETUID
#define CAP_SETUID 7
#endif

#ifndef CAP_SETGID
#define CAP_SETGID 6
#endif

/* prctl */
#ifndef PR_CAPBSET_READ
#define PR_CAPBSET_READ 23
#endif

#ifndef PR_CAPBSET_DROP
#define PR_CAPBSET_DROP 24
#endif

/* Control the ambient capability set */
#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT 47
#endif

#ifndef PR_CAP_AMBIENT_IS_SET
#define PR_CAP_AMBIENT_IS_SET 1
#endif

#ifndef PR_CAP_AMBIENT_RAISE
#define PR_CAP_AMBIENT_RAISE 2
#endif

#ifndef PR_CAP_AMBIENT_LOWER
#define PR_CAP_AMBIENT_LOWER 3
#endif

#ifndef PR_CAP_AMBIENT_CLEAR_ALL
#define PR_CAP_AMBIENT_CLEAR_ALL 4
#endif

#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif

#ifndef PR_GET_NO_NEW_PRIVS
#define PR_GET_NO_NEW_PRIVS 39
#endif

/* filesystem magic values */
#ifndef CGROUP_SUPER_MAGIC
#define CGROUP_SUPER_MAGIC 0x27e0eb
#endif

#ifndef CGROUP2_SUPER_MAGIC
#define CGROUP2_SUPER_MAGIC 0x63677270
#endif

#ifndef NSFS_MAGIC
#define NSFS_MAGIC 0x6e736673
#endif

/* current overlayfs */
#ifndef OVERLAY_SUPER_MAGIC
#define OVERLAY_SUPER_MAGIC 0x794c7630
#endif

/* legacy overlayfs */
#ifndef OVERLAYFS_SUPER_MAGIC
#define OVERLAYFS_SUPER_MAGIC 0x794c764f
#endif

/* Calculate the number of chars needed to represent a given integer as a C
 * string. Include room for '-' to indicate negative numbers and the \0 byte.
 * This is based on systemd.
 */
#define INTTYPE_TO_STRLEN(type)                   \
	(2 + (sizeof(type) <= 1                   \
		  ? 3                             \
		  : sizeof(type) <= 2             \
			? 5                       \
			: sizeof(type) <= 4       \
			      ? 10                \
			      : sizeof(type) <= 8 \
				    ? 20          \
				    : sizeof(int[-2 * (sizeof(type) > 8)])))

/* Useful macros */
#define LXC_LINELEN 4096
#define LXC_IDMAPLEN 4096
#define LXC_MAX_BUFFER 4096

/* /proc/       =    6
 *                +
 * <pid-as-str> =   INTTYPE_TO_STRLEN(pid_t)
 *                +
 * /fd/         =    4
 *                +
 * <fd-as-str>  =   INTTYPE_TO_STRLEN(int)
 *                +
 * \0           =    1
 */
#define LXC_PROC_PID_FD_LEN \
	(6 + INTTYPE_TO_STRLEN(pid_t) + 4 + INTTYPE_TO_STRLEN(int) + 1)

/* /proc/        = 6
 *               +
 * <pid-as-str>  = INTTYPE_TO_STRLEN(pid_t)
 *               +
 * /status       = 7
 *               +
 * \0            = 1
 */
#define LXC_PROC_STATUS_LEN (6 + INTTYPE_TO_STRLEN(pid_t) + 7 + 1)

/* /proc/        = 6
 *               +
 * <pid-as-str>  = INTTYPE_TO_STRLEN(pid_t)
 *               +
 * /attr/        = 6
 *               +
 * /current      = 8
 *               +
 * \0            = 1
 */
#define LXC_LSMATTRLEN (6 + INTTYPE_TO_STRLEN(pid_t) + 6 + 8 + 1)

#define LXC_CMD_DATA_MAX (PATH_MAX * 2)

/* loop devices */
#ifndef LO_FLAGS_AUTOCLEAR
#define LO_FLAGS_AUTOCLEAR 4
#endif

#ifndef LOOP_CTL_GET_FREE
#define LOOP_CTL_GET_FREE 0x4C82
#endif

/* memfd_create() */
#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

#ifndef MFD_ALLOW_SEALING
#define MFD_ALLOW_SEALING 0x0002U
#endif

/**
 * BUILD_BUG_ON - break compile if a condition is true.
 * @condition: the condition which the compiler should know is false.
 *
 * If you have some code which relies on certain constants being equal, or
 * other compile-time-evaluated condition, you should use BUILD_BUG_ON to
 * detect if someone changes it.
 *
 * The implementation uses gcc's reluctance to create a negative array, but
 * gcc (as of 4.4) only emits that error for obvious cases (eg. not arguments
 * to inline functions).  So as a fallback we use the optimizer; if it can't
 * prove the condition is false, it will cause a link error on the undefined
 * "__build_bug_on_failed".  This error message can be harder to track down
 * though, hence the two different methods.
 */
#ifndef __OPTIMIZE__
#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2 * !!(condition)]))
#else
extern int __build_bug_on_failed;
#define BUILD_BUG_ON(condition)                              \
	do {                                                 \
		((void)sizeof(char[1 - 2 * !!(condition)])); \
		if (condition)                               \
			__build_bug_on_failed = 1;           \
	} while (0)
#endif

#define lxc_iterate_parts(__iterator, __splitme, __separators)                  \
	for (char *__p = NULL, *__it = strtok_r(__splitme, __separators, &__p); \
	     (__iterator = __it);                                               \
	     __iterator = __it = strtok_r(NULL, __separators, &__p))

#define prctl_arg(x) ((unsigned long)x)

/* networking */
#ifndef NETLINK_DUMP_STRICT_CHK
#define NETLINK_DUMP_STRICT_CHK 12
#endif

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

#ifndef IFLA_LINKMODE
#define IFLA_LINKMODE 17
#endif

#ifndef IFLA_LINKINFO
#define IFLA_LINKINFO 18
#endif

#ifndef IFLA_NET_NS_PID
#define IFLA_NET_NS_PID 19
#endif

#ifndef IFLA_INFO_KIND
#define IFLA_INFO_KIND 1
#endif

#ifndef IFLA_VLAN_ID
#define IFLA_VLAN_ID 1
#endif

#ifndef IFLA_INFO_DATA
#define IFLA_INFO_DATA 2
#endif

#ifndef VETH_INFO_PEER
#define VETH_INFO_PEER 1
#endif

#ifndef IFLA_MACVLAN_MODE
#define IFLA_MACVLAN_MODE 1
#endif

#ifndef IFLA_NEW_NETNSID
#define IFLA_NEW_NETNSID 45
#endif

#ifdef IFLA_IF_NETNSID
#ifndef IFLA_TARGET_NETNSID
#define IFLA_TARGET_NETNSID = IFLA_IF_NETNSID
#endif
#else
#define IFLA_IF_NETNSID 46
#define IFLA_TARGET_NETNSID 46
#endif

#ifndef IFA_TARGET_NETNSID
#define IFA_TARGET_NETNSID 10
#endif

#ifndef IFLA_STATS
#define IFLA_STATS 7
#endif

#ifndef IFLA_STATS64
#define IFLA_STATS64 23
#endif

#ifndef RTM_NEWNSID
#define RTM_NEWNSID 88
#endif

#ifndef RTM_GETNSID
#define RTM_GETNSID 90
#endif

#ifndef NLMSG_ERROR
#define NLMSG_ERROR 0x2
#endif

#ifndef MACVLAN_MODE_PRIVATE
#define MACVLAN_MODE_PRIVATE 1
#endif

#ifndef MACVLAN_MODE_VEPA
#define MACVLAN_MODE_VEPA 2
#endif

#ifndef MACVLAN_MODE_BRIDGE
#define MACVLAN_MODE_BRIDGE 4
#endif

#ifndef MACVLAN_MODE_PASSTHRU
#define MACVLAN_MODE_PASSTHRU 8
#endif

/* Attributes of RTM_NEWNSID/RTM_GETNSID messages */
enum {
	__LXC_NETNSA_NONE,
#define __LXC_NETNSA_NSID_NOT_ASSIGNED -1
	__LXC_NETNSA_NSID,
	__LXC_NETNSA_PID,
	__LXC_NETNSA_FD,
	__LXC_NETNSA_MAX,
};

/* Length of abstract unix domain socket socket address. */
#define LXC_AUDS_ADDR_LEN sizeof(((struct sockaddr_un *)0)->sun_path)

/* mount */
#ifndef MS_PRIVATE
#define MS_PRIVATE (1<<18)
#endif

#ifndef MS_SLAVE
#define MS_SLAVE (1 << 19)
#endif

#ifndef MS_LAZYTIME
#define MS_LAZYTIME (1<<25)
#endif

#ifndef MS_REC
#define MS_REC 16384
#endif

/* open */
#ifndef O_PATH
#define O_PATH      010000000
#endif

#ifndef O_NOFOLLOW
#define O_NOFOLLOW  00400000
#endif

/* sockets */
#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 02000000
#endif

/* pointer conversion macros */
#define PTR_TO_INT(p) ((int)((intptr_t)(p)))
#define INT_TO_PTR(u) ((void *)((intptr_t)(u)))

#define PTR_TO_INTMAX(p) ((intmax_t)((intptr_t)(p)))
#define INTMAX_TO_PTR(u) ((void *)((intptr_t)(u)))

#define LXC_INVALID_UID ((uid_t)-1)
#define LXC_INVALID_GID ((gid_t)-1)

#define STRLITERALLEN(x) (sizeof(""x"") - 1)
#define STRARRAYLEN(x) (sizeof(x) - 1)

/* Maximum number of bytes sendfile() is able to send in one go. */
#define LXC_SENDFILE_MAX 0x7ffff000

#endif /* __LXC_MACRO_H */

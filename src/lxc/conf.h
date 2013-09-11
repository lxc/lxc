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
#ifndef _conf_h
#define _conf_h

#include "config.h"

#include <netinet/in.h>
#include <net/if.h>
#include <sys/param.h>
#include <sys/types.h>
#include <stdbool.h>

#include <lxc/list.h>

#include <lxc/start.h> /* for lxc_handler */

#if HAVE_SCMP_FILTER_CTX
typedef void * scmp_filter_ctx;
#endif

enum {
	LXC_NET_EMPTY,
	LXC_NET_VETH,
	LXC_NET_MACVLAN,
	LXC_NET_PHYS,
	LXC_NET_VLAN,
	LXC_NET_MAXCONFTYPE,
};

/*
 * Defines the structure to configure an ipv4 address
 * @address   : ipv4 address
 * @broadcast : ipv4 broadcast address
 * @mask      : network mask
 */
struct lxc_inetdev {
	struct in_addr addr;
	struct in_addr bcast;
	int prefix;
};

struct lxc_route {
	struct in_addr addr;
};

/*
 * Defines the structure to configure an ipv6 address
 * @flags     : set the address up
 * @address   : ipv6 address
 * @broadcast : ipv6 broadcast address
 * @mask      : network mask
 */
struct lxc_inet6dev {
	struct in6_addr addr;
	struct in6_addr mcast;
	struct in6_addr acast;
	int prefix;
};

struct lxc_route6 {
	struct in6_addr addr;
};

struct ifla_veth {
	char *pair; /* pair name */
	char veth1[IFNAMSIZ]; /* needed for deconf */
};

struct ifla_vlan {
	uint   flags;
	uint   fmask;
	unsigned short   vid;
	unsigned short   pad;
};

struct ifla_macvlan {
	int mode; /* private, vepa, bridge */
};

union netdev_p {
	struct ifla_veth veth_attr;
	struct ifla_vlan vlan_attr;
	struct ifla_macvlan macvlan_attr;
};

/*
 * Defines a structure to configure a network device
 * @link       : lxc.network.link, name of bridge or host iface to attach if any
 * @name       : lxc.network.name, name of iface on the container side
 * @flags      : flag of the network device (IFF_UP, ... )
 * @ipv4       : a list of ipv4 addresses to be set on the network device
 * @ipv6       : a list of ipv6 addresses to be set on the network device
 * @upscript   : a script filename to be executed during interface configuration
 * @downscript : a script filename to be executed during interface destruction
 */
struct lxc_netdev {
	int type;
	int flags;
	int ifindex;
	char *link;
	char *name;
	char *hwaddr;
	char *mtu;
	union netdev_p priv;
	struct lxc_list ipv4;
	struct lxc_list ipv6;
	struct in_addr *ipv4_gateway;
	bool ipv4_gateway_auto;
	struct in6_addr *ipv6_gateway;
	bool ipv6_gateway_auto;
	char *upscript;
	char *downscript;
};

/*
 * Defines a generic struct to configure the control group.
 * It is up to the programmer to specify the right subsystem.
 * @subsystem : the targetted subsystem
 * @value     : the value to set
 */
struct lxc_cgroup {
	char *subsystem;
	char *value;
};

enum idtype {
	ID_TYPE_UID,
	ID_TYPE_GID
};

/*
 * id_map is an id map entry.  Form in confile is:
 * lxc.id_map = u 0    9800 100
 * lxc.id_map = u 1000 9900 100
 * lxc.id_map = g 0    9800 100
 * lxc.id_map = g 1000 9900 100
 * meaning the container can use uids and gids 0-99 and 1000-1099,
 * with [ug]id 0 mapping to [ug]id 9800 on the host, and [ug]id 1000 to
 * [ug]id 9900 on the host.
 */
struct id_map {
	enum idtype idtype;
	unsigned long hostid, nsid, range;
};

/*
 * Defines a structure containing a pty information for
 * virtualizing a tty
 * @name   : the path name of the slave pty side
 * @master : the file descriptor of the master
 * @slave  : the file descriptor of the slave
 */
struct lxc_pty_info {
	char name[MAXPATHLEN];
	int master;
	int slave;
	int busy;
};

/*
 * Defines the number of tty configured and contains the
 * instanciated ptys
 * @nbtty = number of configured ttys
 */
struct lxc_tty_info {
	int nbtty;
	struct lxc_pty_info *pty_info;
};

struct lxc_tty_state;

/*
 * Defines the structure to store the console information
 * @peer   : the file descriptor put/get console traffic
 * @name   : the file name of the slave pty
 */
struct lxc_console {
	int slave;
	int master;
	int peer;
	struct lxc_pty_info peerpty;
	struct lxc_epoll_descr *descr;
	char *path;
	char *log_path;
	int log_fd;
	char name[MAXPATHLEN];
	struct termios *tios;
	struct lxc_tty_state *tty_state;
};

/*
 * Defines a structure to store the rootfs location, the
 * optionals pivot_root, rootfs mount paths
 * @rootfs     : a path to the rootfs
 * @pivot_root : a path to a pivot_root location to be used
 */
struct lxc_rootfs {
	char *path;
	char *mount;
	char *pivot;
};

/*
 * Automatic mounts for LXC to perform inside the container
 */
enum {
	LXC_AUTO_PROC        = 0x01,   /* /proc */
	LXC_AUTO_SYS         = 0x02,   /* /sys*/
	LXC_AUTO_CGROUP      = 0x04,   /* /sys/fs/cgroup */
	LXC_AUTO_PROC_SYSRQ  = 0x08,   /* /proc/sysrq-trigger over-bind-mounted with /dev/null */
};

/*
 * Defines the global container configuration
 * @rootfs     : root directory to run the container
 * @pivotdir   : pivotdir path, if not set default will be used
 * @mount      : list of mount points
 * @tty        : numbers of tty
 * @pts        : new pts instance
 * @mount_list : list of mount point (alternative to fstab file)
 * @network    : network configuration
 * @utsname    : container utsname
 * @fstab      : path to a fstab file format
 * @caps       : list of the capabilities to drop
 * @keepcaps   : list of the capabilities to keep
 * @tty_info   : tty data
 * @console    : console data
 * @ttydir     : directory (under /dev) in which to create console and ttys
#if HAVE_APPARMOR
 * @aa_profile : apparmor profile to switch to
#endif
 */
enum lxchooks {
	LXCHOOK_PRESTART, LXCHOOK_PREMOUNT, LXCHOOK_MOUNT, LXCHOOK_AUTODEV,
	LXCHOOK_START, LXCHOOK_POSTSTOP, LXCHOOK_CLONE, NUM_LXC_HOOKS};
extern char *lxchook_names[NUM_LXC_HOOKS];

struct saved_nic {
	int ifindex;
	char *orig_name;
};

struct lxc_conf {
	int is_execute;
	char *fstab;
	int tty;
	int pts;
	int reboot;
	int need_utmp_watch;
	int personality;
	struct utsname *utsname;
	struct lxc_list cgroup;
	struct lxc_list id_map;
	struct lxc_list network;
	struct saved_nic *saved_nics;
	int num_savednics;
	int auto_mounts;
	struct lxc_list mount_list;
	struct lxc_list caps;
	struct lxc_list keepcaps;
	struct lxc_tty_info tty_info;
	struct lxc_console console;
	struct lxc_rootfs rootfs;
	char *ttydir;
	int close_all_fds;
	struct lxc_list hooks[NUM_LXC_HOOKS];
#if HAVE_APPARMOR
	char *aa_profile;
#endif

#if HAVE_APPARMOR /* || HAVE_SELINUX || HAVE_SMACK */
	int lsm_umount_proc;
#endif
	char *seccomp;  // filename with the seccomp rules
#if HAVE_SCMP_FILTER_CTX
	scmp_filter_ctx *seccomp_ctx;
#endif
	int maincmd_fd;
	int autodev;  // if 1, mount and fill a /dev at start
	int stopsignal; // signal used to stop container
	int kmsg;  // if 1, create /dev/kmsg symlink
	char *rcfile;	// Copy of the top level rcfile we read

	// Logfile and logleve can be set in a container config file.
	// Those function as defaults.  The defaults can be overriden
	// by command line.  However we don't want the command line
	// specified values to be saved on c->save_config().  So we
	// store the config file specified values here.
	char *logfile;  // the logfile as specifed in config
	int loglevel;   // loglevel as specifed in config (if any)
};

int run_lxc_hooks(const char *name, char *hook, struct lxc_conf *conf,
		  const char *lxcpath, char *argv[]);

extern int detect_shared_rootfs(void);

/*
 * Initialize the lxc configuration structure
 */
extern struct lxc_conf *lxc_conf_init(void);
extern void lxc_conf_free(struct lxc_conf *conf);

extern int pin_rootfs(const char *rootfs);

extern int lxc_create_network(struct lxc_handler *handler);
extern void lxc_delete_network(struct lxc_handler *handler);
extern int lxc_assign_network(struct lxc_list *networks, pid_t pid);
extern int lxc_map_ids(struct lxc_list *idmap, pid_t pid);
extern int lxc_find_gateway_addresses(struct lxc_handler *handler);

extern int lxc_create_tty(const char *name, struct lxc_conf *conf);
extern void lxc_delete_tty(struct lxc_tty_info *tty_info);

extern int lxc_clear_config_network(struct lxc_conf *c);
extern int lxc_clear_nic(struct lxc_conf *c, const char *key);
extern int lxc_clear_config_caps(struct lxc_conf *c);
extern int lxc_clear_config_keepcaps(struct lxc_conf *c);
extern int lxc_clear_cgroups(struct lxc_conf *c, const char *key);
extern int lxc_clear_mount_entries(struct lxc_conf *c);
extern int lxc_clear_hooks(struct lxc_conf *c, const char *key);

extern int uid_shift_ttys(int pid, struct lxc_conf *conf);

/*
 * Configure the container from inside
 */

struct cgroup_process_info;
extern int lxc_setup(const char *name, struct lxc_conf *lxc_conf,
			const char *lxcpath, struct cgroup_process_info *cgroup_info);

extern void lxc_rename_phys_nics_on_shutdown(struct lxc_conf *conf);
#endif

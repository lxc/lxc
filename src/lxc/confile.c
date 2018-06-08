/*
 * lxc: linux Container library
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
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/utsname.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <time.h>
#include <dirent.h>

#include "storage/storage_utils.h"
#include "parse.h"
#include "config.h"
#include "confile.h"
#include "confile_utils.h"
#include "utils.h"
#include "log.h"
#include "conf.h"
#include "network.h"
#include "lxcseccomp.h"
#include "storage.h"

#if HAVE_SYS_PERSONALITY_H
#include <sys/personality.h>
#endif

lxc_log_define(lxc_confile, lxc);

static int set_config_personality(const char *, const char *, struct lxc_conf *,
				  void *);
static int get_config_personality(const char *, char *, int, struct lxc_conf *);
static int clr_config_personality(const char *, struct lxc_conf *, void *);

static int set_config_pts(const char *, const char *, struct lxc_conf *,
			  void *);
static int get_config_pts(const char *, char *, int, struct lxc_conf *);
static int clr_config_pts(const char *, struct lxc_conf *, void *);

static int set_config_tty(const char *, const char *, struct lxc_conf *,
			  void *);
static int get_config_tty(const char *, char *, int, struct lxc_conf *);
static int clr_config_tty(const char *, struct lxc_conf *, void *);

static int set_config_ttydir(const char *, const char *, struct lxc_conf *,
			     void *);
static int get_config_ttydir(const char *, char *, int, struct lxc_conf *);
static int clr_config_ttydir(const char *, struct lxc_conf *, void *);

static int set_config_kmsg(const char *, const char *, struct lxc_conf *,
			   void *);
static int get_config_kmsg(const char *, char *, int, struct lxc_conf *);
static int clr_config_kmsg(const char *, struct lxc_conf *, void *);

static int set_config_lsm_aa_profile(const char *, const char *,
				     struct lxc_conf *, void *);
static int get_config_lsm_aa_profile(const char *, char *, int,
				     struct lxc_conf *);
static int clr_config_lsm_aa_profile(const char *, struct lxc_conf *, void *);

static int set_config_lsm_aa_incomplete(const char *, const char *,
					struct lxc_conf *, void *);
static int get_config_lsm_aa_incomplete(const char *, char *, int,
					struct lxc_conf *);
static int clr_config_lsm_aa_incomplete(const char *, struct lxc_conf *,
					void *);

static int set_config_lsm_se_context(const char *, const char *,
				     struct lxc_conf *, void *);
static int get_config_lsm_se_context(const char *, char *, int,
				     struct lxc_conf *);
static int clr_config_lsm_se_context(const char *, struct lxc_conf *, void *);

static int set_config_cgroup(const char *, const char *, struct lxc_conf *,
			     void *);
static int get_config_cgroup(const char *, char *, int, struct lxc_conf *);
static int clr_config_cgroup(const char *, struct lxc_conf *, void *);

static int set_config_idmaps(const char *, const char *, struct lxc_conf *,
			     void *);
static int get_config_idmaps(const char *, char *, int, struct lxc_conf *);
static int clr_config_idmaps(const char *, struct lxc_conf *, void *);

static int set_config_loglevel(const char *, const char *, struct lxc_conf *,
			       void *);
static int get_config_loglevel(const char *, char *, int, struct lxc_conf *);
static int clr_config_loglevel(const char *, struct lxc_conf *, void *);

static int set_config_logfile(const char *, const char *, struct lxc_conf *,
			      void *);
static int get_config_logfile(const char *, char *, int, struct lxc_conf *);
static int clr_config_logfile(const char *, struct lxc_conf *, void *);

static int set_config_mount(const char *, const char *, struct lxc_conf *,
			    void *);
static int get_config_mount(const char *, char *, int, struct lxc_conf *);
static int clr_config_mount(const char *, struct lxc_conf *, void *);

static int set_config_mount_auto(const char *, const char *, struct lxc_conf *,
				 void *);
static int get_config_mount_auto(const char *, char *, int, struct lxc_conf *);
static int clr_config_mount_auto(const char *, struct lxc_conf *, void *);

static int set_config_fstab(const char *, const char *, struct lxc_conf *,
			    void *);
static int get_config_fstab(const char *, char *, int, struct lxc_conf *);
static int clr_config_fstab(const char *, struct lxc_conf *, void *);

static int set_config_rootfs_mount(const char *, const char *,
				   struct lxc_conf *, void *);
static int get_config_rootfs_mount(const char *, char *, int,
				   struct lxc_conf *);
static int clr_config_rootfs_mount(const char *, struct lxc_conf *, void *);

static int set_config_rootfs_options(const char *, const char *,
				     struct lxc_conf *, void *);
static int get_config_rootfs_options(const char *, char *, int,
				     struct lxc_conf *);
static int clr_config_rootfs_options(const char *, struct lxc_conf *, void *);

static int set_config_rootfs_backend(const char *, const char *,
				     struct lxc_conf *, void *);
static int get_config_rootfs_backend(const char *, char *, int,
				     struct lxc_conf *);
static int clr_config_rootfs_backend(const char *, struct lxc_conf *, void *);

static int set_config_rootfs(const char *, const char *, struct lxc_conf *,
			     void *);
static int get_config_rootfs(const char *, char *, int, struct lxc_conf *);
static int clr_config_rootfs(const char *, struct lxc_conf *, void *);

static int set_config_pivotdir(const char *, const char *, struct lxc_conf *,
			       void *);
static int get_config_pivotdir(const char *, char *, int, struct lxc_conf *);
static int clr_config_pivotdir(const char *, struct lxc_conf *, void *);

static int set_config_utsname(const char *, const char *, struct lxc_conf *,
			      void *);
static int get_config_utsname(const char *, char *, int, struct lxc_conf *);
static int clr_config_utsname(const char *, struct lxc_conf *, void *);

static int set_config_hooks(const char *, const char *, struct lxc_conf *,
			    void *);
static int get_config_hooks(const char *, char *, int, struct lxc_conf *);
static int clr_config_hooks(const char *, struct lxc_conf *, void *);

static int set_config_network_type(const char *, const char *,
				   struct lxc_conf *, void *);
static int set_config_network_flags(const char *, const char *,
				    struct lxc_conf *, void *);
static int set_config_network_link(const char *, const char *,
				   struct lxc_conf *, void *);
static int set_config_network_name(const char *, const char *,
				   struct lxc_conf *, void *);
static int set_config_network_veth_pair(const char *, const char *,
					struct lxc_conf *, void *);
static int set_config_network_macvlan_mode(const char *, const char *,
					   struct lxc_conf *, void *);
static int set_config_network_hwaddr(const char *, const char *,
				     struct lxc_conf *, void *);
static int set_config_network_vlan_id(const char *, const char *,
				      struct lxc_conf *, void *);
static int set_config_network_mtu(const char *, const char *, struct lxc_conf *,
				  void *);
static int set_config_network_ipv4(const char *, const char *,
				   struct lxc_conf *, void *);
static int set_config_network_ipv4_gateway(const char *, const char *,
					   struct lxc_conf *, void *);
static int set_config_network_script_up(const char *, const char *,
					struct lxc_conf *, void *);
static int set_config_network_script_down(const char *, const char *,
					  struct lxc_conf *, void *);
static int set_config_network_ipv6(const char *, const char *,
				   struct lxc_conf *, void *);
static int set_config_network_ipv6_gateway(const char *, const char *,
					   struct lxc_conf *, void *);
static int set_config_network_nic(const char *, const char *, struct lxc_conf *,
				  void *);
static int get_config_network_item(const char *, char *, int,
				   struct lxc_conf *);
static int clr_config_network_item(const char *, struct lxc_conf *, void *);

static int set_config_network(const char *, const char *, struct lxc_conf *,
			      void *);
static int get_config_network(const char *, char *, int, struct lxc_conf *);
static int clr_config_network(const char *, struct lxc_conf *, void *);

static int set_config_cap_drop(const char *, const char *, struct lxc_conf *,
			       void *);
static int get_config_cap_drop(const char *, char *, int, struct lxc_conf *);
static int clr_config_cap_drop(const char *, struct lxc_conf *, void *);

static int set_config_cap_keep(const char *, const char *, struct lxc_conf *,
			       void *);
static int get_config_cap_keep(const char *, char *, int, struct lxc_conf *);
static int clr_config_cap_keep(const char *, struct lxc_conf *, void *);

static int set_config_console_logfile(const char *, const char *,
				      struct lxc_conf *, void *);
static int get_config_console_logfile(const char *, char *, int,
				      struct lxc_conf *);
static int clr_config_console_logfile(const char *, struct lxc_conf *, void *);

static int set_config_console(const char *, const char *, struct lxc_conf *,
			      void *);
static int get_config_console(const char *, char *, int, struct lxc_conf *);
static int clr_config_console(const char *, struct lxc_conf *, void *);

static int set_config_seccomp(const char *, const char *, struct lxc_conf *,
			      void *);
static int get_config_seccomp(const char *, char *, int, struct lxc_conf *);
static int clr_config_seccomp(const char *, struct lxc_conf *, void *);

static int set_config_includefiles(const char *, const char *,
				   struct lxc_conf *, void *);
static int get_config_includefiles(const char *, char *, int,
				   struct lxc_conf *);
static int clr_config_includefiles(const char *, struct lxc_conf *, void *);

static int set_config_autodev(const char *, const char *, struct lxc_conf *,
			      void *);
static int get_config_autodev(const char *, char *, int, struct lxc_conf *);
static int clr_config_autodev(const char *, struct lxc_conf *, void *);

static int set_config_haltsignal(const char *, const char *, struct lxc_conf *,
				 void *);
static int get_config_haltsignal(const char *, char *, int, struct lxc_conf *);
static int clr_config_haltsignal(const char *, struct lxc_conf *, void *);

static int set_config_rebootsignal(const char *, const char *,
				   struct lxc_conf *, void *);
static int get_config_rebootsignal(const char *, char *, int,
				   struct lxc_conf *);
static int clr_config_rebootsignal(const char *, struct lxc_conf *, void *);

static int set_config_stopsignal(const char *, const char *, struct lxc_conf *,
				 void *);
static int get_config_stopsignal(const char *, char *, int, struct lxc_conf *);
static int clr_config_stopsignal(const char *, struct lxc_conf *, void *);

static int set_config_start(const char *, const char *, struct lxc_conf *,
			    void *);
static int get_config_start(const char *, char *, int, struct lxc_conf *);
static int clr_config_start(const char *, struct lxc_conf *, void *);

static int set_config_monitor(const char *, const char *, struct lxc_conf *,
			      void *);
static int get_config_monitor(const char *, char *, int, struct lxc_conf *);
static int clr_config_monitor(const char *, struct lxc_conf *, void *);

static int set_config_group(const char *, const char *, struct lxc_conf *,
			    void *);
static int get_config_group(const char *, char *, int, struct lxc_conf *);
static int clr_config_group(const char *, struct lxc_conf *, void *);

static int set_config_environment(const char *, const char *, struct lxc_conf *,
				  void *);
static int get_config_environment(const char *, char *, int, struct lxc_conf *);
static int clr_config_environment(const char *, struct lxc_conf *, void *);

static int set_config_init_cmd(const char *, const char *, struct lxc_conf *,
			       void *);
static int get_config_init_cmd(const char *, char *, int, struct lxc_conf *);
static int clr_config_init_cmd(const char *, struct lxc_conf *, void *);

static int set_config_init_uid(const char *, const char *, struct lxc_conf *,
			       void *);
static int get_config_init_uid(const char *, char *, int, struct lxc_conf *);
static int clr_config_init_uid(const char *, struct lxc_conf *, void *);

static int set_config_init_gid(const char *, const char *, struct lxc_conf *,
			       void *);
static int get_config_init_gid(const char *, char *, int, struct lxc_conf *);
static int clr_config_init_gid(const char *, struct lxc_conf *, void *);

static int set_config_ephemeral(const char *, const char *, struct lxc_conf *,
				void *);
static int get_config_ephemeral(const char *, char *, int, struct lxc_conf *);
static int clr_config_ephemeral(const char *, struct lxc_conf *, void *);

static struct lxc_config_t config[] = {
	{ "lxc.arch",                 set_config_personality,          get_config_personality,       clr_config_personality,       },
	{ "lxc.pts",                  set_config_pts,                  get_config_pts,               clr_config_pts,               },
	{ "lxc.tty",                  set_config_tty,                  get_config_tty,               clr_config_tty,               },
	{ "lxc.devttydir",            set_config_ttydir,               get_config_ttydir,            clr_config_ttydir,            },
	{ "lxc.kmsg",                 set_config_kmsg,                 get_config_kmsg,              clr_config_kmsg,              },
	{ "lxc.aa_profile",           set_config_lsm_aa_profile,       get_config_lsm_aa_profile,    clr_config_lsm_aa_profile,    },
	{ "lxc.aa_allow_incomplete",  set_config_lsm_aa_incomplete,    get_config_lsm_aa_incomplete, clr_config_lsm_aa_incomplete, },
	{ "lxc.se_context",           set_config_lsm_se_context,       get_config_lsm_se_context,    clr_config_lsm_se_context,    },
	{ "lxc.cgroup",               set_config_cgroup,               get_config_cgroup,            clr_config_cgroup,            },
	{ "lxc.id_map",               set_config_idmaps,               get_config_idmaps,            clr_config_idmaps,            },
	{ "lxc.loglevel",             set_config_loglevel,             get_config_loglevel,          clr_config_loglevel,          },
	{ "lxc.logfile",              set_config_logfile,              get_config_logfile,           clr_config_logfile,           },
	{ "lxc.mount.entry",          set_config_mount,                get_config_mount,             clr_config_mount,             },
	{ "lxc.mount.auto",           set_config_mount_auto,           get_config_mount_auto,        clr_config_mount_auto,        },
	{ "lxc.mount",                set_config_fstab,	               get_config_fstab,             clr_config_fstab,             },
	{ "lxc.rootfs.mount",         set_config_rootfs_mount,         get_config_rootfs_mount,      clr_config_rootfs_mount,      },
	{ "lxc.rootfs.options",       set_config_rootfs_options,       get_config_rootfs_options,    clr_config_rootfs_options,    },
	{ "lxc.rootfs.backend",       set_config_rootfs_backend,       get_config_rootfs_backend,    clr_config_rootfs_backend,    },
	{ "lxc.rootfs",               set_config_rootfs,               get_config_rootfs,            clr_config_rootfs,            },
	{ "lxc.pivotdir",             set_config_pivotdir,             get_config_pivotdir,          clr_config_pivotdir,          },
	{ "lxc.utsname",              set_config_utsname,              get_config_utsname,           clr_config_utsname,           },
	{ "lxc.hook.pre-start",       set_config_hooks,                get_config_hooks,             clr_config_hooks,             },
	{ "lxc.hook.pre-mount",       set_config_hooks,                get_config_hooks,             clr_config_hooks,             },
	{ "lxc.hook.mount",           set_config_hooks,                get_config_hooks,             clr_config_hooks,             },
	{ "lxc.hook.autodev",         set_config_hooks,                get_config_hooks,             clr_config_hooks,             },
	{ "lxc.hook.start",           set_config_hooks,                get_config_hooks,             clr_config_hooks,             },
	{ "lxc.hook.stop",            set_config_hooks,                get_config_hooks,             clr_config_hooks,             },
	{ "lxc.hook.post-stop",       set_config_hooks,                get_config_hooks,             clr_config_hooks,             },
	{ "lxc.hook.clone",           set_config_hooks,                get_config_hooks,             clr_config_hooks,             },
	{ "lxc.hook.destroy",         set_config_hooks,                get_config_hooks,             clr_config_hooks,             },
	{ "lxc.hook",                 set_config_hooks,                get_config_hooks,             clr_config_hooks,             },
	{ "lxc.network.type",         set_config_network_type,         get_config_network_item,      clr_config_network_item,      },
	{ "lxc.network.flags",        set_config_network_flags,        get_config_network_item,      clr_config_network_item,      },
	{ "lxc.network.link",         set_config_network_link,         get_config_network_item,      clr_config_network_item,      },
	{ "lxc.network.name",         set_config_network_name,         get_config_network_item,      clr_config_network_item,      },
	{ "lxc.network.macvlan.mode", set_config_network_macvlan_mode, get_config_network_item,      clr_config_network_item,      },
	{ "lxc.network.veth.pair",    set_config_network_veth_pair,    get_config_network_item,      clr_config_network_item,      },
	{ "lxc.network.script.up",    set_config_network_script_up,    get_config_network_item,      clr_config_network_item,      },
	{ "lxc.network.script.down",  set_config_network_script_down,  get_config_network_item,      clr_config_network_item,      },
	{ "lxc.network.hwaddr",       set_config_network_hwaddr,       get_config_network_item,      clr_config_network_item,      },
	{ "lxc.network.mtu",          set_config_network_mtu,          get_config_network_item,      clr_config_network_item,      },
	{ "lxc.network.vlan.id",      set_config_network_vlan_id,      get_config_network_item,      clr_config_network_item,      },
	{ "lxc.network.ipv4.gateway", set_config_network_ipv4_gateway, get_config_network_item,      clr_config_network_item,      },
	{ "lxc.network.ipv4",         set_config_network_ipv4,         get_config_network_item,      clr_config_network_item,      },
	{ "lxc.network.ipv6.gateway", set_config_network_ipv6_gateway, get_config_network_item,      clr_config_network_item,      },
	{ "lxc.network.ipv6",         set_config_network_ipv6,         get_config_network_item,      clr_config_network_item,      },
	{ "lxc.network.",             set_config_network_nic,          get_config_network_item,      clr_config_network_item,      },
	{ "lxc.network",              set_config_network,              get_config_network,           clr_config_network,           },
	{ "lxc.cap.drop",             set_config_cap_drop,             get_config_cap_drop,          clr_config_cap_drop,          },
	{ "lxc.cap.keep",             set_config_cap_keep,             get_config_cap_keep,          clr_config_cap_keep,          },
	{ "lxc.console.logfile",      set_config_console_logfile,      get_config_console_logfile,   clr_config_console_logfile,   },
	{ "lxc.console",              set_config_console,              get_config_console,           clr_config_console,           },
	{ "lxc.seccomp",              set_config_seccomp,              get_config_seccomp,           clr_config_seccomp,           },
	{ "lxc.include",              set_config_includefiles,         get_config_includefiles,      clr_config_includefiles,      },
	{ "lxc.autodev",              set_config_autodev,              get_config_autodev,           clr_config_autodev,           },
	{ "lxc.haltsignal",           set_config_haltsignal,           get_config_haltsignal,        clr_config_haltsignal,        },
	{ "lxc.rebootsignal",         set_config_rebootsignal,         get_config_rebootsignal,      clr_config_rebootsignal,      },
	{ "lxc.stopsignal",           set_config_stopsignal,           get_config_stopsignal,        clr_config_stopsignal,        },
	{ "lxc.start.auto",           set_config_start,                get_config_start,             clr_config_start,             },
	{ "lxc.start.delay",          set_config_start,                get_config_start,             clr_config_start,             },
	{ "lxc.start.order",          set_config_start,                get_config_start,             clr_config_start,             },
	{ "lxc.monitor.unshare",      set_config_monitor,              get_config_monitor,           clr_config_monitor,           },
	{ "lxc.group",                set_config_group,                get_config_group,             clr_config_group,             },
	{ "lxc.environment",          set_config_environment,          get_config_environment,       clr_config_environment,       },
	{ "lxc.init_cmd",             set_config_init_cmd,             get_config_init_cmd,          clr_config_init_cmd,          },
	{ "lxc.init_uid",             set_config_init_uid,             get_config_init_uid,          clr_config_init_uid,          },
	{ "lxc.init_gid",             set_config_init_gid,             get_config_init_gid,          clr_config_init_gid,          },
	{ "lxc.ephemeral",            set_config_ephemeral,            get_config_ephemeral,         clr_config_ephemeral,         },
};

struct signame {
	int num;
	const char *name;
};

static const struct signame signames[] = {
	{ SIGHUP,    "HUP"    },
	{ SIGINT,    "INT"    },
	{ SIGQUIT,   "QUIT"   },
	{ SIGILL,    "ILL"    },
	{ SIGABRT,   "ABRT"   },
	{ SIGFPE,    "FPE"    },
	{ SIGKILL,   "KILL"   },
	{ SIGSEGV,   "SEGV"   },
	{ SIGPIPE,   "PIPE"   },
	{ SIGALRM,   "ALRM"   },
	{ SIGTERM,   "TERM"   },
	{ SIGUSR1,   "USR1"   },
	{ SIGUSR2,   "USR2"   },
	{ SIGCHLD,   "CHLD"   },
	{ SIGCONT,   "CONT"   },
	{ SIGSTOP,   "STOP"   },
	{ SIGTSTP,   "TSTP"   },
	{ SIGTTIN,   "TTIN"   },
	{ SIGTTOU,   "TTOU"   },
#ifdef SIGTRAP
	{ SIGTRAP,   "TRAP"   },
#endif
#ifdef SIGIOT
	{ SIGIOT,    "IOT"    },
#endif
#ifdef SIGEMT
	{ SIGEMT,    "EMT"    },
#endif
#ifdef SIGBUS
	{ SIGBUS,    "BUS"    },
#endif
#ifdef SIGSTKFLT
	{ SIGSTKFLT, "STKFLT" },
#endif
#ifdef SIGCLD
	{ SIGCLD,    "CLD"    },
#endif
#ifdef SIGURG
	{ SIGURG,    "URG"    },
#endif
#ifdef SIGXCPU
	{ SIGXCPU,   "XCPU"   },
#endif
#ifdef SIGXFSZ
	{ SIGXFSZ,   "XFSZ"   },
#endif
#ifdef SIGVTALRM
	{ SIGVTALRM, "VTALRM" },
#endif
#ifdef SIGPROF
	{ SIGPROF,   "PROF"   },
#endif
#ifdef SIGWINCH
	{ SIGWINCH,  "WINCH"  },
#endif
#ifdef SIGIO
	{ SIGIO,     "IO"     },
#endif
#ifdef SIGPOLL
	{ SIGPOLL,   "POLL"   },
#endif
#ifdef SIGINFO
	{ SIGINFO,   "INFO"   },
#endif
#ifdef SIGLOST
	{ SIGLOST,   "LOST"   },
#endif
#ifdef SIGPWR
	{ SIGPWR,    "PWR"    },
#endif
#ifdef SIGUNUSED
	{ SIGUNUSED, "UNUSED" },
#endif
#ifdef SIGSYS
	{ SIGSYS,    "SYS"    },
#endif
};

static const size_t config_size = sizeof(config) / sizeof(struct lxc_config_t);

extern struct lxc_config_t *lxc_getconfig(const char *key)
{
	size_t i;

	for (i = 0; i < config_size; i++)
		if (!strncmp(config[i].name, key, strlen(config[i].name)))
			return &config[i];
	return NULL;
}

static int set_config_string_item(char **conf_item, const char *value)
{
	char *new_value;

	if (lxc_config_value_empty(value)) {
		free(*conf_item);
		*conf_item = NULL;
		return 0;
	}

	new_value = strdup(value);
	if (!new_value) {
		SYSERROR("failed to duplicate string \"%s\"", value);
		return -1;
	}

	free(*conf_item);
	*conf_item = new_value;
	return 0;
}

static int set_config_string_item_max(char **conf_item, const char *value,
				      size_t max)
{
	if (strlen(value) >= max) {
		ERROR("%s is too long (>= %lu)", value, (unsigned long)max);
		return -1;
	}

	return set_config_string_item(conf_item, value);
}

static int set_config_path_item(char **conf_item, const char *value)
{
	return set_config_string_item_max(conf_item, value, PATH_MAX);
}

static struct lxc_config_t *get_network_config_ops(const char *key,
						   struct lxc_conf *lxc_conf,
						   ssize_t *idx,
						   char **deindexed_key)
{
	int ret;
	unsigned int tmpidx;
	size_t numstrlen;
	char *copy, *idx_start, *idx_end;
	struct lxc_config_t *config = NULL;

	/* check that this is a sensible network key */
	if (strncmp("lxc.network.", key, 12)) {
		ERROR("Invalid network configuration key \"%s\"", key);
		return NULL;
	}

	copy = strdup(key);
	if (!copy) {
		ERROR("Failed to duplicate string \"%s\"", key);
		return NULL;
	}

	/* lxc.network.<n> */
	if (!isdigit(*(key + 12))) {
		ERROR("Failed to detect digit in string \"%s\"", key + 12);
		goto on_error;
	}

	/* beginning of index string */
	idx_start = (copy + 11);
	*idx_start = '\0';

	/* end of index string */
	idx_end = strchr((copy + 12), '.');
	if (idx_end)
		*idx_end = '\0';

	/* parse current index */
	ret = lxc_safe_uint((idx_start + 1), &tmpidx);
	if (ret < 0) {
		ERROR("Failed to parse usigned integer from string \"%s\": %s",
		      idx_start + 1, strerror(-ret));
		*idx = ret;
		goto on_error;
	}

	/* This, of course is utterly nonsensical on so many levels, but
	 * better safe than sorry.
	 * (Checking for INT_MAX here is intentional.)
	 */
	if (tmpidx == INT_MAX) {
		SYSERROR("Number of configured networks would overflow the "
			 "counter");
		goto on_error;
	}
	*idx = tmpidx;

	numstrlen = strlen((idx_start + 1));

	/* repair configuration key */
	*idx_start = '.';

	/* lxc.network.<idx>.<subkey> */
	if (idx_end) {
		*idx_end = '.';
		if (strlen(idx_end + 1) == 0) {
			ERROR("No subkey in network configuration key \"%s\"", key);
			goto on_error;
		}

		memmove(copy + 12, idx_end + 1, strlen(idx_end + 1));
		copy[strlen(key) - numstrlen + 1] = '\0';

		config = lxc_getconfig(copy);
		if (!config) {
			ERROR("Unknown network configuration key \"%s\"", key);
			goto on_error;
		}
	}

	if (deindexed_key)
		*deindexed_key = copy;

	return config;

on_error:
	free(copy);
	return NULL;
}

/* Config entry is something like "lxc.network.0.ipv4" the key 'lxc.network.'
*  was found. So we make sure next comes an integer, find the right callback
*  (by rewriting the key), and call it.
 */
static int set_config_network_nic(const char *key, const char *value,
				  struct lxc_conf *lxc_conf, void *data)
{
	int ret;
	const char *idxstring;
	struct lxc_config_t *config;
	struct lxc_netdev *netdev;
	ssize_t idx = -1;
	char *deindexed_key = NULL;

	idxstring = key + 12;
	if (!isdigit(*idxstring))
		return -1;

	if (lxc_config_value_empty(value))
		return clr_config_network_item(key, lxc_conf, data);

	config = get_network_config_ops(key, lxc_conf, &idx, &deindexed_key);
	if (!config || idx < 0)
		return -1;

	netdev = lxc_get_netdev_by_idx(lxc_conf, (unsigned int)idx);
	if (!netdev) {
		free(deindexed_key);
		return -1;
	}

	ret = config->set(deindexed_key, value, lxc_conf, netdev);
	free(deindexed_key);
	return ret;
}

static int set_config_network(const char *key, const char *value,
			      struct lxc_conf *lxc_conf, void *data)
{
	if (!lxc_config_value_empty(value)) {
		ERROR("lxc.network must not have a value");
		return -1;
	}

	return lxc_clear_config_network(lxc_conf);
}

static int macvlan_mode(int *valuep, const char *value);

static int set_config_network_type(const char *key, const char *value,
				   struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_list *network = &lxc_conf->network;
	struct lxc_netdev *netdev;
	struct lxc_list *list;

	if (lxc_config_value_empty(value))
		return lxc_clear_config_network(lxc_conf);

	netdev = malloc(sizeof(*netdev));
	if (!netdev) {
		SYSERROR("failed to allocate memory");
		return -1;
	}

	memset(netdev, 0, sizeof(*netdev));
	lxc_list_init(&netdev->ipv4);
	lxc_list_init(&netdev->ipv6);

	list = malloc(sizeof(*list));
	if (!list) {
		SYSERROR("failed to allocate memory");
		free(netdev);
		return -1;
	}

	lxc_list_init(list);
	list->elem = netdev;

	lxc_list_add_tail(network, list);

	if (!strcmp(value, "veth"))
		netdev->type = LXC_NET_VETH;
	else if (!strcmp(value, "macvlan")) {
		netdev->type = LXC_NET_MACVLAN;
		macvlan_mode(&netdev->priv.macvlan_attr.mode, "private");
	} else if (!strcmp(value, "vlan"))
		netdev->type = LXC_NET_VLAN;
	else if (!strcmp(value, "phys"))
		netdev->type = LXC_NET_PHYS;
	else if (!strcmp(value, "empty"))
		netdev->type = LXC_NET_EMPTY;
	else if (!strcmp(value, "none"))
		netdev->type = LXC_NET_NONE;
	else {
		ERROR("invalid network type %s", value);
		return -1;
	}
	return 0;
}

static int config_ip_prefix(struct in_addr *addr)
{
	if (IN_CLASSA(addr->s_addr))
		return 32 - IN_CLASSA_NSHIFT;
	if (IN_CLASSB(addr->s_addr))
		return 32 - IN_CLASSB_NSHIFT;
	if (IN_CLASSC(addr->s_addr))
		return 32 - IN_CLASSC_NSHIFT;

	return 0;
}

/*
 * If you have p="lxc.network.0.link", pass it p+12
 * to get back '0' (the index of the nic).
 */
static int get_network_netdev_idx(const char *key)
{
	int ret, idx;

	if (*key < '0' || *key > '9')
		return -1;

	ret = sscanf(key, "%d", &idx);
	if (ret != 1)
		return -1;

	return idx;
}

/*
 * If you have p="lxc.network.0", pass this p+12 and it will return
 * the netdev of the first configured nic.
 */
static struct lxc_netdev *get_netdev_from_key(const char *key,
					      struct lxc_list *network)
{
	int idx;
	struct lxc_list *it;
	int i = 0;
	struct lxc_netdev *netdev = NULL;

	idx = get_network_netdev_idx(key);
	if (idx == -1)
		return NULL;

	lxc_list_for_each(it, network) {
		if (idx == i++) {
			netdev = it->elem;
			break;
		}
	}

	return netdev;
}

extern int lxc_list_nicconfigs(struct lxc_conf *c, const char *key, char *retv,
			       int inlen)
{
	struct lxc_netdev *netdev;
	int len;
	int fulllen = 0;

	netdev = get_netdev_from_key(key + 12, &c->network);
	if (!netdev)
		return -1;

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	strprint(retv, inlen, "type\n");
	strprint(retv, inlen, "script.up\n");
	strprint(retv, inlen, "script.down\n");
	if (netdev->type != LXC_NET_EMPTY) {
		strprint(retv, inlen, "flags\n");
		strprint(retv, inlen, "link\n");
		strprint(retv, inlen, "name\n");
		strprint(retv, inlen, "hwaddr\n");
		strprint(retv, inlen, "mtu\n");
		strprint(retv, inlen, "ipv6\n");
		strprint(retv, inlen, "ipv6.gateway\n");
		strprint(retv, inlen, "ipv4\n");
		strprint(retv, inlen, "ipv4.gateway\n");
	}

	switch (netdev->type) {
	case LXC_NET_VETH:
		strprint(retv, inlen, "veth.pair\n");
		break;
	case LXC_NET_MACVLAN:
		strprint(retv, inlen, "macvlan.mode\n");
		break;
	case LXC_NET_VLAN:
		strprint(retv, inlen, "vlan.id\n");
		break;
	case LXC_NET_PHYS:
		break;
	}

	return fulllen;
}

static struct lxc_netdev *network_netdev(const char *key, const char *value,
					 struct lxc_list *network)
{
	struct lxc_netdev *netdev = NULL;

	if (lxc_list_empty(network)) {
		ERROR("network is not created for '%s' = '%s' option", key,
		      value);
		return NULL;
	}

	if (get_network_netdev_idx(key + 12) == -1)
		netdev = lxc_list_last_elem(network);
	else
		netdev = get_netdev_from_key(key + 12, network);

	if (!netdev) {
		ERROR("no network device defined for '%s' = '%s' option", key,
		      value);
		return NULL;
	}

	return netdev;
}

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

static int macvlan_mode(int *valuep, const char *value)
{
	struct mc_mode {
		char *name;
		int mode;
	} m[] = {
	    { "private",  MACVLAN_MODE_PRIVATE  },
	    { "vepa",     MACVLAN_MODE_VEPA     },
	    { "bridge",   MACVLAN_MODE_BRIDGE   },
	    { "passthru", MACVLAN_MODE_PASSTHRU },
	};

	size_t i;

	for (i = 0; i < sizeof(m) / sizeof(m[0]); i++) {
		if (strcmp(m[i].name, value))
			continue;

		*valuep = m[i].mode;
		return 0;
	}

	return -1;
}

static int rand_complete_hwaddr(char *hwaddr)
{
	const char hex[] = "0123456789abcdef";
	char *curs = hwaddr;

#ifndef HAVE_RAND_R
	randseed(true);
#else
	unsigned int seed;

	seed = randseed(false);
#endif
	while (*curs != '\0' && *curs != '\n') {
		if (*curs == 'x' || *curs == 'X') {
			if (curs - hwaddr == 1) {
				/* ensure address is unicast */
#ifdef HAVE_RAND_R
				*curs = hex[rand_r(&seed) & 0x0E];
			} else {
				*curs = hex[rand_r(&seed) & 0x0F];
#else
				*curs = hex[rand() & 0x0E];
			} else {
				*curs = hex[rand() & 0x0F];
#endif
			}
		}
		curs++;
	}
	return 0;
}

static int set_config_network_flags(const char *key, const char *value,
				    struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_netdev *netdev;

	netdev = network_netdev(key, value, &lxc_conf->network);
	if (!netdev)
		return -1;

	if (lxc_config_value_empty(value)) {
		netdev->flags = 0;
		return 0;
	}

	netdev->flags |= IFF_UP;

	return 0;
}

static int set_config_network_link(const char *key, const char *value,
				   struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_netdev *netdev;

	netdev = network_netdev(key, value, &lxc_conf->network);
	if (!netdev)
		return -1;

	return network_ifname(netdev->link, value);
}

static int set_config_network_name(const char *key, const char *value,
				   struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_netdev *netdev;

	netdev = network_netdev(key, value, &lxc_conf->network);
	if (!netdev)
		return -1;

	return network_ifname(netdev->name, value);
}

static int set_config_network_veth_pair(const char *key, const char *value,
					struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_netdev *netdev;

	netdev = network_netdev(key, value, &lxc_conf->network);
	if (!netdev)
		return -1;

	if (netdev->type != LXC_NET_VETH) {
		ERROR("Invalid veth pair for a non-veth netdev");
		return -1;
	}

	return network_ifname(netdev->priv.veth_attr.pair, value);
}

static int set_config_network_macvlan_mode(const char *key, const char *value,
					   struct lxc_conf *lxc_conf,
					   void *data)
{
	struct lxc_netdev *netdev;

	netdev = network_netdev(key, value, &lxc_conf->network);
	if (!netdev)
		return -1;

	if (netdev->type != LXC_NET_MACVLAN) {
		ERROR("Invalid macvlan.mode for a non-macvlan netdev");
		return -1;
	}

	if (lxc_config_value_empty(value)) {
		netdev->priv.macvlan_attr.mode = 0;
		return 0;
	}

	return macvlan_mode(&netdev->priv.macvlan_attr.mode, value);
}

static int set_config_network_hwaddr(const char *key, const char *value,
				     struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_netdev *netdev;
	char *new_value;

	new_value = strdup(value);
	if (!new_value) {
		SYSERROR("failed to strdup \"%s\"", value);
		return -1;
	}
	rand_complete_hwaddr(new_value);

	netdev = network_netdev(key, new_value, &lxc_conf->network);
	if (!netdev) {
		free(new_value);
		return -1;
	};

	if (lxc_config_value_empty(new_value)) {
		free(new_value);
		netdev->hwaddr = NULL;
		return 0;
	}

	netdev->hwaddr = new_value;
	return 0;
}

static int set_config_network_vlan_id(const char *key, const char *value,
				      struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_netdev *netdev;

	netdev = network_netdev(key, value, &lxc_conf->network);
	if (!netdev)
		return -1;

	if (netdev->type != LXC_NET_VLAN) {
		ERROR("Invalid vlan.id for a non-macvlan netdev");
		return -1;
	}

	if (lxc_config_value_empty(value)) {
		netdev->priv.vlan_attr.vid = 0;
		return 0;
	}

	if (get_u16(&netdev->priv.vlan_attr.vid, value, 0))
		return -1;

	return 0;
}

static int set_config_network_mtu(const char *key, const char *value,
				  struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_netdev *netdev;

	netdev = network_netdev(key, value, &lxc_conf->network);
	if (!netdev)
		return -1;

	return set_config_string_item(&netdev->mtu, value);
}

static int set_config_network_ipv4(const char *key, const char *value,
				   struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_netdev *netdev;
	struct lxc_inetdev *inetdev;
	struct lxc_list *list;
	char *cursor, *slash;
	char *addr = NULL, *bcast = NULL, *prefix = NULL;

	if (lxc_config_value_empty(value))
		return clr_config_network_item(key, lxc_conf, NULL);

	netdev = network_netdev(key, value, &lxc_conf->network);
	if (!netdev)
		return -1;

	inetdev = malloc(sizeof(*inetdev));
	if (!inetdev) {
		SYSERROR("failed to allocate ipv4 address");
		return -1;
	}
	memset(inetdev, 0, sizeof(*inetdev));

	list = malloc(sizeof(*list));
	if (!list) {
		SYSERROR("failed to allocate memory");
		free(inetdev);
		return -1;
	}

	lxc_list_init(list);
	list->elem = inetdev;

	addr = strdup(value);
	if (!addr) {
		ERROR("no address specified");
		free(inetdev);
		free(list);
		return -1;
	}

	cursor = strstr(addr, " ");
	if (cursor) {
		*cursor = '\0';
		bcast = cursor + 1;
	}

	slash = strstr(addr, "/");
	if (slash) {
		*slash = '\0';
		prefix = slash + 1;
	}

	if (!inet_pton(AF_INET, addr, &inetdev->addr)) {
		SYSERROR("invalid ipv4 address: %s", value);
		free(inetdev);
		free(addr);
		free(list);
		return -1;
	}

	if (bcast && !inet_pton(AF_INET, bcast, &inetdev->bcast)) {
		SYSERROR("invalid ipv4 broadcast address: %s", value);
		free(inetdev);
		free(list);
		free(addr);
		return -1;
	}

	/* No prefix specified, determine it from the network class. */
	if (prefix) {
		if (lxc_safe_uint(prefix, &inetdev->prefix) < 0)
			return -1;
	} else {
		inetdev->prefix = config_ip_prefix(&inetdev->addr);
	}

	/* If no broadcast address, let compute one from the
	 * prefix and address.
	 */
	if (!bcast) {
		inetdev->bcast.s_addr = inetdev->addr.s_addr;
		inetdev->bcast.s_addr |=
		    htonl(INADDR_BROADCAST >> inetdev->prefix);
	}

	lxc_list_add_tail(&netdev->ipv4, list);

	free(addr);
	return 0;
}

static int set_config_network_ipv4_gateway(const char *key, const char *value,
					   struct lxc_conf *lxc_conf,
					   void *data)
{
	struct lxc_netdev *netdev;

	netdev = network_netdev(key, value, &lxc_conf->network);
	if (!netdev)
		return -1;

	free(netdev->ipv4_gateway);

	if (lxc_config_value_empty(value)) {
		netdev->ipv4_gateway = NULL;
		return 0;
	}

	if (!strcmp(value, "auto")) {
		netdev->ipv4_gateway = NULL;
		netdev->ipv4_gateway_auto = true;
	} else {
		struct in_addr *gw;

		gw = malloc(sizeof(*gw));
		if (!gw) {
			SYSERROR("failed to allocate ipv4 gateway address");
			return -1;
		}

		if (!inet_pton(AF_INET, value, gw)) {
			SYSERROR("invalid ipv4 gateway address: %s", value);
			free(gw);
			return -1;
		}

		netdev->ipv4_gateway = gw;
		netdev->ipv4_gateway_auto = false;
	}

	return 0;
}

static int set_config_network_ipv6(const char *key, const char *value,
				   struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_netdev *netdev;
	struct lxc_inet6dev *inet6dev;
	struct lxc_list *list;
	char *slash, *valdup, *netmask;

	if (lxc_config_value_empty(value))
		return clr_config_network_item(key, lxc_conf, NULL);

	netdev = network_netdev(key, value, &lxc_conf->network);
	if (!netdev)
		return -1;

	inet6dev = malloc(sizeof(*inet6dev));
	if (!inet6dev) {
		SYSERROR("failed to allocate ipv6 address");
		return -1;
	}
	memset(inet6dev, 0, sizeof(*inet6dev));

	list = malloc(sizeof(*list));
	if (!list) {
		SYSERROR("failed to allocate memory");
		free(inet6dev);
		return -1;
	}

	lxc_list_init(list);
	list->elem = inet6dev;

	valdup = strdup(value);
	if (!valdup) {
		ERROR("no address specified");
		free(list);
		free(inet6dev);
		return -1;
	}

	inet6dev->prefix = 64;
	slash = strstr(valdup, "/");
	if (slash) {
		*slash = '\0';
		netmask = slash + 1;
		if (lxc_safe_uint(netmask, &inet6dev->prefix) < 0)
			return -1;
	}

	if (!inet_pton(AF_INET6, valdup, &inet6dev->addr)) {
		SYSERROR("invalid ipv6 address: %s", valdup);
		free(list);
		free(inet6dev);
		free(valdup);
		return -1;
	}

	lxc_list_add_tail(&netdev->ipv6, list);

	free(valdup);
	return 0;
}

static int set_config_network_ipv6_gateway(const char *key, const char *value,
					   struct lxc_conf *lxc_conf,
					   void *data)
{
	struct lxc_netdev *netdev;

	netdev = network_netdev(key, value, &lxc_conf->network);
	if (!netdev)
		return -1;

	free(netdev->ipv6_gateway);

	if (lxc_config_value_empty(value)) {
		netdev->ipv6_gateway = NULL;
		return 0;
	}

	if (!strcmp(value, "auto")) {
		netdev->ipv6_gateway = NULL;
		netdev->ipv6_gateway_auto = true;
	} else {
		struct in6_addr *gw;

		gw = malloc(sizeof(*gw));
		if (!gw) {
			SYSERROR("failed to allocate ipv6 gateway address");
			return -1;
		}

		if (!inet_pton(AF_INET6, value, gw)) {
			SYSERROR("invalid ipv6 gateway address: %s", value);
			free(gw);
			return -1;
		}

		netdev->ipv6_gateway = gw;
		netdev->ipv6_gateway_auto = false;
	}

	return 0;
}

static int set_config_network_script_up(const char *key, const char *value,
					struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_netdev *netdev;

	netdev = network_netdev(key, value, &lxc_conf->network);
	if (!netdev)
		return -1;

	return set_config_string_item(&netdev->upscript, value);
}

static int set_config_network_script_down(const char *key, const char *value,
					  struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_netdev *netdev;

	netdev = network_netdev(key, value, &lxc_conf->network);
	if (!netdev)
		return -1;

	return set_config_string_item(&netdev->downscript, value);
}

static int add_hook(struct lxc_conf *lxc_conf, int which, char *hook)
{
	struct lxc_list *hooklist;

	hooklist = malloc(sizeof(*hooklist));
	if (!hooklist) {
		free(hook);
		return -1;
	}

	hooklist->elem = hook;
	lxc_list_add_tail(&lxc_conf->hooks[which], hooklist);
	return 0;
}

static int set_config_seccomp(const char *key, const char *value,
			      struct lxc_conf *lxc_conf, void *data)
{
	return set_config_path_item(&lxc_conf->seccomp, value);
}

static int set_config_init_cmd(const char *key, const char *value,
			       struct lxc_conf *lxc_conf, void *data)
{
	return set_config_path_item(&lxc_conf->init_cmd, value);
}

static int set_config_init_uid(const char *key, const char *value,
			       struct lxc_conf *lxc_conf, void *data)
{
	unsigned int init_uid;

	/* Set config value to default. */
	if (lxc_config_value_empty(value)) {
		lxc_conf->init_uid = 0;
		return 0;
	}

	/* Parse new config value. */
	if (lxc_safe_uint(value, &init_uid) < 0)
		return -1;
	lxc_conf->init_uid = init_uid;

	return 0;
}

static int set_config_init_gid(const char *key, const char *value,
			       struct lxc_conf *lxc_conf, void *data)
{
	unsigned int init_gid;

	/* Set config value to default. */
	if (lxc_config_value_empty(value)) {
		lxc_conf->init_gid = 0;
		return 0;
	}

	/* Parse new config value. */
	if (lxc_safe_uint(value, &init_gid) < 0)
		return -1;
	lxc_conf->init_gid = init_gid;

	return 0;
}

static int set_config_hooks(const char *key, const char *value,
			    struct lxc_conf *lxc_conf, void *data)
{
	char *copy;

	if (lxc_config_value_empty(value))
		return lxc_clear_hooks(lxc_conf, key);

	if (strcmp(key + 4, "hook") == 0) {
		ERROR("lxc.hook cannot take a value");
		return -1;
	}
	copy = strdup(value);
	if (!copy) {
		SYSERROR("failed to dup string '%s'", value);
		return -1;
	}

	if (strcmp(key + 9, "pre-start") == 0)
		return add_hook(lxc_conf, LXCHOOK_PRESTART, copy);
	else if (strcmp(key + 9, "pre-mount") == 0)
		return add_hook(lxc_conf, LXCHOOK_PREMOUNT, copy);
	else if (strcmp(key + 9, "autodev") == 0)
		return add_hook(lxc_conf, LXCHOOK_AUTODEV, copy);
	else if (strcmp(key + 9, "mount") == 0)
		return add_hook(lxc_conf, LXCHOOK_MOUNT, copy);
	else if (strcmp(key + 9, "start") == 0)
		return add_hook(lxc_conf, LXCHOOK_START, copy);
	else if (strcmp(key + 9, "stop") == 0)
		return add_hook(lxc_conf, LXCHOOK_STOP, copy);
	else if (strcmp(key + 9, "post-stop") == 0)
		return add_hook(lxc_conf, LXCHOOK_POSTSTOP, copy);
	else if (strcmp(key + 9, "clone") == 0)
		return add_hook(lxc_conf, LXCHOOK_CLONE, copy);
	else if (strcmp(key + 9, "destroy") == 0)
		return add_hook(lxc_conf, LXCHOOK_DESTROY, copy);

	SYSERROR("Unknown key: %s", key);
	free(copy);
	return -1;
}

static int set_config_personality(const char *key, const char *value,
				  struct lxc_conf *lxc_conf, void *data)
{
	signed long personality = lxc_config_parse_arch(value);

	if (personality >= 0)
		lxc_conf->personality = personality;
	else
		WARN("unsupported personality '%s'", value);

	return 0;
}

static int set_config_pts(const char *key, const char *value,
			  struct lxc_conf *lxc_conf, void *data)
{
	/* Set config value to default. */
	if (lxc_config_value_empty(value)) {
		lxc_conf->pts = 0;
		return 0;
	}

	/* Parse new config value. */
	if (lxc_safe_uint(value, &lxc_conf->pts) < 0)
		return -1;

	return 0;
}

/* We only need to check whether the first byte of the key after the lxc.start.
 * prefix matches our expectations since they fortunately all start with a
 * different letter. If anything was wrong with the key we would have already
 * noticed when the callback was called.
 */
static int set_config_start(const char *key, const char *value,
			    struct lxc_conf *lxc_conf, void *data)
{
	bool is_empty;

	is_empty = lxc_config_value_empty(value);

	if (*(key + 10) == 'a') { /* lxc.start.auto */
		/* Set config value to default. */
		if (is_empty) {
			lxc_conf->start_auto = 0;
			return 0;
		}

		/* Parse new config value. */
		if (lxc_safe_uint(value, &lxc_conf->start_auto) < 0)
			return -1;

		if (lxc_conf->start_auto > 1)
			return -1;

		return 0;
	} else if (*(key + 10) == 'd') { /* lxc.start.delay */
		/* Set config value to default. */
		if (is_empty) {
			lxc_conf->start_delay = 0;
			return 0;
		}

		/* Parse new config value. */
		return lxc_safe_uint(value, &lxc_conf->start_delay);
	} else if (*(key + 10) == 'o') { /* lxc.start.order */
		/* Set config value to default. */
		if (is_empty) {
			lxc_conf->start_order = 0;
			return 0;
		}

		/* Parse new config value. */
		return lxc_safe_int(value, &lxc_conf->start_order);
	}

	SYSERROR("Unknown key: %s", key);
	return -1;
}

static int set_config_monitor(const char *key, const char *value,
			      struct lxc_conf *lxc_conf, void *data)
{
	/* Set config value to default. */
	if (lxc_config_value_empty(value)) {
		lxc_conf->monitor_unshare = 0;
		return 0;
	}

	/* Parse new config value. */
	if (strcmp(key + 12, "unshare") == 0)
		return lxc_safe_uint(value, &lxc_conf->monitor_unshare);

	SYSERROR("Unknown key: %s", key);
	return -1;
}

static int set_config_group(const char *key, const char *value,
			    struct lxc_conf *lxc_conf, void *data)
{
	char *groups, *groupptr, *sptr, *token;
	struct lxc_list *grouplist;
	int ret = -1;

	if (lxc_config_value_empty(value))
		return lxc_clear_groups(lxc_conf);

	groups = strdup(value);
	if (!groups) {
		SYSERROR("failed to dup '%s'", value);
		return -1;
	}

	/* In case several groups are specified in a single line
	 * split these groups in a single element for the list.
	 */
	for (groupptr = groups;; groupptr = NULL) {
		token = strtok_r(groupptr, " \t", &sptr);
		if (!token) {
			ret = 0;
			break;
		}

		grouplist = malloc(sizeof(*grouplist));
		if (!grouplist) {
			SYSERROR("failed to allocate groups list");
			break;
		}

		grouplist->elem = strdup(token);
		if (!grouplist->elem) {
			SYSERROR("failed to dup '%s'", token);
			free(grouplist);
			break;
		}

		lxc_list_add_tail(&lxc_conf->groups, grouplist);
	}

	free(groups);
	return ret;
}

static int set_config_environment(const char *key, const char *value,
				  struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_list *list_item = NULL;

	if (lxc_config_value_empty(value))
		return lxc_clear_environment(lxc_conf);

	list_item = malloc(sizeof(*list_item));
	if (!list_item)
		goto on_error;

	list_item->elem = strdup(value);

	if (!list_item->elem)
		goto on_error;

	lxc_list_add_tail(&lxc_conf->environment, list_item);

	return 0;

on_error:
	free(list_item);
	return -1;
}

static int set_config_tty(const char *key, const char *value,
			  struct lxc_conf *lxc_conf, void *data)
{
	/* Set config value to default. */
	if (lxc_config_value_empty(value)) {
		lxc_conf->tty = 0;
		return 0;
	}

	/* Parse new config value. */
	return lxc_safe_uint(value, &lxc_conf->tty);
}

static int set_config_ttydir(const char *key, const char *value,
			     struct lxc_conf *lxc_conf, void *data)
{
	return set_config_string_item_max(&lxc_conf->ttydir, value,
					  NAME_MAX + 1);
}

static int set_config_kmsg(const char *key, const char *value,
			   struct lxc_conf *lxc_conf, void *data)
{
	/* Set config value to default. */
	if (lxc_config_value_empty(value)) {
		lxc_conf->kmsg = 0;
		return 0;
	}

	/* Parse new config value. */
	if (lxc_safe_uint(value, &lxc_conf->kmsg) < 0)
		return -1;

	if (lxc_conf->kmsg > 1)
		return -1;

	return 0;
}

static int set_config_lsm_aa_profile(const char *key, const char *value,
				     struct lxc_conf *lxc_conf, void *data)
{
	return set_config_string_item(&lxc_conf->lsm_aa_profile, value);
}

static int set_config_lsm_aa_incomplete(const char *key, const char *value,
					struct lxc_conf *lxc_conf, void *data)
{
	/* Set config value to default. */
	if (lxc_config_value_empty(value)) {
		lxc_conf->lsm_aa_allow_incomplete = 0;
		return 0;
	}

	/* Parse new config value. */
	if (lxc_safe_uint(value, &lxc_conf->lsm_aa_allow_incomplete) < 0)
		return -1;

	if (lxc_conf->lsm_aa_allow_incomplete > 1) {
		ERROR("Wrong value for lxc.lsm_aa_allow_incomplete. Can only "
		      "be set to 0 or 1");
		return -1;
	}

	return 0;
}

static int set_config_lsm_se_context(const char *key, const char *value,
				     struct lxc_conf *lxc_conf, void *data)
{
	return set_config_string_item(&lxc_conf->lsm_se_context, value);
}

static int set_config_logfile(const char *key, const char *value,
			      struct lxc_conf *c, void *data)
{
	int ret;

	if (lxc_config_value_empty(value)) {
		free(c->logfile);
		c->logfile = NULL;
		return 0;
	}

	/* Store these values in the lxc_conf, and then try to set for actual
	 * current logging.
	 */
	ret = set_config_path_item(&c->logfile, value);
	if (ret == 0)
		ret = lxc_log_set_file(&c->logfd, c->logfile);
	return ret;
}

static int set_config_loglevel(const char *key, const char *value,
			       struct lxc_conf *lxc_conf, void *data)
{
	int newlevel;

	/* Set config value to default. */
	if (lxc_config_value_empty(value)) {
		lxc_conf->loglevel = LXC_LOG_LEVEL_NOTSET;
		return 0;
	}

	/* Parse new config value. */
	if (value[0] >= '0' && value[0] <= '9') {
		if (lxc_safe_int(value, &newlevel) < 0)
			return -1;
	} else {
		newlevel = lxc_log_priority_to_int(value);
	}

	/* Store these values in the lxc_conf, and then try to set for actual
	 * current logging.
	 */
	lxc_conf->loglevel = newlevel;
	return lxc_log_set_level(&lxc_conf->loglevel, newlevel);
}

static int set_config_autodev(const char *key, const char *value,
			      struct lxc_conf *lxc_conf, void *data)
{
	/* Set config value to default. */
	if (lxc_config_value_empty(value)) {
		lxc_conf->autodev = 0;
		return 0;
	}

	/* Parse new config value. */
	if (lxc_safe_uint(value, &lxc_conf->autodev) < 0)
		return -1;

	if (lxc_conf->autodev > 1) {
		ERROR("Wrong value for lxc.autodev. Can only be set to 0 or 1");
		return -1;
	}

	return 0;
}

static int sig_num(const char *sig)
{
	unsigned int signum;

	if (lxc_safe_uint(sig, &signum) < 0)
		return -1;

	return signum;
}

static int rt_sig_num(const char *signame)
{
	int rtmax = 0, sig_n = 0;

	if (strncasecmp(signame, "max-", 4) == 0) {
		rtmax = 1;
	}

	signame += 4;
	if (!isdigit(*signame))
		return -1;

	sig_n = sig_num(signame);
	sig_n = rtmax ? SIGRTMAX - sig_n : SIGRTMIN + sig_n;
	if (sig_n > SIGRTMAX || sig_n < SIGRTMIN)
		return -1;

	return sig_n;
}

static int sig_parse(const char *signame)
{
	size_t n;

	if (isdigit(*signame)) {
		return sig_num(signame);
	} else if (strncasecmp(signame, "sig", 3) == 0) {
		signame += 3;
		if (strncasecmp(signame, "rt", 2) == 0)
			return rt_sig_num(signame + 2);
		for (n = 0; n < sizeof(signames) / sizeof((signames)[0]); n++) {
			if (strcasecmp(signames[n].name, signame) == 0)
				return signames[n].num;
		}
	}

	return -1;
}

static int set_config_haltsignal(const char *key, const char *value,
				 struct lxc_conf *lxc_conf, void *data)
{
	int sig_n;

	/* Set config value to default. */
	if (lxc_config_value_empty(value)) {
		lxc_conf->haltsignal = 0;
		return 0;
	}

	/* Parse new config value. */
	sig_n = sig_parse(value);

	if (sig_n < 0)
		return -1;
	lxc_conf->haltsignal = sig_n;

	return 0;
}

static int set_config_rebootsignal(const char *key, const char *value,
				   struct lxc_conf *lxc_conf, void *data)
{
	int sig_n;

	/* Set config value to default. */
	if (lxc_config_value_empty(value)) {
		lxc_conf->rebootsignal = 0;
		return 0;
	}

	/* Parse new config value. */
	sig_n = sig_parse(value);
	if (sig_n < 0)
		return -1;
	lxc_conf->rebootsignal = sig_n;

	return 0;
}

static int set_config_stopsignal(const char *key, const char *value,
				 struct lxc_conf *lxc_conf, void *data)
{
	int sig_n;

	/* Set config value to default. */
	if (lxc_config_value_empty(value)) {
		lxc_conf->stopsignal = 0;
		return 0;
	}

	/* Parse new config value. */
	sig_n = sig_parse(value);
	if (sig_n < 0)
		return -1;
	lxc_conf->stopsignal = sig_n;

	return 0;
}

static int set_config_cgroup(const char *key, const char *value,
			     struct lxc_conf *lxc_conf, void *data)
{
	char *subkey;
	char *token = "lxc.cgroup.";
	struct lxc_list *cglist = NULL;
	struct lxc_cgroup *cgelem = NULL;

	if (lxc_config_value_empty(value))
		return lxc_clear_cgroups(lxc_conf, key);

	subkey = strstr(key, token);
	if (!subkey)
		return -1;

	if (!strlen(subkey))
		return -1;

	if (strlen(subkey) == strlen(token))
		return -1;

	subkey += strlen(token);

	cglist = malloc(sizeof(*cglist));
	if (!cglist)
		goto out;

	cgelem = malloc(sizeof(*cgelem));
	if (!cgelem)
		goto out;
	memset(cgelem, 0, sizeof(*cgelem));

	cgelem->subsystem = strdup(subkey);
	cgelem->value = strdup(value);

	if (!cgelem->subsystem || !cgelem->value)
		goto out;

	cglist->elem = cgelem;

	lxc_list_add_tail(&lxc_conf->cgroup, cglist);

	return 0;

out:
	free(cglist);

	if (cgelem) {
		free(cgelem->subsystem);

		free(cgelem->value);

		free(cgelem);
	}

	return -1;
}

static int set_config_idmaps(const char *key, const char *value,
			     struct lxc_conf *lxc_conf, void *data)
{
	unsigned long hostid, nsid, range;
	char type;
	int ret;
	struct lxc_list *idmaplist = NULL;
	struct id_map *idmap = NULL;

	if (lxc_config_value_empty(value))
		return lxc_clear_idmaps(lxc_conf);

	idmaplist = malloc(sizeof(*idmaplist));
	if (!idmaplist)
		goto on_error;

	idmap = malloc(sizeof(*idmap));
	if (!idmap)
		goto on_error;
	memset(idmap, 0, sizeof(*idmap));

	ret = parse_idmaps(value, &type, &nsid, &hostid, &range);
	if (ret < 0)
		goto on_error;

	INFO("Read uid map: type %c nsid %lu hostid %lu range %lu", type, nsid, hostid, range);
	if (type == 'u')
		idmap->idtype = ID_TYPE_UID;
	else if (type == 'g')
		idmap->idtype = ID_TYPE_GID;
	else
		goto on_error;

	idmap->hostid = hostid;
	idmap->nsid = nsid;
	idmap->range = range;
	idmaplist->elem = idmap;
	lxc_list_add_tail(&lxc_conf->id_map, idmaplist);

	if (!lxc_conf->root_nsuid_map && idmap->idtype == ID_TYPE_UID)
		if (idmap->nsid == 0)
			lxc_conf->root_nsuid_map = idmap;


	if (!lxc_conf->root_nsgid_map && idmap->idtype == ID_TYPE_GID)
		if (idmap->nsid == 0)
			lxc_conf->root_nsgid_map = idmap;

	idmap = NULL;

	return 0;

on_error:
	free(idmaplist);
	free(idmap);

	return -1;
}

static int set_config_fstab(const char *key, const char *value,
			    struct lxc_conf *lxc_conf, void *data)
{
	if (lxc_config_value_empty(value)) {
		clr_config_fstab(key, lxc_conf, NULL);
		return -1;
	}

	return set_config_path_item(&lxc_conf->fstab, value);
}

static int set_config_mount_auto(const char *key, const char *value,
				 struct lxc_conf *lxc_conf, void *data)
{
	char *autos, *autoptr, *sptr, *token;
	int i;
	int ret = -1;
	static struct {
		const char *token;
		int mask;
		int flag;
	} allowed_auto_mounts[] = {
	    { "proc",                    LXC_AUTO_PROC_MASK,   LXC_AUTO_PROC_MIXED                                 },
	    { "proc:mixed",              LXC_AUTO_PROC_MASK,   LXC_AUTO_PROC_MIXED                                 },
	    { "proc:rw",                 LXC_AUTO_PROC_MASK,   LXC_AUTO_PROC_RW                                    },
	    { "sys",                     LXC_AUTO_SYS_MASK,    LXC_AUTO_SYS_MIXED                                  },
	    { "sys:ro",                  LXC_AUTO_SYS_MASK,    LXC_AUTO_SYS_RO                                     },
	    { "sys:mixed",               LXC_AUTO_SYS_MASK,    LXC_AUTO_SYS_MIXED                                  },
	    { "sys:rw",                  LXC_AUTO_SYS_MASK,    LXC_AUTO_SYS_RW                                     },
	    { "cgroup",                  LXC_AUTO_CGROUP_MASK, LXC_AUTO_CGROUP_NOSPEC                              },
	    { "cgroup:mixed",            LXC_AUTO_CGROUP_MASK, LXC_AUTO_CGROUP_MIXED                               },
	    { "cgroup:ro",               LXC_AUTO_CGROUP_MASK, LXC_AUTO_CGROUP_RO                                  },
	    { "cgroup:rw",               LXC_AUTO_CGROUP_MASK, LXC_AUTO_CGROUP_RW                                  },
	    { "cgroup:force",            LXC_AUTO_CGROUP_MASK, LXC_AUTO_CGROUP_NOSPEC | LXC_AUTO_CGROUP_FORCE      },
	    { "cgroup:mixed:force",      LXC_AUTO_CGROUP_MASK, LXC_AUTO_CGROUP_MIXED | LXC_AUTO_CGROUP_FORCE       },
	    { "cgroup:ro:force",         LXC_AUTO_CGROUP_MASK, LXC_AUTO_CGROUP_RO | LXC_AUTO_CGROUP_FORCE          },
	    { "cgroup:rw:force",         LXC_AUTO_CGROUP_MASK, LXC_AUTO_CGROUP_RW | LXC_AUTO_CGROUP_FORCE          },
	    { "cgroup-full",             LXC_AUTO_CGROUP_MASK, LXC_AUTO_CGROUP_FULL_NOSPEC                         },
	    { "cgroup-full:mixed",       LXC_AUTO_CGROUP_MASK, LXC_AUTO_CGROUP_FULL_MIXED                          },
	    { "cgroup-full:ro",          LXC_AUTO_CGROUP_MASK, LXC_AUTO_CGROUP_FULL_RO                             },
	    { "cgroup-full:rw",          LXC_AUTO_CGROUP_MASK, LXC_AUTO_CGROUP_FULL_RW                             },
	    { "cgroup-full:force",       LXC_AUTO_CGROUP_MASK, LXC_AUTO_CGROUP_FULL_NOSPEC | LXC_AUTO_CGROUP_FORCE },
	    { "cgroup-full:mixed:force", LXC_AUTO_CGROUP_MASK, LXC_AUTO_CGROUP_FULL_MIXED | LXC_AUTO_CGROUP_FORCE  },
	    { "cgroup-full:ro:force",    LXC_AUTO_CGROUP_MASK, LXC_AUTO_CGROUP_FULL_RO | LXC_AUTO_CGROUP_FORCE     },
	    { "cgroup-full:rw:force",    LXC_AUTO_CGROUP_MASK, LXC_AUTO_CGROUP_FULL_RW | LXC_AUTO_CGROUP_FORCE     },
	    /* For adding anything that is just a single on/off, but has no
	     * options: keep mask and flag identical and just define the enum
	     * value as an unused bit so far
	     */
	    { NULL,                      0,                     0                                             }
	};

	if (lxc_config_value_empty(value)) {
		lxc_conf->auto_mounts = 0;
		return 0;
	}

	autos = strdup(value);
	if (!autos) {
		SYSERROR("failed to dup '%s'", value);
		return -1;
	}

	for (autoptr = autos;; autoptr = NULL) {
		token = strtok_r(autoptr, " \t", &sptr);
		if (!token) {
			ret = 0;
			break;
		}

		for (i = 0; allowed_auto_mounts[i].token; i++) {
			if (!strcmp(allowed_auto_mounts[i].token, token))
				break;
		}

		if (!allowed_auto_mounts[i].token) {
			ERROR("Invalid filesystem to automount: %s", token);
			break;
		}

		lxc_conf->auto_mounts &= ~allowed_auto_mounts[i].mask;
		lxc_conf->auto_mounts |= allowed_auto_mounts[i].flag;
	}

	free(autos);
	return ret;
}

static int set_config_mount(const char *key, const char *value,
			    struct lxc_conf *lxc_conf, void *data)
{
	char *mntelem;
	struct lxc_list *mntlist;

	if (lxc_config_value_empty(value))
		return lxc_clear_mount_entries(lxc_conf);

	mntlist = malloc(sizeof(*mntlist));
	if (!mntlist)
		return -1;

	mntelem = strdup(value);
	if (!mntelem) {
		free(mntlist);
		return -1;
	}
	mntlist->elem = mntelem;

	lxc_list_add_tail(&lxc_conf->mount_list, mntlist);

	return 0;
}

static int set_config_cap_keep(const char *key, const char *value,
			       struct lxc_conf *lxc_conf, void *data)
{
	char *keepcaps, *keepptr, *sptr, *token;
	struct lxc_list *keeplist;
	int ret = -1;

	if (lxc_config_value_empty(value))
		return lxc_clear_config_keepcaps(lxc_conf);

	keepcaps = strdup(value);
	if (!keepcaps) {
		SYSERROR("failed to dup '%s'", value);
		return -1;
	}

	/* In case several capability keep is specified in a single line
	 * split these caps in a single element for the list.
	 */
	for (keepptr = keepcaps;; keepptr = NULL) {
		token = strtok_r(keepptr, " \t", &sptr);
		if (!token) {
			ret = 0;
			break;
		}

		if (!strcmp(token, "none"))
			lxc_clear_config_keepcaps(lxc_conf);

		keeplist = malloc(sizeof(*keeplist));
		if (!keeplist) {
			SYSERROR("failed to allocate keepcap list");
			break;
		}

		keeplist->elem = strdup(token);
		if (!keeplist->elem) {
			SYSERROR("failed to dup '%s'", token);
			free(keeplist);
			break;
		}

		lxc_list_add_tail(&lxc_conf->keepcaps, keeplist);
	}

	free(keepcaps);

	return ret;
}

static int set_config_cap_drop(const char *key, const char *value,
			       struct lxc_conf *lxc_conf, void *data)
{
	char *dropcaps, *dropptr, *sptr, *token;
	struct lxc_list *droplist;
	int ret = -1;

	if (lxc_config_value_empty(value))
		return lxc_clear_config_caps(lxc_conf);

	dropcaps = strdup(value);
	if (!dropcaps) {
		SYSERROR("failed to dup '%s'", value);
		return -1;
	}

	/* In case several capability drop is specified in a single line
	 * split these caps in a single element for the list.
	 */
	for (dropptr = dropcaps;; dropptr = NULL) {
		token = strtok_r(dropptr, " \t", &sptr);
		if (!token) {
			ret = 0;
			break;
		}

		droplist = malloc(sizeof(*droplist));
		if (!droplist) {
			SYSERROR("failed to allocate drop list");
			break;
		}

		droplist->elem = strdup(token);
		if (!droplist->elem) {
			SYSERROR("failed to dup '%s'", token);
			free(droplist);
			break;
		}

		lxc_list_add_tail(&lxc_conf->caps, droplist);
	}

	free(dropcaps);

	return ret;
}

static int set_config_console(const char *key, const char *value,
			      struct lxc_conf *lxc_conf, void *data)
{
	return set_config_path_item(&lxc_conf->console.path, value);
}

static int set_config_console_logfile(const char *key, const char *value,
				      struct lxc_conf *lxc_conf, void *data)
{
	return set_config_path_item(&lxc_conf->console.log_path, value);
}

/*
 * If we find a lxc.network.hwaddr in the original config file, we expand it in
 * the unexpanded_config, so that after a save_config we store the hwaddr for
 * re-use.
 * This is only called when reading the config file, not when executing a
 * lxc.include.
 * 'x' and 'X' are substituted in-place.
 */
static void update_hwaddr(const char *line)
{
	char *p;

	line += lxc_char_left_gc(line, strlen(line));
	if (line[0] == '#')
		return;

	if (strncmp(line, "lxc.network.hwaddr", 18) != 0)
		return;

	/* Let config_network_hwaddr raise the error. */
	p = strchr(line, '=');
	if (!p)
		return;
	p++;

	while (isblank(*p))
		p++;

	if (!*p)
		return;

	rand_complete_hwaddr(p);
}

int append_unexp_config_line(const char *line, struct lxc_conf *conf)
{
	size_t len = conf->unexpanded_len, linelen = strlen(line);

	update_hwaddr(line);

	while (conf->unexpanded_alloced <= len + linelen + 2) {
		char *tmp = realloc(conf->unexpanded_config,
				    conf->unexpanded_alloced + 1024);
		if (!tmp)
			return -1;

		if (!conf->unexpanded_config)
			*tmp = '\0';
		conf->unexpanded_config = tmp;
		conf->unexpanded_alloced += 1024;
	}
	strcat(conf->unexpanded_config, line);
	conf->unexpanded_len += linelen;
	if (line[linelen - 1] != '\n') {
		strcat(conf->unexpanded_config, "\n");
		conf->unexpanded_len++;
	}
	return 0;
}

static int do_includedir(const char *dirp, struct lxc_conf *lxc_conf)
{
	struct dirent *direntp;
	DIR *dir;
	char path[MAXPATHLEN];
	int len;
	int ret = -1;

	dir = opendir(dirp);
	if (!dir) {
		SYSERROR("failed to open '%s'", dirp);
		return -1;
	}

	while ((direntp = readdir(dir))) {
		const char *fnam;

		fnam = direntp->d_name;
		if (!strcmp(fnam, "."))
			continue;

		if (!strcmp(fnam, ".."))
			continue;

		len = strlen(fnam);
		if (len < 6 || strncmp(fnam + len - 5, ".conf", 5) != 0)
			continue;
		len = snprintf(path, MAXPATHLEN, "%s/%s", dirp, fnam);
		if (len < 0 || len >= MAXPATHLEN) {
			ERROR("lxc.include filename too long under '%s'", dirp);
			ret = -1;
			goto out;
		}

		ret = lxc_config_read(path, lxc_conf, true);
		if (ret < 0)
			goto out;
	}
	ret = 0;

out:
	if (closedir(dir))
		WARN("lxc.include dir: failed to close directory");

	return ret;
}

static int set_config_includefiles(const char *key, const char *value,
				   struct lxc_conf *lxc_conf, void *data)
{
	/* Set config value to default. */
	if (lxc_config_value_empty(value)) {
		clr_config_includefiles(key, lxc_conf, NULL);
		return 0;
	}

	/* Parse new config value. */
	if (is_dir(value))
		return do_includedir(value, lxc_conf);

	return lxc_config_read(value, lxc_conf, true);
}

static int set_config_rootfs(const char *key, const char *value,
			     struct lxc_conf *lxc_conf, void *data)
{
	return set_config_path_item(&lxc_conf->rootfs.path, value);
}

static int set_config_rootfs_mount(const char *key, const char *value,
				   struct lxc_conf *lxc_conf, void *data)
{
	return set_config_path_item(&lxc_conf->rootfs.mount, value);
}

static int set_config_rootfs_options(const char *key, const char *value,
				     struct lxc_conf *lxc_conf, void *data)
{
	return set_config_string_item(&lxc_conf->rootfs.options, value);
}

static int set_config_rootfs_backend(const char *key, const char *value,
				     struct lxc_conf *lxc_conf, void *data)
{
	if (lxc_config_value_empty(value)) {
		free(lxc_conf->rootfs.bdev_type);
		lxc_conf->rootfs.bdev_type = NULL;
		return 0;
	}

	if (!is_valid_storage_type(value)) {
		ERROR("Bad rootfs.backend: '%s'", value);
		return -1;
	}

	return set_config_string_item(&lxc_conf->rootfs.bdev_type, value);
}

static int set_config_pivotdir(const char *key, const char *value,
			       struct lxc_conf *lxc_conf, void *data)
{
	WARN("lxc.pivotdir is ignored.  It will soon become an error.");
	return 0;
}

static int set_config_utsname(const char *key, const char *value,
			      struct lxc_conf *lxc_conf, void *data)
{
	struct utsname *utsname;

	if (lxc_config_value_empty(value)) {
		clr_config_utsname(key, lxc_conf, NULL);
		return 0;
	}

	utsname = malloc(sizeof(*utsname));
	if (!utsname) {
		SYSERROR("failed to allocate memory");
		return -1;
	}

	if (strlen(value) >= sizeof(utsname->nodename)) {
		ERROR("node name '%s' is too long", value);
		free(utsname);
		return -1;
	}

	strcpy(utsname->nodename, value);
	free(lxc_conf->utsname);
	lxc_conf->utsname = utsname;

	return 0;
}

struct parse_line_conf {
	struct lxc_conf *conf;
	bool from_include;
};

static int parse_line(char *buffer, void *data)
{
	char *dot, *key, *line, *linep, *value;
	bool empty_line;
	struct lxc_config_t *config;
	int ret = 0;
	char *dup = buffer;
	struct parse_line_conf *plc = data;

	/* If there are newlines in the config file we should keep them. */
	empty_line = lxc_is_line_empty(dup);
	if (empty_line)
		dup = "\n";

	/* we have to dup the buffer otherwise, at the re-exec for
	 * reboot we modified the original string on the stack by
	 * replacing '=' by '\0' below
	 */
	linep = line = strdup(buffer);
	if (!line)
		return -1;

	if (!plc->from_include) {
		ret = append_unexp_config_line(line, plc->conf);
		if (ret < 0)
			goto on_error;
	}

	if (empty_line)
		goto on_error;

	line += lxc_char_left_gc(line, strlen(line));

	/* ignore comments */
	if (line[0] == '#')
		goto on_error;

	/* martian option - don't add it to the config itself */
	if (strncmp(line, "lxc.", 4))
		goto on_error;

	ret = -1;

	dot = strchr(line, '=');
	if (!dot) {
		ERROR("Invalid configuration line: %s", line);
		goto on_error;
	}

	*dot = '\0';
	value = dot + 1;

	key = line;
	key[lxc_char_right_gc(key, strlen(key))] = '\0';

	value += lxc_char_left_gc(value, strlen(value));
	value[lxc_char_right_gc(value, strlen(value))] = '\0';

	if (*value == '\'' || *value == '\"') {
		size_t len = strlen(value);
		if (len > 1 && value[len - 1] == *value) {
			value[len - 1] = '\0';
			value++;
		}
	}

	config = lxc_getconfig(key);
	if (!config) {
		ERROR("Unknown configuration key \"%s\"", key);
		goto on_error;
	}

	ret = config->set(key, value, plc->conf, data);

on_error:
	free(linep);
	return ret;
}

static int lxc_config_readline(char *buffer, struct lxc_conf *conf)
{
	struct parse_line_conf c;

	c.conf = conf;
	c.from_include = false;

	return parse_line(buffer, &c);
}

int lxc_config_read(const char *file, struct lxc_conf *conf, bool from_include)
{
	struct parse_line_conf c;

	c.conf = conf;
	c.from_include = from_include;

	if (access(file, R_OK) == -1) {
		return -1;
	}

	/* Catch only the top level config file name in the structure */
	if (!conf->rcfile)
		conf->rcfile = strdup(file);

	return lxc_file_for_each_line(file, parse_line, &c);
}

int lxc_config_define_add(struct lxc_list *defines, char *arg)
{
	struct lxc_list *dent;

	dent = malloc(sizeof(struct lxc_list));
	if (!dent)
		return -1;

	dent->elem = arg;
	lxc_list_add_tail(defines, dent);
	return 0;
}

int lxc_config_define_load(struct lxc_list *defines, struct lxc_conf *conf)
{
	struct lxc_list *it, *next;
	int ret = 0;

	lxc_list_for_each(it, defines) {
		ret = lxc_config_readline(it->elem, conf);
		if (ret)
			break;
	}

	lxc_list_for_each_safe(it, defines, next) {
		lxc_list_del(it);
		free(it);
	}

	return ret;
}

signed long lxc_config_parse_arch(const char *arch)
{
#if HAVE_SYS_PERSONALITY_H
	size_t i;
	struct per_name {
		char *name;
		unsigned long per;
	} pername[] = {
	    { "arm",       PER_LINUX32 },
	    { "armel",     PER_LINUX32 },
	    { "armhf",     PER_LINUX32 },
	    { "armv7l",    PER_LINUX32 },
	    { "athlon",    PER_LINUX32 },
	    { "i386",      PER_LINUX32 },
	    { "i486",      PER_LINUX32 },
	    { "i586",      PER_LINUX32 },
	    { "i686",      PER_LINUX32 },
	    { "linux32",   PER_LINUX32 },
	    { "mips",      PER_LINUX32 },
	    { "mipsel",    PER_LINUX32 },
	    { "ppc",       PER_LINUX32 },
	    { "powerpc",   PER_LINUX32 },
	    { "x86",       PER_LINUX32 },
	    { "amd64",     PER_LINUX   },
	    { "arm64",     PER_LINUX   },
	    { "linux64",   PER_LINUX   },
	    { "mips64",    PER_LINUX   },
	    { "mips64el",  PER_LINUX   },
	    { "ppc64",     PER_LINUX   },
	    { "ppc64el",   PER_LINUX   },
	    { "ppc64le",   PER_LINUX   },
	    { "powerpc64", PER_LINUX   },
	    { "s390x",     PER_LINUX   },
	    { "x86_64",    PER_LINUX   },
	};
	size_t len = sizeof(pername) / sizeof(pername[0]);

	for (i = 0; i < len; i++)
		if (!strcmp(pername[i].name, arch))
			return pername[i].per;
#endif

	return -1;
}

int lxc_fill_elevated_privileges(char *flaglist, int *flags)
{
	char *token, *saveptr = NULL;
	int i, aflag;
	struct {
		const char *token;
		int flag;
	} all_privs[] = {
		{ "CGROUP", LXC_ATTACH_MOVE_TO_CGROUP    },
		{ "CAP",    LXC_ATTACH_DROP_CAPABILITIES },
		{ "LSM",    LXC_ATTACH_LSM_EXEC          },
		{ NULL,     0                            }
	};

	if (!flaglist) {
		/* For the sake of backward compatibility, drop all privileges
		 * if none is specified.
		 */
		for (i = 0; all_privs[i].token; i++) {
			*flags |= all_privs[i].flag;
		}
		return 0;
	}

	token = strtok_r(flaglist, "|", &saveptr);
	while (token) {
		aflag = -1;
		for (i = 0; all_privs[i].token; i++) {
			if (!strcmp(all_privs[i].token, token))
				aflag = all_privs[i].flag;
		}
		if (aflag < 0)
			return -1;

		*flags |= aflag;

		token = strtok_r(NULL, "|", &saveptr);
	}

	return 0;
}

static inline int lxc_get_conf_int(struct lxc_conf *c, char *retv, int inlen,
				   int v)
{
	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	return snprintf(retv, inlen, "%d", v);
}

/* Write out a configuration file. */
void write_config(FILE *fout, struct lxc_conf *c)
{
	int ret;
	size_t len = c->unexpanded_len;

	if (!len)
		return;

	ret = fwrite(c->unexpanded_config, 1, len, fout);
	if (ret != len)
		SYSERROR("Error writing configuration file");
}

bool do_append_unexp_config_line(struct lxc_conf *conf, const char *key,
				 const char *v)
{
	int ret;
	size_t len;
	char *tmp;

	len = strlen(key) + strlen(v) + 4;
	tmp = alloca(len);

	if (lxc_config_value_empty(v))
		ret = snprintf(tmp, len, "%s =", key);
	else
		ret = snprintf(tmp, len, "%s = %s", key, v);
	if (ret < 0 || ret >= len)
		return false;

	/* Save the line verbatim into unexpanded_conf */
	if (append_unexp_config_line(tmp, conf))
		return false;

	return true;
}

void clear_unexp_config_line(struct lxc_conf *conf, const char *key,
			     bool rm_subkeys)
{
	char *lend;
	char *lstart = conf->unexpanded_config;

	if (!conf->unexpanded_config)
		return;

	while (*lstart) {
		lend = strchr(lstart, '\n');
		char v;
		if (!lend)
			lend = lstart + strlen(lstart);
		else
			lend++;
		if (strncmp(lstart, key, strlen(key)) != 0) {
			lstart = lend;
			continue;
		}
		if (!rm_subkeys) {
			v = lstart[strlen(key)];
			if (!isspace(v) && v != '=') {
				lstart = lend;
				continue;
			}
		}
		conf->unexpanded_len -= (lend - lstart);
		if (*lend == '\0') {
			*lstart = '\0';
			return;
		}
		memmove(lstart, lend, strlen(lend) + 1);
	}
}

bool clone_update_unexp_ovl_paths(struct lxc_conf *conf, const char *oldpath,
				  const char *newpath, const char *oldname,
				  const char *newname, const char *ovldir)
{
	int ret;
	char *lend, *newdir, *olddir, *p, *q;
	size_t newdirlen, olddirlen;
	char *lstart = conf->unexpanded_config;
	const char *key = "lxc.mount.entry";

	olddirlen = strlen(ovldir) + strlen(oldpath) + strlen(oldname) + 2;
	olddir = alloca(olddirlen + 1);
	ret = snprintf(olddir, olddirlen + 1, "%s=%s/%s", ovldir, oldpath,
		       oldname);
	if (ret < 0 || ret >= olddirlen + 1) {
		ERROR("failed to create string");
		return false;
	}

	newdirlen = strlen(ovldir) + strlen(newpath) + strlen(newname) + 2;
	newdir = alloca(newdirlen + 1);
	ret = snprintf(newdir, newdirlen + 1, "%s=%s/%s", ovldir, newpath,
		       newname);
	if (ret < 0 || ret >= newdirlen + 1) {
		ERROR("failed to create string");
		return false;
	}

	if (!conf->unexpanded_config)
		return true;

	while (*lstart) {
		lend = strchr(lstart, '\n');
		if (!lend)
			lend = lstart + strlen(lstart);
		else
			lend++;

		if (strncmp(lstart, key, strlen(key)) != 0)
			goto next;

		p = strchr(lstart + strlen(key), '=');
		if (!p)
			goto next;
		p++;

		while (isblank(*p))
			p++;

		if (p >= lend)
			goto next;

		/* Whenever an lxc.mount.entry entry is found in a line we check
		*  if the substring " overlay" or the substring " aufs" is
		*  present before doing any further work. We check for "
		*  overlay" and " aufs" since both substrings need to have at
		*  least one space before them in a valid overlay
		*  lxc.mount.entry (/A B overlay).  When the space before is
		*  missing it is very likely that these substrings are part of a
		*  path or something else. (Checking q >= lend ensures that we
		*  only count matches in the current line.) */
		if ((!(q = strstr(p, " overlay")) || q >= lend) &&
		    (!(q = strstr(p, " aufs")) || q >= lend))
			goto next;

		if (!(q = strstr(p, olddir)) || (q >= lend))
			goto next;

		/* replace the olddir with newdir */
		if (olddirlen >= newdirlen) {
			size_t diff = olddirlen - newdirlen;
			memcpy(q, newdir, newdirlen);
			if (olddirlen != newdirlen) {
				memmove(q + newdirlen, q + newdirlen + diff,
					strlen(q) - newdirlen - diff + 1);
				lend -= diff;
				conf->unexpanded_len -= diff;
			}
		} else {
			char *new;
			size_t diff = newdirlen - olddirlen;
			size_t oldlen = conf->unexpanded_len;
			size_t newlen = oldlen + diff;
			size_t poffset = q - conf->unexpanded_config;

			new = realloc(conf->unexpanded_config, newlen + 1);
			if (!new) {
				ERROR("Out of memory");
				return false;
			}
			conf->unexpanded_len = newlen;
			conf->unexpanded_alloced = newlen + 1;
			new[newlen - 1] = '\0';
			lend = new + (lend - conf->unexpanded_config);
			/* move over the remainder to make room for the newdir
			 */
			memmove(new + poffset + newdirlen,
				new + poffset + olddirlen,
				oldlen - poffset - olddirlen + 1);
			conf->unexpanded_config = new;
			memcpy(new + poffset, newdir, newdirlen);
			lend += diff;
		}
	next:
		lstart = lend;
	}

	return true;
}

bool clone_update_unexp_hooks(struct lxc_conf *conf, const char *oldpath,
			      const char *newpath, const char *oldname,
			      const char *newname)
{
	int ret;
	char *lend, *newdir, *olddir, *p;
	char *lstart = conf->unexpanded_config;
	size_t newdirlen, olddirlen;
	const char *key = "lxc.hook";

	olddirlen = strlen(oldpath) + strlen(oldname) + 1;
	olddir = alloca(olddirlen + 1);
	ret = snprintf(olddir, olddirlen + 1, "%s/%s", oldpath, oldname);
	if (ret < 0 || ret >= olddirlen + 1) {
		ERROR("failed to create string");
		return false;
	}

	newdirlen = strlen(newpath) + strlen(newname) + 1;
	newdir = alloca(newdirlen + 1);
	ret = snprintf(newdir, newdirlen + 1, "%s/%s", newpath, newname);
	if (ret < 0 || ret >= newdirlen + 1) {
		ERROR("failed to create string");
		return false;
	}
	if (!conf->unexpanded_config)
		return true;
	while (*lstart) {
		lend = strchr(lstart, '\n');
		if (!lend)
			lend = lstart + strlen(lstart);
		else
			lend++;

		if (strncmp(lstart, key, strlen(key)) != 0)
			goto next;

		p = strchr(lstart + strlen(key), '=');
		if (!p)
			goto next;
		p++;

		while (isblank(*p))
			p++;

		if (p >= lend)
			goto next;

		if (strncmp(p, olddir, strlen(olddir)) != 0)
			goto next;

		/* replace the olddir with newdir */
		if (olddirlen >= newdirlen) {
			size_t diff = olddirlen - newdirlen;
			memcpy(p, newdir, newdirlen);
			if (olddirlen != newdirlen) {
				memmove(p + newdirlen, p + newdirlen + diff,
					strlen(p) - newdirlen - diff + 1);
				lend -= diff;
				conf->unexpanded_len -= diff;
			}
		} else {
			char *new;
			size_t diff = newdirlen - olddirlen;
			size_t oldlen = conf->unexpanded_len;
			size_t newlen = oldlen + diff;
			size_t poffset = p - conf->unexpanded_config;

			new = realloc(conf->unexpanded_config, newlen + 1);
			if (!new) {
				ERROR("failed to allocate memory");
				return false;
			}
			conf->unexpanded_len = newlen;
			conf->unexpanded_alloced = newlen + 1;
			new[newlen - 1] = '\0';
			lend = new + (lend - conf->unexpanded_config);
			/* move over the remainder to make room for the newdir
			 */
			memmove(new + poffset + newdirlen,
				new + poffset + olddirlen,
				oldlen - poffset - olddirlen + 1);
			conf->unexpanded_config = new;
			memcpy(new + poffset, newdir, newdirlen);
			lend += diff;
		}
	next:
		lstart = lend;
	}

	return true;
}

#define DO(cmd)                                                                \
	{                                                                      \
		if (!(cmd)) {                                                  \
			ERROR("Error writing to new config");                  \
			return false;                                          \
		}                                                              \
	}

static bool new_hwaddr(char *hwaddr)
{
	int ret;

	(void)randseed(true);

	ret = snprintf(hwaddr, 18, "00:16:3e:%02x:%02x:%02x", rand() % 255,
		       rand() % 255, rand() % 255);
	if (ret < 0 || ret >= 18) {
		SYSERROR("Failed to call snprintf().");
		return false;
	}

	return true;
}

/*
 * This is called only from clone.  We wish to update all hwaddrs in the
 * unexpanded config file.  We can't/don't want to update any which come from
 * lxc.includes (there shouldn't be any).
 * We can't just walk the c->lxc-conf->network list because that includes netifs
 * from the include files.  So we update the ones which we find in the unexp
 * config file, then find the original macaddr in the conf->network, and update
 * that to the same value.
 */
bool network_new_hwaddrs(struct lxc_conf *conf)
{
	char *lend, *p, *p2;
	struct lxc_list *it;
	const char *key = "lxc.network.hwaddr";
	char *lstart = conf->unexpanded_config;

	if (!conf->unexpanded_config)
		return true;

	while (*lstart) {
		char newhwaddr[18], oldhwaddr[17];

		lend = strchr(lstart, '\n');
		if (!lend)
			lend = lstart + strlen(lstart);
		else
			lend++;

		if (strncmp(lstart, key, strlen(key)) != 0) {
			lstart = lend;
			continue;
		}

		p = strchr(lstart + strlen(key), '=');
		if (!p) {
			lstart = lend;
			continue;
		}

		p++;
		while (isblank(*p))
			p++;
		if (!*p)
			return true;

		p2 = p;
		while (*p2 && !isblank(*p2) && *p2 != '\n')
			p2++;

		if ((p2 - p) != 17) {
			WARN("Bad hwaddr entry");
			lstart = lend;
			continue;
		}

		memcpy(oldhwaddr, p, 17);

		if (!new_hwaddr(newhwaddr))
			return false;

		memcpy(p, newhwaddr, 17);
		lxc_list_for_each(it, &conf->network)
		{
			struct lxc_netdev *n = it->elem;
			if (n->hwaddr && memcmp(oldhwaddr, n->hwaddr, 17) == 0)
				memcpy(n->hwaddr, newhwaddr, 17);
		}

		lstart = lend;
	}

	return true;
}

static int set_config_ephemeral(const char *key, const char *value,
				struct lxc_conf *lxc_conf, void *data)
{
	/* Set config value to default. */
	if (lxc_config_value_empty(value)) {
		lxc_conf->ephemeral = 0;
		return 0;
	}

	/* Parse new config value. */
	if (lxc_safe_uint(value, &lxc_conf->ephemeral) < 0)
		return -1;

	if (lxc_conf->ephemeral > 1) {
		ERROR(
		    "Wrong value for lxc.ephemeral. Can only be set to 0 or 1");
		return -1;
	}

	return 0;
}

/* Callbacks to get configuration items. */
static int get_config_personality(const char *key, char *retv, int inlen,
				  struct lxc_conf *c)
{
	int fulllen = 0;

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

#if HAVE_SYS_PERSONALITY_H
	int len = 0;

	switch (c->personality) {
	case PER_LINUX32:
		strprint(retv, inlen, "i686");
		break;
	case PER_LINUX:
		strprint(retv, inlen, "x86_64");
		break;
	default:
		break;
	}
#endif

	return fulllen;
}

static int get_config_pts(const char *key, char *retv, int inlen,
			  struct lxc_conf *c)
{
	return lxc_get_conf_int(c, retv, inlen, c->pts);
}

static int get_config_tty(const char *key, char *retv, int inlen,
			  struct lxc_conf *c)
{
	return lxc_get_conf_int(c, retv, inlen, c->tty);
}

static inline int lxc_get_conf_str(char *retv, int inlen, const char *value)
{
	if (!value)
		return 0;
	if (retv && inlen >= strlen(value) + 1)
		strncpy(retv, value, strlen(value) + 1);

	return strlen(value);
}

static int get_config_ttydir(const char *key, char *retv, int inlen,
			     struct lxc_conf *c)
{
	return lxc_get_conf_str(retv, inlen, c->ttydir);
}

static int get_config_kmsg(const char *key, char *retv, int inlen,
			   struct lxc_conf *c)
{
	return lxc_get_conf_int(c, retv, inlen, c->kmsg);
}

static int get_config_lsm_aa_profile(const char *key, char *retv, int inlen,
				     struct lxc_conf *c)
{
	return lxc_get_conf_str(retv, inlen, c->lsm_aa_profile);
}

static int get_config_lsm_aa_incomplete(const char *key, char *retv, int inlen,
					struct lxc_conf *c)
{
	return lxc_get_conf_int(c, retv, inlen,
				c->lsm_aa_allow_incomplete);
}

static int get_config_lsm_se_context(const char *key, char *retv, int inlen,
				     struct lxc_conf *c)
{
	return lxc_get_conf_str(retv, inlen, c->lsm_se_context);
}

/*
 * If you ask for a specific cgroup value, i.e. lxc.cgroup.devices.list,
 * then just the value(s) will be printed.  Since there still could be
 * more than one, it is newline-separated.
 * (Maybe that's ambigous, since some values, i.e. devices.list, will
 * already have newlines?)
 * If you ask for 'lxc.cgroup", then all cgroup entries will be printed,
 * in 'lxc.cgroup.subsystem.key = value' format.
 */
static int get_config_cgroup(const char *key, char *retv, int inlen,
			     struct lxc_conf *c)
{
	struct lxc_list *it;
	int len;
	int fulllen = 0;
	bool get_all = false;

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	if (!strcmp(key, "lxc.cgroup"))
		get_all = true;
	else if (!strncmp(key, "lxc.cgroup.", 11))
		key += 11;
	else
		return -1;

	lxc_list_for_each(it, &c->cgroup) {
		struct lxc_cgroup *cg = it->elem;
		if (get_all) {
			strprint(retv, inlen, "lxc.cgroup.%s = %s\n", cg->subsystem, cg->value);
		} else if (!strcmp(cg->subsystem, key)) {
			strprint(retv, inlen, "%s\n", cg->value);
		}
	}

	return fulllen;
}

static int get_config_idmaps(const char *key, char *retv, int inlen,
			     struct lxc_conf *c)
{
	struct lxc_list *it;
	int len, listlen, ret;
	int fulllen = 0;
/* "u 1000 1000000 65536"
 *
 * let's render this as
 *
 * sizeof(char)
 * +
 * sizeof(" ")
 * +
 * sizeof(uint64_t)
 * +
 * sizeof(" ")
 * +
 * sizeof(uint64_t)
 * +
 * sizeof(" ")
 * +
 * sizeof(uint64_t)
 * +
 * \0
 */
#define __LXC_IDMAP_STR_BUF (3 * LXC_NUMSTRLEN64 + 3 + 1 + 1)
	char buf[__LXC_IDMAP_STR_BUF];

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	listlen = lxc_list_len(&c->id_map);
	lxc_list_for_each(it, &c->id_map)
	{
		struct id_map *map = it->elem;
		ret = snprintf(buf, __LXC_IDMAP_STR_BUF, "%c %lu %lu %lu",
			       (map->idtype == ID_TYPE_UID) ? 'u' : 'g',
			       map->nsid, map->hostid, map->range);
		if (ret < 0 || ret >= __LXC_IDMAP_STR_BUF)
			return -1;

		strprint(retv, inlen, "%s%s", buf, (listlen-- > 1) ? "\n" : "");
	}
	return fulllen;
}

static int get_config_loglevel(const char *key, char *retv, int inlen,
			       struct lxc_conf *c)
{
	const char *v;
	v = lxc_log_priority_to_string(c->loglevel);
	return lxc_get_conf_str(retv, inlen, v);
}

static int get_config_logfile(const char *key, char *retv, int inlen,
			      struct lxc_conf *c)
{
	return lxc_get_conf_str(retv, inlen, c->logfile);
}

static int get_config_fstab(const char *key, char *retv, int inlen,
			    struct lxc_conf *c)
{
	return lxc_get_conf_str(retv, inlen, c->fstab);
}

static int get_config_mount_auto(const char *key, char *retv, int inlen,
				 struct lxc_conf *c)
{
	int len, fulllen = 0;
	const char *sep = "";

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	if (!(c->auto_mounts & LXC_AUTO_ALL_MASK))
		return 0;

	switch (c->auto_mounts & LXC_AUTO_PROC_MASK) {
	case LXC_AUTO_PROC_MIXED:
		strprint(retv, inlen, "%sproc:mixed", sep);
		sep = " ";
		break;
	case LXC_AUTO_PROC_RW:
		strprint(retv, inlen, "%sproc:rw", sep);
		sep = " ";
		break;
	default:
		break;
	}

	switch (c->auto_mounts & LXC_AUTO_SYS_MASK) {
	case LXC_AUTO_SYS_RO:
		strprint(retv, inlen, "%ssys:ro", sep);
		sep = " ";
		break;
	case LXC_AUTO_SYS_RW:
		strprint(retv, inlen, "%ssys:rw", sep);
		sep = " ";
		break;
	case LXC_AUTO_SYS_MIXED:
		strprint(retv, inlen, "%ssys:mixed", sep);
		sep = " ";
		break;
	default:
		break;
	}

	switch (c->auto_mounts & LXC_AUTO_CGROUP_MASK) {
	case LXC_AUTO_CGROUP_NOSPEC:
		strprint(retv, inlen, "%scgroup", sep);
		break;
	case LXC_AUTO_CGROUP_MIXED:
		strprint(retv, inlen, "%scgroup:mixed", sep);
		break;
	case LXC_AUTO_CGROUP_RO:
		strprint(retv, inlen, "%scgroup:ro", sep);
		break;
	case LXC_AUTO_CGROUP_RW:
		strprint(retv, inlen, "%scgroup:rw", sep);
		break;
	case LXC_AUTO_CGROUP_FULL_NOSPEC:
		strprint(retv, inlen, "%scgroup-full", sep);
		break;
	case LXC_AUTO_CGROUP_FULL_MIXED:
		strprint(retv, inlen, "%scgroup-full:mixed", sep);
		break;
	case LXC_AUTO_CGROUP_FULL_RO:
		strprint(retv, inlen, "%scgroup-full:ro", sep);
		break;
	case LXC_AUTO_CGROUP_FULL_RW:
		strprint(retv, inlen, "%scgroup-full:rw", sep);
		break;
	default:
		break;
	}

	return fulllen;
}

static int get_config_mount(const char *key, char *retv, int inlen,
			    struct lxc_conf *c)
{
	int len, fulllen = 0;
	struct lxc_list *it;

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	lxc_list_for_each(it, &c->mount_list)
	{
		strprint(retv, inlen, "%s\n", (char *)it->elem);
	}

	return fulllen;
}

static int get_config_rootfs(const char *key, char *retv, int inlen,
			     struct lxc_conf *c)
{
	return lxc_get_conf_str(retv, inlen, c->rootfs.path);
}

static int get_config_rootfs_mount(const char *key, char *retv, int inlen,
				   struct lxc_conf *c)
{
	return lxc_get_conf_str(retv, inlen, c->rootfs.mount);
}

static int get_config_rootfs_options(const char *key, char *retv, int inlen,
				     struct lxc_conf *c)
{
	return lxc_get_conf_str(retv, inlen, c->rootfs.options);
}

static int get_config_rootfs_backend(const char *key, char *retv, int inlen,
				     struct lxc_conf *c)
{
	return lxc_get_conf_str(retv, inlen, c->rootfs.bdev_type);
}

static int get_config_pivotdir(const char *key, char *retv, int inlen,
			       struct lxc_conf *c)
{
	return 0;
}

static int get_config_utsname(const char *key, char *retv, int inlen,
			      struct lxc_conf *c)
{
	return lxc_get_conf_str(
	    retv, inlen,
	    c->utsname ? c->utsname->nodename : NULL);
}

static int get_config_hooks(const char *key, char *retv, int inlen,
			    struct lxc_conf *c)
{
	char *subkey;
	int len, fulllen = 0, found = -1;
	struct lxc_list *it;
	int i;

	/* "lxc.hook.mount" */
	subkey = strchr(key, '.');
	if (subkey)
		subkey = strchr(subkey + 1, '.');
	if (!subkey)
		return -1;
	subkey++;
	if (!*subkey)
		return -1;
	for (i = 0; i < NUM_LXC_HOOKS; i++) {
		if (strcmp(lxchook_names[i], subkey) == 0) {
			found = i;
			break;
		}
	}
	if (found == -1)
		return -1;

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	lxc_list_for_each(it, &c->hooks[found]) {
		strprint(retv, inlen, "%s\n", (char *)it->elem);
	}
	return fulllen;
}

static int get_config_network(const char *key, char *retv, int inlen,
			      struct lxc_conf *c)
{
	int len, fulllen = 0;
	struct lxc_list *it;

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	lxc_list_for_each(it, &c->network) {
		struct lxc_netdev *n = it->elem;
		const char *t = lxc_net_type_to_str(n->type);
		strprint(retv, inlen, "%s\n", t ? t : "(invalid)");
	}

	return fulllen;
}

/*
 * lxc.network.0.XXX, where XXX can be: name, type, link, flags, type,
 * macvlan.mode, veth.pair, vlan, ipv4, ipv6, script.up, hwaddr, mtu,
 * ipv4.gateway, ipv6.gateway.  ipvX.gateway can return 'auto' instead
 * of an address.  ipv4 and ipv6 return lists (newline-separated).
 * things like veth.pair return '' if invalid (i.e. if called for vlan
 * type).
 */
static int get_config_network_item(const char *key, char *retv, int inlen,
				   struct lxc_conf *c)
{
	char *p1;
	int len, fulllen = 0;
	struct lxc_netdev *netdev;

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	if (!strncmp(key, "lxc.network.", 12))
		key += 12;
	else
		return -1;

	p1 = strchr(key, '.');
	if (!p1 || *(p1 + 1) == '\0')
		return -1;
	p1++;

	netdev = get_netdev_from_key(key, &c->network);
	if (!netdev)
		return -1;
	if (strcmp(p1, "name") == 0) {
		if (netdev->name[0] != '\0')
			strprint(retv, inlen, "%s", netdev->name);
	} else if (strcmp(p1, "type") == 0) {
		strprint(retv, inlen, "%s", lxc_net_type_to_str(netdev->type));
	} else if (strcmp(p1, "link") == 0) {
		if (netdev->link[0] != '\0')
			strprint(retv, inlen, "%s", netdev->link);
	} else if (strcmp(p1, "flags") == 0) {
		if (netdev->flags & IFF_UP)
			strprint(retv, inlen, "up");
	} else if (strcmp(p1, "script.up") == 0) {
		if (netdev->upscript)
			strprint(retv, inlen, "%s", netdev->upscript);
	} else if (strcmp(p1, "script.down") == 0) {
		if (netdev->downscript)
			strprint(retv, inlen, "%s", netdev->downscript);
	} else if (strcmp(p1, "hwaddr") == 0) {
		if (netdev->hwaddr)
			strprint(retv, inlen, "%s", netdev->hwaddr);
	} else if (strcmp(p1, "mtu") == 0) {
		if (netdev->mtu)
			strprint(retv, inlen, "%s", netdev->mtu);
	} else if (strcmp(p1, "macvlan.mode") == 0) {
		if (netdev->type == LXC_NET_MACVLAN) {
			const char *mode;
			switch (netdev->priv.macvlan_attr.mode) {
			case MACVLAN_MODE_PRIVATE:
				mode = "private";
				break;
			case MACVLAN_MODE_VEPA:
				mode = "vepa";
				break;
			case MACVLAN_MODE_BRIDGE:
				mode = "bridge";
				break;
			case MACVLAN_MODE_PASSTHRU:
				mode = "passthru";
				break;
			default:
				mode = "(invalid)";
				break;
			}
			strprint(retv, inlen, "%s", mode);
		}
	} else if (strcmp(p1, "veth.pair") == 0) {
		if (netdev->type == LXC_NET_VETH) {
			strprint(retv, inlen, "%s",
				 netdev->priv.veth_attr.pair[0] != '\0'
				     ? netdev->priv.veth_attr.pair
				     : netdev->priv.veth_attr.veth1);
		}
	} else if (strcmp(p1, "vlan") == 0) {
		if (netdev->type == LXC_NET_VLAN) {
			strprint(retv, inlen, "%d", netdev->priv.vlan_attr.vid);
		}
	} else if (strcmp(p1, "ipv4.gateway") == 0) {
		if (netdev->ipv4_gateway_auto) {
			strprint(retv, inlen, "auto");
		} else if (netdev->ipv4_gateway) {
			char buf[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, netdev->ipv4_gateway, buf,
				  sizeof(buf));
			strprint(retv, inlen, "%s", buf);
		}
	} else if (strcmp(p1, "ipv4") == 0) {
		struct lxc_list *it2;
		lxc_list_for_each(it2, &netdev->ipv4) {
			struct lxc_inetdev *i = it2->elem;
			char buf[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &i->addr, buf, sizeof(buf));
			strprint(retv, inlen, "%s/%d\n", buf, i->prefix);
		}
	} else if (strcmp(p1, "ipv6.gateway") == 0) {
		if (netdev->ipv6_gateway_auto) {
			strprint(retv, inlen, "auto");
		} else if (netdev->ipv6_gateway) {
			char buf[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, netdev->ipv6_gateway, buf,
				  sizeof(buf));
			strprint(retv, inlen, "%s", buf);
		}
	} else if (strcmp(p1, "ipv6") == 0) {
		struct lxc_list *it2;
		lxc_list_for_each(it2, &netdev->ipv6) {
			struct lxc_inet6dev *i = it2->elem;
			char buf[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, &i->addr, buf, sizeof(buf));
			strprint(retv, inlen, "%s/%d\n", buf, i->prefix);
		}
	}
	return fulllen;
}

static int get_config_cap_drop(const char *key, char *retv, int inlen,
			       struct lxc_conf *c)
{
	int len, fulllen = 0;
	struct lxc_list *it;

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	lxc_list_for_each(it, &c->caps) {
		strprint(retv, inlen, "%s\n", (char *)it->elem);
	}
	return fulllen;
}

static int get_config_cap_keep(const char *key, char *retv, int inlen,
			       struct lxc_conf *c)
{
	int len, fulllen = 0;
	struct lxc_list *it;

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	lxc_list_for_each(it, &c->keepcaps) {
		strprint(retv, inlen, "%s\n", (char *)it->elem);
	}
	return fulllen;
}

static int get_config_console(const char *key, char *retv, int inlen,
			      struct lxc_conf *c)
{
	return lxc_get_conf_str(retv, inlen, c->console.path);
}

static int get_config_console_logfile(const char *key, char *retv, int inlen,
				      struct lxc_conf *c)
{
	return lxc_get_conf_str(retv, inlen, c->console.log_path);
}

static int get_config_seccomp(const char *key, char *retv, int inlen,
			      struct lxc_conf *c)
{
	return lxc_get_conf_str(retv, inlen, c->seccomp);
}

static int get_config_autodev(const char *key, char *retv, int inlen,
			      struct lxc_conf *c)
{
	return lxc_get_conf_int(c, retv, inlen, c->autodev);
}

static int get_config_haltsignal(const char *key, char *retv, int inlen,
				 struct lxc_conf *c)
{
	return lxc_get_conf_int(c, retv, inlen, c->haltsignal);
}

static int get_config_rebootsignal(const char *key, char *retv, int inlen,
				   struct lxc_conf *c)
{
	return lxc_get_conf_int(c, retv, inlen, c->rebootsignal);
}

static int get_config_stopsignal(const char *key, char *retv, int inlen,
				 struct lxc_conf *c)
{
	return lxc_get_conf_int(c, retv, inlen, c->stopsignal);
}

static int get_config_start(const char *key, char *retv, int inlen,
			    struct lxc_conf *c)
{
	if (strcmp(key + 10, "auto") == 0)
		return lxc_get_conf_int(c, retv, inlen, c->start_auto);
	else if (strcmp(key + 10, "delay") == 0)
		return lxc_get_conf_int(c, retv, inlen, c->start_delay);
	else if (strcmp(key + 10, "order") == 0)
		return lxc_get_conf_int(c, retv, inlen, c->start_order);

	return -1;
}

static int get_config_monitor(const char *key, char *retv, int inlen,
			      struct lxc_conf *c)
{
	return lxc_get_conf_int(c, retv, inlen, c->monitor_unshare);
}

static int get_config_group(const char *key, char *retv, int inlen,
			    struct lxc_conf *c)
{
	int len, fulllen = 0;
	struct lxc_list *it;

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	lxc_list_for_each(it, &c->groups) {
		strprint(retv, inlen, "%s\n", (char *)it->elem);
	}
	return fulllen;
}

static int get_config_environment(const char *key, char *retv, int inlen,
				  struct lxc_conf *c)
{
	int len, fulllen = 0;
	struct lxc_list *it;

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	lxc_list_for_each(it, &c->environment) {
		strprint(retv, inlen, "%s\n", (char *)it->elem);
	}
	return fulllen;
}

static int get_config_init_cmd(const char *key, char *retv, int inlen,
			       struct lxc_conf *c)
{
	return lxc_get_conf_str(retv, inlen, c->init_cmd);
}

static int get_config_init_uid(const char *key, char *retv, int inlen,
			       struct lxc_conf *c)
{
	return lxc_get_conf_int(c, retv, inlen, c->init_uid);
}

static int get_config_init_gid(const char *key, char *retv, int inlen,
			       struct lxc_conf *c)
{
	return lxc_get_conf_int(c, retv, inlen, c->init_gid);
}

static int get_config_ephemeral(const char *key, char *retv, int inlen,
				struct lxc_conf *c)
{
	return lxc_get_conf_int(c, retv, inlen, c->ephemeral);
}

/* Callbacks to clear config items. */
static inline int clr_config_personality(const char *key, struct lxc_conf *c,
					 void *data)
{
	c->personality = -1;
	return 0;
}

static inline int clr_config_pts(const char *key, struct lxc_conf *c,
				 void *data)
{
	c->pts = 0;
	return 0;
}

static inline int clr_config_tty(const char *key, struct lxc_conf *c,
				 void *data)
{
	c->tty = 0;
	return 0;
}

static inline int clr_config_ttydir(const char *key, struct lxc_conf *c,
				    void *data)
{
	free(c->ttydir);
	c->ttydir = NULL;
	return 0;
}

static inline int clr_config_kmsg(const char *key, struct lxc_conf *c,
				  void *data)
{
	c->kmsg = 0;
	return 0;
}

static inline int clr_config_lsm_aa_profile(const char *key, struct lxc_conf *c,
					    void *data)
{
	free(c->lsm_aa_profile);
	c->lsm_aa_profile = NULL;
	return 0;
}

static inline int clr_config_lsm_aa_incomplete(const char *key,
					       struct lxc_conf *c, void *data)
{
	c->lsm_aa_allow_incomplete = 0;
	return 0;
}

static inline int clr_config_lsm_se_context(const char *key, struct lxc_conf *c,
					    void *data)
{
	free(c->lsm_se_context);
	c->lsm_se_context = NULL;
	return 0;
}

static inline int clr_config_cgroup(const char *key, struct lxc_conf *c,
				    void *data)
{
	return lxc_clear_cgroups(c, key);
}

static inline int clr_config_idmaps(const char *key, struct lxc_conf *c,
				    void *data)
{
	return lxc_clear_idmaps(c);
}

static inline int clr_config_loglevel(const char *key, struct lxc_conf *c,
				      void *data)
{
	c->loglevel = LXC_LOG_LEVEL_NOTSET;
	return 0;
}

static inline int clr_config_logfile(const char *key, struct lxc_conf *c,
				     void *data)
{
	free(c->logfile);
	c->logfile = NULL;
	return 0;
}

static inline int clr_config_mount(const char *key, struct lxc_conf *c,
				   void *data)
{
	return lxc_clear_mount_entries(c);
}

static inline int clr_config_mount_auto(const char *key, struct lxc_conf *c,
					void *data)
{
	return lxc_clear_automounts(c);
}

static inline int clr_config_fstab(const char *key, struct lxc_conf *c,
				   void *data)
{
	free(c->fstab);
	c->fstab = NULL;
	return 0;
}

static inline int clr_config_rootfs(const char *key, struct lxc_conf *c,
				    void *data)
{
	free(c->rootfs.path);
	c->rootfs.path = NULL;
	return 0;
}

static inline int clr_config_rootfs_mount(const char *key, struct lxc_conf *c,
					  void *data)
{
	free(c->rootfs.mount);
	c->rootfs.mount = NULL;
	return 0;
}

static inline int clr_config_rootfs_options(const char *key, struct lxc_conf *c,
					    void *data)
{
	free(c->rootfs.options);
	c->rootfs.options = NULL;
	return 0;
}

static inline int clr_config_rootfs_backend(const char *key, struct lxc_conf *c,
					    void *data)
{
	free(c->rootfs.bdev_type);
	c->rootfs.bdev_type = NULL;
	return 0;
}

static inline int clr_config_pivotdir(const char *key, struct lxc_conf *c,
				      void *data)
{
	return 0;
}

static inline int clr_config_utsname(const char *key, struct lxc_conf *c,
				     void *data)
{
	free(c->utsname);
	c->utsname = NULL;
	return 0;
}

static inline int clr_config_hooks(const char *key, struct lxc_conf *c,
				   void *data)
{
	return lxc_clear_hooks(c, key);
}

static inline int clr_config_network_item(const char *key, struct lxc_conf *c,
					  void *data)
{
	return lxc_clear_nic(c, key + 12);
}

static inline int clr_config_network(const char *key, struct lxc_conf *c,
				     void *data)
{
	return lxc_clear_config_network(c);
}

static inline int clr_config_cap_drop(const char *key, struct lxc_conf *c,
				      void *data)
{
	return lxc_clear_config_caps(c);
}

static inline int clr_config_cap_keep(const char *key, struct lxc_conf *c,
				      void *data)
{
	return lxc_clear_config_keepcaps(c);
}

static inline int clr_config_console(const char *key, struct lxc_conf *c,
				     void *data)
{
	free(c->console.path);
	c->console.path = NULL;
	return 0;
}

static inline int clr_config_console_logfile(const char *key,
					     struct lxc_conf *c, void *data)
{
	free(c->console.log_path);
	c->console.log_path = NULL;
	return 0;
}

static inline int clr_config_seccomp(const char *key, struct lxc_conf *c,
				     void *data)
{
	free(c->seccomp);
	c->seccomp = NULL;
	return 0;
}

static inline int clr_config_autodev(const char *key, struct lxc_conf *c,
				     void *data)
{
	c->autodev = 1;
	return 0;
}

static inline int clr_config_haltsignal(const char *key, struct lxc_conf *c,
					void *data)
{
	c->haltsignal = 0;
	return 0;
}

static inline int clr_config_rebootsignal(const char *key, struct lxc_conf *c,
					  void *data)
{
	c->rebootsignal = 0;
	return 0;
}

static inline int clr_config_stopsignal(const char *key, struct lxc_conf *c,
					void *data)
{
	c->stopsignal = 0;
	return 0;
}

static inline int clr_config_start(const char *key, struct lxc_conf *c,
				   void *data)
{
	if (strcmp(key + 10, "auto") == 0)
		c->start_auto = 0;
	else if (strcmp(key + 10, "delay") == 0)
		c->start_delay = 0;
	else if (strcmp(key + 10, "order") == 0)
		c->start_order = 0;

	return 0;
}

static inline int clr_config_monitor(const char *key, struct lxc_conf *c,
				     void *data)
{
	c->monitor_unshare = 0;
	return 0;
}

static inline int clr_config_group(const char *key, struct lxc_conf *c,
				   void *data)
{
	return lxc_clear_groups(c);
}

static inline int clr_config_environment(const char *key, struct lxc_conf *c,
					 void *data)
{
	return lxc_clear_environment(c);
}

static inline int clr_config_init_cmd(const char *key, struct lxc_conf *c,
				      void *data)
{
	free(c->init_cmd);
	c->init_cmd = NULL;
	return 0;
}

static inline int clr_config_init_uid(const char *key, struct lxc_conf *c,
				      void *data)
{
	c->init_uid = 0;
	return 0;
}

static inline int clr_config_init_gid(const char *key, struct lxc_conf *c,
				      void *data)
{
	c->init_gid = 0;
	return 0;
}

static inline int clr_config_ephemeral(const char *key, struct lxc_conf *c,
				       void *data)
{
	c->ephemeral = 0;
	return 0;
}

static inline int clr_config_includefiles(const char *key, struct lxc_conf *c,
					  void *data)
{
	lxc_clear_includes(c);
	return 0;
}

static int get_config_includefiles(const char *key, char *retv, int inlen,
				   struct lxc_conf *c)
{
	return -ENOSYS;
}

int lxc_list_config_items(char *retv, int inlen)
{
	size_t i;
	int len;
	int fulllen = 0;

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	for (i = 0; i < config_size; i++) {
		char *s = config[i].name;
		if (s[strlen(s) - 1] == '.')
			continue;
		strprint(retv, inlen, "%s\n", s);
	}

	return fulllen;
}

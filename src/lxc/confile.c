/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#define __STDC_FORMAT_MACROS
#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <net/if.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "af_unix.h"
#include "conf.h"
#include "config.h"
#include "confile.h"
#include "confile_utils.h"
#include "../include/netns_ifaddrs.h"
#include "log.h"
#include "lxcseccomp.h"
#include "macro.h"
#include "memory_utils.h"
#include "network.h"
#include "parse.h"
#include "storage/storage.h"
#include "utils.h"

#ifndef HAVE_STRLCPY
#include "include/strlcpy.h"
#endif

#ifndef HAVE_STRLCAT
#include "include/strlcat.h"
#endif

lxc_log_define(confile, lxc);

#define lxc_config_define(name)                                             \
	__hot static int set_config_##name(const char *, const char *,      \
					   struct lxc_conf *, void *);      \
	__hot static int get_config_##name(const char *, char *, int,       \
					   struct lxc_conf *, void *);      \
	__hot static int clr_config_##name(const char *, struct lxc_conf *, \
					   void *);

lxc_config_define(autodev);
lxc_config_define(autodev_tmpfs_size);
lxc_config_define(apparmor_allow_incomplete);
lxc_config_define(apparmor_allow_nesting);
lxc_config_define(apparmor_profile);
lxc_config_define(apparmor_raw);
lxc_config_define(cap_drop);
lxc_config_define(cap_keep);
lxc_config_define(cgroup_controller);
lxc_config_define(cgroup2_controller);
lxc_config_define(cgroup_dir);
lxc_config_define(cgroup_monitor_dir);
lxc_config_define(cgroup_monitor_pivot_dir);
lxc_config_define(cgroup_container_dir);
lxc_config_define(cgroup_container_inner_dir);
lxc_config_define(cgroup_relative);
lxc_config_define(console_buffer_size);
lxc_config_define(console_logfile);
lxc_config_define(console_path);
lxc_config_define(console_rotate);
lxc_config_define(console_size);
lxc_config_define(unsupported_key);
lxc_config_define(environment);
lxc_config_define(ephemeral);
lxc_config_define(execute_cmd);
lxc_config_define(group);
lxc_config_define(hooks);
lxc_config_define(hooks_version);
lxc_config_define(idmaps);
lxc_config_define(includefiles);
lxc_config_define(init_cmd);
lxc_config_define(init_cwd);
lxc_config_define(init_gid);
lxc_config_define(init_uid);
lxc_config_define(init_groups);
lxc_config_define(jump_table_net);
lxc_config_define(keyring_session);
lxc_config_define(log_file);
lxc_config_define(log_level);
lxc_config_define(log_syslog);
lxc_config_define(monitor);
lxc_config_define(monitor_signal_pdeath);
lxc_config_define(mount);
lxc_config_define(mount_auto);
lxc_config_define(mount_fstab);
lxc_config_define(namespace_clone);
lxc_config_define(namespace_keep);
lxc_config_define(time_offset_boot);
lxc_config_define(time_offset_monotonic);
lxc_config_define(namespace_share);
lxc_config_define(net);
lxc_config_define(net_flags);
lxc_config_define(net_hwaddr);
lxc_config_define(net_ipv4_address);
lxc_config_define(net_ipv4_gateway);
lxc_config_define(net_ipv6_address);
lxc_config_define(net_ipv6_gateway);
lxc_config_define(net_link);
lxc_config_define(net_l2proxy);
lxc_config_define(net_macvlan_mode);
lxc_config_define(net_ipvlan_mode);
lxc_config_define(net_ipvlan_isolation);
lxc_config_define(net_mtu);
lxc_config_define(net_name);
lxc_config_define(net_script_down);
lxc_config_define(net_script_up);
lxc_config_define(net_type);
lxc_config_define(net_veth_mode);
lxc_config_define(net_veth_pair);
lxc_config_define(net_veth_ipv4_route);
lxc_config_define(net_veth_ipv6_route);
lxc_config_define(net_veth_vlan_id);
lxc_config_define(net_veth_vlan_tagged_id);
lxc_config_define(net_vlan_id);
lxc_config_define(no_new_privs);
lxc_config_define(personality);
lxc_config_define(prlimit);
lxc_config_define(pty_max);
lxc_config_define(rootfs_managed);
lxc_config_define(rootfs_mount);
lxc_config_define(rootfs_options);
lxc_config_define(rootfs_path);
lxc_config_define(seccomp_profile);
lxc_config_define(seccomp_allow_nesting);
lxc_config_define(seccomp_notify_cookie);
lxc_config_define(seccomp_notify_proxy);
lxc_config_define(selinux_context);
lxc_config_define(selinux_context_keyring);
lxc_config_define(signal_halt);
lxc_config_define(signal_reboot);
lxc_config_define(signal_stop);
lxc_config_define(start);
lxc_config_define(tty_max);
lxc_config_define(tty_dir);
lxc_config_define(uts_name);
lxc_config_define(sysctl);
lxc_config_define(proc);

static int set_config_unsupported_key(const char *key, const char *value,
				      struct lxc_conf *lxc_conf, void *data)
{
	return syserror_set(-EINVAL, "Unsupported config key \"%s\"", key);
}

static int get_config_unsupported_key(const char *key, char *retv, int inlen,
				      struct lxc_conf *c, void *data)
{
	return syserror_set(-EINVAL, "Unsupported config key \"%s\"", key);
}

static int clr_config_unsupported_key(const char *key,
				      struct lxc_conf *lxc_conf, void *data)
{
	return syserror_set(-EINVAL, "Unsupported config key \"%s\"", key);
}

/*
 * Important Note:
 * If a new config option is added to this table, be aware that
 * the order in which the options are places into the table matters.
 * That means that more specific options of a namespace have to be
 * placed above more generic ones.
 *
 * For instance: If lxc.ab is placed before lxc.ab.c, the config option
 * lxc.ab.c will always be matched to lxc.ab. That is, the lxc.ab.c option
 * has to be placed above lxc.ab.
 */
static struct lxc_config_t config_jump_table[] = {
	{ "lxc.arch",                       true,  set_config_personality,                get_config_personality,                clr_config_personality,                },
	{ "lxc.apparmor.profile",           true,  set_config_apparmor_profile,           get_config_apparmor_profile,           clr_config_apparmor_profile,           },
	{ "lxc.apparmor.allow_incomplete",  true,  set_config_apparmor_allow_incomplete,  get_config_apparmor_allow_incomplete,  clr_config_apparmor_allow_incomplete,  },
	{ "lxc.apparmor.allow_nesting",     true,  set_config_apparmor_allow_nesting,     get_config_apparmor_allow_nesting,     clr_config_apparmor_allow_nesting,     },
	{ "lxc.apparmor.raw",               true,  set_config_apparmor_raw,               get_config_apparmor_raw,               clr_config_apparmor_raw,               },
	{ "lxc.autodev.tmpfs.size",         true,  set_config_autodev_tmpfs_size,         get_config_autodev_tmpfs_size,         clr_config_autodev_tmpfs_size,         },
	{ "lxc.autodev",                    true,  set_config_autodev,                    get_config_autodev,                    clr_config_autodev,                    },
	{ "lxc.cap.drop",                   true,  set_config_cap_drop,                   get_config_cap_drop,                   clr_config_cap_drop,                   },
	{ "lxc.cap.keep",                   true,  set_config_cap_keep,                   get_config_cap_keep,                   clr_config_cap_keep,                   },
	{ "lxc.cgroup2",                    false, set_config_cgroup2_controller,         get_config_cgroup2_controller,         clr_config_cgroup2_controller,         },
	{ "lxc.cgroup.dir.monitor.pivot",   true,  set_config_cgroup_monitor_pivot_dir,   get_config_cgroup_monitor_pivot_dir,   clr_config_cgroup_monitor_pivot_dir,   },
	{ "lxc.cgroup.dir.monitor",         true,  set_config_cgroup_monitor_dir,         get_config_cgroup_monitor_dir,         clr_config_cgroup_monitor_dir,         },
	{ "lxc.cgroup.dir.container.inner", true,  set_config_cgroup_container_inner_dir, get_config_cgroup_container_inner_dir, clr_config_cgroup_container_inner_dir, },
	{ "lxc.cgroup.dir.container",       true,  set_config_cgroup_container_dir,       get_config_cgroup_container_dir,       clr_config_cgroup_container_dir,       },
	{ "lxc.cgroup.dir",                 true,  set_config_cgroup_dir,                 get_config_cgroup_dir,                 clr_config_cgroup_dir,                 },
	{ "lxc.cgroup.relative",            true,  set_config_cgroup_relative,            get_config_cgroup_relative,            clr_config_cgroup_relative,            },
	{ "lxc.cgroup",                     false, set_config_cgroup_controller,          get_config_cgroup_controller,          clr_config_cgroup_controller,          },
	{ "lxc.console.buffer.size",        true,  set_config_console_buffer_size,        get_config_console_buffer_size,        clr_config_console_buffer_size,        },
	{ "lxc.console.logfile",            true,  set_config_console_logfile,            get_config_console_logfile,            clr_config_console_logfile,            },
	{ "lxc.console.path",               true,  set_config_console_path,               get_config_console_path,               clr_config_console_path,               },
	{ "lxc.console.rotate",             true,  set_config_console_rotate,             get_config_console_rotate,             clr_config_console_rotate,             },
	{ "lxc.console.size",               true,  set_config_console_size,               get_config_console_size,               clr_config_console_size,               },
	{ "lxc.environment",                true,  set_config_environment,                get_config_environment,                clr_config_environment,                },
	{ "lxc.ephemeral",                  true,  set_config_ephemeral,                  get_config_ephemeral,                  clr_config_ephemeral,                  },
	{ "lxc.execute.cmd",                true,  set_config_execute_cmd,                get_config_execute_cmd,                clr_config_execute_cmd,                },
	{ "lxc.group",                      true,  set_config_group,                      get_config_group,                      clr_config_group,                      },
	{ "lxc.hook.autodev",               true,  set_config_hooks,                      get_config_hooks,                      clr_config_hooks,                      },
	{ "lxc.hook.clone",                 true,  set_config_hooks,                      get_config_hooks,                      clr_config_hooks,                      },
	{ "lxc.hook.destroy",               true,  set_config_hooks,                      get_config_hooks,                      clr_config_hooks,                      },
	{ "lxc.hook.mount",                 true,  set_config_hooks,                      get_config_hooks,                      clr_config_hooks,                      },
	{ "lxc.hook.post-stop",             true,  set_config_hooks,                      get_config_hooks,                      clr_config_hooks,                      },
	{ "lxc.hook.pre-mount",             true,  set_config_hooks,                      get_config_hooks,                      clr_config_hooks,                      },
	{ "lxc.hook.pre-start",             true,  set_config_hooks,                      get_config_hooks,                      clr_config_hooks,                      },
	{ "lxc.hook.start",                 true,  set_config_hooks,                      get_config_hooks,                      clr_config_hooks,                      },
	{ "lxc.hook.start-host",            true,  set_config_hooks,                      get_config_hooks,                      clr_config_hooks,                      },
	{ "lxc.hook.stop",                  true,  set_config_hooks,                      get_config_hooks,                      clr_config_hooks,                      },
	{ "lxc.hook.version",               true,  set_config_hooks_version,              get_config_hooks_version,              clr_config_hooks_version,              },
	{ "lxc.hook",                       true,  set_config_hooks,                      get_config_hooks,                      clr_config_hooks,                      },
	{ "lxc.idmap",                      true,  set_config_idmaps,                     get_config_idmaps,                     clr_config_idmaps,                     },
	{ "lxc.include",                    true,  set_config_includefiles,               get_config_includefiles,               clr_config_includefiles,               },
	{ "lxc.init.cmd",                   true,  set_config_init_cmd,                   get_config_init_cmd,                   clr_config_init_cmd,                   },
	{ "lxc.init.gid",                   true,  set_config_init_gid,                   get_config_init_gid,                   clr_config_init_gid,                   },
	{ "lxc.init.groups",                true,  set_config_init_groups,                get_config_init_groups,                clr_config_init_groups,                },
	{ "lxc.init.uid",                   true,  set_config_init_uid,                   get_config_init_uid,                   clr_config_init_uid,                   },
	{ "lxc.init.cwd",                   true,  set_config_init_cwd,                   get_config_init_cwd,                   clr_config_init_cwd,                   },
	{ "lxc.keyring.session",            true,  set_config_keyring_session,            get_config_keyring_session,            clr_config_keyring_session             },
	{ "lxc.log.file",                   true,  set_config_log_file,                   get_config_log_file,                   clr_config_log_file,                   },
	{ "lxc.log.level",                  true,  set_config_log_level,                  get_config_log_level,                  clr_config_log_level,                  },
	{ "lxc.log.syslog",                 true,  set_config_log_syslog,                 get_config_log_syslog,                 clr_config_log_syslog,                 },
	{ "lxc.monitor.unshare",            true,  set_config_monitor,                    get_config_monitor,                    clr_config_monitor,                    },
	{ "lxc.monitor.signal.pdeath",      true,  set_config_monitor_signal_pdeath,      get_config_monitor_signal_pdeath,      clr_config_monitor_signal_pdeath,      },
	{ "lxc.mount.auto",                 true,  set_config_mount_auto,                 get_config_mount_auto,                 clr_config_mount_auto,                 },
	{ "lxc.mount.entry",                true,  set_config_mount,                      get_config_mount,                      clr_config_mount,                      },
	{ "lxc.mount.fstab",                true,  set_config_mount_fstab,                get_config_mount_fstab,                clr_config_mount_fstab,                },
	{ "lxc.namespace.clone",            true,  set_config_namespace_clone,            get_config_namespace_clone,            clr_config_namespace_clone,            },
	{ "lxc.namespace.keep",             true,  set_config_namespace_keep,             get_config_namespace_keep,             clr_config_namespace_keep,             },
	{ "lxc.namespace.share.",           false, set_config_namespace_share,            get_config_namespace_share,            clr_config_namespace_share,            },
	{ "lxc.time.offset.boot",           true,  set_config_time_offset_boot,           get_config_time_offset_boot,           clr_config_time_offset_boot,           },
	{ "lxc.time.offset.monotonic",      true,  set_config_time_offset_monotonic,      get_config_time_offset_monotonic,      clr_config_time_offset_monotonic,      },
	{ "lxc.net.",                       false, set_config_jump_table_net,             get_config_jump_table_net,             clr_config_jump_table_net,             },
	{ "lxc.net",                        true,  set_config_net,                        get_config_net,                        clr_config_net,                        },
	{ "lxc.no_new_privs",	            true,  set_config_no_new_privs,               get_config_no_new_privs,               clr_config_no_new_privs,               },
	{ "lxc.prlimit",                    false, set_config_prlimit,                    get_config_prlimit,                    clr_config_prlimit,                    },
	{ "lxc.pty.max",                    true,  set_config_pty_max,                    get_config_pty_max,                    clr_config_pty_max,                    },
	{ "lxc.rootfs.managed",             true,  set_config_rootfs_managed,             get_config_rootfs_managed,             clr_config_rootfs_managed,             },
	{ "lxc.rootfs.mount",               true,  set_config_rootfs_mount,               get_config_rootfs_mount,               clr_config_rootfs_mount,               },
	{ "lxc.rootfs.options",             true,  set_config_rootfs_options,             get_config_rootfs_options,             clr_config_rootfs_options,             },
	{ "lxc.rootfs.path",                true,  set_config_rootfs_path,                get_config_rootfs_path,                clr_config_rootfs_path,                },
	{ "lxc.seccomp.allow_nesting",      true,  set_config_seccomp_allow_nesting,      get_config_seccomp_allow_nesting,      clr_config_seccomp_allow_nesting,      },
	{ "lxc.seccomp.notify.cookie",      true,  set_config_seccomp_notify_cookie,      get_config_seccomp_notify_cookie,      clr_config_seccomp_notify_cookie,      },
	{ "lxc.seccomp.notify.proxy",       true,  set_config_seccomp_notify_proxy,       get_config_seccomp_notify_proxy,       clr_config_seccomp_notify_proxy,       },
	{ "lxc.seccomp.profile",            true,  set_config_seccomp_profile,            get_config_seccomp_profile,            clr_config_seccomp_profile,            },
	{ "lxc.selinux.context.keyring",    true,  set_config_selinux_context_keyring,    get_config_selinux_context_keyring,    clr_config_selinux_context_keyring     },
	{ "lxc.selinux.context",            true,  set_config_selinux_context,            get_config_selinux_context,            clr_config_selinux_context,            },
	{ "lxc.signal.halt",                true,  set_config_signal_halt,                get_config_signal_halt,                clr_config_signal_halt,                },
	{ "lxc.signal.reboot",              true,  set_config_signal_reboot,              get_config_signal_reboot,              clr_config_signal_reboot,              },
	{ "lxc.signal.stop",                true,  set_config_signal_stop,                get_config_signal_stop,                clr_config_signal_stop,                },
	{ "lxc.start.auto",                 true,  set_config_start,                      get_config_start,                      clr_config_start,                      },
	{ "lxc.start.delay",                true,  set_config_start,                      get_config_start,                      clr_config_start,                      },
	{ "lxc.start.order",                true,  set_config_start,                      get_config_start,                      clr_config_start,                      },
	{ "lxc.tty.dir",                    true,  set_config_tty_dir,                    get_config_tty_dir,                    clr_config_tty_dir,                    },
	{ "lxc.tty.max",                    true,  set_config_tty_max,                    get_config_tty_max,                    clr_config_tty_max,                    },
	{ "lxc.uts.name",                   true,  set_config_uts_name,                   get_config_uts_name,                   clr_config_uts_name,                   },
	{ "lxc.sysctl",                     false, set_config_sysctl,                     get_config_sysctl,                     clr_config_sysctl,                     },
	{ "lxc.proc",                       false, set_config_proc,                       get_config_proc,                       clr_config_proc,                       },
};

static struct lxc_config_t unsupported_config_key = {
	NULL,
	false,
	set_config_unsupported_key,
	get_config_unsupported_key,
	clr_config_unsupported_key,
};

struct lxc_config_net_t {
	LXC_CONFIG_MEMBERS;
};

static struct lxc_config_net_t config_jump_table_net[] = {
	/* If a longer key is added please update. */
	#define NETWORK_SUBKEY_SIZE_MAX (STRLITERALLEN("veth.vlan.tagged.id") * 2)
	{ "flags",                  true,  set_config_net_flags,                  get_config_net_flags,                  clr_config_net_flags,                  },
	{ "hwaddr",                 true,  set_config_net_hwaddr,                 get_config_net_hwaddr,                 clr_config_net_hwaddr,                 },
	{ "ipv4.address",           true,  set_config_net_ipv4_address,           get_config_net_ipv4_address,           clr_config_net_ipv4_address,           },
	{ "ipv4.gateway",           true,  set_config_net_ipv4_gateway,           get_config_net_ipv4_gateway,           clr_config_net_ipv4_gateway,           },
	{ "ipv6.address",           true,  set_config_net_ipv6_address,           get_config_net_ipv6_address,           clr_config_net_ipv6_address,           },
	{ "ipv6.gateway",           true,  set_config_net_ipv6_gateway,           get_config_net_ipv6_gateway,           clr_config_net_ipv6_gateway,           },
	{ "link",                   true,  set_config_net_link,                   get_config_net_link,                   clr_config_net_link,                   },
	{ "l2proxy",                true,  set_config_net_l2proxy,                get_config_net_l2proxy,                clr_config_net_l2proxy,                },
	{ "macvlan.mode",           true,  set_config_net_macvlan_mode,           get_config_net_macvlan_mode,           clr_config_net_macvlan_mode,           },
	{ "ipvlan.mode",            true,  set_config_net_ipvlan_mode,            get_config_net_ipvlan_mode,            clr_config_net_ipvlan_mode,            },
	{ "ipvlan.isolation",       true,  set_config_net_ipvlan_isolation,       get_config_net_ipvlan_isolation,       clr_config_net_ipvlan_isolation,       },
	{ "mtu",                    true,  set_config_net_mtu,                    get_config_net_mtu,                    clr_config_net_mtu,                    },
	{ "name",                   true,  set_config_net_name,                   get_config_net_name,                   clr_config_net_name,                   },
	{ "script.down",            true,  set_config_net_script_down,            get_config_net_script_down,            clr_config_net_script_down,            },
	{ "script.up",              true,  set_config_net_script_up,              get_config_net_script_up,              clr_config_net_script_up,              },
	{ "type",                   true,  set_config_net_type,                   get_config_net_type,                   clr_config_net_type,                   },
	{ "vlan.id",                true,  set_config_net_vlan_id,                get_config_net_vlan_id,                clr_config_net_vlan_id,                },
	{ "veth.mode",              true,  set_config_net_veth_mode,              get_config_net_veth_mode,              clr_config_net_veth_mode,              },
	{ "veth.pair",              true,  set_config_net_veth_pair,              get_config_net_veth_pair,              clr_config_net_veth_pair,              },
	{ "veth.ipv4.route",        true,  set_config_net_veth_ipv4_route,        get_config_net_veth_ipv4_route,        clr_config_net_veth_ipv4_route,        },
	{ "veth.ipv6.route",        true,  set_config_net_veth_ipv6_route,        get_config_net_veth_ipv6_route,        clr_config_net_veth_ipv6_route,        },
	{ "veth.vlan.id",           true,  set_config_net_veth_vlan_id,           get_config_net_veth_vlan_id,           clr_config_net_veth_vlan_id,           },
	{ "veth.vlan.tagged.id",    true,  set_config_net_veth_vlan_tagged_id,    get_config_net_veth_vlan_tagged_id,    clr_config_net_veth_vlan_tagged_id,    },
};

static struct lxc_config_net_t unsupported_config_net_key = {
	NULL,
	false,
	set_config_unsupported_key,
	get_config_unsupported_key,
	clr_config_unsupported_key,
};

struct lxc_config_t *lxc_get_config_exact(const char *key)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(config_jump_table); i++)
		if (strequal(config_jump_table[i].name, key))
			return &config_jump_table[i];

	return NULL;
}

/* Assume a reasonable subkey size limit. */
#define LXC_SUBKEY_LEN_MAX 256

static inline int match_config_item(const struct lxc_config_t *entry, const char *key)
{
	size_t len;

	if (entry->strict)
		return strequal(entry->name, key);

	/* There should be no subkey longer than this. */
	len = strnlen(entry->name, LXC_SUBKEY_LEN_MAX);
	if (len == LXC_SUBKEY_LEN_MAX)
		return error_ret(-E2BIG, "Excessive subkey length");

	return strnequal(entry->name, key, len);
}

struct lxc_config_t *lxc_get_config(const char *key)
{
	for (size_t i = 0; i < ARRAY_SIZE(config_jump_table); i++) {
		struct lxc_config_t *cur = &config_jump_table[i];

		switch (match_config_item(cur, key)) {
		case 0:
			continue;
		case -E2BIG:
			return &unsupported_config_key;
		}

		return cur;
	}

	return &unsupported_config_key;
}

static inline bool match_config_net_item(const struct lxc_config_net_t *entry,
					 const char *key)
{
	if (entry->strict)
		return strequal(entry->name, key);
	return strnequal(entry->name, key, strlen(entry->name));
}

static struct lxc_config_net_t *lxc_get_config_net(const char *key)
{
	for (size_t i = 0; i < ARRAY_SIZE(config_jump_table_net); i++) {
		struct lxc_config_net_t *cur = &config_jump_table_net[i];

		if (!match_config_net_item(cur, key))
			continue;

		return cur;
	}

	return &unsupported_config_net_key;
}

static int set_config_net(const char *key, const char *value,
			  struct lxc_conf *lxc_conf, void *data)
{
	if (!lxc_config_value_empty(value)) {
		ERROR("lxc.net must not have a value");
		return -1;
	}

	return clr_config_net(key, lxc_conf, data);
}

static int set_config_net_type(const char *key, const char *value,
			       struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	clr_config_net_type(key, lxc_conf, data);
	if (lxc_config_value_empty(value))
		return 0;

	if (strequal(value, "veth")) {
		netdev->type = LXC_NET_VETH;
		lxc_list_init(&netdev->priv.veth_attr.ipv4_routes);
		lxc_list_init(&netdev->priv.veth_attr.ipv6_routes);
		lxc_list_init(&netdev->priv.veth_attr.vlan_tagged_ids);
		if (!lxc_veth_flag_to_mode(netdev->priv.veth_attr.mode))
			lxc_veth_mode_to_flag(&netdev->priv.veth_attr.mode, "bridge");
	} else if (strequal(value, "macvlan")) {
		netdev->type = LXC_NET_MACVLAN;
		if (!lxc_macvlan_flag_to_mode(netdev->priv.veth_attr.mode))
			lxc_macvlan_mode_to_flag(&netdev->priv.macvlan_attr.mode, "private");
	} else if (strequal(value, "ipvlan")) {
		netdev->type = LXC_NET_IPVLAN;
		if (!lxc_ipvlan_flag_to_mode(netdev->priv.ipvlan_attr.mode))
			lxc_ipvlan_mode_to_flag(&netdev->priv.ipvlan_attr.mode, "l3");
		if (!lxc_ipvlan_flag_to_isolation(netdev->priv.ipvlan_attr.isolation))
			lxc_ipvlan_isolation_to_flag(&netdev->priv.ipvlan_attr.isolation, "bridge");
	} else if (strequal(value, "vlan")) {
		netdev->type = LXC_NET_VLAN;
	} else if (strequal(value, "phys")) {
		netdev->type = LXC_NET_PHYS;
	} else if (strequal(value, "empty")) {
		netdev->type = LXC_NET_EMPTY;
	} else if (strequal(value, "none")) {
		netdev->type = LXC_NET_NONE;
	} else {
		return log_error(-1, "Invalid network type %s", value);
	}

	return 0;
}

static int set_config_net_flags(const char *key, const char *value,
				struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	if (lxc_config_value_empty(value))
		return clr_config_net_flags(key, lxc_conf, data);

	netdev->flags |= IFF_UP;

	return 0;
}

static int create_matched_ifnames(const char *value, struct lxc_conf *lxc_conf,
				  struct lxc_netdev *netdev)
{
	call_cleaner(netns_freeifaddrs) struct netns_ifaddrs *ifaddr = NULL;
	struct netns_ifaddrs *ifa;
	int n;
	int ret = 0;
	const char *type_key = "lxc.net.type";
	const char *link_key = "lxc.net.link";
	const char *tmpvalue = "phys";

	if (netns_getifaddrs(&ifaddr, -1, &(bool){false}) < 0)
		return log_error_errno(-1, errno, "Failed to get network interfaces");

	for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
		if (!ifa->ifa_addr)
			continue;

		if (ifa->ifa_addr->sa_family != AF_PACKET)
			continue;

		if (strnequal(value, ifa->ifa_name, strlen(value) - 1)) {
			ret = set_config_net_type(type_key, tmpvalue, lxc_conf,
						  netdev);
			if (!ret) {
				ret = set_config_net_link(
				    link_key, ifa->ifa_name, lxc_conf, netdev);
				if (ret) {
					ERROR("Failed to create matched ifnames");
					break;
				}
			} else {
				ERROR("Failed to create matched ifnames");
				break;
			}
		}
	}

	return ret;
}

static int set_config_net_link(const char *key, const char *value,
			       struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_netdev *netdev = data;
	int ret = 0;

	if (!netdev)
		return ret_errno(EINVAL);

	if (lxc_config_value_empty(value))
		return clr_config_net_link(key, lxc_conf, data);

	if (value[strlen(value) - 1] == '+' && netdev->type == LXC_NET_PHYS)
		ret = create_matched_ifnames(value, lxc_conf, netdev);
	else
		ret = network_ifname(netdev->link, value, sizeof(netdev->link));

	return ret;
}

static int set_config_net_l2proxy(const char *key, const char *value,
				     struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_netdev *netdev = data;
	unsigned int val = 0;
	int ret;

	if (!netdev)
		return ret_errno(EINVAL);

	if (lxc_config_value_empty(value))
		return clr_config_net_l2proxy(key, lxc_conf, data);

	ret = lxc_safe_uint(value, &val);
	if (ret < 0)
		return ret_errno(ret);

	switch (val) {
	case 0:
		netdev->l2proxy = false;
		return 0;
	case 1:
		netdev->l2proxy = true;
		return 0;
	}

	return ret_errno(EINVAL);
}

static int set_config_net_name(const char *key, const char *value,
			       struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	if (lxc_config_value_empty(value))
		return clr_config_net_name(key, lxc_conf, data);

	return network_ifname(netdev->name, value, sizeof(netdev->name));
}


static int set_config_net_veth_mode(const char *key, const char *value,
				       struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	if (netdev->type != LXC_NET_VETH)
		return ret_errno(EINVAL);

	if (lxc_config_value_empty(value))
		return clr_config_net_veth_mode(key, lxc_conf, data);

	if (!netdev)
		return ret_errno(EINVAL);

	return lxc_veth_mode_to_flag(&netdev->priv.veth_attr.mode, value);
}

static int set_config_net_veth_pair(const char *key, const char *value,
				    struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	if (netdev->type != LXC_NET_VETH)
		return ret_errno(EINVAL);

	if (lxc_config_value_empty(value))
		return clr_config_net_veth_pair(key, lxc_conf, data);

	return network_ifname(netdev->priv.veth_attr.pair, value,
			      sizeof(netdev->priv.veth_attr.pair));
}

static int set_config_net_veth_vlan_id(const char *key, const char *value,
				       struct lxc_conf *lxc_conf, void *data)
{
	int ret;
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	if (netdev->type != LXC_NET_VETH)
		return ret_errno(EINVAL);

	if (lxc_config_value_empty(value))
		return clr_config_net_veth_vlan_id(key, lxc_conf, data);

	if (strequal(value, "none")) {
		netdev->priv.veth_attr.vlan_id = BRIDGE_VLAN_NONE;
	} else {
		unsigned short vlan_id;

		ret = get_u16(&vlan_id, value, 0);
		if (ret < 0)
			return ret_errno(EINVAL);

		if (vlan_id > BRIDGE_VLAN_ID_MAX)
			return ret_errno(EINVAL);

		netdev->priv.veth_attr.vlan_id = vlan_id;
	}

	netdev->priv.veth_attr.vlan_id_set = true;
	return 0;
}

static int set_config_net_veth_vlan_tagged_id(const char *key, const char *value,
					      struct lxc_conf *lxc_conf,
					      void *data)
{
	__do_free struct lxc_list *list = NULL;
	int ret;
	unsigned short vlan_id;
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	if (netdev->type != LXC_NET_VETH)
		return ret_errno(EINVAL);

	if (lxc_config_value_empty(value))
		return clr_config_net_veth_vlan_tagged_id(key, lxc_conf, data);

	ret = get_u16(&vlan_id, value, 0);
	if (ret < 0)
		return ret_errno(EINVAL);

	if (vlan_id > BRIDGE_VLAN_ID_MAX)
		return ret_errno(EINVAL);

	list = lxc_list_new();
	if (!list)
		return ret_errno(ENOMEM);

	list->elem = UINT_TO_PTR(vlan_id);

	lxc_list_add_tail(&netdev->priv.veth_attr.vlan_tagged_ids, move_ptr(list));

	return 0;
}

static int set_config_net_macvlan_mode(const char *key, const char *value,
				       struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	if (netdev->type != LXC_NET_MACVLAN)
		return ret_errno(EINVAL);

	if (lxc_config_value_empty(value))
		return clr_config_net_macvlan_mode(key, lxc_conf, data);

	return lxc_macvlan_mode_to_flag(&netdev->priv.macvlan_attr.mode, value);
}

static int set_config_net_ipvlan_mode(const char *key, const char *value,
				      struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	if (netdev->type != LXC_NET_IPVLAN)
		return syserror_set(-EINVAL, "Invalid ipvlan mode \"%s\", can only be used with ipvlan network", value);

	if (lxc_config_value_empty(value))
		return clr_config_net_ipvlan_mode(key, lxc_conf, data);

	return lxc_ipvlan_mode_to_flag(&netdev->priv.ipvlan_attr.mode, value);
}

static int set_config_net_ipvlan_isolation(const char *key, const char *value,
					   struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	if (netdev->type != LXC_NET_IPVLAN)
		return syserror_set(-EINVAL, "Invalid ipvlan isolation \"%s\", can only be used with ipvlan network", value);

	if (lxc_config_value_empty(value))
		return clr_config_net_ipvlan_isolation(key, lxc_conf, data);

	return lxc_ipvlan_isolation_to_flag(&netdev->priv.ipvlan_attr.isolation, value);
}

static int set_config_net_hwaddr(const char *key, const char *value,
				 struct lxc_conf *lxc_conf, void *data)
{
	__do_free char *new_value = NULL;
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	clr_config_net_hwaddr(key, lxc_conf, data);
	if (lxc_config_value_empty(value))
		return 0;

	new_value = strdup(value);
	if (!new_value)
		return ret_errno(ENOMEM);

	rand_complete_hwaddr(new_value);
	if (!lxc_config_value_empty(new_value))
		netdev->hwaddr = move_ptr(new_value);

	return 0;
}

static int set_config_net_vlan_id(const char *key, const char *value,
				  struct lxc_conf *lxc_conf, void *data)
{
	int ret;
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	if (netdev->type != LXC_NET_VLAN)
		return ret_errno(EINVAL);

	if (lxc_config_value_empty(value))
		return clr_config_net_vlan_id(key, lxc_conf, data);

	ret = get_u16(&netdev->priv.vlan_attr.vid, value, 0);
	if (ret < 0)
		return ret;

	return 0;
}

static int set_config_net_mtu(const char *key, const char *value,
			      struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	clr_config_net_mtu(key, lxc_conf, data);
	if (lxc_config_value_empty(value))
		return 0;

	return set_config_string_item(&netdev->mtu, value);
}

static int set_config_net_ipv4_address(const char *key, const char *value,
				       struct lxc_conf *lxc_conf, void *data)
{
	__do_free char *addr = NULL;
	__do_free struct lxc_inetdev *inetdev = NULL;
	__do_free struct lxc_list *list = NULL;
	int ret;
	struct lxc_netdev *netdev = data;
	char *cursor, *slash;
	char *bcast = NULL, *prefix = NULL;

	if (!netdev)
		return ret_errno(EINVAL);

	if (lxc_config_value_empty(value))
		return clr_config_net_ipv4_address(key, lxc_conf, data);

	inetdev = zalloc(sizeof(*inetdev));
	if (!inetdev)
		return ret_errno(ENOMEM);

	list = lxc_list_new();
	if (!list)
		return ret_errno(ENOMEM);

	addr = strdup(value);
	if (!addr)
		return ret_errno(ENOMEM);

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

	ret = inet_pton(AF_INET, addr, &inetdev->addr);
	if (!ret || ret < 0)
		return log_error_errno(-1, errno, "Invalid ipv4 address \"%s\"", value);

	if (bcast) {
		ret = inet_pton(AF_INET, bcast, &inetdev->bcast);
		if (!ret || ret < 0)
			return log_error_errno(-1, errno, "Invalid ipv4 broadcast address \"%s\"", value);

	}

	/* No prefix specified, determine it from the network class. */
	ret = 0;
	if (prefix)
		ret = lxc_safe_uint(prefix, &inetdev->prefix);
	else
		inetdev->prefix = config_ip_prefix(&inetdev->addr);
	if (ret || inetdev->prefix > 32)
		return ret_errno(EINVAL);

	/* If no broadcast address, compute one from the prefix and address. */
	if (!bcast) {
		unsigned int shift = LAST_BIT_PER_TYPE(inetdev->prefix);

		inetdev->bcast.s_addr = inetdev->addr.s_addr;
		if (inetdev->prefix < shift)
			shift = inetdev->prefix;
		inetdev->bcast.s_addr |= htonl(INADDR_BROADCAST >> shift);
	}

	list->elem = inetdev;
	lxc_list_add_tail(&netdev->ipv4, list);
	move_ptr(inetdev);
	move_ptr(list);

	return 0;
}

static int set_config_net_ipv4_gateway(const char *key, const char *value,
				       struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	clr_config_net_ipv4_gateway(key, lxc_conf, data);
	if (lxc_config_value_empty(value))
		return 0;

	if (strequal(value, "auto")) {
		netdev->ipv4_gateway = NULL;
		netdev->ipv4_gateway_auto = true;
	} else if (strequal(value, "dev")) {
		netdev->ipv4_gateway = NULL;
		netdev->ipv4_gateway_auto = false;
		netdev->ipv4_gateway_dev = true;
	} else {
		__do_free struct in_addr *gw = NULL;
		int ret;

		gw = zalloc(sizeof(*gw));
		if (!gw)
			return ret_errno(ENOMEM);

		ret = inet_pton(AF_INET, value, gw);
		if (!ret || ret < 0)
			return log_error_errno(-1, errno, "Invalid ipv4 gateway address \"%s\"", value);

		netdev->ipv4_gateway = move_ptr(gw);
		netdev->ipv4_gateway_auto = false;
	}

	return 0;
}

static int set_config_net_veth_ipv4_route(const char *key, const char *value,
					  struct lxc_conf *lxc_conf, void *data)
{
	__do_free char *valdup = NULL;
	__do_free struct lxc_inetdev *inetdev = NULL;
	__do_free struct lxc_list *list = NULL;
	int ret;
	char *netmask, *slash;
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	if (netdev->type != LXC_NET_VETH)
		return syserror_set(-EINVAL, "Invalid ipv4 route \"%s\", can only be used with veth network", value);

	if (lxc_config_value_empty(value))
		return clr_config_net_veth_ipv4_route(key, lxc_conf, data);

	inetdev = zalloc(sizeof(*inetdev));
	if (!inetdev)
		return ret_errno(ENOMEM);

	list = lxc_list_new();
	if (!list)
		return ret_errno(ENOMEM);

	list->elem = inetdev;

	valdup = strdup(value);
	if (!valdup)
		return ret_errno(ENOMEM);

	slash = strchr(valdup, '/');
	if (!slash)
		return ret_errno(EINVAL);

	*slash = '\0';
	slash++;
	if (*slash == '\0')
		return ret_errno(EINVAL);

	netmask = slash;

	ret = lxc_safe_uint(netmask, &inetdev->prefix);
	if (ret < 0 || inetdev->prefix > 32)
		return ret_errno(EINVAL);

	ret = inet_pton(AF_INET, valdup, &inetdev->addr);
	if (!ret || ret < 0)
		return ret_errno(EINVAL);

	lxc_list_add_tail(&netdev->priv.veth_attr.ipv4_routes, list);
	move_ptr(inetdev);
	move_ptr(list);

	return 0;
}

static int set_config_net_ipv6_address(const char *key, const char *value,
				       struct lxc_conf *lxc_conf, void *data)
{
	__do_free char *valdup = NULL;
	__do_free struct lxc_inet6dev *inet6dev = NULL;
	__do_free struct lxc_list *list = NULL;
	int ret;
	struct lxc_netdev *netdev = data;
	char *slash, *netmask;

	if (!netdev)
		return ret_errno(EINVAL);

	if (lxc_config_value_empty(value))
		return clr_config_net_ipv6_address(key, lxc_conf, data);

	inet6dev = zalloc(sizeof(*inet6dev));
	if (!inet6dev)
		return ret_errno(ENOMEM);

	list = lxc_list_new();
	if (!list)
		return ret_errno(ENOMEM);

	valdup = strdup(value);
	if (!valdup)
		return ret_errno(ENOMEM);

	inet6dev->prefix = 64;
	slash = strstr(valdup, "/");
	if (slash) {
		*slash = '\0';
		netmask = slash + 1;

		ret = lxc_safe_uint(netmask, &inet6dev->prefix);
		if (ret < 0)
			return ret;
	}

	ret = inet_pton(AF_INET6, valdup, &inet6dev->addr);
	if (!ret || ret < 0)
		return log_error_errno(-EINVAL, EINVAL, "Invalid ipv6 address \"%s\"", valdup);

	list->elem = inet6dev;
	lxc_list_add_tail(&netdev->ipv6, list);
	move_ptr(inet6dev);
	move_ptr(list);

	return 0;
}

static int set_config_net_ipv6_gateway(const char *key, const char *value,
				       struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	clr_config_net_ipv6_gateway(key, lxc_conf, data);
	if (lxc_config_value_empty(value))
		return 0;

	if (strequal(value, "auto")) {
		netdev->ipv6_gateway = NULL;
		netdev->ipv6_gateway_auto = true;
	} else if (strequal(value, "dev")) {
		netdev->ipv6_gateway = NULL;
		netdev->ipv6_gateway_auto = false;
		netdev->ipv6_gateway_dev = true;
	} else {
		int ret;
		__do_free struct in6_addr *gw = NULL;

		gw = zalloc(sizeof(*gw));
		if (!gw)
			return ret_errno(ENOMEM);

		ret = inet_pton(AF_INET6, value, gw);
		if (!ret || ret < 0)
			return log_error_errno(-EINVAL, EINVAL,
					       "Invalid ipv6 gateway address \"%s\"", value);

		netdev->ipv6_gateway = move_ptr(gw);
		netdev->ipv6_gateway_auto = false;
	}

	return 0;
}

static int set_config_net_veth_ipv6_route(const char *key, const char *value,
					  struct lxc_conf *lxc_conf, void *data)
{
	__do_free char *valdup = NULL;
	__do_free struct lxc_inet6dev *inet6dev = NULL;
	__do_free struct lxc_list *list = NULL;
	int ret;
	char *netmask, *slash;
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	if (netdev->type != LXC_NET_VETH)
		return syserror_set(-EINVAL, "Invalid ipv6 route \"%s\", can only be used with veth network", value);

	if (lxc_config_value_empty(value))
		return clr_config_net_veth_ipv6_route(key, lxc_conf, data);

	inet6dev = zalloc(sizeof(*inet6dev));
	if (!inet6dev)
		return ret_errno(ENOMEM);

	list = lxc_list_new();
	if (!list)
		return ret_errno(ENOMEM);

	valdup = strdup(value);
	if (!valdup)
		return -1;

	slash = strchr(valdup, '/');
	if (!slash)
		return ret_errno(EINVAL);

	*slash = '\0';
	slash++;
	if (*slash == '\0')
		return ret_errno(EINVAL);

	netmask = slash;

	ret = lxc_safe_uint(netmask, &inet6dev->prefix);
	if (ret < 0 || inet6dev->prefix > 128)
		return ret_errno(EINVAL);

	ret = inet_pton(AF_INET6, valdup, &inet6dev->addr);
	if (!ret || ret < 0)
		return ret_errno(EINVAL);

	list->elem = inet6dev;
	lxc_list_add_tail(&netdev->priv.veth_attr.ipv6_routes, list);
	move_ptr(inet6dev);
	move_ptr(list);

	return 0;
}

static int set_config_net_script_up(const char *key, const char *value,
				    struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	clr_config_net_script_up(key, lxc_conf, data);
	if (lxc_config_value_empty(value))
		return 0;

	return set_config_string_item(&netdev->upscript, value);
}

static int set_config_net_script_down(const char *key, const char *value,
				      struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	clr_config_net_script_down(key, lxc_conf, data);
	if (lxc_config_value_empty(value))
		return 0;

	return set_config_string_item(&netdev->downscript, value);
}

static int add_hook(struct lxc_conf *lxc_conf, int which, __owns char *hook)
{
	__do_free char *val = hook;
	struct lxc_list *hooklist;

	hooklist = lxc_list_new();
	if (!hooklist)
		return ret_errno(ENOMEM);

	hooklist->elem = move_ptr(val);
	lxc_list_add_tail(&lxc_conf->hooks[which], hooklist);

	return 0;
}

static int set_config_seccomp_allow_nesting(const char *key, const char *value,
					    struct lxc_conf *lxc_conf, void *data)
{
#ifdef HAVE_SECCOMP
	if (lxc_config_value_empty(value))
		return clr_config_seccomp_allow_nesting(key, lxc_conf, NULL);

	if (lxc_safe_uint(value, &lxc_conf->seccomp.allow_nesting) < 0)
		return -1;

	if (lxc_conf->seccomp.allow_nesting > 1)
		return ret_set_errno(-1, EINVAL);

	return 0;
#else
	errno = ENOSYS;
	return -1;
#endif
}

static int set_config_seccomp_notify_cookie(const char *key, const char *value,
					    struct lxc_conf *lxc_conf, void *data)
{
#ifdef HAVE_SECCOMP_NOTIFY
	return set_config_string_item(&lxc_conf->seccomp.notifier.cookie, value);
#else
	return ret_set_errno(-1, ENOSYS);
#endif
}

static int set_config_seccomp_notify_proxy(const char *key, const char *value,
					   struct lxc_conf *lxc_conf, void *data)
{
#ifdef HAVE_SECCOMP_NOTIFY
	const char *offset;

	if (lxc_config_value_empty(value))
		return clr_config_seccomp_notify_proxy(key, lxc_conf, NULL);

	if (!strnequal(value, "unix:", 5))
		return ret_set_errno(-1, EINVAL);

	offset = value + 5;
	if (lxc_unix_sockaddr(&lxc_conf->seccomp.notifier.proxy_addr, offset) < 0)
		return -1;

	return 0;
#else
	return ret_set_errno(-1, ENOSYS);
#endif
}

static int set_config_seccomp_profile(const char *key, const char *value,
				      struct lxc_conf *lxc_conf, void *data)
{
	return set_config_path_item(&lxc_conf->seccomp.seccomp, value);
}

static int set_config_execute_cmd(const char *key, const char *value,
			       struct lxc_conf *lxc_conf, void *data)
{
	return set_config_path_item(&lxc_conf->execute_cmd, value);
}

static int set_config_init_cmd(const char *key, const char *value,
			       struct lxc_conf *lxc_conf, void *data)
{
	return set_config_path_item(&lxc_conf->init_cmd, value);
}

static int set_config_init_cwd(const char *key, const char *value,
			       struct lxc_conf *lxc_conf, void *data)
{
	return set_config_path_item(&lxc_conf->init_cwd, value);
}

static int set_config_init_uid(const char *key, const char *value,
			       struct lxc_conf *lxc_conf, void *data)
{
	unsigned int init_uid;

	if (lxc_config_value_empty(value)) {
		lxc_conf->init_uid = 0;
		return 0;
	}

	if (lxc_safe_uint(value, &init_uid) < 0)
		return -1;

	lxc_conf->init_uid = init_uid;

	return 0;
}

static int set_config_init_gid(const char *key, const char *value,
			       struct lxc_conf *lxc_conf, void *data)
{
	unsigned int init_gid;

	if (lxc_config_value_empty(value)) {
		lxc_conf->init_gid = 0;
		return 0;
	}

	if (lxc_safe_uint(value, &init_gid) < 0)
		return -1;

	lxc_conf->init_gid = init_gid;

	return 0;
}

static int set_config_init_groups(const char *key, const char *value,
				  struct lxc_conf *lxc_conf, void *data)
{
	__do_free char *value_dup = NULL;
	gid_t *init_groups = NULL;
	size_t num_groups = 0;
	size_t idx;
	char *token;

	if (lxc_config_value_empty(value))
		return clr_config_init_groups(key, lxc_conf, NULL);

	value_dup = strdup(value);
	if (!value_dup)
		return -ENOMEM;

	lxc_iterate_parts(token, value_dup, ",")
		num_groups++;

	if (num_groups == INT_MAX)
		return log_error_errno(-ERANGE, ERANGE, "Excessive number of supplementary groups specified");

	/* This means the string wasn't empty and all we found was garbage. */
	if (num_groups == 0)
		return log_error_errno(-EINVAL, EINVAL, "No valid groups specified %s", value);

	idx = lxc_conf->init_groups.size;
	init_groups = realloc(lxc_conf->init_groups.list, sizeof(gid_t) * (idx + num_groups));
	if (!init_groups)
		return ret_errno(ENOMEM);

	/*
	 * Once the realloc() succeeded we need to hand control of the memory
	 * back to the config otherwise we risk a double-free when
	 * lxc_conf_free() is called.
	 */
	lxc_conf->init_groups.list = init_groups;

	/* Restore duplicated value so we can call lxc_iterate_parts() again. */
	strcpy(value_dup, value);

	lxc_iterate_parts(token, value_dup, ",") {
		int ret;

		gid_t group;

		ret = lxc_safe_uint(token, &group);
		if (ret)
			return log_error_errno(ret, -ret, "Failed to parse group %s", token);

		init_groups[idx++] = group;
	}

	lxc_conf->init_groups.size += num_groups;

	return 0;
}

static int set_config_hooks(const char *key, const char *value,
			    struct lxc_conf *lxc_conf, void *data)
{
	__do_free char *copy = NULL;

	if (lxc_config_value_empty(value))
		return lxc_clear_hooks(lxc_conf, key);

	if (strequal(key + 4, "hook"))
		return log_error_errno(-EINVAL, EINVAL, "lxc.hook must not have a value");

	copy = strdup(value);
	if (!copy)
		return ret_errno(ENOMEM);

	if (strequal(key + 9, "pre-start"))
		return add_hook(lxc_conf, LXCHOOK_PRESTART, move_ptr(copy));
	else if (strequal(key + 9, "start-host"))
		return add_hook(lxc_conf, LXCHOOK_START_HOST, move_ptr(copy));
	else if (strequal(key + 9, "pre-mount"))
		return add_hook(lxc_conf, LXCHOOK_PREMOUNT, move_ptr(copy));
	else if (strequal(key + 9, "autodev"))
		return add_hook(lxc_conf, LXCHOOK_AUTODEV, move_ptr(copy));
	else if (strequal(key + 9, "mount"))
		return add_hook(lxc_conf, LXCHOOK_MOUNT, move_ptr(copy));
	else if (strequal(key + 9, "start"))
		return add_hook(lxc_conf, LXCHOOK_START, move_ptr(copy));
	else if (strequal(key + 9, "stop"))
		return add_hook(lxc_conf, LXCHOOK_STOP, move_ptr(copy));
	else if (strequal(key + 9, "post-stop"))
		return add_hook(lxc_conf, LXCHOOK_POSTSTOP, move_ptr(copy));
	else if (strequal(key + 9, "clone"))
		return add_hook(lxc_conf, LXCHOOK_CLONE, move_ptr(copy));
	else if (strequal(key + 9, "destroy"))
		return add_hook(lxc_conf, LXCHOOK_DESTROY, move_ptr(copy));

	return ret_errno(EINVAL);
}

static int set_config_hooks_version(const char *key, const char *value,
				    struct lxc_conf *lxc_conf, void *data)
{
	int ret;
	unsigned int tmp;

	if (lxc_config_value_empty(value))
		return clr_config_hooks_version(key, lxc_conf, NULL);

	ret = lxc_safe_uint(value, &tmp);
	if (ret < 0)
		return -1;

	if (tmp > 1)
		return log_error_errno(-EINVAL,
				       EINVAL, "Invalid hook version specified. Currently only 0 (legacy) and 1 are supported");

	lxc_conf->hooks_version = tmp;

	return 0;
}

static int set_config_personality(const char *key, const char *value,
				  struct lxc_conf *lxc_conf, void *data)
{
	int ret;
	personality_t personality;

	ret = lxc_config_parse_arch(value, &personality);
	if (ret < 0)
		return syserror("Unsupported personality \"%s\"", value);

	lxc_conf->personality = personality;
	return 0;
}

static int set_config_pty_max(const char *key, const char *value,
			      struct lxc_conf *lxc_conf, void *data)
{
	int ret;
	unsigned int max = 0;

	if (lxc_config_value_empty(value)) {
		lxc_conf->pty_max = 0;
		return 0;
	}

	ret = lxc_safe_uint(value, &max);
	if (ret < 0)
		return ret_errno(EINVAL);

	lxc_conf->pty_max = max;

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
	int ret;
	bool is_empty;

	is_empty = lxc_config_value_empty(value);

	if (*(key + 10) == 'a') { /* lxc.start.auto */
		if (is_empty) {
			lxc_conf->start_auto = 0;
			return 0;
		}

		ret = lxc_safe_uint(value, &lxc_conf->start_auto);
		if (ret)
			return ret;

		if (lxc_conf->start_auto > 1)
			return ret_errno(EINVAL);

		return 0;
	} else if (*(key + 10) == 'd') { /* lxc.start.delay */
		if (is_empty) {
			lxc_conf->start_delay = 0;
			return 0;
		}

		return lxc_safe_uint(value, &lxc_conf->start_delay);
	} else if (*(key + 10) == 'o') { /* lxc.start.order */
		if (is_empty) {
			lxc_conf->start_order = 0;
			return 0;
		}

		return lxc_safe_int(value, &lxc_conf->start_order);
	}

	return ret_errno(EINVAL);
}

static int set_config_monitor(const char *key, const char *value,
			      struct lxc_conf *lxc_conf, void *data)
{
	if (lxc_config_value_empty(value)) {
		lxc_conf->monitor_unshare = 0;
		return 0;
	}

	if (strequal(key + 12, "unshare"))
		return lxc_safe_uint(value, &lxc_conf->monitor_unshare);

	return ret_errno(EINVAL);
}

static int set_config_monitor_signal_pdeath(const char *key, const char *value,
					    struct lxc_conf *lxc_conf, void *data)
{
	if (lxc_config_value_empty(value)) {
		lxc_conf->monitor_signal_pdeath = 0;
		return 0;
	}

	if (strequal(key + 12, "signal.pdeath")) {
		int sig_n;

		sig_n = sig_parse(value);
		if (sig_n < 0)
			return ret_errno(EINVAL);

		lxc_conf->monitor_signal_pdeath = sig_n;
		return 0;
	}

	return ret_errno(EINVAL);
}

static int set_config_group(const char *key, const char *value,
			    struct lxc_conf *lxc_conf, void *data)
{
	__do_free char *groups = NULL;
	char *token;

	if (lxc_config_value_empty(value))
		return lxc_clear_groups(lxc_conf);

	groups = strdup(value);
	if (!groups)
		return ret_errno(ENOMEM);

	/* In case several groups are specified in a single line split these
	 * groups in a single element for the list.
	 */
	lxc_iterate_parts(token, groups, " \t") {
		__do_free struct lxc_list *grouplist = NULL;

		grouplist = lxc_list_new();
		if (!grouplist)
			return ret_errno(ENOMEM);

		grouplist->elem = strdup(token);
		if (!grouplist->elem)
			return ret_errno(ENOMEM);

		lxc_list_add_tail(&lxc_conf->groups, move_ptr(grouplist));
	}

	return 0;
}

static int set_config_environment(const char *key, const char *value,
				  struct lxc_conf *lxc_conf, void *data)
{
	__do_free struct lxc_list *list_item = NULL;

	if (lxc_config_value_empty(value))
		return lxc_clear_environment(lxc_conf);

	list_item = lxc_list_new();
	if (!list_item)
		return ret_errno(ENOMEM);

	if (!strchr(value, '=')) {
		const char *env_val;
		const char *env_key = value;
		const char *env_var[3] = {0};

		env_val = getenv(env_key);
		if (!env_val)
			return ret_errno(ENOENT);

		env_var[0] = env_key;
		env_var[1] = env_val;
		list_item->elem = lxc_string_join("=", env_var, false);
	} else {
		list_item->elem = strdup(value);
	}

	if (!list_item->elem)
		return ret_errno(ENOMEM);

	lxc_list_add_tail(&lxc_conf->environment, move_ptr(list_item));

	return 0;
}

static int set_config_tty_max(const char *key, const char *value,
			      struct lxc_conf *lxc_conf, void *data)
{
	int ret;
	unsigned int nbtty = 0;

	if (lxc_config_value_empty(value)) {
		lxc_conf->ttys.max = 0;
		return 0;
	}

	ret = lxc_safe_uint(value, &nbtty);
	if (ret < 0)
		return ret;

	lxc_conf->ttys.max = nbtty;

	return 0;
}

static int set_config_tty_dir(const char *key, const char *value,
			     struct lxc_conf *lxc_conf, void *data)
{
	return set_config_string_item_max(&lxc_conf->ttys.dir, value,
					  NAME_MAX + 1);
}

static int set_config_apparmor_profile(const char *key, const char *value,
				       struct lxc_conf *lxc_conf, void *data)
{
#if HAVE_APPARMOR
	return set_config_string_item(&lxc_conf->lsm_aa_profile, value);
#else
	return syserror_set(-EINVAL, "Built without AppArmor support");
#endif
}

static int set_config_apparmor_allow_incomplete(const char *key,
						const char *value,
						struct lxc_conf *lxc_conf,
						void *data)
{
#if HAVE_APPARMOR
	int ret;

	if (lxc_config_value_empty(value)) {
		lxc_conf->lsm_aa_allow_incomplete = 0;
		return 0;
	}

	ret = lxc_safe_uint(value, &lxc_conf->lsm_aa_allow_incomplete);
	if (ret)
		return ret;

	if (lxc_conf->lsm_aa_allow_incomplete > 1)
		return ret_errno(EINVAL);

	return 0;
#else
	return syserror_set(-EINVAL, "Built without AppArmor support");
#endif
}

static int set_config_apparmor_allow_nesting(const char *key,
					     const char *value,
					     struct lxc_conf *lxc_conf,
					     void *data)
{
#if HAVE_APPARMOR
	int ret;

	if (lxc_config_value_empty(value))
		return clr_config_apparmor_allow_nesting(key, lxc_conf, NULL);

	ret = lxc_safe_uint(value, &lxc_conf->lsm_aa_allow_nesting);
	if (ret)
		return ret;

	if (lxc_conf->lsm_aa_allow_nesting > 1)
		return ret_errno(EINVAL);

	return 0;
#else
	return syserror_set(-EINVAL, "Built without AppArmor support");
#endif
}

static int set_config_apparmor_raw(const char *key,
				   const char *value,
				   struct lxc_conf *lxc_conf,
				   void *data)
{
#if HAVE_APPARMOR
	__do_free char *elem = NULL;
	__do_free struct lxc_list *list = NULL;

	if (lxc_config_value_empty(value))
		return lxc_clear_apparmor_raw(lxc_conf);

	list = lxc_list_new();
	if (!list)
		return ret_errno(ENOMEM);

	elem = strdup(value);
	if (!elem)
		return ret_errno(ENOMEM);

	list->elem = move_ptr(elem);
	lxc_list_add_tail(&lxc_conf->lsm_aa_raw, move_ptr(list));

	return 0;
#else
	return syserror_set(-EINVAL, "Built without AppArmor support");
#endif
}

static int set_config_selinux_context(const char *key, const char *value,
				      struct lxc_conf *lxc_conf, void *data)
{
#if HAVE_SELINUX
	return set_config_string_item(&lxc_conf->lsm_se_context, value);
#else
	return syserror_set(-EINVAL, "Built without SELinux support");
#endif
}

static int set_config_selinux_context_keyring(const char *key, const char *value,
					      struct lxc_conf *lxc_conf, void *data)
{
#if HAVE_SELINUX
	return set_config_string_item(&lxc_conf->lsm_se_keyring_context, value);
#else
	return syserror_set(-EINVAL, "Built without SELinux support");
#endif
}

static int set_config_keyring_session(const char *key, const char *value,
				      struct lxc_conf *lxc_conf, void *data)
{
	return set_config_bool_item(&lxc_conf->keyring_disable_session, value, false);
}

static int set_config_log_file(const char *key, const char *value,
			      struct lxc_conf *c, void *data)
{
	int ret;

	if (lxc_config_value_empty(value)) {
		free_disarm(c->logfile);
		return 0;
	}

	/*
	 * Store these values in the lxc_conf, and then try to set for actual
	 * current logging.
	 */
	ret = set_config_path_item(&c->logfile, value);
	if (ret == 0)
		ret = lxc_log_set_file(&c->logfd, c->logfile);

	return ret;
}

static int set_config_log_level(const char *key, const char *value,
			       struct lxc_conf *lxc_conf, void *data)
{
	int newlevel;

	if (lxc_config_value_empty(value)) {
		lxc_conf->loglevel = LXC_LOG_LEVEL_NOTSET;
		return 0;
	}

	if (value[0] >= '0' && value[0] <= '9') {
		int ret;

		ret = lxc_safe_int(value, &newlevel);
		if (ret)
			return ret_errno(EINVAL);
	} else {
		newlevel = lxc_log_priority_to_int(value);
	}

	/*
	 * Store these values in the lxc_conf, and then try to set for actual
	 * current logging.
	 */
	lxc_conf->loglevel = newlevel;

	return lxc_log_set_level(&lxc_conf->loglevel, newlevel);
}

static int set_config_autodev(const char *key, const char *value,
			      struct lxc_conf *lxc_conf, void *data)
{
	int ret;

	if (lxc_config_value_empty(value)) {
		lxc_conf->autodev = 0;
		return 0;
	}

	ret = lxc_safe_uint(value, &lxc_conf->autodev);
	if (ret)
		return ret_errno(EINVAL);

	if (lxc_conf->autodev > 1)
		return ret_errno(EINVAL);

	return 0;
}

static int set_config_autodev_tmpfs_size(const char *key, const char *value,
			      struct lxc_conf *lxc_conf, void *data)
{
	if (lxc_config_value_empty(value)) {
		lxc_conf->autodevtmpfssize = 500000;
		return 0;
	}

	if (lxc_safe_int(value, &lxc_conf->autodevtmpfssize) < 0)
		lxc_conf->autodevtmpfssize = 500000;

	return 0;
}

static int set_config_signal_halt(const char *key, const char *value,
				 struct lxc_conf *lxc_conf, void *data)
{
	int sig_n;

	if (lxc_config_value_empty(value)) {
		lxc_conf->haltsignal = 0;
		return 0;
	}

	sig_n = sig_parse(value);
	if (sig_n < 0)
		return ret_errno(EINVAL);

	lxc_conf->haltsignal = sig_n;

	return 0;
}

static int set_config_signal_reboot(const char *key, const char *value,
				   struct lxc_conf *lxc_conf, void *data)
{
	int sig_n;

	if (lxc_config_value_empty(value)) {
		lxc_conf->rebootsignal = 0;
		return 0;
	}

	sig_n = sig_parse(value);
	if (sig_n < 0)
		return ret_errno(EINVAL);

	lxc_conf->rebootsignal = sig_n;

	return 0;
}

static int set_config_signal_stop(const char *key, const char *value,
				 struct lxc_conf *lxc_conf, void *data)
{
	int sig_n;

	if (lxc_config_value_empty(value)) {
		lxc_conf->stopsignal = 0;
		return 0;
	}

	sig_n = sig_parse(value);
	if (sig_n < 0)
		return ret_errno(EINVAL);

	lxc_conf->stopsignal = sig_n;

	return 0;
}

static int __set_config_cgroup_controller(const char *key, const char *value,
					  struct lxc_conf *lxc_conf, int version)
{
	__do_free struct lxc_list *cglist = NULL;
	call_cleaner(free_lxc_cgroup) struct lxc_cgroup *cgelem = NULL;
	const char *subkey, *token;
	size_t token_len;

	if (lxc_config_value_empty(value))
		return lxc_clear_cgroups(lxc_conf, key, version);

	if (version == CGROUP2_SUPER_MAGIC) {
		token = "lxc.cgroup2.";
		token_len = 12;
	} else if (version == CGROUP_SUPER_MAGIC) {
		token = "lxc.cgroup.";
		token_len = 11;
	} else {
		return ret_errno(EINVAL);
	}

	if (!strnequal(key, token, token_len))
		return ret_errno(EINVAL);

	subkey = key + token_len;
	if (*subkey == '\0')
		return ret_errno(EINVAL);

	cglist = lxc_list_new();
	if (!cglist)
		return ret_errno(ENOMEM);

	cgelem = zalloc(sizeof(*cgelem));
	if (!cgelem)
		return ret_errno(ENOMEM);

	cgelem->subsystem = strdup(subkey);
	if (!cgelem->subsystem)
		return ret_errno(ENOMEM);

	cgelem->value = strdup(value);
	if (!cgelem->value)
		return ret_errno(ENOMEM);

	cgelem->version = version;

	lxc_list_add_elem(cglist, move_ptr(cgelem));

	if (version == CGROUP2_SUPER_MAGIC)
		lxc_list_add_tail(&lxc_conf->cgroup2, cglist);
	else
		lxc_list_add_tail(&lxc_conf->cgroup, cglist);
	move_ptr(cglist);

	return 0;
}

static int set_config_cgroup_controller(const char *key, const char *value,
					struct lxc_conf *lxc_conf, void *data)
{
	return __set_config_cgroup_controller(key, value, lxc_conf,
					      CGROUP_SUPER_MAGIC);
}

static int set_config_cgroup2_controller(const char *key, const char *value,
					 struct lxc_conf *lxc_conf, void *data)
{
	return __set_config_cgroup_controller(key, value, lxc_conf,
					      CGROUP2_SUPER_MAGIC);
}

static int set_config_cgroup_dir(const char *key, const char *value,
				 struct lxc_conf *lxc_conf, void *data)
{
	if (!strequal(key, "lxc.cgroup.dir"))
		return ret_errno(EINVAL);

	if (lxc_config_value_empty(value))
		return clr_config_cgroup_dir(key, lxc_conf, NULL);

	if (abspath(value))
		return syserror_set(-EINVAL, "%s paths may not be absolute", key);

	if (dotdot(value))
		return syserror_set(-EINVAL, "%s paths may not walk upwards via \"../\"", key);

	return set_config_path_item(&lxc_conf->cgroup_meta.dir, value);
}

static int set_config_cgroup_monitor_dir(const char *key, const char *value,
					 struct lxc_conf *lxc_conf, void *data)
{
	if (lxc_config_value_empty(value))
		return clr_config_cgroup_monitor_dir(key, lxc_conf, NULL);

	if (abspath(value))
		return syserror_set(-EINVAL, "%s paths may not be absolute", key);

	if (dotdot(value))
		return syserror_set(-EINVAL, "%s paths may not walk upwards via \"../\"", key);

	return set_config_path_item(&lxc_conf->cgroup_meta.monitor_dir, value);
}

static int set_config_cgroup_monitor_pivot_dir(const char *key, const char *value,
					 struct lxc_conf *lxc_conf, void *data)
{
	if (lxc_config_value_empty(value))
		return clr_config_cgroup_monitor_pivot_dir(key, lxc_conf, NULL);

	if (abspath(value))
		return syserror_set(-EINVAL, "%s paths may not be absolute", key);

	if (dotdot(value))
		return syserror_set(-EINVAL, "%s paths may not walk upwards via \"../\"", key);

	return set_config_path_item(&lxc_conf->cgroup_meta.monitor_pivot_dir, value);
}

static int set_config_cgroup_container_dir(const char *key, const char *value,
					   struct lxc_conf *lxc_conf,
					   void *data)
{
	if (lxc_config_value_empty(value))
		return clr_config_cgroup_container_dir(key, lxc_conf, NULL);

	if (abspath(value))
		return syserror_set(-EINVAL, "%s paths may not be absolute", key);

	if (dotdot(value))
		return syserror_set(-EINVAL, "%s paths may not walk upwards via \"../\"", key);

	return set_config_path_item(&lxc_conf->cgroup_meta.container_dir, value);
}

static int set_config_cgroup_container_inner_dir(const char *key,
						 const char *value,
						 struct lxc_conf *lxc_conf,
						 void *data)
{
	if (lxc_config_value_empty(value))
		return clr_config_cgroup_container_inner_dir(key, lxc_conf, NULL);

	if (abspath(value))
		return syserror_set(-EINVAL, "%s paths may not be absolute", key);

	if (strchr(value, '/') || strequal(value, ".") || strequal(value, ".."))
		return log_error_errno(-EINVAL, EINVAL, "lxc.cgroup.dir.container.inner must be a single directory name");

	return set_config_string_item(&lxc_conf->cgroup_meta.namespace_dir, value);
}

static int set_config_cgroup_relative(const char *key, const char *value,
				      struct lxc_conf *lxc_conf, void *data)
{
	unsigned int converted;
	int ret;

	if (lxc_config_value_empty(value))
		return clr_config_cgroup_relative(key, lxc_conf, NULL);

	ret = lxc_safe_uint(value, &converted);
	if (ret)
		return ret;

	if (converted == 1) {
		lxc_conf->cgroup_meta.relative = true;
		return 0;
	}

	if (converted == 0) {
		lxc_conf->cgroup_meta.relative = false;
		return 0;
	}

	return ret_errno(EINVAL);
}

static bool parse_limit_value(const char **value, rlim_t *res)
{
	char *endptr = NULL;

	if (strnequal(*value, "unlimited", STRLITERALLEN("unlimited"))) {
		*res = RLIM_INFINITY;
		*value += STRLITERALLEN("unlimited");
		return true;
	}

	errno = 0;
	*res = strtoull(*value, &endptr, 10);
	if (errno || !endptr)
		return false;

	*value = endptr;

	return true;
}

static int set_config_prlimit(const char *key, const char *value,
			    struct lxc_conf *lxc_conf, void *data)
{
	__do_free struct lxc_list *list = NULL;
	call_cleaner(free_lxc_limit) struct lxc_limit *elem = NULL;
	struct lxc_list *iter;
	struct rlimit limit;
	rlim_t limit_value;

	if (lxc_config_value_empty(value))
		return lxc_clear_limits(lxc_conf, key);

	if (!strnequal(key, "lxc.prlimit.", STRLITERALLEN("lxc.prlimit.")))
		return ret_errno(EINVAL);

	key += STRLITERALLEN("lxc.prlimit.");

	/* soft limit comes first in the value */
	if (!parse_limit_value(&value, &limit_value))
		return ret_errno(EINVAL);

	limit.rlim_cur = limit_value;

	/* skip spaces and a colon */
	while (isspace(*value))
		++value;

	if (*value == ':')
		++value;
	else if (*value) /* any other character is an error here */
		return ret_errno(EINVAL);

	while (isspace(*value))
		++value;

	/* optional hard limit */
	if (*value) {
		if (!parse_limit_value(&value, &limit_value))
			return ret_errno(EINVAL);

		limit.rlim_max = limit_value;

		/* check for trailing garbage */
		while (isspace(*value))
			++value;

		if (*value)
			return ret_errno(EINVAL);
	} else {
		/* a single value sets both hard and soft limit */
		limit.rlim_max = limit.rlim_cur;
	}

	/* find existing list element */
	lxc_list_for_each(iter, &lxc_conf->limits) {
		struct lxc_limit *cur = iter->elem;

		if (!strequal(key, cur->resource))
			continue;

		cur->limit = limit;
		return 0;
	}

	/* allocate list element */
	list = lxc_list_new();
	if (!list)
		return ret_errno(ENOMEM);

	elem = zalloc(sizeof(*elem));
	if (!elem)
		return ret_errno(ENOMEM);

	elem->resource = strdup(key);
	if (!elem->resource)
		return ret_errno(ENOMEM);

	elem->limit = limit;
	lxc_list_add_elem(list, move_ptr(elem));;
	lxc_list_add_tail(&lxc_conf->limits, move_ptr(list));

	return 0;
}

static int set_config_sysctl(const char *key, const char *value,
			    struct lxc_conf *lxc_conf, void *data)
{
	__do_free struct lxc_list *sysctl_list = NULL;
	call_cleaner(free_lxc_sysctl) struct lxc_sysctl *sysctl_elem = NULL;
	struct lxc_list *iter;

	if (lxc_config_value_empty(value))
		return clr_config_sysctl(key, lxc_conf, NULL);

	if (!strnequal(key, "lxc.sysctl.", STRLITERALLEN("lxc.sysctl.")))
		return -1;

	key += STRLITERALLEN("lxc.sysctl.");
	if (is_empty_string(key))
		return ret_errno(-EINVAL);

	/* find existing list element */
	lxc_list_for_each(iter, &lxc_conf->sysctls) {
		__do_free char *replace_value = NULL;
		struct lxc_sysctl *cur = iter->elem;

		if (!strequal(key, cur->key))
			continue;

		replace_value = strdup(value);
		if (!replace_value)
			return ret_errno(EINVAL);

		free(cur->value);
		cur->value = move_ptr(replace_value);

		return 0;
	}

	/* allocate list element */
	sysctl_list = lxc_list_new();
	if (!sysctl_list)
		return ret_errno(ENOMEM);

	sysctl_elem = zalloc(sizeof(*sysctl_elem));
	if (!sysctl_elem)
		return ret_errno(ENOMEM);

	sysctl_elem->key = strdup(key);
	if (!sysctl_elem->key)
		return ret_errno(ENOMEM);

	sysctl_elem->value = strdup(value);
	if (!sysctl_elem->value)
		return ret_errno(ENOMEM);

	lxc_list_add_elem(sysctl_list, move_ptr(sysctl_elem));
	lxc_list_add_tail(&lxc_conf->sysctls, move_ptr(sysctl_list));

	return 0;
}

static int set_config_proc(const char *key, const char *value,
			    struct lxc_conf *lxc_conf, void *data)
{
	__do_free struct lxc_list *proclist = NULL;
	call_cleaner(free_lxc_proc) struct lxc_proc *procelem = NULL;
	const char *subkey;

	if (lxc_config_value_empty(value))
		return clr_config_proc(key, lxc_conf, NULL);

	if (!strnequal(key, "lxc.proc.", STRLITERALLEN("lxc.proc.")))
		return -1;

	subkey = key + STRLITERALLEN("lxc.proc.");
	if (*subkey == '\0')
		return ret_errno(EINVAL);

	proclist = lxc_list_new();
	if (!proclist)
		return ret_errno(ENOMEM);

	procelem = zalloc(sizeof(*procelem));
	if (!procelem)
		return ret_errno(ENOMEM);

	procelem->filename = strdup(subkey);
	if (!procelem->filename)
		return ret_errno(ENOMEM);

	procelem->value = strdup(value);
	if (!procelem->value)
		return ret_errno(ENOMEM);

	proclist->elem = move_ptr(procelem);
	lxc_list_add_tail(&lxc_conf->procs, move_ptr(proclist));

	return 0;
}

static int set_config_idmaps(const char *key, const char *value,
			     struct lxc_conf *lxc_conf, void *data)
{
	__do_free struct lxc_list *idmaplist = NULL;
	__do_free struct id_map *idmap = NULL;
	unsigned long hostid, nsid, range;
	char type;
	int ret;

	if (lxc_config_value_empty(value))
		return lxc_clear_idmaps(lxc_conf);

	idmaplist = lxc_list_new();
	if (!idmaplist)
		return ret_errno(ENOMEM);

	idmap = zalloc(sizeof(*idmap));
	if (!idmap)
		return ret_errno(ENOMEM);

	ret = parse_idmaps(value, &type, &nsid, &hostid, &range);
	if (ret < 0)
		return log_error_errno(-EINVAL, EINVAL, "Failed to parse id mappings");

	INFO("Read uid map: type %c nsid %lu hostid %lu range %lu", type, nsid, hostid, range);
	if (type == 'u')
		idmap->idtype = ID_TYPE_UID;
	else if (type == 'g')
		idmap->idtype = ID_TYPE_GID;
	else
		return ret_errno(EINVAL);

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

	move_ptr(idmap);
	move_ptr(idmaplist);

	return 0;
}

static int set_config_mount_fstab(const char *key, const char *value,
				  struct lxc_conf *lxc_conf, void *data)
{
	if (lxc_config_value_empty(value)) {
		clr_config_mount_fstab(key, lxc_conf, NULL);
		return ret_errno(EINVAL);
	}

	return set_config_path_item(&lxc_conf->fstab, value);
}

static int set_config_mount_auto(const char *key, const char *value,
				 struct lxc_conf *lxc_conf, void *data)
{
	__do_free char *autos = NULL;
	char *token;
	int i;
	static struct {
		const char *token;
		int mask;
		int flag;
	} allowed_auto_mounts[] = {
		{ "proc",			LXC_AUTO_PROC_MASK,	LXC_AUTO_PROC_MIXED					},
		{ "proc:mixed",			LXC_AUTO_PROC_MASK,	LXC_AUTO_PROC_MIXED					},
		{ "proc:rw",			LXC_AUTO_PROC_MASK,	LXC_AUTO_PROC_RW					},
		{ "sys",			LXC_AUTO_SYS_MASK,	LXC_AUTO_SYS_MIXED					},
		{ "sys:ro",			LXC_AUTO_SYS_MASK,	LXC_AUTO_SYS_RO						},
		{ "sys:mixed",			LXC_AUTO_SYS_MASK,	LXC_AUTO_SYS_MIXED					},
		{ "sys:rw",			LXC_AUTO_SYS_MASK,	LXC_AUTO_SYS_RW						},
		{ "cgroup",			LXC_AUTO_CGROUP_MASK,	LXC_AUTO_CGROUP_NOSPEC					},
		{ "cgroup:mixed",		LXC_AUTO_CGROUP_MASK,	LXC_AUTO_CGROUP_MIXED					},
		{ "cgroup:ro",			LXC_AUTO_CGROUP_MASK,	LXC_AUTO_CGROUP_RO					},
		{ "cgroup:rw",			LXC_AUTO_CGROUP_MASK,	LXC_AUTO_CGROUP_RW					},
		{ "cgroup:force",		LXC_AUTO_CGROUP_MASK,	LXC_AUTO_CGROUP_NOSPEC | LXC_AUTO_CGROUP_FORCE		},
		{ "cgroup:mixed:force",		LXC_AUTO_CGROUP_MASK,	LXC_AUTO_CGROUP_MIXED | LXC_AUTO_CGROUP_FORCE		},
		{ "cgroup:ro:force",		LXC_AUTO_CGROUP_MASK,	LXC_AUTO_CGROUP_RO | LXC_AUTO_CGROUP_FORCE		},
		{ "cgroup:rw:force",		LXC_AUTO_CGROUP_MASK,	LXC_AUTO_CGROUP_RW | LXC_AUTO_CGROUP_FORCE		},
		{ "cgroup-full",		LXC_AUTO_CGROUP_MASK,	LXC_AUTO_CGROUP_FULL_NOSPEC				},
		{ "cgroup-full:mixed",		LXC_AUTO_CGROUP_MASK,	LXC_AUTO_CGROUP_FULL_MIXED				},
		{ "cgroup-full:ro",		LXC_AUTO_CGROUP_MASK,	LXC_AUTO_CGROUP_FULL_RO					},
		{ "cgroup-full:rw",		LXC_AUTO_CGROUP_MASK,	LXC_AUTO_CGROUP_FULL_RW					},
		{ "cgroup-full:force",		LXC_AUTO_CGROUP_MASK,	LXC_AUTO_CGROUP_FULL_NOSPEC | LXC_AUTO_CGROUP_FORCE	},
		{ "cgroup-full:mixed:force",	LXC_AUTO_CGROUP_MASK,	LXC_AUTO_CGROUP_FULL_MIXED | LXC_AUTO_CGROUP_FORCE	},
		{ "cgroup-full:ro:force",	LXC_AUTO_CGROUP_MASK,	LXC_AUTO_CGROUP_FULL_RO | LXC_AUTO_CGROUP_FORCE		},
		{ "cgroup-full:rw:force",	LXC_AUTO_CGROUP_MASK,	LXC_AUTO_CGROUP_FULL_RW | LXC_AUTO_CGROUP_FORCE		},
		{ "shmounts:",			LXC_AUTO_SHMOUNTS_MASK,	LXC_AUTO_SHMOUNTS					},
		/*
		 * For adding anything that is just a single on/off, but has no
		 * options: keep mask and flag identical and just define the
		 * enum value as an unused bit so far
		 */
		{ NULL,				0,			0							}
	};

	if (lxc_config_value_empty(value)) {
		lxc_conf->auto_mounts = 0;
		return 0;
	}

	autos = strdup(value);
	if (!autos)
		return ret_errno(ENOMEM);

	lxc_iterate_parts(token, autos, " \t") {
		bool is_shmounts = false;

		for (i = 0; allowed_auto_mounts[i].token; i++) {
			if (strequal(allowed_auto_mounts[i].token, token))
				break;

			if (strequal("shmounts:", allowed_auto_mounts[i].token) &&
			    strnequal("shmounts:", token, STRLITERALLEN("shmounts:"))) {
				is_shmounts = true;
				break;
			}
		}

		if (!allowed_auto_mounts[i].token)
			return log_error_errno(-EINVAL, EINVAL, "Invalid filesystem to automount \"%s\"", token);

		lxc_conf->auto_mounts &= ~allowed_auto_mounts[i].mask;
		lxc_conf->auto_mounts |= allowed_auto_mounts[i].flag;

		if (is_shmounts) {
			__do_free char *container_path = NULL, *host_path = NULL;
			char *val;

			val = token + STRLITERALLEN("shmounts:");
			if (*val == '\0')
				return log_error_errno(-EINVAL, EINVAL, "Failed to copy shmounts host path");

			host_path = strdup(val);
			if (!host_path)
				return log_error_errno(-EINVAL, EINVAL, "Failed to copy shmounts host path");

			val = strchr(host_path, ':');
			if (!val || *(val + 1) == '\0')
				val = "/dev/.lxc-mounts";
			else
				*val++ = '\0';

			container_path = strdup(val);
			if(!container_path)
				return log_error_errno(-EINVAL, EINVAL, "Failed to copy shmounts container path");

			free_disarm(lxc_conf->shmount.path_host);
			lxc_conf->shmount.path_host = move_ptr(host_path);

			free_disarm(lxc_conf->shmount.path_cont);
			lxc_conf->shmount.path_cont = move_ptr(container_path);
		}
	}

	return 0;
}

static int set_config_mount(const char *key, const char *value,
			    struct lxc_conf *lxc_conf, void *data)
{
	__do_free char *mntelem = NULL;
	__do_free struct lxc_list *mntlist = NULL;

	if (lxc_config_value_empty(value))
		return lxc_clear_mount_entries(lxc_conf);

	mntlist = lxc_list_new();
	if (!mntlist)
		return ret_errno(ENOMEM);

	mntelem = strdup(value);
	if (!mntelem)
		return ret_errno(ENOMEM);

	mntlist->elem = move_ptr(mntelem);
	lxc_list_add_tail(&lxc_conf->mount_list, move_ptr(mntlist));

	return 0;
}

int add_elem_to_mount_list(const char *value, struct lxc_conf *lxc_conf) {
	return set_config_mount(NULL, value, lxc_conf, NULL);
}

static int set_config_cap_keep(const char *key, const char *value,
			       struct lxc_conf *lxc_conf, void *data)
{
	__do_free char *keepcaps = NULL;
	__do_free struct lxc_list *keeplist = NULL;
	char *token;

	if (lxc_config_value_empty(value))
		return lxc_clear_config_keepcaps(lxc_conf);

	keepcaps = strdup(value);
	if (!keepcaps)
		return ret_errno(ENOMEM);

	/* In case several capability keep is specified in a single line
	 * split these caps in a single element for the list.
	 */
	lxc_iterate_parts(token, keepcaps, " \t") {
		if (strequal(token, "none"))
			lxc_clear_config_keepcaps(lxc_conf);

		keeplist = lxc_list_new();
		if (!keeplist)
			return ret_errno(ENOMEM);

		keeplist->elem = strdup(token);
		if (!keeplist->elem)
			return ret_errno(ENOMEM);

		lxc_list_add_tail(&lxc_conf->keepcaps, move_ptr(keeplist));
	}

	return 0;
}

static int set_config_cap_drop(const char *key, const char *value,
			       struct lxc_conf *lxc_conf, void *data)
{
	__do_free char *dropcaps = NULL;
	__do_free struct lxc_list *droplist = NULL;
	char *token;

	if (lxc_config_value_empty(value))
		return lxc_clear_config_caps(lxc_conf);

	dropcaps = strdup(value);
	if (!dropcaps)
		return ret_errno(ENOMEM);

	/* In case several capability drop is specified in a single line
	 * split these caps in a single element for the list.
	 */
	lxc_iterate_parts(token, dropcaps, " \t") {
		droplist = lxc_list_new();
		if (!droplist)
			return ret_errno(ENOMEM);

		droplist->elem = strdup(token);
		if (!droplist->elem)
			return ret_errno(ENOMEM);

		lxc_list_add_tail(&lxc_conf->caps, move_ptr(droplist));
	}

	return 0;
}

static int set_config_console_path(const char *key, const char *value,
				   struct lxc_conf *lxc_conf, void *data)
{
	return set_config_path_item(&lxc_conf->console.path, value);
}

static int set_config_console_rotate(const char *key, const char *value,
				     struct lxc_conf *lxc_conf, void *data)
{
	int ret;

	if (lxc_config_value_empty(value)) {
		lxc_conf->console.log_rotate = 0;
		return 0;
	}

	ret = lxc_safe_uint(value, &lxc_conf->console.log_rotate);
	if (ret)
		return ret_errno(EINVAL);

	if (lxc_conf->console.log_rotate > 1)
		return log_error_errno(-EINVAL, EINVAL, "The \"lxc.console.rotate\" config key can only be set to 0 or 1");

	return 0;
}

static int set_config_console_logfile(const char *key, const char *value,
				      struct lxc_conf *lxc_conf, void *data)
{
	return set_config_path_item(&lxc_conf->console.log_path, value);
}

static int set_config_console_buffer_size(const char *key, const char *value,
					  struct lxc_conf *lxc_conf, void *data)
{
	int ret;
	long long int size;
	uint64_t buffer_size, pgsz;

	if (lxc_config_value_empty(value)) {
		lxc_conf->console.buffer_size = 0;
		return 0;
	}

	/* If the user specified "auto" the default log size is 2^17 = 128 Kib */
	if (strequal(value, "auto")) {
		lxc_conf->console.buffer_size = 1 << 17;
		return 0;
	}

	ret = parse_byte_size_string(value, &size);
	if (ret)
		return ret;

	if (size < 0)
		return ret_errno(EINVAL);

	/* must be at least a page size */
	pgsz = lxc_getpagesize();
	if ((uint64_t)size < pgsz) {
		NOTICE("Requested ringbuffer size for the console is %lld but must be at least %" PRId64 " bytes. Setting ringbuffer size to %" PRId64 " bytes",
		       size, pgsz, pgsz);
		size = pgsz;
	}

	buffer_size = lxc_find_next_power2((uint64_t)size);
	if (buffer_size == 0)
		return ret_errno(EINVAL);

	if (buffer_size != size)
		NOTICE("Passed size was not a power of 2. Rounding log size to next power of two: %" PRIu64 " bytes", buffer_size);

	lxc_conf->console.buffer_size = buffer_size;

	return 0;
}

static int set_config_console_size(const char *key, const char *value,
				   struct lxc_conf *lxc_conf, void *data)
{
	int ret;
	long long int size;
	uint64_t log_size, pgsz;

	if (lxc_config_value_empty(value)) {
		lxc_conf->console.log_size = 0;
		return 0;
	}

	/* If the user specified "auto" the default log size is 2^17 = 128 Kib */
	if (strequal(value, "auto")) {
		lxc_conf->console.log_size = 1 << 17;
		return 0;
	}

	ret = parse_byte_size_string(value, &size);
	if (ret)
		return ret_errno(EINVAL);

	if (size < 0)
		return ret_errno(EINVAL);

	/* must be at least a page size */
	pgsz = lxc_getpagesize();
	if ((uint64_t)size < pgsz) {
		NOTICE("Requested ringbuffer size for the console is %lld but must be at least %" PRId64 " bytes. Setting ringbuffer size to %" PRId64 " bytes",
		       size, pgsz, pgsz);
		size = pgsz;
	}

	log_size = lxc_find_next_power2((uint64_t)size);
	if (log_size == 0)
		return ret_errno(EINVAL);

	if (log_size != size)
		NOTICE("Passed size was not a power of 2. Rounding log size to next power of two: %" PRIu64 " bytes", log_size);

	lxc_conf->console.log_size = log_size;

	return 0;
}

/*
 * If we find a lxc.net.[i].hwaddr or lxc.network.hwaddr in the original config
 * file, we expand it in the unexpanded_config, so that after a save_config we
 * store the hwaddr for re-use.
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

	if (!lxc_config_net_is_hwaddr(line))
		return;

	/* Let config_net_hwaddr raise the error. */
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
	size_t linelen;
	size_t len = conf->unexpanded_len;

	update_hwaddr(line);

	linelen = strlen(line);
	while (conf->unexpanded_alloced <= len + linelen + 2) {
		char *tmp;

		tmp = realloc(conf->unexpanded_config, conf->unexpanded_alloced + 1024);
		if (!tmp)
			return ret_errno(EINVAL);

		if (!conf->unexpanded_config)
			*tmp = '\0';

		conf->unexpanded_config = tmp;
		conf->unexpanded_alloced += 1024;
	}

	memcpy(conf->unexpanded_config + conf->unexpanded_len, line, linelen);
	conf->unexpanded_len += linelen;
	if (line[linelen - 1] != '\n')
		conf->unexpanded_config[conf->unexpanded_len++] = '\n';
	conf->unexpanded_config[conf->unexpanded_len] = '\0';

	return 0;
}

static int do_includedir(const char *dirp, struct lxc_conf *lxc_conf)
{
	__do_closedir DIR *dir = NULL;
	struct dirent *direntp;
	int len, ret;

	dir = opendir(dirp);
	if (!dir)
		return -errno;

	while ((direntp = readdir(dir))) {
		const char *fnam;
		char path[PATH_MAX];

		fnam = direntp->d_name;
		if (strequal(fnam, "."))
			continue;

		if (strequal(fnam, ".."))
			continue;

		len = strlen(fnam);
		if (len < 6 || !strnequal(fnam + len - 5, ".conf", 5))
			continue;

		len = strnprintf(path, sizeof(path), "%s/%s", dirp, fnam);
		if (len < 0)
			return ret_errno(EIO);

		ret = lxc_config_read(path, lxc_conf, true);
		if (ret < 0)
			return ret;
	}

	return 0;
}

static int set_config_includefiles(const char *key, const char *value,
				   struct lxc_conf *lxc_conf, void *data)
{
	if (lxc_config_value_empty(value)) {
		clr_config_includefiles(key, lxc_conf, NULL);
		return 0;
	}

	if (is_dir(value))
		return do_includedir(value, lxc_conf);

	return lxc_config_read(value, lxc_conf, true);
}

static int set_config_rootfs_path(const char *key, const char *value,
				  struct lxc_conf *lxc_conf, void *data)
{
	__do_free char *dup = NULL;
	int ret;
	char *tmp;
	const char *container_path;

	if (lxc_config_value_empty(value)) {
		free(lxc_conf->rootfs.path);
		lxc_conf->rootfs.path = NULL;
		return 0;
	}

	dup = strdup(value);
	if (!dup)
		return ret_errno(ENOMEM);

	/* Split <storage type>:<container path> into <storage type> and
	 * <container path>. Set "rootfs.bdev_type" to <storage type> and
	 * "rootfs.path" to <container path>.
	 */
	tmp = strchr(dup, ':');
	if (tmp) {
		*tmp = '\0';

		ret = set_config_path_item(&lxc_conf->rootfs.bdev_type, dup);
		if (ret < 0)
			return ret_errno(ENOMEM);

		tmp++;
		container_path = tmp;
	} else {
		container_path = value;
	}

	return set_config_path_item(&lxc_conf->rootfs.path, container_path);
}

static int set_config_rootfs_managed(const char *key, const char *value,
				     struct lxc_conf *lxc_conf, void *data)
{
	return set_config_bool_item(&lxc_conf->rootfs.managed, value, true);
}

static int set_config_rootfs_mount(const char *key, const char *value,
				   struct lxc_conf *lxc_conf, void *data)
{
	return set_config_path_item(&lxc_conf->rootfs.mount, value);
}

static int set_config_rootfs_options(const char *key, const char *value,
				     struct lxc_conf *lxc_conf, void *data)
{
	__do_free char *__data = NULL, *dup = NULL, *mdata = NULL, *opts = NULL;
	struct lxc_rootfs *rootfs = &lxc_conf->rootfs;
	struct lxc_mount_options *mnt_opts = &rootfs->mnt_opts;
	int ret;

	clr_config_rootfs_options(key, lxc_conf, data);
	if (lxc_config_value_empty(value))
		return 0;

	dup = strdup(value);
	if (!dup)
		return -ENOMEM;

	ret = parse_lxc_mount_attrs(mnt_opts, dup);
	if (ret < 0)
		return ret;
	__data = mnt_opts->data;

	ret = parse_mntopts_legacy(dup, &mnt_opts->mnt_flags, &mdata);
	if (ret < 0)
		return ret_errno(EINVAL);

	ret = parse_propagationopts(dup, &mnt_opts->prop_flags);
	if (ret < 0)
		return ret_errno(EINVAL);

	ret = set_config_string_item(&opts, dup);
	if (ret < 0)
		return ret_errno(ENOMEM);

	if (mnt_opts->create_dir || mnt_opts->create_file ||
	    mnt_opts->optional || mnt_opts->relative)
		return syserror_set(-EINVAL, "Invalid LXC specifc mount option for rootfs mount");

	mnt_opts->data		= move_ptr(mdata);
	rootfs->options		= move_ptr(opts);

	return 0;
}

static int set_config_uts_name(const char *key, const char *value,
			      struct lxc_conf *lxc_conf, void *data)
{
	__do_free struct utsname *utsname = NULL;

	if (lxc_config_value_empty(value)) {
		clr_config_uts_name(key, lxc_conf, NULL);
		return 0;
	}

	utsname = zalloc(sizeof(*utsname));
	if (!utsname)
		return ret_errno(ENOMEM);

	if (strlen(value) >= sizeof(utsname->nodename))
		return ret_errno(EINVAL);

	(void)strlcpy(utsname->nodename, value, sizeof(utsname->nodename));
	free(lxc_conf->utsname);
	lxc_conf->utsname = move_ptr(utsname);

	return 0;
}

static int set_config_namespace_clone(const char *key, const char *value,
				      struct lxc_conf *lxc_conf, void *data)
{
	__do_free char *ns = NULL;
	char *token;
	int cloneflag = 0;

	if (lxc_config_value_empty(value))
		return clr_config_namespace_clone(key, lxc_conf, data);

	if (lxc_conf->ns_keep != 0)
		return log_error_errno(-EINVAL, EINVAL, "Cannot set both \"lxc.namespace.clone\" and \"lxc.namespace.keep\"");

	ns = strdup(value);
	if (!ns)
		return ret_errno(ENOMEM);

	lxc_iterate_parts(token, ns, " \t") {
		token += lxc_char_left_gc(token, strlen(token));
		token[lxc_char_right_gc(token, strlen(token))] = '\0';
		cloneflag = lxc_namespace_2_cloneflag(token);
		if (cloneflag < 0)
			return ret_errno(EINVAL);
		lxc_conf->ns_clone |= cloneflag;
	}

	return 0;
}

static int set_config_namespace_keep(const char *key, const char *value,
				     struct lxc_conf *lxc_conf, void *data)
{
	__do_free char *ns = NULL;
	char *token;
	int cloneflag = 0;

	if (lxc_config_value_empty(value))
		return clr_config_namespace_keep(key, lxc_conf, data);

	if (lxc_conf->ns_clone != 0)
		return log_error_errno(-EINVAL, EINVAL, "Cannot set both \"lxc.namespace.clone\" and \"lxc.namespace.keep\"");

	ns = strdup(value);
	if (!ns)
		return ret_errno(ENOMEM);

	lxc_iterate_parts(token, ns, " \t") {
		token += lxc_char_left_gc(token, strlen(token));
		token[lxc_char_right_gc(token, strlen(token))] = '\0';
		cloneflag = lxc_namespace_2_cloneflag(token);
		if (cloneflag < 0)
			return ret_errno(EINVAL);
		lxc_conf->ns_keep |= cloneflag;
	}

	return 0;
}

static int set_config_time_offset_boot(const char *key, const char *value,
				       struct lxc_conf *lxc_conf, void *data)
{
	int ret;
	char *unit;
	int64_t offset = 0;
	char buf[STRLITERALLEN("ms") + 1];

	if (lxc_config_value_empty(value))
		return clr_config_time_offset_boot(key, lxc_conf, data);

	ret = lxc_safe_int64_residual(value, &offset, 10, buf, sizeof(buf));
	if (ret)
		return ret;

	unit = lxc_trim_whitespace_in_place(buf);
	if (strequal(unit, "h")) {
		if (!multiply_overflow(offset, 3600, &lxc_conf->timens.s_boot))
			return ret_errno(EOVERFLOW);
	} else if (strequal(unit, "m")) {
		if (!multiply_overflow(offset, 60, &lxc_conf->timens.s_boot))
			return ret_errno(EOVERFLOW);
	} else if (strequal(unit, "s")) {
		lxc_conf->timens.s_boot = offset;
	} else if (strequal(unit, "ms")) {
		if (!multiply_overflow(offset, 1000000, &lxc_conf->timens.ns_boot))
			return ret_errno(EOVERFLOW);
	} else if (strequal(unit, "us")) {
		if (!multiply_overflow(offset, 1000, &lxc_conf->timens.ns_boot))
			return ret_errno(EOVERFLOW);
	} else if (strequal(unit, "ns")) {
		lxc_conf->timens.ns_boot = offset;
	} else {
		return ret_errno(EINVAL);
	}

	return 0;
}

static int set_config_time_offset_monotonic(const char *key, const char *value,
					    struct lxc_conf *lxc_conf, void *data)
{
	int ret;
	char *unit;
	int64_t offset = 0;
	char buf[STRLITERALLEN("ms") + 1];

	if (lxc_config_value_empty(value))
		return clr_config_time_offset_monotonic(key, lxc_conf, data);

	ret = lxc_safe_int64_residual(value, &offset, 10, buf, sizeof(buf));
	if (ret)
		return ret;

	unit = lxc_trim_whitespace_in_place(buf);
	if (strequal(unit, "h")) {
		if (!multiply_overflow(offset, 3600, &lxc_conf->timens.s_monotonic))
			return ret_errno(EOVERFLOW);
	} else if (strequal(unit, "m")) {
		if (!multiply_overflow(offset, 60, &lxc_conf->timens.s_monotonic))
			return ret_errno(EOVERFLOW);
	} else if (strequal(unit, "s")) {
		lxc_conf->timens.s_monotonic = offset;
	} else if (strequal(unit, "ms")) {
		if (!multiply_overflow(offset, 1000000, &lxc_conf->timens.ns_monotonic))
			return ret_errno(EOVERFLOW);
	} else if (strequal(unit, "us")) {
		if (!multiply_overflow(offset, 1000, &lxc_conf->timens.ns_monotonic))
			return ret_errno(EOVERFLOW);
	} else if (strequal(unit, "ns")) {
		lxc_conf->timens.ns_monotonic = offset;
	} else {
		return ret_errno(EINVAL);
	}

	return 0;
}

static int set_config_namespace_share(const char *key, const char *value,
				      struct lxc_conf *lxc_conf, void *data)
{
	int ns_idx;
	const char *namespace;

	if (lxc_config_value_empty(value))
		return clr_config_namespace_share(key, lxc_conf, data);

	namespace = key + STRLITERALLEN("lxc.namespace.share.");
	if (is_empty_string(namespace))
		return ret_errno(EINVAL);

	ns_idx = lxc_namespace_2_ns_idx(namespace);
	if (ns_idx < 0)
		return ns_idx;

	return set_config_string_item(&lxc_conf->ns_share[ns_idx], value);
}

struct parse_line_conf {
	struct lxc_conf *conf;
	bool from_include;
};

static int parse_line(char *buffer, void *data)
{
	__do_free char *linep = NULL;
	char *dot, *key, *line, *value;
	bool empty_line;
	struct lxc_config_t *config;
	int ret;
	char *dup = buffer;
	struct parse_line_conf *plc = data;

	if (!plc->conf)
		return syserror_set(-EINVAL, "Missing config");

	/* If there are newlines in the config file we should keep them. */
	empty_line = lxc_is_line_empty(dup);
	if (empty_line)
		dup = "\n";

	/* We have to dup the buffer otherwise, at the re-exec for reboot we
	 * modified the original string on the stack by replacing '=' by '\0'
	 * below.
	 */
	linep = line = strdup(dup);
	if (!line)
		return ret_errno(ENOMEM);

	if (!plc->from_include) {
		ret = append_unexp_config_line(line, plc->conf);
		if (ret < 0)
			return ret;
	}

	if (empty_line)
		return 0;

	line += lxc_char_left_gc(line, strlen(line));

	/* ignore comments */
	if (line[0] == '#')
		return 0;

	/* martian option - don't add it to the config itself */
	if (!strnequal(line, "lxc.", 4))
		return 0;

	dot = strchr(line, '=');
	if (!dot)
		return log_error_errno(-EINVAL, EINVAL, "Invalid configuration line: %s", line);

	*dot = '\0';
	value = dot + 1;

	key = line;
	key[lxc_char_right_gc(key, strlen(key))] = '\0';

	value += lxc_char_left_gc(value, strlen(value));
	value[lxc_char_right_gc(value, strlen(value))] = '\0';

	if (*value == '\'' || *value == '\"') {
		size_t len;

		len = strlen(value);
		if (len > 1 && value[len - 1] == *value) {
			value[len - 1] = '\0';
			value++;
		}
	}

	config = lxc_get_config(key);
	return config->set(key, value, plc->conf, NULL);
}

static struct new_config_item *parse_new_conf_line(char *buffer)
{
	__do_free char *k = NULL, *linep = NULL, *v = NULL;
	__do_free struct new_config_item *new = NULL;
	char *dup = buffer;
	char *dot, *key, *line, *value;

	if (is_empty_string(buffer))
		return log_error_errno(NULL, EINVAL, "Empty configuration line");

	linep = line = strdup(dup);
	if (!line)
		return NULL;

	line += lxc_char_left_gc(line, strlen(line));

	/* martian option - don't add it to the config itself */
	if (!strnequal(line, "lxc.", 4))
		return 0;

	dot = strchr(line, '=');
	if (!dot)
		return log_error_errno(NULL, EINVAL, "Invalid configuration line: %s", line);

	*dot = '\0';
	value = dot + 1;

	key = line;
	key[lxc_char_right_gc(key, strlen(key))] = '\0';

	value += lxc_char_left_gc(value, strlen(value));
	value[lxc_char_right_gc(value, strlen(value))] = '\0';

	if (*value == '\'' || *value == '\"') {
		size_t len;

		len = strlen(value);
		if (len > 1 && value[len - 1] == *value) {
			value[len - 1] = '\0';
			value++;
		}
	}

	new = zalloc(sizeof(struct new_config_item));
	if (!new)
		return NULL;

	k = strdup(key);
	if (!k)
		return NULL;

	v = strdup(value);
	if (!v)
		return NULL;

	new->key = move_ptr(k);
	new->val = move_ptr(v);
	return move_ptr(new);
}

int lxc_config_read(const char *file, struct lxc_conf *conf, bool from_include)
{
	struct parse_line_conf plc;

	if (!conf)
		return syserror_set(-EINVAL, "Missing config");

	plc.conf = conf;
	plc.from_include = from_include;

	/* Catch only the top level config file name in the structure. */
	if (!conf->rcfile)
		conf->rcfile = strdup(file);

	return lxc_file_for_each_line_mmap(file, parse_line, &plc);
}

int lxc_config_define_add(struct lxc_list *defines, char *arg)
{
	__do_free struct lxc_list *dent = NULL;

	dent = lxc_list_new();
	if (!dent)
		return ret_errno(ENOMEM);

	dent->elem = parse_new_conf_line(arg);
	if (!dent->elem)
		return ret_errno(ENOMEM);

	lxc_list_add_tail(defines, move_ptr(dent));

	return 0;
}

bool lxc_config_define_load(struct lxc_list *defines, struct lxc_container *c)
{
	struct lxc_list *it;
	bool bret = true;

	lxc_list_for_each(it, defines) {
		struct new_config_item *new_item = it->elem;
		bret = c->set_config_item(c, new_item->key, new_item->val);
		if (!bret)
			break;
	}

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
	lxc_config_define_free(defines);
#endif /* !FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */

	return bret;
}

void lxc_config_define_free(struct lxc_list *defines)
{
	struct lxc_list *it, *next;

	lxc_list_for_each_safe(it, defines, next) {
		struct new_config_item *new_item = it->elem;
		free(new_item->key);
		free(new_item->val);
		lxc_list_del(it);
		free(it->elem);
		free(it);
	}
}

int lxc_config_parse_arch(const char *arch, signed long *persona)
{
	static struct per_name {
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
		{ "aarch64",   PER_LINUX   },
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

	for (int i = 0; i < ARRAY_SIZE(pername); i++) {
		if (!strequal(pername[i].name, arch))
			continue;

		*persona = pername[i].per;
		return 0;
	}

	return ret_errno(EINVAL);
}

int lxc_fill_elevated_privileges(char *flaglist, int *flags)
{
	char *token;
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
		*  if none is specified.
		 */
		for (i = 0; all_privs[i].token; i++)
			*flags |= all_privs[i].flag;

		return 0;
	}

	lxc_iterate_parts(token, flaglist, "|") {
		aflag = -1;

		for (i = 0; all_privs[i].token; i++)
			if (strequal(all_privs[i].token, token))
				aflag = all_privs[i].flag;

		if (aflag < 0)
			return ret_errno(EINVAL);

		*flags |= aflag;
	}

	return 0;
}

/* Write out a configuration file. */
int write_config(int fd, const struct lxc_conf *conf)
{
	int ret;
	size_t len = conf->unexpanded_len;

	if (len == 0)
		return 0;

	ret = lxc_write_nointr(fd, conf->unexpanded_config, len);
	if (ret < 0)
		return log_error_errno(-errno, errno, "Failed to write configuration file");

	return 0;
}

bool do_append_unexp_config_line(struct lxc_conf *conf, const char *key,
				 const char *v)
{
	__do_free char *tmp = NULL;
	int ret;
	size_t len;

	len = strlen(key) + strlen(v) + 4;
	tmp = must_realloc(NULL, len);

	if (lxc_config_value_empty(v))
		ret = strnprintf(tmp, len, "%s =", key);
	else
		ret = strnprintf(tmp, len, "%s = %s", key, v);
	if (ret < 0)
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

		if (!strnequal(lstart, key, strlen(key))) {
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
	__do_free char *newdir = NULL, *olddir = NULL;
	char *lstart = conf->unexpanded_config;
	const char *key = "lxc.mount.entry";
	int ret;
	char *lend, *p, *q;
	size_t newdirlen, olddirlen;

	olddirlen = strlen(ovldir) + strlen(oldpath) + strlen(oldname) + 2;
	olddir = must_realloc(NULL, olddirlen + 1);
	ret = strnprintf(olddir, olddirlen + 1, "%s=%s/%s", ovldir, oldpath, oldname);
	if (ret < 0)
		return false;

	newdirlen = strlen(ovldir) + strlen(newpath) + strlen(newname) + 2;
	newdir = must_realloc(NULL, newdirlen + 1);
	ret = strnprintf(newdir, newdirlen + 1, "%s=%s/%s", ovldir, newpath, newname);
	if (ret < 0)
		return false;

	if (!conf->unexpanded_config)
		return true;

	while (*lstart) {
		lend = strchr(lstart, '\n');
		if (!lend)
			lend = lstart + strlen(lstart);
		else
			lend++;

		if (!strnequal(lstart, key, strlen(key)))
			goto next;

		p = strchr(lstart + strlen(key), '=');
		if (!p)
			goto next;
		p++;

		while (isblank(*p))
			p++;

		if (p >= lend)
			goto next;

		/* Whenever a lxc.mount.entry entry is found in a line we check
		*  if the substring "overlay" is present before doing any
		*  further work. We check for "overlay" because substrings need
		*  to have at least one space before them in a valid overlay
		*  lxc.mount.entry (/A B overlay).  When the space before is
		*  missing it is very likely that these substrings are part of a
		*  path or something else. (Checking q >= lend ensures that we
		*  only count matches in the current line.) */
		q = strstr(p, " overlay");
		if (!q || q >= lend)
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
			if (!new)
				return false;

			conf->unexpanded_len = newlen;
			conf->unexpanded_alloced = newlen + 1;
			new[newlen - 1] = '\0';
			lend = new + (lend - conf->unexpanded_config);

			/* Move over the remainder to make room for the newdir.
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
	__do_free char *newdir = NULL, *olddir = NULL;
	char *lstart = conf->unexpanded_config;
	const char *key = "lxc.hook";
	int ret;
	char *lend, *p;
	size_t newdirlen, olddirlen;

	olddirlen = strlen(oldpath) + strlen(oldname) + 1;
	olddir = must_realloc(NULL, olddirlen + 1);
	ret = strnprintf(olddir, olddirlen + 1, "%s/%s", oldpath, oldname);
	if (ret < 0)
		return false;

	newdirlen = strlen(newpath) + strlen(newname) + 1;
	newdir = must_realloc(NULL, newdirlen + 1);
	ret = strnprintf(newdir, newdirlen + 1, "%s/%s", newpath, newname);
	if (ret < 0)
		return false;

	if (!conf->unexpanded_config)
		return true;

	while (*lstart) {
		lend = strchr(lstart, '\n');
		if (!lend)
			lend = lstart + strlen(lstart);
		else
			lend++;

		if (!strnequal(lstart, key, strlen(key)))
			goto next;

		p = strchr(lstart + strlen(key), '=');
		if (!p)
			goto next;
		p++;

		while (isblank(*p))
			p++;

		if (p >= lend)
			goto next;

		if (!strnequal(p, olddir, strlen(olddir)))
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
			if (!new)
				return false;

			conf->unexpanded_len = newlen;
			conf->unexpanded_alloced = newlen + 1;
			new[newlen - 1] = '\0';
			lend = new + (lend - conf->unexpanded_config);

			/* Move over the remainder to make room for the newdir.
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

/* This is called only from clone.  We wish to update all hwaddrs in the
 * unexpanded config file. We can't/don't want to update any which come from
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

		if (!lxc_config_net_is_hwaddr(lstart)) {
			lstart = lend;
			continue;
		}

		p = strchr(lstart, '=');
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
		lxc_list_for_each(it, &conf->network) {
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
	int ret;

	if (lxc_config_value_empty(value)) {
		lxc_conf->ephemeral = 0;
		return 0;
	}

	ret = lxc_safe_uint(value, &lxc_conf->ephemeral);
	if (ret < 0)
		return ret;

	if (lxc_conf->ephemeral > 1)
		return ret_errno(EINVAL);

	return 0;
}

static int set_config_log_syslog(const char *key, const char *value,
			     struct lxc_conf *lxc_conf, void *data)
{
	int facility;

	if (lxc_conf->syslog)
		free_disarm(lxc_conf->syslog);

	if (lxc_config_value_empty(value))
		return 0;

	facility = lxc_syslog_priority_to_int(value);
	if (facility == -EINVAL)
		return ret_errno(EINVAL);

	lxc_log_syslog(facility);

	return set_config_string_item(&lxc_conf->syslog, value);
}

static int set_config_no_new_privs(const char *key, const char *value,
				   struct lxc_conf *lxc_conf, void *data)
{
	int ret;
	unsigned int v;

	if (lxc_config_value_empty(value)) {
		lxc_conf->no_new_privs = false;
		return 0;
	}

	ret = lxc_safe_uint(value, &v);
	if (ret < 0)
		return ret;

	if (v > 1)
		return ret_errno(EINVAL);

	lxc_conf->no_new_privs = v ? true : false;

	return 0;
}

/* Callbacks to get configuration items. */
static int get_config_personality(const char *key, char *retv, int inlen,
				  struct lxc_conf *c, void *data)
{
	int fulllen = 0;

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

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

	return fulllen;
}

static int get_config_pty_max(const char *key, char *retv, int inlen,
			      struct lxc_conf *c, void *data)
{
	return lxc_get_conf_size_t(c, retv, inlen, c->pty_max);
}

static int get_config_tty_max(const char *key, char *retv, int inlen,
			      struct lxc_conf *c, void *data)
{
	return lxc_get_conf_size_t(c, retv, inlen, c->ttys.max);
}

static int get_config_tty_dir(const char *key, char *retv, int inlen,
			     struct lxc_conf *c, void *data)
{
	return lxc_get_conf_str(retv, inlen, c->ttys.dir);
}

static int get_config_apparmor_profile(const char *key, char *retv, int inlen,
				       struct lxc_conf *c, void *data)
{
#if HAVE_APPARMOR
	return lxc_get_conf_str(retv, inlen, c->lsm_aa_profile);
#else
	return syserror_set(-EINVAL, "Built without AppArmor support");
#endif
}

static int get_config_apparmor_allow_incomplete(const char *key, char *retv,
						int inlen, struct lxc_conf *c,
						void *data)
{
#if HAVE_APPARMOR
	return lxc_get_conf_int(c, retv, inlen, c->lsm_aa_allow_incomplete);
#else
	return syserror_set(-EINVAL, "Built without AppArmor support");
#endif
}

static int get_config_apparmor_allow_nesting(const char *key, char *retv,
					     int inlen, struct lxc_conf *c,
					     void *data)
{
#if HAVE_APPARMOR
	return lxc_get_conf_int(c, retv, inlen, c->lsm_aa_allow_nesting);
#else
	return syserror_set(-EINVAL, "Built without AppArmor support");
#endif
}

static int get_config_apparmor_raw(const char *key, char *retv,
				   int inlen, struct lxc_conf *c,
				   void *data)
{
#if HAVE_APPARMOR
	int len;
	struct lxc_list *it;
	int fulllen = 0;

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	lxc_list_for_each(it, &c->lsm_aa_raw) {
		strprint(retv, inlen, "%s\n", (char *)it->elem);
	}

	return fulllen;
#else
	return syserror_set(-EINVAL, "Built without AppArmor support");
#endif
}

static int get_config_selinux_context(const char *key, char *retv, int inlen,
				      struct lxc_conf *c, void *data)
{
#if HAVE_SELINUX
	return lxc_get_conf_str(retv, inlen, c->lsm_se_context);
#else
	return syserror_set(-EINVAL, "Built without SELinux support");
#endif
}

static int get_config_selinux_context_keyring(const char *key, char *retv, int inlen,
					      struct lxc_conf *c, void *data)
{
#if HAVE_SELINUX
	return lxc_get_conf_str(retv, inlen, c->lsm_se_keyring_context);
#else
	return syserror_set(-EINVAL, "Built without SELinux support");
#endif
}

static int get_config_keyring_session(const char *key, char *retv, int inlen,
				      struct lxc_conf *c, void *data)
{
	return lxc_get_conf_bool(c, retv, inlen, c->keyring_disable_session);
}


/* If you ask for a specific cgroup value, i.e. lxc.cgroup.devices.list, then
 * just the value(s) will be printed. Since there still could be more than one,
 * it is newline-separated.
 * (Maybe that's ambiguous, since some values, i.e. devices.list, will already
 * have newlines?)
 * If you ask for 'lxc.cgroup", then all cgroup entries will be printed, in
 * 'lxc.cgroup.subsystem.key = value' format.
 */
static int __get_config_cgroup_controller(const char *key, char *retv,
					  int inlen, struct lxc_conf *c,
					  int version)
{
	int len;
	size_t namespaced_token_len;
	char *global_token, *namespaced_token;
	struct lxc_list *it;
	int fulllen = 0;
	bool get_all = false;

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	if (version == CGROUP2_SUPER_MAGIC) {
		global_token = "lxc.cgroup2";
		namespaced_token = "lxc.cgroup2.";
		namespaced_token_len = STRLITERALLEN("lxc.cgroup2.");
	} else if (version == CGROUP_SUPER_MAGIC) {
		global_token = "lxc.cgroup";
		namespaced_token = "lxc.cgroup.";
		namespaced_token_len = STRLITERALLEN("lxc.cgroup.");
	} else {
		return ret_errno(EINVAL);
	}

	if (strequal(key, global_token))
		get_all = true;
	else if (strnequal(key, namespaced_token, namespaced_token_len))
		key += namespaced_token_len;
	else
		return ret_errno(EINVAL);

	lxc_list_for_each(it, &c->cgroup) {
		struct lxc_cgroup *cg = it->elem;

		if (get_all) {
			if (version != cg->version)
				continue;

			strprint(retv, inlen, "%s.%s = %s\n", global_token,
				 cg->subsystem, cg->value);
		} else if (strequal(cg->subsystem, key)) {
			strprint(retv, inlen, "%s\n", cg->value);
		}
	}

	return fulllen;
}

static int get_config_cgroup_controller(const char *key, char *retv, int inlen,
					struct lxc_conf *c, void *data)
{
	return __get_config_cgroup_controller(key, retv, inlen, c,
					      CGROUP_SUPER_MAGIC);
}

static int get_config_cgroup2_controller(const char *key, char *retv, int inlen,
					 struct lxc_conf *c, void *data)
{
	return __get_config_cgroup_controller(key, retv, inlen, c,
					      CGROUP2_SUPER_MAGIC);
}

static int get_config_cgroup_dir(const char *key, char *retv, int inlen,
				 struct lxc_conf *lxc_conf, void *data)
{
	int len;
	int fulllen = 0;

	if (!strequal(key, "lxc.cgroup.dir"))
		return ret_errno(EINVAL);

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	strprint(retv, inlen, "%s", lxc_conf->cgroup_meta.dir);

	return fulllen;
}

static int get_config_cgroup_monitor_dir(const char *key, char *retv, int inlen,
					 struct lxc_conf *lxc_conf, void *data)
{
	int len;
	int fulllen = 0;

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	strprint(retv, inlen, "%s", lxc_conf->cgroup_meta.monitor_dir);

	return fulllen;
}

static int get_config_cgroup_monitor_pivot_dir(const char *key, char *retv, int inlen,
					 struct lxc_conf *lxc_conf, void *data)
{
	int len;
	int fulllen = 0;

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	strprint(retv, inlen, "%s", lxc_conf->cgroup_meta.monitor_pivot_dir);

	return fulllen;
}

static int get_config_cgroup_container_dir(const char *key, char *retv,
					   int inlen,
					   struct lxc_conf *lxc_conf,
					   void *data)
{
	int len;
	int fulllen = 0;

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	strprint(retv, inlen, "%s", lxc_conf->cgroup_meta.container_dir);

	return fulllen;
}

static int get_config_cgroup_container_inner_dir(const char *key, char *retv,
						 int inlen,
						 struct lxc_conf *lxc_conf,
						 void *data)
{
	int len;
	int fulllen = 0;

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	strprint(retv, inlen, "%s", lxc_conf->cgroup_meta.namespace_dir);

	return fulllen;
}

static inline int get_config_cgroup_relative(const char *key, char *retv,
					     int inlen, struct lxc_conf *lxc_conf,
					     void *data)
{
	return lxc_get_conf_int(lxc_conf, retv, inlen,
				lxc_conf->cgroup_meta.relative);
}

static int get_config_idmaps(const char *key, char *retv, int inlen,
			     struct lxc_conf *c, void *data)
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
 * sizeof(uint32_t)
 * +
 * sizeof(" ")
 * +
 * sizeof(uint32_t)
 * +
 * sizeof(" ")
 * +
 * sizeof(uint32_t)
 * +
 * \0
 */
#define __LXC_IDMAP_STR_BUF (3 * INTTYPE_TO_STRLEN(uint32_t) + 3 + 1 + 1)
	char buf[__LXC_IDMAP_STR_BUF];

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	listlen = lxc_list_len(&c->id_map);
	lxc_list_for_each(it, &c->id_map) {
		struct id_map *map = it->elem;
		ret = strnprintf(buf, sizeof(buf), "%c %lu %lu %lu",
				 (map->idtype == ID_TYPE_UID) ? 'u' : 'g',
				 map->nsid, map->hostid, map->range);
		if (ret < 0)
			return ret_errno(EIO);

		strprint(retv, inlen, "%s%s", buf, (listlen-- > 1) ? "\n" : "");
	}

	return fulllen;
}

static int get_config_log_level(const char *key, char *retv, int inlen,
			       struct lxc_conf *c, void *data)
{
	const char *v;
	v = lxc_log_priority_to_string(c->loglevel);
	return lxc_get_conf_str(retv, inlen, v);
}

static int get_config_log_file(const char *key, char *retv, int inlen,
			      struct lxc_conf *c, void *data)
{
	return lxc_get_conf_str(retv, inlen, c->logfile);
}

static int get_config_mount_fstab(const char *key, char *retv, int inlen,
				  struct lxc_conf *c, void *data)
{
	return lxc_get_conf_str(retv, inlen, c->fstab);
}

static int get_config_mount_auto(const char *key, char *retv, int inlen,
				 struct lxc_conf *c, void *data)
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
			    struct lxc_conf *c, void *data)
{
	int len, fulllen = 0;
	struct lxc_list *it;

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	lxc_list_for_each(it, &c->mount_list) {
		strprint(retv, inlen, "%s\n", (char *)it->elem);
	}

	return fulllen;
}

static int get_config_rootfs_path(const char *key, char *retv, int inlen,
				  struct lxc_conf *c, void *data)
{
	return lxc_get_conf_str(retv, inlen, c->rootfs.path);
}

static int get_config_rootfs_managed(const char *key, char *retv, int inlen,
				     struct lxc_conf *c, void *data)
{
	return lxc_get_conf_bool(c, retv, inlen, c->rootfs.managed);
}

static int get_config_rootfs_mount(const char *key, char *retv, int inlen,
				   struct lxc_conf *c, void *data)
{
	return lxc_get_conf_str(retv, inlen, c->rootfs.mount);
}

static int get_config_rootfs_options(const char *key, char *retv, int inlen,
				     struct lxc_conf *c, void *data)
{
	return lxc_get_conf_str(retv, inlen, c->rootfs.options);
}

static int get_config_uts_name(const char *key, char *retv, int inlen,
			      struct lxc_conf *c, void *data)
{
	return lxc_get_conf_str(
	    retv, inlen,
	    c->utsname ? c->utsname->nodename : NULL);
}

static int get_config_hooks(const char *key, char *retv, int inlen,
			    struct lxc_conf *c, void *data)
{
	char *subkey;
	int len, fulllen = 0, found = -1;
	struct lxc_list *it;
	int i;

	subkey = strchr(key, '.');
	if (!subkey)
		return ret_errno(EINVAL);

	subkey = strchr(subkey + 1, '.');
	if (!subkey)
		return ret_errno(EINVAL);
	subkey++;
	if (*subkey == '\0')
		return ret_errno(EINVAL);

	for (i = 0; i < NUM_LXC_HOOKS; i++) {
		if (strequal(lxchook_names[i], subkey)) {
			found = i;
			break;
		}
	}

	if (found == -1)
		return ret_errno(EINVAL);

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	lxc_list_for_each(it, &c->hooks[found]) {
		strprint(retv, inlen, "%s\n", (char *)it->elem);
	}

	return fulllen;
}

static int get_config_hooks_version(const char *key, char *retv, int inlen,
				    struct lxc_conf *c, void *data)
{
	return lxc_get_conf_int(c, retv, inlen, c->hooks_version);
}

static int get_config_net(const char *key, char *retv, int inlen,
			  struct lxc_conf *c, void *data)
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

static int get_config_cap_drop(const char *key, char *retv, int inlen,
			       struct lxc_conf *c, void *data)
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
			       struct lxc_conf *c, void *data)
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

static int get_config_console_path(const char *key, char *retv, int inlen,
				   struct lxc_conf *c, void *data)
{
	return lxc_get_conf_str(retv, inlen, c->console.path);
}

static int get_config_console_logfile(const char *key, char *retv, int inlen,
				      struct lxc_conf *c, void *data)
{
	return lxc_get_conf_str(retv, inlen, c->console.log_path);
}

static int get_config_console_rotate(const char *key, char *retv, int inlen,
				     struct lxc_conf *c, void *data)
{
	return lxc_get_conf_int(c, retv, inlen, c->console.log_rotate);
}


static int get_config_console_buffer_size(const char *key, char *retv,
					  int inlen, struct lxc_conf *c,
					  void *data)
{
	return lxc_get_conf_uint64(c, retv, inlen, c->console.buffer_size);
}

static int get_config_console_size(const char *key, char *retv, int inlen,
				   struct lxc_conf *c, void *data)
{
	return lxc_get_conf_uint64(c, retv, inlen, c->console.log_size);
}

static int get_config_seccomp_allow_nesting(const char *key, char *retv,
					    int inlen, struct lxc_conf *c,
					    void *data)
{
#ifdef HAVE_SECCOMP
	return lxc_get_conf_int(c, retv, inlen, c->seccomp.allow_nesting);
#else
	return ret_errno(ENOSYS);
#endif
}

static int get_config_seccomp_notify_cookie(const char *key, char *retv, int inlen,
					    struct lxc_conf *c, void *data)
{
#ifdef HAVE_SECCOMP_NOTIFY
	return lxc_get_conf_str(retv, inlen, c->seccomp.notifier.cookie);
#else
	return ret_errno(ENOSYS);
#endif
}

static int get_config_seccomp_notify_proxy(const char *key, char *retv, int inlen,
					   struct lxc_conf *c, void *data)
{
#ifdef HAVE_SECCOMP_NOTIFY
	return lxc_get_conf_str(retv, inlen,
				(c->seccomp.notifier.proxy_addr.sun_path[0]) == '/'
				    ? &c->seccomp.notifier.proxy_addr.sun_path[0]
				    : &c->seccomp.notifier.proxy_addr.sun_path[1]);
#else
	return ret_errno(ENOSYS);
#endif
}

static int get_config_seccomp_profile(const char *key, char *retv, int inlen,
				      struct lxc_conf *c, void *data)
{
	return lxc_get_conf_str(retv, inlen, c->seccomp.seccomp);
}

static int get_config_autodev(const char *key, char *retv, int inlen,
			      struct lxc_conf *c, void *data)
{
	return lxc_get_conf_int(c, retv, inlen, c->autodev);
}

static int get_config_autodev_tmpfs_size(const char *key, char *retv, int inlen,
			      struct lxc_conf *c, void *data)
{
	return lxc_get_conf_int(c, retv, inlen, c->autodevtmpfssize);
}

static int get_config_signal_halt(const char *key, char *retv, int inlen,
				  struct lxc_conf *c, void *data)
{
	return lxc_get_conf_int(c, retv, inlen, c->haltsignal);
}

static int get_config_signal_reboot(const char *key, char *retv, int inlen,
				    struct lxc_conf *c, void *data)
{
	return lxc_get_conf_int(c, retv, inlen, c->rebootsignal);
}

static int get_config_signal_stop(const char *key, char *retv, int inlen,
				  struct lxc_conf *c, void *data)
{
	return lxc_get_conf_int(c, retv, inlen, c->stopsignal);
}

static int get_config_start(const char *key, char *retv, int inlen,
			    struct lxc_conf *c, void *data)
{
	if (strequal(key + 10, "auto"))
		return lxc_get_conf_int(c, retv, inlen, c->start_auto);
	else if (strequal(key + 10, "delay"))
		return lxc_get_conf_int(c, retv, inlen, c->start_delay);
	else if (strequal(key + 10, "order"))
		return lxc_get_conf_int(c, retv, inlen, c->start_order);

	return -1;
}

static int get_config_log_syslog(const char *key, char *retv, int inlen,
				 struct lxc_conf *c, void *data)
{
	return lxc_get_conf_str(retv, inlen, c->syslog);
}

static int get_config_monitor(const char *key, char *retv, int inlen,
			      struct lxc_conf *c, void *data)
{
	return lxc_get_conf_int(c, retv, inlen, c->monitor_unshare);
}

static int get_config_monitor_signal_pdeath(const char *key, char *retv,
					    int inlen, struct lxc_conf *c,
					    void *data)
{
	return lxc_get_conf_int(c, retv, inlen, c->monitor_signal_pdeath);
}

static int get_config_group(const char *key, char *retv, int inlen,
			    struct lxc_conf *c, void *data)
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
				  struct lxc_conf *c, void *data)
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

static int get_config_execute_cmd(const char *key, char *retv, int inlen,
			       struct lxc_conf *c, void *data)
{
	return lxc_get_conf_str(retv, inlen, c->execute_cmd);
}

static int get_config_init_cmd(const char *key, char *retv, int inlen,
			       struct lxc_conf *c, void *data)
{
	return lxc_get_conf_str(retv, inlen, c->init_cmd);
}

static int get_config_init_cwd(const char *key, char *retv, int inlen,
			       struct lxc_conf *c, void *data)
{
	return lxc_get_conf_str(retv, inlen, c->init_cwd);
}

static int get_config_init_uid(const char *key, char *retv, int inlen,
			       struct lxc_conf *c, void *data)
{
	return lxc_get_conf_int(c, retv, inlen, c->init_uid);
}

static int get_config_init_gid(const char *key, char *retv, int inlen,
			       struct lxc_conf *c, void *data)
{
	return lxc_get_conf_int(c, retv, inlen, c->init_gid);
}

static int get_config_init_groups(const char *key, char *retv, int inlen,
				  struct lxc_conf *c, void *data)
{
	int fulllen = 0, len;

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	if (c->init_groups.size == 0)
		return 0;

	for (int i = 0; i < c->init_groups.size; i++)
		strprint(retv, inlen, "%s%d", (i > 0) ? "," : "",
			 c->init_groups.list[i]);

	return fulllen;
}

static int get_config_ephemeral(const char *key, char *retv, int inlen,
				struct lxc_conf *c, void *data)
{
	return lxc_get_conf_int(c, retv, inlen, c->ephemeral);
}

static int get_config_no_new_privs(const char *key, char *retv, int inlen,
				   struct lxc_conf *c, void *data)
{
	return lxc_get_conf_int(c, retv, inlen, c->no_new_privs);
}

/* If you ask for a specific value, i.e. lxc.prlimit.nofile, then just the value
 * will be printed. If you ask for 'lxc.prlimit', then all limit entries will be
 * printed, in 'lxc.prlimit.resource = value' format.
 */
static int get_config_prlimit(const char *key, char *retv, int inlen,
			      struct lxc_conf *c, void *data)
{
	int fulllen = 0, len;
	bool get_all = false;
	struct lxc_list *it;

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	if (strequal(key, "lxc.prlimit"))
		get_all = true;
	else if (strnequal(key, "lxc.prlimit.", 12))
		key += 12;
	else
		return ret_errno(EINVAL);

	lxc_list_for_each(it, &c->limits) {
		/* 2 colon separated 64 bit integers or the word 'unlimited' */
		char buf[INTTYPE_TO_STRLEN(uint64_t) * 2 + 2];
		int partlen;
		struct lxc_limit *lim = it->elem;

		if (lim->limit.rlim_cur == RLIM_INFINITY) {
			memcpy(buf, "unlimited", STRLITERALLEN("unlimited") + 1);
			partlen = STRLITERALLEN("unlimited");
		} else {
			partlen = sprintf(buf, "%" PRIu64,
					  (uint64_t)lim->limit.rlim_cur);
		}

		if (lim->limit.rlim_cur != lim->limit.rlim_max) {
			if (lim->limit.rlim_max == RLIM_INFINITY)
				memcpy(buf + partlen, ":unlimited",
				       STRLITERALLEN(":unlimited") + 1);
			else
				sprintf(buf + partlen, ":%" PRIu64,
					(uint64_t)lim->limit.rlim_max);
		}

		if (get_all) {
			strprint(retv, inlen, "lxc.prlimit.%s = %s\n",
				 lim->resource, buf);
		} else if (strequal(lim->resource, key)) {
			strprint(retv, inlen, "%s", buf);
		}
	}

	return fulllen;
}

/* If you ask for a specific value, i.e. lxc.sysctl.net.ipv4.ip_forward, then
 * just the value will be printed. If you ask for 'lxc.sysctl', then all sysctl
 * entries will be printed, in 'lxc.sysctl.key = value' format.
 */
static int get_config_sysctl(const char *key, char *retv, int inlen,
			     struct lxc_conf *c, void *data)
{
	int len;
	struct lxc_list *it;
	int fulllen = 0;
	bool get_all = false;

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	if (strequal(key, "lxc.sysctl"))
		get_all = true;
	else if (strnequal(key, "lxc.sysctl.", STRLITERALLEN("lxc.sysctl.")))
		key += STRLITERALLEN("lxc.sysctl.");
	else
		return ret_errno(EINVAL);

	lxc_list_for_each(it, &c->sysctls) {
		struct lxc_sysctl *elem = it->elem;
		if (get_all) {
			strprint(retv, inlen, "lxc.sysctl.%s = %s\n", elem->key,
				 elem->value);
		} else if (strequal(elem->key, key)) {
			strprint(retv, inlen, "%s", elem->value);
		}
	}

	return fulllen;
}

static int get_config_proc(const char *key, char *retv, int inlen,
			   struct lxc_conf *c, void *data)
{
	struct lxc_list *it;
	int len;
	int fulllen = 0;
	bool get_all = false;

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	if (strequal(key, "lxc.proc"))
		get_all = true;
	else if (strnequal(key, "lxc.proc.", STRLITERALLEN("lxc.proc.")))
		key += STRLITERALLEN("lxc.proc.");
	else
		return ret_errno(EINVAL);

	lxc_list_for_each(it, &c->procs) {
		struct lxc_proc *proc = it->elem;

		if (get_all) {
			strprint(retv, inlen, "lxc.proc.%s = %s\n",
			         proc->filename, proc->value);
		} else if (strequal(proc->filename, key)) {
			strprint(retv, inlen, "%s", proc->value);
		}
	}

	return fulllen;
}

static int get_config_namespace_clone(const char *key, char *retv, int inlen,
				      struct lxc_conf *c, void *data)
{
	int i, len;
	int fulllen = 0;

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	for (i = 0; i < LXC_NS_MAX; i++) {
		if (c->ns_clone & ns_info[i].clone_flag)
			strprint(retv, inlen, "%s\n", ns_info[i].proc_name);
	}

	return fulllen;
}

static int get_config_namespace_keep(const char *key, char *retv, int inlen,
				     struct lxc_conf *c, void *data)
{
	int i, len;
	int fulllen = 0;

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	for (i = 0; i < LXC_NS_MAX; i++) {
		if (c->ns_keep & ns_info[i].clone_flag)
			strprint(retv, inlen, "%s\n", ns_info[i].proc_name);
	}

	return fulllen;
}

static int get_config_time_offset_boot(const char *key, char *retv, int inlen, struct lxc_conf *c,
				       void *data)
{
	int len;
	int fulllen = 0;

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	if (c->timens.s_boot) {
		strprint(retv, inlen, "%" PRId64 " s\n", c->timens.s_boot);
	} else {
		strprint(retv, inlen, "%" PRId64 " ns\n", c->timens.ns_boot);
	}

	return fulllen;
}

static int get_config_time_offset_monotonic(const char *key, char *retv, int inlen,
					    struct lxc_conf *c, void *data)
{
	int len;
	int fulllen = 0;

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	if (c->timens.s_monotonic) {
		strprint(retv, inlen, "%" PRId64 "s\n", c->timens.s_monotonic);
	} else {
		strprint(retv, inlen, "%" PRId64 "ns\n", c->timens.ns_monotonic);
	}

	return fulllen;
}

static int get_config_namespace_share(const char *key, char *retv, int inlen,
				      struct lxc_conf *c, void *data)
{
	int len, ns_idx;
	const char *namespace;
	int fulllen = 0;

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	namespace = key + STRLITERALLEN("lxc.namespace.share.");
	if (is_empty_string(namespace))
		return ret_errno(EINVAL);

	ns_idx = lxc_namespace_2_ns_idx(namespace);
	if (ns_idx < 0)
		return ns_idx;

	strprint(retv, inlen, "%s", c->ns_share[ns_idx]);

	return fulllen;
}

/* Callbacks to clear config items. */
static inline int clr_config_personality(const char *key, struct lxc_conf *c,
					 void *data)
{
	c->personality = -1;
	return 0;
}

static inline int clr_config_pty_max(const char *key, struct lxc_conf *c,
				     void *data)
{
	c->pty_max = 0;
	return 0;
}

static inline int clr_config_tty_max(const char *key, struct lxc_conf *c,
				     void *data)
{
	c->ttys.tty = 0;
	return 0;
}

static inline int clr_config_tty_dir(const char *key, struct lxc_conf *c,
				    void *data)
{
	free_disarm(c->ttys.dir);
	return 0;
}

static inline int clr_config_apparmor_profile(const char *key,
					      struct lxc_conf *c, void *data)
{
#if HAVE_APPARMOR
	free_disarm(c->lsm_aa_profile);
	return 0;
#else
	return syserror_set(-EINVAL, "Built without AppArmor support");
#endif
}

static inline int clr_config_apparmor_allow_incomplete(const char *key,
						       struct lxc_conf *c,
						       void *data)
{
#if HAVE_APPARMOR
	c->lsm_aa_allow_incomplete = 0;
	return 0;
#else
	return syserror_set(-EINVAL, "Built without AppArmor support");
#endif
}

static inline int clr_config_apparmor_allow_nesting(const char *key,
						    struct lxc_conf *c,
						    void *data)
{
#if HAVE_APPARMOR
	c->lsm_aa_allow_nesting = 0;
	return 0;
#else
	return syserror_set(-EINVAL, "Built without AppArmor support");
#endif
}

static inline int clr_config_apparmor_raw(const char *key,
					  struct lxc_conf *c,
					  void *data)
{
#if HAVE_APPARMOR
	return lxc_clear_apparmor_raw(c);
#else
	return syserror_set(-EINVAL, "Built without AppArmor support");
#endif
}

static inline int clr_config_selinux_context(const char *key,
					     struct lxc_conf *c, void *data)
{
#if HAVE_SELINUX
	free_disarm(c->lsm_se_context);
	return 0;
#else
	return syserror_set(-EINVAL, "Built without SELinux support");
#endif
}

static inline int clr_config_selinux_context_keyring(const char *key,
						     struct lxc_conf *c, void *data)
{
#if HAVE_SELINUX
	free_disarm(c->lsm_se_keyring_context);
	return 0;
#else
	return syserror_set(-EINVAL, "Built without SELinux support");
#endif
}

static inline int clr_config_keyring_session(const char *key,
					     struct lxc_conf *c, void *data)
{
	c->keyring_disable_session = false;
	return 0;
}

static inline int clr_config_cgroup_controller(const char *key,
					       struct lxc_conf *c, void *data)
{
	return lxc_clear_cgroups(c, key, CGROUP_SUPER_MAGIC);
}

static inline int clr_config_cgroup2_controller(const char *key,
						struct lxc_conf *c, void *data)
{
	return lxc_clear_cgroups(c, key, CGROUP2_SUPER_MAGIC);
}

static int clr_config_cgroup_dir(const char *key, struct lxc_conf *lxc_conf,
				 void *data)
{
	if (!strequal(key, "lxc.cgroup.dir"))
		return ret_errno(EINVAL);

	if (lxc_conf->cgroup_meta.dir)
		free_disarm(lxc_conf->cgroup_meta.dir);

	return 0;
}

static int clr_config_cgroup_monitor_dir(const char *key,
					 struct lxc_conf *lxc_conf,
					 void *data)
{
	free_disarm(lxc_conf->cgroup_meta.monitor_dir);
	return 0;
}

static int clr_config_cgroup_monitor_pivot_dir(const char *key,
					 struct lxc_conf *lxc_conf,
					 void *data)
{
	free_disarm(lxc_conf->cgroup_meta.monitor_pivot_dir);
	return 0;
}

static int clr_config_cgroup_container_dir(const char *key,
					   struct lxc_conf *lxc_conf,
					   void *data)
{
	free_disarm(lxc_conf->cgroup_meta.container_dir);
	return 0;
}

static int clr_config_cgroup_container_inner_dir(const char *key,
						 struct lxc_conf *lxc_conf,
						 void *data)
{
	free_disarm(lxc_conf->cgroup_meta.namespace_dir);
	return 0;
}

static inline int clr_config_cgroup_relative(const char *key,
					     struct lxc_conf *lxc_conf,
					     void *data)
{
	lxc_conf->cgroup_meta.relative = false;
	return 0;
}

static inline int clr_config_idmaps(const char *key, struct lxc_conf *c,
				    void *data)
{
	return lxc_clear_idmaps(c);
}

static inline int clr_config_log_level(const char *key, struct lxc_conf *c,
				      void *data)
{
	c->loglevel = LXC_LOG_LEVEL_NOTSET;
	return 0;
}

static inline int clr_config_log_file(const char *key, struct lxc_conf *c,
				     void *data)
{
	free_disarm(c->logfile);
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

static inline int clr_config_mount_fstab(const char *key, struct lxc_conf *c,
					 void *data)
{
	free_disarm(c->fstab);
	return 0;
}

static inline int clr_config_rootfs_path(const char *key, struct lxc_conf *c,
					 void *data)
{
	free_disarm(c->rootfs.path);
	return 0;
}

static inline int clr_config_rootfs_managed(const char *key, struct lxc_conf *c,
					    void *data)
{
	c->rootfs.managed = true;
	return 0;
}

static inline int clr_config_rootfs_mount(const char *key, struct lxc_conf *c,
					  void *data)
{
	free_disarm(c->rootfs.mount);
	return 0;
}

static inline int clr_config_rootfs_options(const char *key, struct lxc_conf *c,
					    void *data)
{
	free_disarm(c->rootfs.options);
	put_lxc_mount_options(&c->rootfs.mnt_opts);

	return 0;
}

static inline int clr_config_uts_name(const char *key, struct lxc_conf *c,
				     void *data)
{
	free_disarm(c->utsname);
	return 0;
}

static inline int clr_config_hooks(const char *key, struct lxc_conf *c,
				   void *data)
{
	return lxc_clear_hooks(c, key);
}

static inline int clr_config_hooks_version(const char *key, struct lxc_conf *c,
					   void *data)
{
	/* default to legacy hooks version */
	c->hooks_version = 0;
	return 0;
}

static inline int clr_config_net(const char *key, struct lxc_conf *c,
				 void *data)
{
	lxc_free_networks(&c->network);

	return 0;
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

static inline int clr_config_console_path(const char *key, struct lxc_conf *c,
					  void *data)
{
	free_disarm(c->console.path);
	return 0;
}

static inline int clr_config_console_logfile(const char *key,
					     struct lxc_conf *c, void *data)
{
	free_disarm(c->console.log_path);
	return 0;
}

static inline int clr_config_console_rotate(const char *key, struct lxc_conf *c,
					    void *data)
{
	c->console.log_rotate = 0;
	return 0;
}

static inline int clr_config_console_buffer_size(const char *key,
						 struct lxc_conf *c, void *data)
{
	c->console.buffer_size = 0;
	return 0;
}

static inline int clr_config_console_size(const char *key, struct lxc_conf *c,
					  void *data)
{
	c->console.log_size = 0;
	return 0;
}

static inline int clr_config_seccomp_allow_nesting(const char *key,
						   struct lxc_conf *c, void *data)
{
#ifdef HAVE_SECCOMP
	c->seccomp.allow_nesting = 0;
	return 0;
#else
	return ret_errno(ENOSYS);
#endif
}

static inline int clr_config_seccomp_notify_cookie(const char *key,
						   struct lxc_conf *c, void *data)
{
#ifdef HAVE_SECCOMP_NOTIFY
	free_disarm(c->seccomp.notifier.cookie);
	return 0;
#else
	return ret_errno(ENOSYS);
#endif
}

static inline int clr_config_seccomp_notify_proxy(const char *key,
						   struct lxc_conf *c, void *data)
{
#ifdef HAVE_SECCOMP_NOTIFY
	memset(&c->seccomp.notifier.proxy_addr, 0,
	       sizeof(c->seccomp.notifier.proxy_addr));
	return 0;
#else
	return ret_errno(ENOSYS);
#endif
}

static inline int clr_config_seccomp_profile(const char *key,
					     struct lxc_conf *c, void *data)
{
	free_disarm(c->seccomp.seccomp);
	return 0;
}

static inline int clr_config_autodev(const char *key, struct lxc_conf *c,
				     void *data)
{
	c->autodev = 1;
	return 0;
}

static inline int clr_config_autodev_tmpfs_size(const char *key, struct lxc_conf *c,
				     void *data)
{
	c->autodevtmpfssize = 500000;
	return 0;
}

static inline int clr_config_signal_halt(const char *key, struct lxc_conf *c,
					void *data)
{
	c->haltsignal = 0;
	return 0;
}

static inline int clr_config_signal_reboot(const char *key, struct lxc_conf *c,
					  void *data)
{
	c->rebootsignal = 0;
	return 0;
}

static inline int clr_config_signal_stop(const char *key, struct lxc_conf *c,
					void *data)
{
	c->stopsignal = 0;
	return 0;
}

static inline int clr_config_start(const char *key, struct lxc_conf *c,
				   void *data)
{
	if (strequal(key + 10, "auto"))
		c->start_auto = 0;
	else if (strequal(key + 10, "delay"))
		c->start_delay = 0;
	else if (strequal(key + 10, "order"))
		c->start_order = 0;

	return 0;
}

static inline int clr_config_log_syslog(const char *key, struct lxc_conf *c,
				    void *data)
{
	free_disarm(c->syslog);
	return 0;
}

static inline int clr_config_monitor(const char *key, struct lxc_conf *c,
				     void *data)
{
	c->monitor_unshare = 0;
	return 0;
}

static inline int clr_config_monitor_signal_pdeath(const char *key,
						   struct lxc_conf *c, void *data)
{
	c->monitor_signal_pdeath = 0;
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

static inline int clr_config_execute_cmd(const char *key, struct lxc_conf *c,
				      void *data)
{
	free_disarm(c->execute_cmd);
	return 0;
}

static inline int clr_config_init_cmd(const char *key, struct lxc_conf *c,
				      void *data)
{
	free_disarm(c->init_cmd);
	return 0;
}

static inline int clr_config_init_cwd(const char *key, struct lxc_conf *c,
				      void *data)
{
	free_disarm(c->init_cwd);
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

static inline int clr_config_init_groups(const char *key, struct lxc_conf *c,
					 void *data)
{
	c->init_groups.size = 0;
	free_disarm(c->init_groups.list);
	return 0;
}

static inline int clr_config_ephemeral(const char *key, struct lxc_conf *c,
				       void *data)
{
	c->ephemeral = 0;
	return 0;
}

static inline int clr_config_no_new_privs(const char *key, struct lxc_conf *c,
					  void *data)
{
	c->no_new_privs = false;
	return 0;
}

static inline int clr_config_prlimit(const char *key, struct lxc_conf *c,
				   void *data)
{
	return lxc_clear_limits(c, key);
}

static inline int clr_config_sysctl(const char *key, struct lxc_conf *c,
				   void *data)
{
	return lxc_clear_sysctls(c, key);
}

static inline int clr_config_proc(const char *key, struct lxc_conf *c,
				   void *data)
{
	return lxc_clear_procs(c, key);
}

static inline int clr_config_includefiles(const char *key, struct lxc_conf *c,
					  void *data)
{
	lxc_clear_includes(c);
	return 0;
}

static int clr_config_namespace_clone(const char *key,
				      struct lxc_conf *lxc_conf, void *data)
{
	lxc_conf->ns_clone = 0;
	return 0;
}

static int clr_config_namespace_keep(const char *key, struct lxc_conf *lxc_conf,
				     void *data)
{
	lxc_conf->ns_keep = 0;
	return 0;
}

static int clr_config_time_offset_boot(const char *key, struct lxc_conf *lxc_conf, void *data)
{
	lxc_conf->timens.s_boot = 0;
	lxc_conf->timens.ns_boot = 0;
	return 0;
}

static int clr_config_time_offset_monotonic(const char *key, struct lxc_conf *lxc_conf, void *data)
{
	lxc_conf->timens.s_monotonic = 0;
	lxc_conf->timens.ns_monotonic = 0;
	return 0;
}

static int clr_config_namespace_share(const char *key,
				      struct lxc_conf *lxc_conf, void *data)
{
	int ns_idx;
	const char *namespace;

	namespace = key + STRLITERALLEN("lxc.namespace.share.");
	if (is_empty_string(namespace))
		return ret_errno(EINVAL);

	ns_idx = lxc_namespace_2_ns_idx(namespace);
	if (ns_idx < 0)
		return ns_idx;

	free(lxc_conf->ns_share[ns_idx]);
	lxc_conf->ns_share[ns_idx] = NULL;

	return 0;
}

static int get_config_includefiles(const char *key, char *retv, int inlen,
				   struct lxc_conf *c, void *data)
{
	return ret_errno(ENOSYS);
}

struct config_net_info {
	char buf[NETWORK_SUBKEY_SIZE_MAX];
	const char *subkey;
	const struct lxc_config_net_t *ops;
	struct lxc_netdev *netdev;
};

static int get_network_config_ops(const char *key, struct lxc_conf *lxc_conf,
				  struct config_net_info *info, bool allocate)
{
	int ret;
	int64_t tmpidx;
	unsigned int idx;
	const char *idx_start;

	if (is_empty_string(key))
		return ret_errno(EINVAL);

	/* check that this is a sensible network key */
	if (!strnequal("lxc.net.", key, STRLITERALLEN("lxc.net.")))
		return syserror_set(-EINVAL, "Invalid network configuration key \"%s\"", key);

	/* lxc.net.<n> */
	/* beginning of index string */
	idx_start = key + STRLITERALLEN("lxc.net.");
	if (!isdigit(*idx_start))
		return syserror_set(-EINVAL, "Failed to detect digit in string \"%s\"", key + 8);

	ret = lxc_safe_int64_residual(idx_start, &tmpidx, 10, info->buf, sizeof(info->buf));
	if (ret)
		return syserror("Failed to parse network index");

	if (tmpidx < 0 || tmpidx >= INT_MAX)
		return syserror_set(-ERANGE, "Number of configured networks would overflow the counter");
	idx = (unsigned int)tmpidx;

	info->netdev = lxc_get_netdev_by_idx(lxc_conf, idx, allocate);
	if (!info->netdev)
		return ret_errno(EINVAL);

	/* Make sure subkey points to the empty string. */
	info->subkey = info->buf;
	if (is_empty_string(info->subkey))
		return ret_errno(ENOENT);

	if (info->subkey[0] != '.')
		return syserror_set(-EINVAL, "Invalid subkey");
	info->subkey++;

	/* lxc.net.<idx>.<subkey> */
	info->ops = lxc_get_config_net(info->subkey);
	if (info->ops == &unsupported_config_net_key)
		return syserror_set(-ENOENT, "Unknown network configuration key \"%s\"", key);

	return 0;
}

/* Config entry is something like "lxc.net.0.ipv4" the key 'lxc.net.' was
 * found. So we make sure next comes an integer, find the right callback (by
 * rewriting the key), and call it.
 */
static int set_config_jump_table_net(const char *key, const char *value,
				     struct lxc_conf *lxc_conf, void *data)
{
	struct config_net_info info = {};
	int ret;
	const char *idxstring;

	idxstring = key + STRLITERALLEN("lxc.net.");
	if (!isdigit(*idxstring))
		return ret_errno(EINVAL);

	if (lxc_config_value_empty(value))
		return clr_config_jump_table_net(key, lxc_conf, data);

	ret = get_network_config_ops(key, lxc_conf, &info, true);
	if (ret)
		return ret;

	return info.ops->set(info.subkey, value, lxc_conf, info.netdev);
}

static int clr_config_jump_table_net(const char *key, struct lxc_conf *lxc_conf,
				     void *data)
{
	struct config_net_info info = {};
	int ret;
	const char *idxstring;

	idxstring = key + 8;
	if (!isdigit(*idxstring))
		return ret_errno(EINVAL);

	/* The left conjunct is pretty self-explanatory. The right conjunct
	 * checks whether the two pointers are equal. If they are we know that
	 * this is not a key that is namespaced any further and so we are
	 * supposed to clear the whole network.
	 */
	if (isdigit(*idxstring) && (strrchr(key, '.') == (idxstring - 1))) {
		unsigned int rmnetdevidx;

		ret = lxc_safe_uint(idxstring, &rmnetdevidx);
		if (ret < 0)
			return ret;

		/* Remove network from network list. */
		lxc_remove_nic_by_idx(lxc_conf, rmnetdevidx);
		return 0;
	}

	ret = get_network_config_ops(key, lxc_conf, &info, false);
	if (ret)
		return ret;

	return info.ops->clr(info.subkey, lxc_conf, info.netdev);
}

static int clr_config_net_type(const char *key, struct lxc_conf *lxc_conf,
			       void *data)
{
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	lxc_clear_netdev(netdev);

	return 0;
}

static int clr_config_net_name(const char *key, struct lxc_conf *lxc_conf,
			       void *data)
{
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	netdev->name[0] = '\0';

	return 0;
}

static int clr_config_net_flags(const char *key, struct lxc_conf *lxc_conf,
				void *data)
{
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	netdev->flags = 0;

	return 0;
}

static int clr_config_net_link(const char *key, struct lxc_conf *lxc_conf,
			       void *data)
{
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	netdev->link[0] = '\0';

	return 0;
}

static int clr_config_net_l2proxy(const char *key, struct lxc_conf *lxc_conf,
			       void *data)
{
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	netdev->l2proxy = false;

	return 0;
}

static int clr_config_net_macvlan_mode(const char *key,
				       struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	if (netdev->type != LXC_NET_MACVLAN)
		return 0;

	netdev->priv.macvlan_attr.mode = -1;

	return 0;
}

static int clr_config_net_ipvlan_mode(const char *key,
				       struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	if (netdev->type != LXC_NET_IPVLAN)
		return 0;

	netdev->priv.ipvlan_attr.mode = -1;

	return 0;
}

static int clr_config_net_ipvlan_isolation(const char *key,
					   struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	if (netdev->type != LXC_NET_IPVLAN)
		return 0;

	netdev->priv.ipvlan_attr.isolation = -1;

	return 0;
}

static int clr_config_net_veth_mode(const char *key,
				       struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	if (netdev->type != LXC_NET_VETH)
		return 0;

	netdev->priv.veth_attr.mode = -1;

	return 0;
}

static int clr_config_net_veth_pair(const char *key, struct lxc_conf *lxc_conf,
				    void *data)
{
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	if (netdev->type != LXC_NET_VETH)
		return 0;

	netdev->priv.veth_attr.pair[0] = '\0';

	return 0;
}

static int clr_config_net_veth_vlan_id(const char *key, struct lxc_conf *lxc_conf,
				  void *data)
{
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	if (netdev->type != LXC_NET_VETH)
		return 0;

	netdev->priv.veth_attr.vlan_id = 0;
	netdev->priv.veth_attr.vlan_id_set = false;

	return 0;
}

static int clr_config_net_veth_vlan_tagged_id(const char *key,
				       struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_netdev *netdev = data;
	struct lxc_list *cur, *next;

	if (!netdev)
		return ret_errno(EINVAL);

	if (netdev->type != LXC_NET_VETH)
		return 0;

	lxc_list_for_each_safe(cur, &netdev->priv.veth_attr.vlan_tagged_ids, next) {
		lxc_list_del(cur);
		free(cur);
	}

	return 0;
}


static int clr_config_net_script_up(const char *key, struct lxc_conf *lxc_conf,
				    void *data)
{
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	free_disarm(netdev->upscript);

	return 0;
}

static int clr_config_net_script_down(const char *key,
				      struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	free_disarm(netdev->downscript);

	return 0;
}

static int clr_config_net_hwaddr(const char *key, struct lxc_conf *lxc_conf,
				 void *data)
{
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	free_disarm(netdev->hwaddr);

	return 0;
}

static int clr_config_net_mtu(const char *key, struct lxc_conf *lxc_conf,
			      void *data)
{
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	free_disarm(netdev->mtu);

	return 0;
}

static int clr_config_net_vlan_id(const char *key, struct lxc_conf *lxc_conf,
				  void *data)
{
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	if (netdev->type != LXC_NET_VLAN)
		return 0;

	netdev->priv.vlan_attr.vid = 0;

	return 0;
}

static int clr_config_net_ipv4_gateway(const char *key,
				       struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	free_disarm(netdev->ipv4_gateway);

	return 0;
}

static int clr_config_net_ipv4_address(const char *key,
				       struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_netdev *netdev = data;
	struct lxc_list *cur, *next;

	if (!netdev)
		return ret_errno(EINVAL);

	lxc_list_for_each_safe(cur, &netdev->ipv4, next) {
		lxc_list_del(cur);
		free(cur->elem);
		free(cur);
	}

	return 0;
}

static int clr_config_net_veth_ipv4_route(const char *key,
					  struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_netdev *netdev = data;
	struct lxc_list *cur, *next;

	if (!netdev)
		return ret_errno(EINVAL);

	if (netdev->type != LXC_NET_VETH)
		return 0;

	lxc_list_for_each_safe(cur, &netdev->priv.veth_attr.ipv4_routes, next) {
		lxc_list_del(cur);
		free(cur->elem);
		free(cur);
	}

	return 0;
}

static int clr_config_net_ipv6_gateway(const char *key,
				       struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	free_disarm(netdev->ipv6_gateway);

	return 0;
}

static int clr_config_net_ipv6_address(const char *key,
				       struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_netdev *netdev = data;
	struct lxc_list *cur, *next;

	if (!netdev)
		return ret_errno(EINVAL);

	lxc_list_for_each_safe(cur, &netdev->ipv6, next) {
		lxc_list_del(cur);
		free(cur->elem);
		free(cur);
	}

	return 0;
}

static int clr_config_net_veth_ipv6_route(const char *key,
					  struct lxc_conf *lxc_conf, void *data)
{
	struct lxc_netdev *netdev = data;
	struct lxc_list *cur, *next;

	if (!netdev)
		return ret_errno(EINVAL);

	if (netdev->type != LXC_NET_VETH)
		return 0;

	lxc_list_for_each_safe(cur, &netdev->priv.veth_attr.ipv6_routes, next) {
		lxc_list_del(cur);
		free(cur->elem);
		free(cur);
	}

	return 0;
}

static int get_config_jump_table_net(const char *key, char *retv, int inlen,
				     struct lxc_conf *c, void *data)
{
	struct config_net_info info = {};
	int ret;
	const char *idxstring;

	idxstring = key + STRLITERALLEN("lxc.net.");
	if (!isdigit(*idxstring))
		return ret_errno(EINVAL);

	ret = get_network_config_ops(key, c, &info, false);
	if (ret)
		return ret;

	return info.ops->get(info.subkey, retv, inlen, c, info.netdev);
}

static int get_config_net_type(const char *key, char *retv, int inlen,
			       struct lxc_conf *c, void *data)
{
	int len;
	int fulllen = 0;
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	strprint(retv, inlen, "%s", lxc_net_type_to_str(netdev->type));

	return fulllen;
}

static int get_config_net_flags(const char *key, char *retv, int inlen,
				struct lxc_conf *c, void *data)
{
	int len;
	int fulllen = 0;
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	if (netdev->flags & IFF_UP)
		strprint(retv, inlen, "up");

	return fulllen;
}

static int get_config_net_link(const char *key, char *retv, int inlen,
			       struct lxc_conf *c, void *data)
{
	int len;
	int fulllen = 0;
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	if (netdev->link[0] != '\0')
		strprint(retv, inlen, "%s", netdev->link);

	return fulllen;
}

static int get_config_net_l2proxy(const char *key, char *retv, int inlen,
				  struct lxc_conf *c, void *data)
{
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	return lxc_get_conf_bool(c, retv, inlen, netdev->l2proxy);
}

static int get_config_net_name(const char *key, char *retv, int inlen,
			       struct lxc_conf *c, void *data)
{
	int len;
	int fulllen = 0;
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	if (netdev->name[0] != '\0')
		strprint(retv, inlen, "%s", netdev->name);

	return fulllen;
}

static int get_config_net_macvlan_mode(const char *key, char *retv, int inlen,
				       struct lxc_conf *c, void *data)
{
	int len;
	int fulllen = 0;
	const char *mode;
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	if (netdev->type != LXC_NET_MACVLAN)
		return ret_errno(EINVAL);

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

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

	return fulllen;
}

static int get_config_net_ipvlan_mode(const char *key, char *retv, int inlen,
				       struct lxc_conf *c, void *data)
{
	int fulllen = 0;
	struct lxc_netdev *netdev = data;
	int len;
	const char *mode;

	if (!netdev)
		return ret_errno(EINVAL);

	if (netdev->type != LXC_NET_IPVLAN)
		return ret_errno(EINVAL);

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	switch (netdev->priv.ipvlan_attr.mode) {
	case IPVLAN_MODE_L3:
		mode = "l3";
		break;
	case IPVLAN_MODE_L3S:
		mode = "l3s";
		break;
	case IPVLAN_MODE_L2:
		mode = "l2";
		break;
	default:
		mode = "(invalid)";
		break;
	}

	strprint(retv, inlen, "%s", mode);

	return fulllen;
}

static int get_config_net_ipvlan_isolation(const char *key, char *retv, int inlen,
				       struct lxc_conf *c, void *data)
{
	int fulllen = 0;
	struct lxc_netdev *netdev = data;
	int len;
	const char *mode;

	if (!netdev)
		return ret_errno(EINVAL);

	if (netdev->type != LXC_NET_IPVLAN)
		return ret_errno(EINVAL);

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	switch (netdev->priv.ipvlan_attr.isolation) {
	case IPVLAN_ISOLATION_BRIDGE:
		mode = "bridge";
		break;
	case IPVLAN_ISOLATION_PRIVATE:
		mode = "private";
		break;
	case IPVLAN_ISOLATION_VEPA:
		mode = "vepa";
		break;
	default:
		mode = "(invalid)";
		break;
	}

	strprint(retv, inlen, "%s", mode);

	return fulllen;
}

static int get_config_net_veth_mode(const char *key, char *retv, int inlen,
				    struct lxc_conf *c, void *data)
{
	int fulllen = 0;
	struct lxc_netdev *netdev = data;
	int len;
	const char *mode;

	if (!netdev)
		return ret_errno(EINVAL);

	if (netdev->type != LXC_NET_VETH)
		return ret_errno(EINVAL);

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	switch (netdev->priv.veth_attr.mode) {
	case VETH_MODE_BRIDGE:
		mode = "bridge";
		break;
	case VETH_MODE_ROUTER:
		mode = "router";
		break;
	default:
		mode = "(invalid)";
		break;
	}

	strprint(retv, inlen, "%s", mode);

	return fulllen;
}

static int get_config_net_veth_pair(const char *key, char *retv, int inlen,
				    struct lxc_conf *c, void *data)
{
	int len;
	int fulllen = 0;
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	if (netdev->type != LXC_NET_VETH)
		return ret_errno(EINVAL);

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	strprint(retv, inlen, "%s",
		 netdev->priv.veth_attr.pair[0] != '\0'
		     ? netdev->priv.veth_attr.pair
		     : netdev->priv.veth_attr.veth1);

	return fulllen;
}

static int get_config_net_veth_vlan_id(const char *key, char *retv, int inlen,
				       struct lxc_conf *c, void *data)
{
	int len;
	int fulllen = 0;
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	if (netdev->type != LXC_NET_VETH)
		return ret_errno(EINVAL);

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	strprint(retv, inlen, "%d", netdev->priv.veth_attr.vlan_id);

	return fulllen;
}

static int get_config_net_veth_vlan_tagged_id(const char *key, char *retv,
					      int inlen, struct lxc_conf *c,
					      void *data)
{
	int len;
	size_t listlen;
	struct lxc_list *it;
	int fulllen = 0;
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	if (netdev->type != LXC_NET_VETH)
		return ret_errno(EINVAL);

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	listlen = lxc_list_len(&netdev->priv.veth_attr.vlan_tagged_ids);

	lxc_list_for_each(it, &netdev->priv.veth_attr.vlan_tagged_ids) {
		unsigned short i = PTR_TO_USHORT(it->elem);
		strprint(retv, inlen, "%u%s", i, (listlen-- > 1) ? "\n" : "");
	}

	return fulllen;
}

static int get_config_net_script_up(const char *key, char *retv, int inlen,
				    struct lxc_conf *c, void *data)
{
	int len;
	int fulllen = 0;
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	if (netdev->upscript)
		strprint(retv, inlen, "%s", netdev->upscript);

	return fulllen;
}

static int get_config_net_script_down(const char *key, char *retv, int inlen,
				      struct lxc_conf *c, void *data)
{
	int len;
	int fulllen = 0;
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	if (netdev->downscript)
		strprint(retv, inlen, "%s", netdev->downscript);

	return fulllen;
}

static int get_config_net_hwaddr(const char *key, char *retv, int inlen,
				 struct lxc_conf *c, void *data)
{
	int len;
	int fulllen = 0;
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	if (netdev->hwaddr)
		strprint(retv, inlen, "%s", netdev->hwaddr);

	return fulllen;
}

static int get_config_net_mtu(const char *key, char *retv, int inlen,
			      struct lxc_conf *c, void *data)
{
	int len;
	int fulllen = 0;
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	if (netdev->mtu)
		strprint(retv, inlen, "%s", netdev->mtu);

	return fulllen;
}

static int get_config_net_vlan_id(const char *key, char *retv, int inlen,
				  struct lxc_conf *c, void *data)
{
	int len;
	int fulllen = 0;
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	if (netdev->type != LXC_NET_VLAN)
		return ret_errno(EINVAL);

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	strprint(retv, inlen, "%d", netdev->priv.vlan_attr.vid);

	return fulllen;
}

static int get_config_net_ipv4_gateway(const char *key, char *retv, int inlen,
				       struct lxc_conf *c, void *data)
{
	int len;
	char buf[INET_ADDRSTRLEN];
	int fulllen = 0;
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	if (netdev->ipv4_gateway_auto) {
		strprint(retv, inlen, "auto");
	} else if (netdev->ipv4_gateway_dev) {
		strprint(retv, inlen, "dev");
	} else if (netdev->ipv4_gateway) {
		if (!inet_ntop(AF_INET, netdev->ipv4_gateway, buf, sizeof(buf)))
			return -errno;
		strprint(retv, inlen, "%s", buf);
	}

	return fulllen;
}

static int get_config_net_ipv4_address(const char *key, char *retv, int inlen,
				       struct lxc_conf *c, void *data)
{
	int len;
	size_t listlen;
	char buf[INET_ADDRSTRLEN];
	struct lxc_list *it;
	int fulllen = 0;
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	listlen = lxc_list_len(&netdev->ipv4);

	lxc_list_for_each(it, &netdev->ipv4) {
		struct lxc_inetdev *i = it->elem;
		if (!inet_ntop(AF_INET, &i->addr, buf, sizeof(buf)))
			return -errno;
		strprint(retv, inlen, "%s/%u%s", buf, i->prefix,
			 (listlen-- > 1) ? "\n" : "");
	}

	return fulllen;
}

static int get_config_net_veth_ipv4_route(const char *key, char *retv, int inlen,
					  struct lxc_conf *c, void *data)
{
	int len;
	size_t listlen;
	char buf[INET_ADDRSTRLEN];
	struct lxc_list *it;
	int fulllen = 0;
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	if (netdev->type != LXC_NET_VETH)
		return ret_errno(EINVAL);

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	listlen = lxc_list_len(&netdev->priv.veth_attr.ipv4_routes);

	lxc_list_for_each(it, &netdev->priv.veth_attr.ipv4_routes) {
		struct lxc_inetdev *i = it->elem;
		if (!inet_ntop(AF_INET, &i->addr, buf, sizeof(buf)))
			return -errno;
		strprint(retv, inlen, "%s/%u%s", buf, i->prefix,
			 (listlen-- > 1) ? "\n" : "");
	}

	return fulllen;
}

static int get_config_net_ipv6_gateway(const char *key, char *retv, int inlen,
				       struct lxc_conf *c, void *data)
{
	int len;
	char buf[INET6_ADDRSTRLEN];
	int fulllen = 0;
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	if (netdev->ipv6_gateway_auto) {
		strprint(retv, inlen, "auto");
	} else if (netdev->ipv6_gateway_dev) {
		strprint(retv, inlen, "dev");
	} else if (netdev->ipv6_gateway) {
		if (!inet_ntop(AF_INET6, netdev->ipv6_gateway, buf, sizeof(buf)))
			return -errno;
		strprint(retv, inlen, "%s", buf);
	}

	return fulllen;
}

static int get_config_net_ipv6_address(const char *key, char *retv, int inlen,
				       struct lxc_conf *c, void *data)
{
	int len;
	size_t listlen;
	char buf[INET6_ADDRSTRLEN];
	struct lxc_list *it;
	int fulllen = 0;
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	listlen = lxc_list_len(&netdev->ipv6);

	lxc_list_for_each(it, &netdev->ipv6) {
		struct lxc_inet6dev *i = it->elem;
		if (!inet_ntop(AF_INET6, &i->addr, buf, sizeof(buf)))
			return -errno;
		strprint(retv, inlen, "%s/%u%s", buf, i->prefix,
			 (listlen-- > 1) ? "\n" : "");
	}

	return fulllen;
}

static int get_config_net_veth_ipv6_route(const char *key, char *retv, int inlen,
					  struct lxc_conf *c, void *data)
{
	int len;
	size_t listlen;
	char buf[INET6_ADDRSTRLEN];
	struct lxc_list *it;
	int fulllen = 0;
	struct lxc_netdev *netdev = data;

	if (!netdev)
		return ret_errno(EINVAL);

	if (netdev->type != LXC_NET_VETH)
		return ret_errno(EINVAL);

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	listlen = lxc_list_len(&netdev->priv.veth_attr.ipv6_routes);

	lxc_list_for_each(it, &netdev->priv.veth_attr.ipv6_routes) {
		struct lxc_inet6dev *i = it->elem;
		if (!inet_ntop(AF_INET6, &i->addr, buf, sizeof(buf)))
			return -errno;
		strprint(retv, inlen, "%s/%u%s", buf, i->prefix,
			 (listlen-- > 1) ? "\n" : "");
	}

	return fulllen;
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

	for (i = 0; i < ARRAY_SIZE(config_jump_table); i++) {
		char *s = config_jump_table[i].name;

		if (s[strlen(s) - 1] == '.')
			continue;

		strprint(retv, inlen, "%s\n", s);
	}

	return fulllen;
}

int lxc_list_subkeys(struct lxc_conf *conf, const char *key, char *retv,
		     int inlen)
{
	int len;
	int fulllen = 0;

	if (!retv)
		inlen = 0;
	else
		memset(retv, 0, inlen);

	if (strequal(key, "lxc.apparmor")) {
		strprint(retv, inlen, "allow_incomplete\n");
		strprint(retv, inlen, "allow_nesting\n");
		strprint(retv, inlen, "profile\n");
		strprint(retv, inlen, "raw\n");
	} else if (strequal(key, "lxc.cgroup")) {
		strprint(retv, inlen, "dir\n");
	} else if (strequal(key, "lxc.selinux")) {
		strprint(retv, inlen, "context\n");
		strprint(retv, inlen, "context.keyring\n");
	} else if (strequal(key, "lxc.mount")) {
		strprint(retv, inlen, "auto\n");
		strprint(retv, inlen, "entry\n");
		strprint(retv, inlen, "fstab\n");
	} else if (strequal(key, "lxc.rootfs")) {
		strprint(retv, inlen, "mount\n");
		strprint(retv, inlen, "options\n");
		strprint(retv, inlen, "path\n");
	} else if (strequal(key, "lxc.uts")) {
		strprint(retv, inlen, "name\n");
	} else if (strequal(key, "lxc.hook")) {
		strprint(retv, inlen, "autodev\n");
		strprint(retv, inlen, "autodevtmpfssize\n");
		strprint(retv, inlen, "clone\n");
		strprint(retv, inlen, "destroy\n");
		strprint(retv, inlen, "mount\n");
		strprint(retv, inlen, "post-stop\n");
		strprint(retv, inlen, "pre-mount\n");
		strprint(retv, inlen, "pre-start\n");
		strprint(retv, inlen, "start-host\n");
		strprint(retv, inlen, "start\n");
		strprint(retv, inlen, "stop\n");
	} else if (strequal(key, "lxc.cap")) {
		strprint(retv, inlen, "drop\n");
		strprint(retv, inlen, "keep\n");
	} else if (strequal(key, "lxc.console")) {
		strprint(retv, inlen, "logfile\n");
		strprint(retv, inlen, "path\n");
	} else if (strequal(key, "lxc.seccomp")) {
		strprint(retv, inlen, "profile\n");
	} else if (strequal(key, "lxc.signal")) {
		strprint(retv, inlen, "halt\n");
		strprint(retv, inlen, "reboot\n");
		strprint(retv, inlen, "stop\n");
	} else if (strequal(key, "lxc.start")) {
		strprint(retv, inlen, "auto\n");
		strprint(retv, inlen, "delay\n");
		strprint(retv, inlen, "order\n");
	} else if (strequal(key, "lxc.monitor")) {
		strprint(retv, inlen, "unshare\n");
	} else if (strequal(key, "lxc.keyring")) {
		strprint(retv, inlen, "session\n");
	} else {
		fulllen = ret_errno(EINVAL);
	}

	return fulllen;
}

int lxc_list_net(struct lxc_conf *c, const char *key, char *retv, int inlen)
{
	struct config_net_info info = {};
	struct lxc_netdev *netdev;
	int len, ret;
	const char *idxstring;
	int fulllen = 0;

	idxstring = key + STRLITERALLEN("lxc.net.");
	if (!isdigit(*idxstring))
		return ret_errno(EINVAL);

	ret = get_network_config_ops(key, c, &info, false);
	if (ret) {
		if (ret != -ENOENT)
			return ret_errno(EINVAL);
	}
	netdev = info.netdev;

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
		strprint(retv, inlen, "ipv6.address\n");
		strprint(retv, inlen, "ipv6.gateway\n");
		strprint(retv, inlen, "ipv4.address\n");
		strprint(retv, inlen, "ipv4.gateway\n");
	}

	switch (netdev->type) {
	case LXC_NET_VETH:
		strprint(retv, inlen, "veth.pair\n");
		strprint(retv, inlen, "veth.ipv4.route\n");
		strprint(retv, inlen, "veth.ipv6.route\n");
		strprint(retv, inlen, "veth.vlan.id\n");
		break;
	case LXC_NET_MACVLAN:
		strprint(retv, inlen, "macvlan.mode\n");
		break;
	case LXC_NET_IPVLAN:
		strprint(retv, inlen, "ipvlan.mode\n");
		strprint(retv, inlen, "ipvlan.isolation\n");
		break;
	case LXC_NET_VLAN:
		strprint(retv, inlen, "vlan.id\n");
		break;
	case LXC_NET_PHYS:
		break;
	}

	return fulllen;
}

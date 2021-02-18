/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_CONF_H
#define __LXC_CONF_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <linux/magic.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/vfs.h>

#include "compiler.h"
#include "config.h"
#include "list.h"
#include "lxcseccomp.h"
#include "ringbuf.h"
#include "start.h"
#include "terminal.h"

#if HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#if HAVE_SCMP_FILTER_CTX
typedef void * scmp_filter_ctx;
#endif

/* worth moving to configure.ac? */
#define subuidfile "/etc/subuid"
#define subgidfile "/etc/subgid"

/*
 * Defines a generic struct to configure the control group. It is up to the
 * programmer to specify the right subsystem.
 * @subsystem : the targeted subsystem
 * @value     : the value to set
 * @version   : The version of the cgroup filesystem on which the controller
 *              resides.
 *
 * @controllers : The controllers to use for this container.
 * @dir         : The name of the directory containing the container's cgroup.
 *                Not that this is a per-container setting.
 */
struct lxc_cgroup {
	union {
		/* information about a specific controller */
		struct /* controller */ {
			int version;
			char *subsystem;
			char *value;
		};

		/* meta information about cgroup configuration */
		struct /* meta */ {
			char *controllers;
			char *dir;
			char *monitor_dir;
			char *container_dir;
			char *namespace_dir;
			bool relative;
		};
	};
};

#if !HAVE_SYS_RESOURCE_H
#define RLIM_INFINITY ((unsigned long)-1)
struct rlimit {
	unsigned long rlim_cur;
	unsigned long rlim_max;
};
#endif

/*
 * Defines a structure to configure resource limits to set via setrlimit().
 * @resource : the resource name in lowercase without the RLIMIT_ prefix
 * @limit    : the limit to set
 */
struct lxc_limit {
	char *resource;
	struct rlimit limit;
};

enum idtype {
	ID_TYPE_UID,
	ID_TYPE_GID
};

/*
 * Defines a structure to configure kernel parameters at runtime.
 * @key      : the kernel parameters will be configured without the "lxc.sysctl" prefix
 * @value    : the value to set
 */
struct lxc_sysctl {
	char *key;
	char *value;
};

/*
 * Defines a structure to configure proc filesystem at runtime.
 * @filename : the proc filesystem will be configured without the "lxc.proc" prefix
 * @value    : the value to set
 */
struct lxc_proc {
	char *filename;
	char *value;
};

/*
 * id_map is an id map entry.  Form in confile is:
 * lxc.idmap = u 0    9800 100
 * lxc.idmap = u 1000 9900 100
 * lxc.idmap = g 0    9800 100
 * lxc.idmap = g 1000 9900 100
 * meaning the container can use uids and gids 0-99 and 1000-1099,
 * with [ug]id 0 mapping to [ug]id 9800 on the host, and [ug]id 1000 to
 * [ug]id 9900 on the host.
 */
struct id_map {
	enum idtype idtype;
	unsigned long hostid, nsid, range;
};

/* Defines the number of tty configured and contains the
 * instantiated ptys
 * @max = number of configured ttys
 */
struct lxc_tty_info {
	size_t max;
	char *dir;
	char *tty_names;
	struct lxc_terminal_info *tty;
};

/* Defines a structure to store the rootfs location, the
 * optionals pivot_root, rootfs mount paths
 * @path         : the rootfs source (directory or device)
 * @mount        : where it is mounted
 * @bev_type     : optional backing store type
 * @options      : mount options
 * @mountflags   : the portion of @options that are flags
 * @data         : the portion of @options that are not flags
 * @managed      : whether it is managed by LXC
 * @mntpt_fd	 : fd for @mount
 * @dev_mntpt_fd : fd for /dev of the container
 */
struct lxc_rootfs {
	int mntpt_fd;
	int dev_mntpt_fd;
	char *path;
	char *mount;
	char *bdev_type;
	char *options;
	unsigned long mountflags;
	char *data;
	bool managed;
};

/*
 * Automatic mounts for LXC to perform inside the container
 */
enum {
	LXC_AUTO_PROC_RW              = 0x001, /* /proc read-write */
	LXC_AUTO_PROC_MIXED           = 0x002, /* /proc/sys and /proc/sysrq-trigger read-only */
	LXC_AUTO_PROC_MASK            = 0x003,

	LXC_AUTO_SYS_RW               = 0x004, /* /sys */
	LXC_AUTO_SYS_RO               = 0x008, /* /sys read-only */
	LXC_AUTO_SYS_MIXED            = 0x00C, /* /sys read-only and /sys/class/net read-write */
	LXC_AUTO_SYS_MASK             = 0x00C,

	LXC_AUTO_CGROUP_RO            = 0x010, /* /sys/fs/cgroup (partial mount, read-only) */
	LXC_AUTO_CGROUP_RW            = 0x020, /* /sys/fs/cgroup (partial mount, read-write) */
	LXC_AUTO_CGROUP_MIXED         = 0x030, /* /sys/fs/cgroup (partial mount, paths r/o, cgroup r/w) */
	LXC_AUTO_CGROUP_FULL_RO       = 0x040, /* /sys/fs/cgroup (full mount, read-only) */
	LXC_AUTO_CGROUP_FULL_RW       = 0x050, /* /sys/fs/cgroup (full mount, read-write) */
	LXC_AUTO_CGROUP_FULL_MIXED    = 0x060, /* /sys/fs/cgroup (full mount, parent r/o, own r/w) */
	/*
	 * These are defined in such a way as to retain binary compatibility
	 * with earlier versions of this code. If the previous mask is applied,
	 * both of these will default back to the _MIXED variants, which is
	 * safe.
	 */
	LXC_AUTO_CGROUP_NOSPEC        = 0x0B0, /* /sys/fs/cgroup (partial mount, r/w or mixed, depending on caps) */
	LXC_AUTO_CGROUP_FULL_NOSPEC   = 0x0E0, /* /sys/fs/cgroup (full mount, r/w or mixed, depending on caps) */
	LXC_AUTO_CGROUP_FORCE         = 0x100, /* mount cgroups even when cgroup namespaces are supported */
	LXC_AUTO_CGROUP_MASK          = 0x1F0, /* all known cgroup options, doe not contain LXC_AUTO_CGROUP_FORCE */

	LXC_AUTO_SHMOUNTS             = 0x200, /* shared mount point */
	LXC_AUTO_SHMOUNTS_MASK        = 0x200, /* shared mount point mask */
	LXC_AUTO_ALL_MASK             = 0x1FF, /* all known settings */
};

enum lxchooks {
	LXCHOOK_PRESTART,
	LXCHOOK_PREMOUNT,
	LXCHOOK_MOUNT,
	LXCHOOK_AUTODEV,
	LXCHOOK_START,
	LXCHOOK_STOP,
	LXCHOOK_POSTSTOP,
	LXCHOOK_CLONE,
	LXCHOOK_DESTROY,
	LXCHOOK_START_HOST,
	NUM_LXC_HOOKS
};

__hidden extern char *lxchook_names[NUM_LXC_HOOKS];

struct lxc_state_client {
	int clientfd;
	lxc_state_t states[MAX_STATE];
};

enum {
	LXC_BPF_DEVICE_CGROUP_LOCAL_RULE = -1,
	LXC_BPF_DEVICE_CGROUP_ALLOWLIST  =  0,
	LXC_BPF_DEVICE_CGROUP_DENYLIST  =  1,
};

struct device_item {
	char type;
	int major;
	int minor;
	char access[4];
	int allow;
	/*
	 * LXC_BPF_DEVICE_CGROUP_LOCAL_RULE -> no global rule
	 * LXC_BPF_DEVICE_CGROUP_ALLOWLIST  -> allowlist (deny all)
	 * LXC_BPF_DEVICE_CGROUP_DENYLIST   -> denylist (allow all)
	 */
	int global_rule;
};

struct timens_offsets {
	/* Currently, either s_boot or ns_boot is set, but not both. */
	int64_t s_boot;
	int64_t ns_boot;

	/* Currently, either s_monotonic or ns_monotonic is set, but not both. */
	int64_t s_monotonic;
	int64_t ns_monotonic;
};

struct lxc_conf {
	/* Pointer to the name of the container. Do not free! */
	const char *name;
	bool is_execute;
	int reboot;
	signed long personality;
	struct utsname *utsname;

	struct {
		struct lxc_list cgroup;
		struct lxc_list cgroup2;
		struct bpf_program *cgroup2_devices;
		/* This should be reimplemented as a hashmap. */
		struct lxc_list devices;
	};

	struct {
		struct lxc_list id_map;

		/*
		 * Pointer to the idmap entry for the container's root uid in
		 * the id_map list. Do not free!
		 */
		const struct id_map *root_nsuid_map;

		/*
		 * Pointer to the idmap entry for the container's root gid in
		 * the id_map list. Do not free!
		 */
		const struct id_map *root_nsgid_map;
	};

	struct lxc_list network;

	struct {
		char *fstab;
		int auto_mounts;
		struct lxc_list mount_list;
	};

	struct lxc_list caps;
	struct lxc_list keepcaps;

	/* /dev/tty<idx> devices */
	struct lxc_tty_info ttys;
	/* /dev/console device */
	struct lxc_terminal console;
	/* maximum pty devices allowed by devpts mount */
	size_t pty_max;
	/* file descriptor for the container's /dev/pts mount */
	int devpts_fd;

	/* set to true when rootfs has been setup */
	bool rootfs_setup;
	struct lxc_rootfs rootfs;

	bool close_all_fds;

	struct {
		unsigned int hooks_version;
		struct lxc_list hooks[NUM_LXC_HOOKS];
	};

	char *lsm_aa_profile;
	char *lsm_aa_profile_computed;
	bool lsm_aa_profile_created;
	unsigned int lsm_aa_allow_nesting;
	unsigned int lsm_aa_allow_incomplete;
	struct lxc_list lsm_aa_raw;
	char *lsm_se_context;
	char *lsm_se_keyring_context;
	bool keyring_disable_session;
	bool tmp_umount_proc;
	struct lxc_seccomp seccomp;
	int maincmd_fd;
	unsigned int autodev;  /* if 1, mount and fill a /dev at start */
	int autodevtmpfssize; /* size of the /dev tmpfs */
	int haltsignal; /* signal used to halt container */
	int rebootsignal; /* signal used to reboot container */
	int stopsignal; /* signal used to hard stop container */
	char *rcfile;	/* Copy of the top level rcfile we read */

	/* Logfile and loglevel can be set in a container config file. Those
	 * function as defaults. The defaults can be overridden by command line.
	 * However we don't want the command line specified values to be saved
	 * on c->save_config(). So we store the config file specified values
	 * here. */
	char *logfile; /* the logfile as specified in config */
	int loglevel; /* loglevel as specified in config (if any) */
	int logfd;

	unsigned int start_auto;
	unsigned int start_delay;
	int start_order;
	struct lxc_list groups;
	int nbd_idx;

	/* unshare the mount namespace in the monitor */
	unsigned int monitor_unshare;
	unsigned int monitor_signal_pdeath;

	/* list of included files */
	struct lxc_list includes;
	/* config entries which are not "lxc.*" are aliens */
	struct lxc_list aliens;

	/* list of environment variables we'll add to the container when
	 * started */
	struct lxc_list environment;

	/* text representation of the config file */
	char *unexpanded_config;
	size_t unexpanded_len;
	size_t unexpanded_alloced;

	/* default command for lxc-execute */
	char *execute_cmd;

	/* init command */
	char *init_cmd;

	/* if running in a new user namespace, the UID/GID that init and COMMAND
	 * should run under when using lxc-execute */
	uid_t init_uid;
	gid_t init_gid;

	/* indicator if the container will be destroyed on shutdown */
	unsigned int ephemeral;

	/* The facility to pass to syslog. Let's users establish as what type of
	 * program liblxc is supposed to write to the syslog. */
	char *syslog;

	/* Whether PR_SET_NO_NEW_PRIVS will be set for the container. */
	bool no_new_privs;

	/* RLIMIT_* limits */
	struct lxc_list limits;

	/* Contains generic info about the cgroup configuration for this
	 * container. Note that struct lxc_cgroup contains a union. It is only
	 * valid to access the members of the anonymous "meta" struct within
	 * that union.
	 */
	struct lxc_cgroup cgroup_meta;

	struct {
		int ns_clone;
		int ns_keep;
		char *ns_share[LXC_NS_MAX];
	};

	/* init working directory */
	char *init_cwd;

	/* A list of clients registered to be informed about a container state. */
	struct lxc_list state_clients;

	/* sysctls */
	struct lxc_list sysctls;

	/* procs */
	struct lxc_list procs;

	struct shmount {
		/* Absolute path to the shared mount point on the host */
		char *path_host;
		/* Absolute path (in the container) to the shared mount point */
		char *path_cont;
	} shmount;

	struct timens_offsets timens;
};

__hidden extern int write_id_mapping(enum idtype idtype, pid_t pid, const char *buf, size_t buf_size)
    __access_r(3, 4);

#ifdef HAVE_TLS
extern thread_local struct lxc_conf *current_config;
#else
extern struct lxc_conf *current_config;
#endif

__hidden extern int run_lxc_hooks(const char *name, char *hook, struct lxc_conf *conf, char *argv[]);
__hidden extern struct lxc_conf *lxc_conf_init(void);
__hidden extern void lxc_conf_free(struct lxc_conf *conf);
__hidden extern int pin_rootfs(const char *rootfs);
__hidden extern int lxc_map_ids(struct lxc_list *idmap, pid_t pid);
__hidden extern int lxc_create_tty(const char *name, struct lxc_conf *conf);
__hidden extern void lxc_delete_tty(struct lxc_tty_info *ttys);
__hidden extern int lxc_clear_config_caps(struct lxc_conf *c);
__hidden extern int lxc_clear_config_keepcaps(struct lxc_conf *c);
__hidden extern int lxc_clear_cgroups(struct lxc_conf *c, const char *key, int version);
__hidden extern int lxc_clear_mount_entries(struct lxc_conf *c);
__hidden extern int lxc_clear_automounts(struct lxc_conf *c);
__hidden extern int lxc_clear_hooks(struct lxc_conf *c, const char *key);
__hidden extern int lxc_clear_idmaps(struct lxc_conf *c);
__hidden extern int lxc_clear_groups(struct lxc_conf *c);
__hidden extern int lxc_clear_environment(struct lxc_conf *c);
__hidden extern int lxc_clear_limits(struct lxc_conf *c, const char *key);
__hidden extern int lxc_delete_autodev(struct lxc_handler *handler);
__hidden extern int lxc_clear_autodev_tmpfs_size(struct lxc_conf *c);
__hidden extern void lxc_clear_includes(struct lxc_conf *conf);
__hidden extern int lxc_setup_rootfs_prepare_root(struct lxc_conf *conf, const char *name,
						  const char *lxcpath);
__hidden extern int lxc_setup(struct lxc_handler *handler);
__hidden extern int lxc_setup_parent(struct lxc_handler *handler);
__hidden extern int setup_resource_limits(struct lxc_list *limits, pid_t pid);
__hidden extern int find_unmapped_nsid(const struct lxc_conf *conf, enum idtype idtype);
__hidden extern int mapped_hostid(unsigned id, const struct lxc_conf *conf, enum idtype idtype);
__hidden extern int userns_exec_1(const struct lxc_conf *conf, int (*fn)(void *), void *data,
				  const char *fn_name);
__hidden extern int userns_exec_full(struct lxc_conf *conf, int (*fn)(void *), void *data,
				     const char *fn_name);
__hidden extern int parse_mntopts(const char *mntopts, unsigned long *mntflags, char **mntdata);
__hidden extern int parse_propagationopts(const char *mntopts, unsigned long *pflags);
__hidden extern void tmp_proc_unmount(struct lxc_conf *lxc_conf);
__hidden extern void turn_into_dependent_mounts(void);
__hidden extern void suggest_default_idmap(void);
__hidden extern FILE *make_anonymous_mount_file(struct lxc_list *mount, bool include_nesting_helpers);
__hidden extern struct lxc_list *sort_cgroup_settings(struct lxc_list *cgroup_settings);
__hidden extern unsigned long add_required_remount_flags(const char *s, const char *d,
							 unsigned long flags);
__hidden extern int run_script(const char *name, const char *section, const char *script, ...);
__hidden extern int run_script_argv(const char *name, unsigned int hook_version, const char *section,
				    const char *script, const char *hookname, char **argsin);
__hidden extern int in_caplist(int cap, struct lxc_list *caps);
__hidden extern int setup_sysctl_parameters(struct lxc_list *sysctls);
__hidden extern int lxc_clear_sysctls(struct lxc_conf *c, const char *key);
__hidden extern int setup_proc_filesystem(struct lxc_list *procs, pid_t pid);
__hidden extern int lxc_clear_procs(struct lxc_conf *c, const char *key);
__hidden extern int lxc_clear_apparmor_raw(struct lxc_conf *c);
__hidden extern int lxc_clear_namespace(struct lxc_conf *c);
__hidden extern int userns_exec_minimal(const struct lxc_conf *conf, int (*fn_parent)(void *),
					void *fn_parent_data, int (*fn_child)(void *),
					void *fn_child_data);
__hidden extern int userns_exec_mapped_root(const char *path, int path_fd,
					    const struct lxc_conf *conf);
static inline int chown_mapped_root(const char *path, const struct lxc_conf *conf)
{
	return userns_exec_mapped_root(path, -EBADF, conf);
}

#endif /* __LXC_CONF_H */

/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_CONF_H
#define __LXC_CONF_H

#include "config.h"

#include <linux/magic.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/vfs.h>

#include "attach_options.h"
#include "caps.h"
#include "compiler.h"
#include "hlist.h"
#include "list.h"
#include "lxcseccomp.h"
#include "memory_utils.h"
#include "mount_utils.h"
#include "namespace.h"
#include "ringbuf.h"
#include "start.h"
#include "state.h"
#include "storage/storage.h"
#include "string_utils.h"
#include "syscall_wrappers.h"
#include "terminal.h"

#if HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#if HAVE_SCMP_FILTER_CTX
typedef void * scmp_filter_ctx;
#endif

typedef signed long personality_t;

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
			char *monitor_pivot_dir;
			char *container_dir;
			char *namespace_dir;
			bool relative;
			/* If an unpriv user in pure unified-only hierarchy
			 * starts a container, then we ask systemd to create
			 * a scope for us, and create the monitor and container
			 * cgroups under that.
			 * This will ignore the above things like monitor_dir
			 */
			char *systemd_scope;
		};
	};

	struct list_head head;
};

static void free_lxc_cgroup(struct lxc_cgroup *ptr)
{
	if (ptr) {
		free(ptr->subsystem);
		free(ptr->value);
		free_disarm(ptr);
	}
}
define_cleanup_function(struct lxc_cgroup *, free_lxc_cgroup);

#if !HAVE_SYS_RESOURCE_H
#define RLIM_INFINITY ((unsigned long)-1)
struct rlimit {
	unsigned long rlim_cur;
	unsigned long rlim_max;
	struct list_head head;
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
	struct list_head head;
};

static void free_lxc_limit(struct lxc_limit *ptr)
{
	if (ptr) {
		free_disarm(ptr->resource);
		free_disarm(ptr);
	}
}
define_cleanup_function(struct lxc_limit *, free_lxc_limit);

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
	struct list_head head;
};

static void free_lxc_sysctl(struct lxc_sysctl *ptr)
{
	if (ptr) {
		free(ptr->key);
		free(ptr->value);
		free_disarm(ptr);
	}
}
define_cleanup_function(struct lxc_sysctl *, free_lxc_sysctl);

/*
 * Defines a structure to configure proc filesystem at runtime.
 * @filename : the proc filesystem will be configured without the "lxc.proc" prefix
 * @value    : the value to set
 */
struct lxc_proc {
	char *filename;
	char *value;
	struct list_head head;
};

static void free_lxc_proc(struct lxc_proc *ptr)
{
	if (ptr) {
		free(ptr->filename);
		free(ptr->value);
		free_disarm(ptr);
	}
}
define_cleanup_function(struct lxc_proc *, free_lxc_proc);

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
	struct list_head head;
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

typedef enum lxc_mount_options_t {
	LXC_MOUNT_CREATE_DIR	= 0,
	LXC_MOUNT_CREATE_FILE	= 1,
	LXC_MOUNT_OPTIONAL	= 2,
	LXC_MOUNT_RELATIVE	= 3,
	LXC_MOUNT_IDMAP		= 4,
	LXC_MOUNT_MAX		= 5,
} lxc_mount_options_t;

__hidden extern const char *lxc_mount_options_info[LXC_MOUNT_MAX];

struct lxc_mount_options {
	unsigned int create_dir : 1;
	unsigned int create_file : 1;
	unsigned int optional : 1;
	unsigned int relative : 1;
	unsigned int bind_recursively : 1;
	unsigned int propagate_recursively : 1;
	unsigned int bind : 1;
	char userns_path[PATH_MAX];
	unsigned long mnt_flags;
	unsigned long prop_flags;
	char *data;
	struct mount_attr attr;
	char *raw_options;
};

/* Defines a structure to store the rootfs location, the
 * optionals pivot_root, rootfs mount paths
 * @path         : the rootfs source (directory or device)
 * @mount        : where it is mounted
 * @buf		 : static buffer to construct paths
 * @bdev_type     : optional backing store type
 * @managed      : whether it is managed by LXC
 * @dfd_mnt	 : fd for @mount
 * @dfd_dev : fd for /dev of the container
 */
struct lxc_rootfs {
	int dfd_host;

	char *path;
	int fd_path_pin;
	int dfd_idmapped;

	int dfd_mnt;
	char *mount;

	int dfd_dev;

	char buf[PATH_MAX];
	char *bdev_type;
	bool managed;
	struct lxc_mount_options mnt_opts;
	struct lxc_storage *storage;
};

/*
 * Automatic mounts for LXC to perform inside the container
 */
enum {
	/* /proc read-write */
	LXC_AUTO_PROC_RW              = BIT(0),
	/* /proc/sys and /proc/sysrq-trigger read-only */
	LXC_AUTO_PROC_MIXED           = BIT(1),
	LXC_AUTO_PROC_MASK            = LXC_AUTO_PROC_RW |
					LXC_AUTO_PROC_MIXED,
	/* /sys read-write */
	LXC_AUTO_SYS_RW               = BIT(2),
	/* /sys read-only */
	LXC_AUTO_SYS_RO               = BIT(3),
	/* /sys read-only and /sys/class/net read-write */
	LXC_AUTO_SYS_MIXED            = LXC_AUTO_SYS_RW |
					LXC_AUTO_SYS_RO,
	LXC_AUTO_SYS_MASK             = LXC_AUTO_SYS_MIXED,

	/* /sys/fs/cgroup (partial mount, read-only) */
	LXC_AUTO_CGROUP_RO            = BIT(4),
	/* /sys/fs/cgroup (partial mount, read-write) */
	LXC_AUTO_CGROUP_RW            = BIT(5),
	/* /sys/fs/cgroup (partial mount, paths r/o, cgroup r/w) */
	LXC_AUTO_CGROUP_MIXED         = LXC_AUTO_CGROUP_RO |
					LXC_AUTO_CGROUP_RW,
	/* /sys/fs/cgroup (full mount, read-only) */
	LXC_AUTO_CGROUP_FULL_RO       = BIT(6),
	/* /sys/fs/cgroup (full mount, read-write) */
	LXC_AUTO_CGROUP_FULL_RW       = BIT(7),
	/* /sys/fs/cgroup (full mount, parent r/o, own r/w) */
	LXC_AUTO_CGROUP_FULL_MIXED    = LXC_AUTO_CGROUP_FULL_RO |
					LXC_AUTO_CGROUP_FULL_RW,

	/*
	 * Mount a pure read-write cgroup2 layout in the container independent
	 * of the cgroup layout used on the host.
	 */
	LXC_AUTO_CGROUP2_RW           = BIT(8),
	/*
	 * Mount a pure read-only cgroup2 layout in the container independent
	 * of the cgroup layout used on the host.
	 */
	LXC_AUTO_CGROUP2_RO           = BIT(9),

	/*
	 * These are defined in such a way as to retain binary compatibility
	 * with earlier versions of this code. If the previous mask is applied,
	 * both of these will default back to the _MIXED variants, which is
	 * safe.
	 */
	/* /sys/fs/cgroup (partial mount, r/w or mixed, depending on caps) */
	LXC_AUTO_CGROUP_NOSPEC        = 0x0B0,
	/* /sys/fs/cgroup (full mount, r/w or mixed, depending on caps) */
	LXC_AUTO_CGROUP_FULL_NOSPEC   = 0x0E0,
	/* mount cgroups even when cgroup namespaces are supported */
	LXC_AUTO_CGROUP_FORCE         = BIT(10),
	/* all known cgroup options */
	LXC_AUTO_CGROUP_MASK          = LXC_AUTO_CGROUP_MIXED |
					LXC_AUTO_CGROUP_FULL_MIXED |
					LXC_AUTO_CGROUP_NOSPEC |
					LXC_AUTO_CGROUP_FULL_NOSPEC |
					LXC_AUTO_CGROUP_FORCE |
					LXC_AUTO_CGROUP2_RW |
					LXC_AUTO_CGROUP2_RO,

	/* shared mount point */
	LXC_AUTO_SHMOUNTS             = BIT(11),
	/* shared mount point mask */
	LXC_AUTO_SHMOUNTS_MASK        = LXC_AUTO_SHMOUNTS,

	/* all known settings */
	LXC_AUTO_ALL_MASK             = LXC_AUTO_PROC_MASK |
					LXC_AUTO_SYS_MASK |
					LXC_AUTO_CGROUP_MASK,
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
	struct list_head head;
};

typedef enum lxc_bpf_devices_rule_t {
	LXC_BPF_DEVICE_CGROUP_ALLOWLIST		= 0,
	LXC_BPF_DEVICE_CGROUP_DENYLIST		= 1,
} lxc_bpf_devices_rule_t;

struct device_item {
	char type;
	int major;
	int minor;
	char access[4];
	int allow;
	struct list_head head;
};

struct bpf_devices {
	lxc_bpf_devices_rule_t list_type;
	struct list_head devices;
};

struct timens_offsets {
	/* Currently, either s_boot or ns_boot is set, but not both. */
	int64_t s_boot;
	int64_t ns_boot;

	/* Currently, either s_monotonic or ns_monotonic is set, but not both. */
	int64_t s_monotonic;
	int64_t ns_monotonic;
};

struct environment_entry {
	char *key;
	char *val;
	struct list_head head;
};

struct cap_entry {
	char *cap_name;
	__u32 cap;
	struct list_head head;
};

struct caps {
	int keep;
	struct list_head list;
};

struct string_entry {
	char *val;
	struct list_head head;
};

struct lxc_conf {
	/* Pointer to the name of the container. Do not free! */
	const char *name;
	bool is_execute;
	int reboot;
	personality_t personality;
	struct utsname *utsname;

	struct {
		struct list_head cgroup;
		struct list_head cgroup2;
		struct bpf_devices bpf_devices;
	};

	struct {
		struct list_head id_map;

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

	struct list_head netdevs;

	struct {
		char *fstab;
		int auto_mounts;
		struct list_head mount_entries;
	};

	struct caps caps;

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
		struct list_head hooks[NUM_LXC_HOOKS];
	};

	char *lsm_aa_profile;
	char *lsm_aa_profile_computed;
	bool lsm_aa_profile_created;
	unsigned int lsm_aa_allow_nesting;
	unsigned int lsm_aa_allow_incomplete;
	struct list_head lsm_aa_raw;
	char *lsm_se_context;
	char *lsm_se_keyring_context;
	bool keyring_disable_session;
	bool transient_procfs_mnt;
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
	struct list_head groups;
	int nbd_idx;

	/* unshare the mount namespace in the monitor */
	unsigned int monitor_unshare;
	unsigned int monitor_signal_pdeath;

	/* list of environment variables we'll add to the container when
	 * started */
	struct list_head environment;

	/* text representation of the config file */
	char *unexpanded_config;
	size_t unexpanded_len;
	size_t unexpanded_alloced;

	/* default command for lxc-execute */
	char *execute_cmd;

	/* init command */
	char *init_cmd;

	/* The uid to use for the container. */
	uid_t init_uid;
	/* The gid to use for the container. */
	gid_t init_gid;
	/* The groups to use for the container. */
	lxc_groups_t init_groups;

	/* indicator if the container will be destroyed on shutdown */
	unsigned int ephemeral;

	/* The facility to pass to syslog. Let's users establish as what type of
	 * program liblxc is supposed to write to the syslog. */
	char *syslog;

	/* Whether PR_SET_NO_NEW_PRIVS will be set for the container. */
	bool no_new_privs;

	/* RLIMIT_* limits */
	struct list_head limits;

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
	struct list_head state_clients;

	/* sysctls */
	struct list_head sysctls;

	/* procs */
	struct list_head procs;

	struct shmount {
		/* Absolute path to the shared mount point on the host */
		char *path_host;
		/* Absolute path (in the container) to the shared mount point */
		char *path_cont;
	} shmount;

	struct timens_offsets timens;

	bool sched_core;
	__u64 sched_core_cookie;
};

__hidden extern int write_id_mapping(enum idtype idtype, pid_t pid, const char *buf, size_t buf_size)
    __access_r(3, 4);

extern thread_local struct lxc_conf *current_config;

__hidden extern int run_lxc_hooks(const char *name, char *hook, struct lxc_conf *conf, char *argv[]);
__hidden extern struct lxc_conf *lxc_conf_init(void);
__hidden extern void lxc_conf_free(struct lxc_conf *conf);
__hidden extern int lxc_storage_prepare(struct lxc_conf *conf);
__hidden extern int lxc_rootfs_prepare(struct lxc_conf *conf, bool userns);
__hidden extern void lxc_storage_put(struct lxc_conf *conf);
__hidden extern int lxc_rootfs_init(struct lxc_conf *conf, bool userns);
__hidden extern int lxc_rootfs_prepare_parent(struct lxc_handler *handler);
__hidden extern int lxc_idmapped_mounts_parent(struct lxc_handler *handler);
__hidden extern int lxc_map_ids(struct list_head *idmap, pid_t pid);
__hidden extern int lxc_create_tty(const char *name, struct lxc_conf *conf);
__hidden extern void lxc_delete_tty(struct lxc_tty_info *ttys);
__hidden extern int lxc_clear_config_caps(struct lxc_conf *c);
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
__hidden extern int lxc_setup_rootfs_prepare_root(struct lxc_conf *conf, const char *name,
						  const char *lxcpath);
__hidden extern int lxc_setup(struct lxc_handler *handler);
__hidden extern int lxc_setup_parent(struct lxc_handler *handler);
__hidden extern int setup_resource_limits(struct lxc_conf *conf, pid_t pid);
__hidden extern int find_unmapped_nsid(const struct lxc_conf *conf, enum idtype idtype);
__hidden extern int mapped_hostid(unsigned id, const struct lxc_conf *conf, enum idtype idtype);
__hidden extern int userns_exec_1(const struct lxc_conf *conf, int (*fn)(void *), void *data,
				  const char *fn_name);
__hidden extern int userns_exec_full(struct lxc_conf *conf, int (*fn)(void *), void *data,
				     const char *fn_name);
__hidden extern int parse_mntopts_legacy(const char *mntopts, unsigned long *mntflags, char **mntdata);
__hidden extern int parse_propagationopts(const char *mntopts, unsigned long *pflags);
__hidden extern int parse_lxc_mount_attrs(struct lxc_mount_options *opts, char *mnt_opts);
__hidden extern int parse_mount_attrs(struct lxc_mount_options *opts, const char *mntopts);
__hidden extern void tmp_proc_unmount(struct lxc_conf *lxc_conf);
__hidden extern void suggest_default_idmap(void);
__hidden extern FILE *make_anonymous_mount_file(const struct list_head *mount,
						bool include_nesting_helpers);
__hidden extern int run_script(const char *name, const char *section, const char *script, ...);
__hidden extern int run_script_argv(const char *name, unsigned int hook_version, const char *section,
				    const char *script, const char *hookname, char **argsin);

__hidden extern bool has_cap(__u32 cap, struct lxc_conf *conf);
static inline bool lxc_wants_cap(__u32 cap, struct lxc_conf *conf)
{
	__u32 last_cap;
	int ret;

	ret = lxc_caps_last_cap(&last_cap);
	if (ret)
		return false;

	if (last_cap < cap)
		return false;

	return has_cap(cap, conf);
}

__hidden extern int setup_sysctl_parameters(struct lxc_conf *conf);
__hidden extern int lxc_clear_sysctls(struct lxc_conf *c, const char *key);
__hidden extern int setup_proc_filesystem(struct lxc_conf *conf, pid_t pid);
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

__hidden extern int lxc_sync_fds_parent(struct lxc_handler *handler);
__hidden extern int lxc_sync_fds_child(struct lxc_handler *handler);

static inline const char *get_rootfs_mnt(const struct lxc_rootfs *rootfs)
{
	static const char *s = "/";

	return !is_empty_string(rootfs->path) ? rootfs->mount : s;
}

static inline void put_lxc_mount_options(struct lxc_mount_options *mnt_opts)
{
	mnt_opts->create_dir = 0;
	mnt_opts->create_file = 0;
	mnt_opts->optional = 0;
	mnt_opts->relative = 0;
	mnt_opts->userns_path[0] = '\0';
	mnt_opts->mnt_flags = 0;
	mnt_opts->prop_flags = 0;

	free_disarm(mnt_opts->data);
	free_disarm(mnt_opts->raw_options);
}

static inline void put_lxc_rootfs(struct lxc_rootfs *rootfs, bool unpin)
{
	if (rootfs) {
		close_prot_errno_disarm(rootfs->dfd_host);
		close_prot_errno_disarm(rootfs->dfd_mnt);
		close_prot_errno_disarm(rootfs->dfd_dev);
		if (unpin)
			close_prot_errno_disarm(rootfs->fd_path_pin);
		close_prot_errno_disarm(rootfs->dfd_idmapped);
		put_lxc_mount_options(&rootfs->mnt_opts);
		storage_put(rootfs->storage);
		rootfs->storage = NULL;
	}
}

static inline void lxc_clear_cgroup2_devices(struct bpf_devices *bpf_devices)
{
	struct device_item *device, *n;

	list_for_each_entry_safe(device, n, &bpf_devices->devices, head)
		list_del(&device->head);

	INIT_LIST_HEAD(&bpf_devices->devices);
}

static inline int lxc_personality(personality_t persona)
{
	if (persona < 0)
		return ret_errno(EINVAL);

	return personality(persona);
}

__hidden extern int lxc_set_environment(const struct lxc_conf *conf);
__hidden extern int parse_cap(const char *cap_name, __u32 *cap);

#endif /* __LXC_CONF_H */

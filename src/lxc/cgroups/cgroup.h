/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_CGROUP_H
#define __LXC_CGROUP_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#include "compiler.h"
#include "macro.h"
#include "memory_utils.h"

#define DEFAULT_CGROUP_MOUNTPOINT_RELATIVE "sys/fs/cgroup"
#define DEFAULT_CGROUP_MOUNTPOINT "/sys/fs/cgroup"
#define DEFAULT_PAYLOAD_CGROUP_PREFIX "lxc.payload."
#define DEFAULT_MONITOR_CGROUP_PREFIX "lxc.monitor."
#define DEFAULT_PAYLOAD_CGROUP "payload"
#define DEFAULT_MONITOR_CGROUP "monitor"
#define CGROUP_CREATE_RETRY "-NNNN"
#define CGROUP_CREATE_RETRY_LEN (STRLITERALLEN(CGROUP_CREATE_RETRY))
#define CGROUP_PIVOT "lxc.pivot"

struct lxc_handler;
struct lxc_conf;
struct lxc_list;

typedef enum {
        CGROUP_LAYOUT_UNKNOWN = -1,
        CGROUP_LAYOUT_LEGACY  =  0,
        CGROUP_LAYOUT_HYBRID  =  1,
        CGROUP_LAYOUT_UNIFIED =  2,
} cgroup_layout_t;

/* A descriptor for a mounted hierarchy
 *
 * @controllers
 * - legacy hierarchy
 *   Either NULL, or a null-terminated list of all the co-mounted controllers.
 * - unified hierarchy
 *   Either NULL, or a null-terminated list of all enabled controllers.
 *
 * @mountpoint
 * - The mountpoint we will use.
 * - legacy hierarchy
 *   It will be either /sys/fs/cgroup/controller or
 *   /sys/fs/cgroup/controllerlist.
 * - unified hierarchy
 *   It will either be /sys/fs/cgroup or /sys/fs/cgroup/<mountpoint-name>
 *   depending on whether this is a hybrid cgroup layout (mix of legacy and
 *   unified hierarchies) or a pure unified cgroup layout.
 *
 * @container_base_path
 * - The cgroup under which the container cgroup path
 *   is created. This will be either the caller's cgroup (if not root), or
 *   init's cgroup (if root).
 *
 * @container_full_path
 * - The full path to the container's cgroup.
 *
 * @container_limit_path
 * - The full path to the container's limiting cgroup. May simply point to
 *   container_full_path.
 *
 * @monitor_full_path
 * - The full path to the monitor's cgroup.
 *
 * @version
 * - legacy hierarchy
 *   If the hierarchy is a legacy hierarchy this will be set to
 *   CGROUP_SUPER_MAGIC.
 * - unified hierarchy
 *   If the hierarchy is a unified hierarchy this will be set to
 *   CGROUP2_SUPER_MAGIC.
 */
struct hierarchy {
	/*
	 * cgroup2 only: what files need to be chowned to delegate a cgroup to
	 * an unprivileged user.
	 */
	char **cgroup2_chown;
	char **controllers;
	char *mountpoint;
	char *container_base_path;
	char *container_full_path;
	char *container_limit_path;
	char *monitor_full_path;
	int version;

	/* cgroup2 only */
	unsigned int bpf_device_controller:1;
	unsigned int freezer_controller:1;

	/* container cgroup fd */
	int cgfd_con;
	/* limiting cgroup fd (may be equal to cgfd_con if not separated) */
	int cgfd_limit;
	/* monitor cgroup fd */
	int cgfd_mon;
};

struct cgroup_ops {
	/* string constant */
	const char *driver;

	/* string constant */
	const char *version;

	/* What controllers is the container supposed to use. */
	char **cgroup_use;
	char *cgroup_pattern;
	char *container_cgroup;
	char *monitor_cgroup;

	/* @hierarchies
	 * - A NULL-terminated array of struct hierarchy, one per legacy
	 *   hierarchy. No duplicates. First sufficient, writeable mounted
	 *   hierarchy wins.
	 */
	struct hierarchy **hierarchies;
	/* Pointer to the unified hierarchy. Do not free! */
	struct hierarchy *unified;

	/*
	 * @cgroup2_devices
	 * bpf program to limit device access; only applicable to privileged
	 * containers.
	 */
	struct bpf_program *cgroup2_devices;

	/*
	 * @cgroup_layout
	 * - What cgroup layout the container is running with.
	 *   - CGROUP_LAYOUT_UNKNOWN
	 *     The cgroup layout could not be determined. This should be treated
	 *     as an error condition.
	 *   - CGROUP_LAYOUT_LEGACY
	 *     The container is running with all controllers mounted into legacy
	 *     cgroup hierarchies.
	 *   - CGROUP_LAYOUT_HYBRID
	 *     The container is running with at least one controller mounted
	 *     into a legacy cgroup hierarchy and a mountpoint for the unified
	 *     hierarchy. The unified hierarchy can be empty (no controllers
	 *     enabled) or non-empty (controllers enabled).
	 *   - CGROUP_LAYOUT_UNIFIED
	 *     The container is running on a pure unified cgroup hierarchy. The
	 *     unified hierarchy can be empty (no controllers enabled) or
	 *     non-empty (controllers enabled).
	 */
	cgroup_layout_t cgroup_layout;

	int (*data_init)(struct cgroup_ops *ops);
	void (*payload_destroy)(struct cgroup_ops *ops, struct lxc_handler *handler);
	void (*monitor_destroy)(struct cgroup_ops *ops, struct lxc_handler *handler);
	bool (*monitor_create)(struct cgroup_ops *ops, struct lxc_handler *handler);
	bool (*monitor_enter)(struct cgroup_ops *ops, struct lxc_handler *handler);
	bool (*payload_create)(struct cgroup_ops *ops, struct lxc_handler *handler);
	bool (*payload_enter)(struct cgroup_ops *ops, struct lxc_handler *handler);
	const char *(*get_cgroup)(struct cgroup_ops *ops, const char *controller);
	bool (*escape)(const struct cgroup_ops *ops, struct lxc_conf *conf);
	int (*num_hierarchies)(struct cgroup_ops *ops);
	bool (*get_hierarchies)(struct cgroup_ops *ops, int n, char ***out);
	int (*set)(struct cgroup_ops *ops, const char *filename,
		   const char *value, const char *name, const char *lxcpath);
	int (*get)(struct cgroup_ops *ops, const char *filename, char *value,
		   size_t len, const char *name, const char *lxcpath);
	int (*freeze)(struct cgroup_ops *ops, int timeout);
	int (*unfreeze)(struct cgroup_ops *ops, int timeout);
	bool (*setup_limits_legacy)(struct cgroup_ops *ops,
				    struct lxc_conf *conf, bool with_devices);
	bool (*setup_limits)(struct cgroup_ops *ops, struct lxc_handler *handler);
	bool (*chown)(struct cgroup_ops *ops, struct lxc_conf *conf);
	bool (*attach)(struct cgroup_ops *ops, const struct lxc_conf *conf,
		       const char *name, const char *lxcpath, pid_t pid);
	bool (*mount)(struct cgroup_ops *ops, struct lxc_conf *conf, int type);
	bool (*devices_activate)(struct cgroup_ops *ops,
				 struct lxc_handler *handler);
	bool (*monitor_delegate_controllers)(struct cgroup_ops *ops);
	bool (*payload_delegate_controllers)(struct cgroup_ops *ops);
	void (*payload_finalize)(struct cgroup_ops *ops);
	const char *(*get_limiting_cgroup)(struct cgroup_ops *ops, const char *controller);
};

__hidden extern struct cgroup_ops *cgroup_init(struct lxc_conf *conf);

__hidden extern void cgroup_exit(struct cgroup_ops *ops);
define_cleanup_function(struct cgroup_ops *, cgroup_exit);

__hidden extern void prune_init_scope(char *cg);

__hidden extern int cgroup_attach(const struct lxc_conf *conf, const char *name,
				  const char *lxcpath, pid_t pid);

static inline bool pure_unified_layout(const struct cgroup_ops *ops)
{
	return ops->cgroup_layout == CGROUP_LAYOUT_UNIFIED;
}

static inline int cgroup_unified_fd(const struct cgroup_ops *ops)
{
	if (!ops->unified)
		return -EBADF;

	return ops->unified->cgfd_con;
}

#endif /* __LXC_CGROUP_H */

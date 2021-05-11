/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_CGROUP_H
#define __LXC_CGROUP_H

#include <stdbool.h>
#include <stddef.h>
#include <linux/types.h>
#include <sys/types.h>
#include <linux/magic.h>

#include "af_unix.h"
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

static inline const char *cgroup_layout_name(cgroup_layout_t layout)
{
	switch (layout) {
	case CGROUP_LAYOUT_LEGACY:
		return "legacy";
	case CGROUP_LAYOUT_HYBRID:
		return "hybrid";
	case CGROUP_LAYOUT_UNIFIED:
		return "unified";
	case CGROUP_LAYOUT_UNKNOWN:
		break;
	}

	return "unknown";
}

typedef enum {
	LEGACY_HIERARCHY  = CGROUP_SUPER_MAGIC,
	UNIFIED_HIERARCHY = CGROUP2_SUPER_MAGIC,
} cgroupfs_type_magic_t;

static inline const char *cgroup_hierarchy_name(cgroupfs_type_magic_t type)
{
	switch (type) {
	case LEGACY_HIERARCHY:
		return "legacy";
	case UNIFIED_HIERARCHY:
		return "unified";
	}

	return "unknown";
}

#define DEVICES_CONTROLLER (1U << 0)
#define FREEZER_CONTROLLER (1U << 1)

/*
 * This is the maximum length of a cgroup controller in the kernel.
 * This includes the \0 byte.
 */
#define MAX_CGROUP_ROOT_NAMELEN 64

/* That's plenty of hierarchies. */
#define CGROUP_CTX_MAX_FD 20

struct cgroup_fd {
	__s32 layout;
	__u32 utilities;
	__s32 type;
	__s32 fd;
	char controller[MAX_CGROUP_ROOT_NAMELEN];
} __attribute__((aligned(8)));

struct cgroup_ctx {
	__s32 layout;
	__u32 utilities;
	__u32 fd_len;
	__s32 fd[CGROUP_CTX_MAX_FD];
} __attribute__((aligned(8)));

/* A descriptor for a mounted hierarchy
 *
 * @controllers
 * - legacy hierarchy
 *   Either NULL, or a null-terminated list of all the co-mounted controllers.
 * - unified hierarchy
 *   Either NULL, or a null-terminated list of all enabled controllers.
 *
 * @at_mnt
 * - The at_mnt we will use.
 * - legacy hierarchy
 *   It will be either /sys/fs/cgroup/controller or
 *   /sys/fs/cgroup/controllerlist.
 * - unified hierarchy
 *   It will either be /sys/fs/cgroup or /sys/fs/cgroup/<mountpoint-name>
 *   depending on whether this is a hybrid cgroup layout (mix of legacy and
 *   unified hierarchies) or a pure unified cgroup layout.
 *
 * @at_base
 * - The cgroup under which the container cgroup path
 *   is created. This will be either the caller's cgroup (if not root), or
 *   init's cgroup (if root).
 *
 * @path_con
 * - The full path to the container's cgroup.
 *
 * @path_lim
 * - The full path to the container's limiting cgroup. May simply point to
 *   path_con.
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
	cgroupfs_type_magic_t fs_type;

	/* File descriptor for the container's cgroup @path_con. */
	int dfd_con;
	char *path_con;

	/*
	 * File descriptor for the container's limiting cgroup
	 * @path_lim.
	 * Will be equal to @dfd_con if no limiting cgroup has been requested.
	 */
	int dfd_lim;
	char *path_lim;

	/* File descriptor for the monitor's cgroup. */
	int dfd_mon;

	/* File descriptor for the controller's mountpoint @at_mnt. */
	int dfd_mnt;
	char *at_mnt;

	/* File descriptor for the controller's base cgroup path @at_base. */
	int dfd_base;
	char *at_base;

	struct /* unified hierarchy specific */ {
		char **delegate;
		unsigned int utilities;
	};

	char **controllers;
};

static inline bool device_utility_controller(const struct hierarchy *h)
{
	if (h->fs_type == UNIFIED_HIERARCHY && (h->utilities & DEVICES_CONTROLLER))
		return true;
	return false;
}

static inline bool freezer_utility_controller(const struct hierarchy *h)
{
	if (h->fs_type == UNIFIED_HIERARCHY && (h->utilities & FREEZER_CONTROLLER))
		return true;
	return false;
}

struct cgroup_ops {
	/* string constant */
	const char *driver;

	/* string constant */
	const char *version;

	/*
	 * File descriptor for the host's cgroupfs mount.  On
	 * CGROUP_LAYOUT_LEGACY or CGROUP_LAYOUT_HYBRID hybrid systems
	 * @dfd_mnt_cgroupfs_host will be a tmpfs fd and the individual
	 * controllers will be cgroupfs fds. On CGROUP_LAYOUT_UNIFIED it will
	 * be a cgroupfs fd itself.
	 *
	 * So for CGROUP_LAYOUT_LEGACY or CGROUP_LAYOUT_HYBRID we allow
	 * mountpoint crossing iff we cross from a tmpfs into a cgroupfs mount.
	 * */
	int dfd_mnt;

	/* What controllers is the container supposed to use. */
	char **cgroup_use;
	char *cgroup_pattern;
	char *container_cgroup;
	char *container_limit_cgroup;
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
	bool (*criu_escape)(const struct cgroup_ops *ops, struct lxc_conf *conf);
	int (*criu_num_hierarchies)(struct cgroup_ops *ops);
	bool (*criu_get_hierarchies)(struct cgroup_ops *ops, int n, char ***out);
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
	bool (*mount)(struct cgroup_ops *ops, struct lxc_handler *handler, int type);
	bool (*devices_activate)(struct cgroup_ops *ops,
				 struct lxc_handler *handler);
	bool (*monitor_delegate_controllers)(struct cgroup_ops *ops);
	bool (*payload_delegate_controllers)(struct cgroup_ops *ops);
	void (*finalize)(struct cgroup_ops *ops);
	const char *(*get_limit_cgroup)(struct cgroup_ops *ops, const char *controller);
};

__hidden extern struct cgroup_ops *cgroup_init(struct lxc_conf *conf);

__hidden extern void cgroup_exit(struct cgroup_ops *ops);
define_cleanup_function(struct cgroup_ops *, cgroup_exit);
#define __cleanup_cgroup_ops call_cleaner(cgroup_exit)

__hidden extern int cgroup_attach(const struct lxc_conf *conf, const char *name,
				  const char *lxcpath, pid_t pid);
__hidden extern int cgroup_get(const char *name, const char *lxcpath,
                               const char *key, char *buf, size_t len);
__hidden extern int cgroup_set(const char *name, const char *lxcpath,
			       const char *key, const char *value);
__hidden extern int cgroup_freeze(const char *name, const char *lxcpath, int timeout);
__hidden extern int cgroup_unfreeze(const char *name, const char *lxcpath, int timeout);
__hidden extern int __cgroup_unfreeze(int unified_fd, int timeout);

static inline bool pure_unified_layout(const struct cgroup_ops *ops)
{
	return ops->cgroup_layout == CGROUP_LAYOUT_UNIFIED;
}

static inline int cgroup_unified_fd(const struct cgroup_ops *ops)
{
	if (!ops->unified)
		return -EBADF;

	return ops->unified->dfd_con;
}

#define make_cgroup_path(__hierarchy, __first, ...)                    \
	({                                                             \
		const struct hierarchy *__h = __hierarchy;             \
		must_make_path(DEFAULT_CGROUP_MOUNTPOINT, __h->at_mnt, \
			       __first, __VA_ARGS__);                  \
	})

static void put_cgroup_ctx(struct cgroup_ctx *ctx)
{
	if (!IS_ERR_OR_NULL(ctx)) {
		for (__u32 idx = 0; idx < ctx->fd_len; idx++)
			close_prot_errno_disarm(ctx->fd[idx]);
	}
}
define_cleanup_function(struct cgroup_ctx *, put_cgroup_ctx);

static inline int prepare_cgroup_ctx(struct cgroup_ops *ops,
				     struct cgroup_ctx *ctx)
{
	__u32 idx;

	for (idx = 0; ops->hierarchies[idx]; idx++) {
		if (idx >= CGROUP_CTX_MAX_FD)
			return ret_errno(E2BIG);

		ctx->fd[idx] = ops->hierarchies[idx]->dfd_con;
	}

	if (idx == 0)
		return ret_errno(ENOENT);

	ctx->fd_len = idx;
	ctx->layout = ops->cgroup_layout;
	if (ops->unified && ops->unified->dfd_con > 0)
		ctx->utilities = ops->unified->utilities;

	return 0;
}
__hidden extern int prepare_cgroup_fd(const struct cgroup_ops *ops,
				      struct cgroup_fd *fd, bool limit);

#endif /* __LXC_CGROUP_H */

/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_LSM_H
#define __LXC_LSM_H

struct lxc_conf;

#include <sys/types.h>

#include "compiler.h"
#include "macro.h"
#include "utils.h"

struct lsm_ops {
	const char *name;

	/* AppArmor specific fields. */
	int aa_enabled;
	int aa_parser_available;
	int aa_supports_unix;
	int aa_can_stack;
	int aa_is_stacked;
	int aa_admin;
	int aa_mount_features_enabled;

	int (*enabled)(struct lsm_ops *ops);
	char *(*process_label_get)(struct lsm_ops *ops, pid_t pid);
	int (*process_label_set)(struct lsm_ops *ops, const char *label, struct lxc_conf *conf, bool on_exec);
	int (*keyring_label_set)(struct lsm_ops *ops, const char *label);
	int (*prepare)(struct lsm_ops *ops, struct lxc_conf *conf, const char *lxcpath);
	void (*cleanup)(struct lsm_ops *ops, struct lxc_conf *conf, const char *lxcpath);
	int (*process_label_fd_get)(struct lsm_ops *ops, pid_t pid, bool on_exec);
	char *(*process_label_get_at)(struct lsm_ops *ops, int fd_pid);
	int (*process_label_set_at)(struct lsm_ops *ops, int label_fd, const char *label, bool on_exec);
};

__hidden extern struct lsm_ops *lsm_init_static(void);

#endif /* __LXC_LSM_H */

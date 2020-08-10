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

	int (*enabled)(void);
	char *(*process_label_get)(pid_t pid);
	int (*process_label_set)(const char *label, struct lxc_conf *conf, bool on_exec);
	int (*keyring_label_set)(const char *label);
	int (*prepare)(struct lxc_conf *conf, const char *lxcpath);
	void (*cleanup)(struct lxc_conf *conf, const char *lxcpath);
	int (*process_label_fd_get)(pid_t pid, bool on_exec);
	int (*process_label_set_at)(int label_fd, const char *label, bool on_exec);
};

__hidden extern const struct lsm_ops *lsm_init(void);

#endif /* __LXC_LSM_H */

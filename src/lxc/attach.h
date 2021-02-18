/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_ATTACH_H
#define __LXC_ATTACH_H

#include <stdbool.h>
#include <lxc/attach_options.h>
#include <sys/types.h>

#include "compiler.h"
#include "namespace.h"

struct lxc_conf;

struct lxc_proc_context_info {
	char *lsm_label;
	struct lxc_container *container;
	signed long personality;
	unsigned long long capability_mask;
	int ns_inherited;
	int ns_fd[LXC_NS_MAX];
	struct lsm_ops *lsm_ops;
};

__hidden extern int lxc_attach(struct lxc_container *container, lxc_attach_exec_t exec_function,
			       void *exec_payload, lxc_attach_options_t *options,
			       pid_t *attached_process);

__hidden extern int lxc_attach_remount_sys_proc(void);

#endif /* __LXC_ATTACH_H */

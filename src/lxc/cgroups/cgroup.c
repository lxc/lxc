/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "cgroup.h"
#include "cgroup2_devices.h"
#include "compiler.h"
#include "conf.h"
#include "config.h"
#include "initutils.h"
#include "memory_utils.h"
#include "log.h"
#include "start.h"
#include "string_utils.h"

lxc_log_define(cgroup, lxc);

__hidden extern struct cgroup_ops *cgfsng_ops_init(struct lxc_conf *conf);

struct cgroup_ops *cgroup_init(struct lxc_conf *conf)
{
	struct cgroup_ops *cgroup_ops;

	if (!conf)
		return log_error_errno(NULL, EINVAL, "No valid conf given");

	cgroup_ops = cgfsng_ops_init(conf);
	if (!cgroup_ops)
		return log_error_errno(NULL, errno, "Failed to initialize cgroup driver");

	if (!cgroup_ops->hierarchies) {
		cgroup_exit(cgroup_ops);
		return log_error_errno(NULL, ENOENT, "No cgroup hierarchies found");
	}

	if (cgroup_ops->data_init(cgroup_ops)) {
		cgroup_exit(cgroup_ops);
		return log_error_errno(NULL, errno, "Failed to initialize cgroup data");
	}

	TRACE("Initialized cgroup driver %s", cgroup_ops->driver);

	if (cgroup_ops->cgroup_layout == CGROUP_LAYOUT_LEGACY)
		TRACE("Running with legacy cgroup layout");
	else if (cgroup_ops->cgroup_layout == CGROUP_LAYOUT_HYBRID)
		TRACE("Running with hybrid cgroup layout");
	else if (cgroup_ops->cgroup_layout == CGROUP_LAYOUT_UNIFIED)
		TRACE("Running with unified cgroup layout");
	else
		WARN("Running with unknown cgroup layout");

	return cgroup_ops;
}

void cgroup_exit(struct cgroup_ops *ops)
{
	if (!ops)
		return;

	for (char **cur = ops->cgroup_use; cur && *cur; cur++)
		free(*cur);

	free(ops->cgroup_pattern);
	free(ops->monitor_cgroup);

	free_equal(ops->container_cgroup, ops->container_limit_cgroup);

	bpf_device_program_free(ops);

	if (ops->dfd_mnt_cgroupfs_host >= 0)
		close(ops->dfd_mnt_cgroupfs_host);

	for (struct hierarchy **it = ops->hierarchies; it && *it; it++) {
		for (char **p = (*it)->controllers; p && *p; p++)
			free(*p);
		free((*it)->controllers);

		for (char **p = (*it)->cgroup2_chown; p && *p; p++)
			free(*p);
		free((*it)->cgroup2_chown);

		free((*it)->mountpoint);
		free((*it)->container_base_path);

		free_equal((*it)->container_full_path,
			   (*it)->container_limit_path);

		close_equal((*it)->cgfd_con, (*it)->cgfd_limit);

		if ((*it)->cgfd_mon >= 0)
			close((*it)->cgfd_mon);

		close_equal((*it)->dfd_base, (*it)->dfd_mnt);

		free(*it);
	}
	free(ops->hierarchies);

	free(ops);

	return;
}

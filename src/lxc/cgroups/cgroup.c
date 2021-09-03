/* SPDX-License-Identifier: LGPL-2.1+ */

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "cgroup.h"
#include "cgroup2_devices.h"
#include "compiler.h"
#include "conf.h"
#include "initutils.h"
#include "memory_utils.h"
#include "log.h"
#include "start.h"
#include "string_utils.h"

lxc_log_define(cgroup, lxc);

__hidden extern struct cgroup_ops *cgroup_ops_init(struct lxc_conf *conf);

struct cgroup_ops *cgroup_init(struct lxc_conf *conf)
{
	struct cgroup_ops *cgroup_ops;

	if (!conf)
		return log_error_errno(NULL, EINVAL, "No valid conf given");

	cgroup_ops = cgroup_ops_init(conf);
	if (!cgroup_ops)
		return log_error_errno(NULL, errno, "Failed to initialize cgroup driver");

	if (cgroup_ops->data_init(cgroup_ops)) {
		cgroup_exit(cgroup_ops);
		return log_error_errno(NULL, errno, "Failed to initialize cgroup data");
	}

	TRACE("Initialized cgroup driver %s", cgroup_ops->driver);

	if (cgroup_ops->cgroup_layout == CGROUP_LAYOUT_LEGACY)
		TRACE("Legacy cgroup layout");
	else if (cgroup_ops->cgroup_layout == CGROUP_LAYOUT_HYBRID)
		TRACE("Hybrid cgroup layout");
	else if (cgroup_ops->cgroup_layout == CGROUP_LAYOUT_UNIFIED)
		TRACE("Unified cgroup layout");
	else
		WARN("Unsupported cgroup layout");

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

	if (ops->dfd_mnt >= 0)
		close(ops->dfd_mnt);

	for (struct hierarchy **it = ops->hierarchies; it && *it; it++) {
		for (char **p = (*it)->controllers; p && *p; p++)
			free(*p);
		free((*it)->controllers);

		for (char **p = (*it)->delegate; p && *p; p++)
			free(*p);
		free((*it)->delegate);

		free((*it)->at_mnt);
		free((*it)->at_base);

		free_equal((*it)->path_con,
			   (*it)->path_lim);

		close_equal((*it)->dfd_con, (*it)->dfd_lim);

		if ((*it)->dfd_mon >= 0)
			close((*it)->dfd_mon);

		close_equal((*it)->dfd_base, (*it)->dfd_mnt);

		free(*it);
	}
	free(ops->hierarchies);

	free(ops);

	return;
}

/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2008
 *
 * Authors:
 * Daniel Lezcano <daniel.lezcano at free.fr>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <unistd.h>
#include <sys/types.h>

#include "cgroup.h"
#include "conf.h"
#include "initutils.h"
#include "log.h"
#include "start.h"

lxc_log_define(lxc_cgroup, lxc);

extern struct cgroup_ops *cgfsng_ops_init(void);

struct cgroup_ops *cgroup_init(struct lxc_handler *handler)
{
	struct cgroup_ops *cgroup_ops;

	cgroup_ops = cgfsng_ops_init();
	if (!cgroup_ops) {
		ERROR("Failed to initialize cgroup driver");
		return NULL;
	}

	if (!cgroup_ops->data_init(cgroup_ops))
		return NULL;

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
	struct hierarchy **it;

	if (!ops)
		return;

	free(ops->cgroup_use);
	free(ops->cgroup_pattern);
	free(ops->container_cgroup);

	for (it = ops->hierarchies; it && *it; it++) {
		char **ctrlr;

		for (ctrlr = (*it)->controllers; ctrlr && *ctrlr; ctrlr++)
			free(*ctrlr);
		free((*it)->controllers);

		free((*it)->mountpoint);
		free((*it)->base_cgroup);
		free((*it)->fullcgpath);
		free(*it);
	}
	free(ops->hierarchies);

	return;
}

#define INIT_SCOPE "/init.scope"
void prune_init_scope(char *cg)
{
	char *point;

	if (!cg)
		return;

	point = cg + strlen(cg) - strlen(INIT_SCOPE);
	if (point < cg)
		return;

	if (strcmp(point, INIT_SCOPE) == 0) {
		if (point == cg)
			*(point + 1) = '\0';
		else
			*point = '\0';
	}
}

/* Return true if this is a subsystem which we cannot do without.
 *
 * systemd is questionable here. The way callers currently use this, if systemd
 * is not mounted then it will be ignored. But if systemd is mounted, then it
 * must be setup so that lxc can create cgroups in it, else containers will
 * fail.
 *
 * cgroups listed in lxc.cgroup.use are also treated as crucial
 *
 */
bool is_crucial_cgroup_subsystem(const char *s)
{
	const char *cgroup_use;

	if (strcmp(s, "systemd") == 0)
		return true;

	if (strcmp(s, "name=systemd") == 0)
		return true;

	if (strcmp(s, "freezer") == 0)
		return true;

	cgroup_use = lxc_global_config_value("lxc.cgroup.use");
	if (cgroup_use && strstr(cgroup_use, s))
		return true;

	return false;
}

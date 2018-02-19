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

static struct cgroup_ops *ops = NULL;

extern struct cgroup_ops *cgfsng_ops_init(void);

__attribute__((constructor)) void cgroup_ops_init(void)
{
	if (ops) {
		INFO("Running with %s in version %s", ops->driver, ops->version);
		return;
	}

	DEBUG("cgroup_init");
	ops = cgfsng_ops_init();
	if (ops)
		INFO("Initialized cgroup driver %s", ops->driver);
}

bool cgroup_init(struct lxc_handler *handler)
{
	if (handler->cgroup_data) {
		ERROR("cgroup_init called on already initialized handler");
		return true;
	}

	if (ops) {
		INFO("cgroup driver %s initing for %s", ops->driver, handler->name);
		handler->cgroup_data = ops->init(handler);
	}

	return handler->cgroup_data != NULL;
}

void cgroup_destroy(struct lxc_handler *handler)
{
	if (ops) {
		ops->destroy(handler->cgroup_data, handler->conf);
		handler->cgroup_data = NULL;
	}
}

/* Create the container cgroups for all requested controllers. */
bool cgroup_create(struct lxc_handler *handler)
{
	if (ops)
		return ops->create(handler->cgroup_data);

	return false;
}

/* Enter the container init into its new cgroups for all requested controllers. */
bool cgroup_enter(struct lxc_handler *handler)
{
	if (ops)
		return ops->enter(handler->cgroup_data, handler->pid);

	return false;
}

bool cgroup_create_legacy(struct lxc_handler *handler)
{
	if (ops && ops->create_legacy)
		return ops->create_legacy(handler->cgroup_data, handler->pid);

	return true;
}

const char *cgroup_get_cgroup(struct lxc_handler *handler,
			      const char *subsystem)
{
	if (ops)
		return ops->get_cgroup(handler->cgroup_data, subsystem);

	return NULL;
}

bool cgroup_escape(struct lxc_handler *handler)
{
	if (ops)
		return ops->escape(handler->cgroup_data);

	return false;
}

int cgroup_num_hierarchies(void)
{
	if (!ops)
		return -1;

	return ops->num_hierarchies();
}

bool cgroup_get_hierarchies(int n, char ***out)
{
	if (!ops)
		return false;

	return ops->get_hierarchies(n, out);
}

bool cgroup_unfreeze(struct lxc_handler *handler)
{
	if (ops)
		return ops->unfreeze(handler->cgroup_data);

	return false;
}

bool cgroup_setup_limits(struct lxc_handler *handler, bool with_devices)
{
	if (ops)
		return ops->setup_limits(handler->cgroup_data,
					 handler->conf, with_devices);

	return false;
}

bool cgroup_chown(struct lxc_handler *handler)
{
	if (ops && ops->chown)
		return ops->chown(handler->cgroup_data, handler->conf);

	return true;
}

bool cgroup_mount(const char *root, struct lxc_handler *handler, int type)
{
	if (ops)
		return ops->mount_cgroup(handler, root, type);

	return false;
}

int cgroup_nrtasks(struct lxc_handler *handler)
{
	if (ops) {
		if (ops->nrtasks)
			return ops->nrtasks(handler->cgroup_data);
		else
			WARN("cgroup driver \"%s\" doesn't implement nrtasks", ops->driver);
	}

	return -1;
}

bool cgroup_attach(const char *name, const char *lxcpath, pid_t pid)
{
	if (ops)
		return ops->attach(name, lxcpath, pid);

	return false;
}

int lxc_cgroup_set(const char *filename, const char *value, const char *name,
		   const char *lxcpath)
{
	if (ops)
		return ops->set(filename, value, name, lxcpath);

	return -1;
}

int lxc_cgroup_get(const char *filename, char *value, size_t len,
		   const char *name, const char *lxcpath)
{
	if (ops)
		return ops->get(filename, value, len, name, lxcpath);

	return -1;
}

void cgroup_disconnect(void)
{
	if (ops && ops->disconnect)
		ops->disconnect();
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

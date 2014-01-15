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
#define _GNU_SOURCE
#include <stdio.h>
#undef _GNU_SOURCE
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/inotify.h>
#include <sys/mount.h>
#include <netinet/in.h>
#include <net/if.h>

#include "error.h"
#include "config.h"
#include "commands.h"
#include "list.h"
#include "conf.h"
#include "utils.h"
#include "bdev.h"
#include "log.h"
#include "cgroup.h"
#include "start.h"
#include "state.h"

#ifdef HAVE_CGMANAGER
lxc_log_define(lxc_cgmanager, lxc);

#include <nih-dbus/dbus_connection.h>
#include <cgmanager-client/cgmanager-client.h>
NihDBusProxy *cgroup_manager = NULL;

extern struct cgroup_ops *active_cg_ops;
bool cgmanager_initialized = false;
bool use_cgmanager = true;
static struct cgroup_ops cgmanager_ops;

bool lxc_init_cgmanager(void);
static void cgmanager_disconnected(DBusConnection *connection)
{
	WARN("Cgroup manager connection was terminated");
	cgroup_manager = NULL;
	cgmanager_initialized = false;
	if (lxc_init_cgmanager()) {
		cgmanager_initialized = true;
		INFO("New cgroup manager connection was opened");
	}
}

#define CGMANAGER_DBUS_SOCK "unix:path=/sys/fs/cgroup/cgmanager/sock"
bool lxc_init_cgmanager(void)
{
	DBusError dbus_error;
	DBusConnection *connection;
	dbus_error_init(&dbus_error);

	connection = nih_dbus_connect(CGMANAGER_DBUS_SOCK, cgmanager_disconnected);
	if (!connection) {
		ERROR("Error opening cgmanager connection at %s", CGMANAGER_DBUS_SOCK);
		return false;
	}
	dbus_connection_set_exit_on_disconnect(connection, FALSE);
	dbus_error_free(&dbus_error);
	cgroup_manager = nih_dbus_proxy_new(NULL, connection,
				NULL /* p2p */,
				"/org/linuxcontainers/cgmanager", NULL, NULL);
	dbus_connection_unref(connection);
	if (!cgroup_manager) {
		return false;
	}
	active_cg_ops = &cgmanager_ops;
	return true;
}

/*
 * Use the cgmanager to move a task into a cgroup for a particular
 * hierarchy.
 * All the subsystems in this hierarchy are co-mounted, so we only
 * need to transition the task into one of the cgroups
 */
static bool lxc_cgmanager_enter(pid_t pid, char *controller, char *cgroup_path)
{
	return cgmanager_move_pid_sync(NULL, cgroup_manager, controller,
				       cgroup_path, pid) == 0;
}

static bool lxc_cgmanager_create(const char *controller, const char *cgroup_path, int32_t *existed)
{
	if ( cgmanager_create_sync(NULL, cgroup_manager, controller,
				       cgroup_path, existed) != 0) {
		ERROR("Failed to create %s:%s", controller, cgroup_path);
		return false;
	}

	// TODO - try to chown the cgroup to the container root
	return true;
}


struct cgm_data {
	int nr_subsystems;
	char **subsystems;
	char *cgroup_path;
};

#define CG_REMOVE_RECURSIVE 1
void cgmanager_remove_cgroup(const char *controller, const char *path)
{
	int existed;
	if ( cgmanager_remove_sync(NULL, cgroup_manager, controller,
				   path, CG_REMOVE_RECURSIVE, &existed) != 0)
		ERROR("Error removing %s:%s", controller, path);
	if (!existed)
		INFO("cgroup removal attempt: %s:%s did not exist");
}

static void cgm_destroy(struct lxc_handler *handler)
{
	struct cgm_data *d = handler->cgroup_info->data;
	int i;

	if (!d)
		return;
	for (i=0; i<d->nr_subsystems; i++) {
		if (d->cgroup_path)
			cgmanager_remove_cgroup(d->subsystems[i], d->cgroup_path);
		free(d->subsystems[i]);
	}
	free(d->subsystems);
	free(d->cgroup_path);
	free(d);
	handler->cgroup_info->data = NULL;
}

/*
 * remove all the cgroups created
 */
static inline void cleanup_cgroups(struct cgm_data *d, char *path)
{
	int i;
	for (i = 0; i < d->nr_subsystems; i++) {
		cgmanager_remove_cgroup(d->subsystems[i], path);
	}
}

static inline bool cgm_create(struct lxc_handler *handler)
{
	int i, index=0, baselen, ret;
	int32_t existed;
	char result[MAXPATHLEN], *tmp;
	struct cgm_data *d = handler->cgroup_info->data;

// XXX we should send a hint to the cgmanager that when these
// cgroups become empty they should be deleted.  Requires a cgmanager
// extension

	memset(result, 0, MAXPATHLEN);
	tmp = lxc_string_replace("%n", handler->name, handler->cgroup_info->cgroup_pattern);
	if (!tmp)
		return false;
	if (strlen(tmp) > MAXPATHLEN)
		return false;
	strcpy(result, tmp);
	baselen = strlen(result);
	free(tmp);
	tmp = result;
	while (*tmp == '/')
		tmp++;
again:
	if (index == 100) { // turn this into a warn later
		ERROR("cgroup error?  100 cgroups with this name already running");
		return false;
	}
	if (index) {
		ret = snprintf(result+baselen, MAXPATHLEN-baselen, "-%d", index);
		if (ret < 0 || ret >= MAXPATHLEN-baselen)
			return false;
	}
	existed = 0;
	for (i = 0; i < d->nr_subsystems; i++) {
		if (!lxc_cgmanager_create(d->subsystems[i], tmp, &existed)) {
			ERROR("Error creating cgroup %s:%s", d->subsystems[i], result);
			cleanup_cgroups(d, tmp);
			return false;
		}
		if (existed)
			goto next;
	}
	// success
	d->cgroup_path = strdup(tmp);
	if (!d->cgroup_path) {
		cleanup_cgroups(d, tmp);
		return false;
	}
	return true;
next:
	cleanup_cgroups(d, tmp);
	index++;
	goto again;
}

static inline bool cgm_enter(struct lxc_handler *handler)
{
	struct cgm_data *d = handler->cgroup_info->data;
	int i;

	for (i = 0; i < d->nr_subsystems; i++) {
		if (!lxc_cgmanager_enter(handler->pid, d->subsystems[i], d->cgroup_path))
			return false;
	}
	return true;
}

static char *cgm_get_cgroup(struct lxc_handler *handler, const char *subsystem)
{
	struct cgm_data *d = handler->cgroup_info->data;
	return d->cgroup_path;
}

int cgm_get(const char *filename, char *value, size_t len, const char *name, const char *lxcpath)
{
	char *result, *controller, *key, *cgroup;

	controller = alloca(strlen(filename)+1);
	key = strchr(controller, '.');
	if (!key)
		return false;
	*key = '\0';
	key++;

	/* use the command interface to look for the cgroup */
	cgroup = lxc_cmd_get_cgroup_path(name, lxcpath, controller);
	if (!cgroup) {
		ERROR("Failed to get cgroup for controller %s for %s:%s",
			controller, lxcpath, name);
		return false;
	}
	if (cgmanager_get_value_sync(NULL, cgroup_manager, controller, cgroup, key, &result) != 0) {
		ERROR("Error getting value for %s from cgmanager for cgroup %s (%s:%s)",
			filename, cgroup, lxcpath, name);
		free(cgroup);
		return false;
	}
	free(cgroup);
	strncpy(value, result, len);
	if (strlen(result) >= len)
		value[len-1] = '\0';
	free(result);
	return true;
}

int cgm_set(const char *filename, const char *value, const char *name, const char *lxcpath)
{
	char *controller, *key, *cgroup;

	controller = alloca(strlen(filename)+1);
	key = strchr(controller, '.');
	if (!key)
		return false;
	*key = '\0';
	key++;

	/* use the command interface to look for the cgroup */
	cgroup = lxc_cmd_get_cgroup_path(name, lxcpath, controller);
	if (!cgroup) {
		ERROR("Failed to get cgroup for controller %s for %s:%s",
			controller, lxcpath, name);
		return false;
	}
	if (cgmanager_set_value_sync(NULL, cgroup_manager, controller, cgroup, key, value) != 0) {
		ERROR("Error setting value for %s from cgmanager for cgroup %s (%s:%s)",
			filename, cgroup, lxcpath, name);
		free(cgroup);
		return false;
	}
	free(cgroup);
	return true;
}

/*
 * TODO really this should be done once for global data, not once
 * per container
 */
static inline bool cgm_init(struct lxc_handler *handler)
{
	struct cgm_data *d = malloc(sizeof(*d));
	char *line = NULL, *tab1;
	size_t sz = 0, i;
	FILE *f;

	if (!d)
		return false;
	d->nr_subsystems = 0;
	d->subsystems = NULL;
	f = fopen_cloexec("/proc/cgroups", "r");
	if (!f) {
		free(d);
		return false;
	}
	while (getline(&line, &sz, f) != -1) {
		char **tmp;
		if (line[0] == '#')
			continue;
		if (!line[0])
			continue;
		tab1 = strchr(line, '\t');
		if (!tab1)
			continue;
		*tab1 = '\0';
		tmp = realloc(d->subsystems, (d->nr_subsystems+1)*sizeof(char *));
		if (!tmp) {
			goto out_free;
		}
		d->subsystems = tmp;
		d->subsystems[d->nr_subsystems] = strdup(line);
		if (!d->subsystems[d->nr_subsystems])
			goto out_free;
		d->nr_subsystems++;
	}
	fclose(f);

	d->cgroup_path = NULL;
	handler->cgroup_info->data = d;
	return true;

out_free:
	for (i=0; i<d->nr_subsystems; i++)
		free(d->subsystems[i]);
	free(d->subsystems);
	free(d);
	return false;
}

static struct cgroup_ops cgmanager_ops = {
	.destroy = cgm_destroy,
	.init = cgm_init,
	.create = cgm_create,
	.enter = cgm_enter,
	.create_legacy = NULL,
	.get_cgroup = cgm_get_cgroup,
	.get = cgm_get,
	.set = cgm_set,
	.name = "cgmanager"
};
#endif

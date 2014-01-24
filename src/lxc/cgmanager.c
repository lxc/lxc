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
#include <nih/alloc.h>
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

static int send_creds(int sock, int rpid, int ruid, int rgid)
{
	struct msghdr msg = { 0 };
	struct iovec iov;
	struct cmsghdr *cmsg;
	struct ucred cred = {
		.pid = rpid,
		.uid = ruid,
		.gid = rgid,
	};
	char cmsgbuf[CMSG_SPACE(sizeof(cred))];
	char buf[1];
	buf[0] = 'p';

	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct ucred));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_CREDENTIALS;
	memcpy(CMSG_DATA(cmsg), &cred, sizeof(cred));

	msg.msg_name = NULL;
	msg.msg_namelen = 0;

	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	if (sendmsg(sock, &msg, 0) < 0) {
		perror("sendmsg");
		return -1;
	}
	return 0;
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

	return true;
}

struct chown_data {
	const char *controller;
	const char *cgroup_path;
};

static int do_chown_cgroup(const char *controller, const char *cgroup_path)
{
	int sv[2] = {-1, -1}, optval = 1;
	char buf[1];

	if (setgid(0) < 0)
		WARN("Failed to setgid to 0");
	if (setuid(0) < 0)
		WARN("Failed to setuid to 0");

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) {
		SYSERROR("Error creating socketpair");
		return -1;
	}
	if (setsockopt(sv[1], SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval)) == -1) {
		SYSERROR("setsockopt failed");
		return -1;
	}
	if (setsockopt(sv[0], SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval)) == -1) {
		SYSERROR("setsockopt failed");
		return -1;
	}
	if ( cgmanager_chown_scm_sync(NULL, cgroup_manager, controller,
				       cgroup_path, sv[1]) != 0) {
		ERROR("call to cgmanager_chown_scm_sync failed");
		return -1;
	}
	/* now send credentials */

	fd_set rfds;
	FD_ZERO(&rfds);
	FD_SET(sv[0], &rfds);
	if (select(sv[0]+1, &rfds, NULL, NULL, NULL) < 0) {
		ERROR("Error getting go-ahead from server: %s", strerror(errno));
		return -1;
	}
	if (read(sv[0], &buf, 1) != 1) {
		ERROR("Error getting reply from server over socketpair");
		return -1;
	}
	if (send_creds(sv[0], getpid(), getuid(), getgid())) {
		ERROR("Error sending pid over SCM_CREDENTIAL");
		return -1;
	}
	FD_ZERO(&rfds);
	FD_SET(sv[0], &rfds);
	if (select(sv[0]+1, &rfds, NULL, NULL, NULL) < 0) {
		ERROR("Error getting go-ahead from server: %s", strerror(errno));
		return -1;
	}
	if (read(sv[0], &buf, 1) != 1) {
		ERROR("Error getting reply from server over socketpair");
		return -1;
	}
	if (send_creds(sv[0], getpid(), 0, 0)) {
		ERROR("Error sending pid over SCM_CREDENTIAL");
		return -1;
	}
	FD_ZERO(&rfds);
	FD_SET(sv[0], &rfds);
	if (select(sv[0]+1, &rfds, NULL, NULL, NULL) < 0) {
		ERROR("Error getting go-ahead from server: %s", strerror(errno));
		return -1;
	}
	int ret = read(sv[0], buf, 1);
	close(sv[0]);
	close(sv[1]);
	if (ret == 1 && *buf == '1')
		return 0;
	return -1;
}

static int chown_cgroup_wrapper(void *data)
{
	struct chown_data *arg = data;
	return do_chown_cgroup(arg->controller, arg->cgroup_path);
}

static bool chown_cgroup(const char *controller, const char *cgroup_path,
			struct lxc_conf *conf)
{
	pid_t pid;
	struct chown_data data;
	data.controller = controller;
	data.cgroup_path = cgroup_path;

	if (lxc_list_empty(&conf->id_map)) {
		if (do_chown_cgroup(controller, cgroup_path) < 0)
			return false;
		return true;
	}

	if ((pid = fork()) < 0) {
		SYSERROR("fork");
		return false;
	}
	if (pid > 0) {
		if (wait_for_pid(pid)) {
			ERROR("Error chowning cgroup");
			return false;
		}
		return true;
	}
	if (userns_exec_1(conf, chown_cgroup_wrapper, &data) < 0)
		exit(1);
	exit(0);
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
	if (existed == -1)
		INFO("cgroup removal attempt: %s:%s did not exist", controller, path);
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
		if (existed == 1)
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
	size_t newlen;

	controller = alloca(strlen(filename)+1);
	strcpy(controller, filename);
	key = strchr(controller, '.');
	if (!key)
		return -1;
	*key = '\0';

	/* use the command interface to look for the cgroup */
	cgroup = lxc_cmd_get_cgroup_path(name, lxcpath, controller);
	if (!cgroup)
		return -1;
	if (cgmanager_get_value_sync(NULL, cgroup_manager, controller, cgroup, filename, &result) != 0) {
		ERROR("Error getting value for %s from cgmanager for cgroup %s (%s:%s)",
			filename, cgroup, lxcpath, name);
		free(cgroup);
		return -1;
	}
	free(cgroup);
	newlen = strlen(result);
	if (!value) {
		// user queries the size
		nih_free(result);
		return newlen+1;
	}

	strncpy(value, result, len);
	if (newlen >= len) {
		value[len-1] = '\0';
		newlen = len-1;
	} else if (newlen+1 < len) {
		// cgmanager doesn't add eol to last entry
		value[newlen++] = '\n';
		value[newlen] = '\0';
	}
	nih_free(result);
	return newlen;
}

static int cgm_do_set(const char *controller, const char *file,
			 const char *cgroup, const char *value)
{
	int ret;
	ret = cgmanager_set_value_sync(NULL, cgroup_manager, controller,
				 cgroup, file, value);
	if (ret != 0)
		ERROR("Error setting cgroup %s limit %s", file, cgroup);
	return ret;
}

int cgm_set(const char *filename, const char *value, const char *name, const char *lxcpath)
{
	char *controller, *key, *cgroup;
	int ret;

	controller = alloca(strlen(filename)+1);
	strcpy(controller, filename);
	key = strchr(controller, '.');
	if (!key)
		return -1;
	*key = '\0';

	/* use the command interface to look for the cgroup */
	cgroup = lxc_cmd_get_cgroup_path(name, lxcpath, controller);
	if (!cgroup) {
		ERROR("Failed to get cgroup for controller %s for %s:%s",
			controller, lxcpath, name);
		return -1;
	}
	ret = cgm_do_set(controller, filename, cgroup, value);
	free(cgroup);
	return ret;
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

static int cgm_unfreeze_fromhandler(struct lxc_handler *handler)
{
	struct cgm_data *d = handler->cgroup_info->data;

	if (cgmanager_set_value_sync(NULL, cgroup_manager, "freezer", d->cgroup_path,
			"freezer.state", "THAWED") != 0) {
		ERROR("Error unfreezing %s", d->cgroup_path);
		return -1;
	}
	return 0;
}

static bool setup_limits(struct lxc_handler *h, bool do_devices)
{
	struct lxc_list *iterator;
	struct lxc_cgroup *cg;
	bool ret = false;
	struct lxc_list *cgroup_settings = &h->conf->cgroup;
	struct cgm_data *d = h->cgroup_info->data;

	if (lxc_list_empty(cgroup_settings))
		return true;

	lxc_list_for_each(iterator, cgroup_settings) {
		char controller[100], *p;
		cg = iterator->elem;
		if (do_devices != !strncmp("devices", cg->subsystem, 7))
			continue;
		if (strlen(cg->subsystem) > 100) // i smell a rat
			goto out;
		strcpy(controller, cg->subsystem);
		p = strchr(controller, '.');
		if (p)
			*p = '\0';
		if (cgm_do_set(controller, cg->subsystem, d->cgroup_path
				, cg->value) < 0) {
			ERROR("Error setting %s to %s for %s\n",
			      cg->subsystem, cg->value, h->name);
			goto out;
		}

		DEBUG("cgroup '%s' set to '%s'", cg->subsystem, cg->value);
	}

	ret = true;
	INFO("cgroup limits have been setup");
out:
	return ret;
}

static bool cgm_setup_limits(struct lxc_handler *handler, bool with_devices)
{
	return setup_limits(handler, with_devices);
}

static bool cgm_chown(struct lxc_handler *handler)
{
	struct cgm_data *d = handler->cgroup_info->data;
	int i;

	for (i = 0; i < d->nr_subsystems; i++) {
		if (!chown_cgroup(d->subsystems[i], d->cgroup_path, handler->conf))
			WARN("Failed to chown %s:%s to container root",
				d->subsystems[i], d->cgroup_path);
	}
	return true;
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
	.unfreeze_fromhandler = cgm_unfreeze_fromhandler,
	.setup_limits = cgm_setup_limits,
	.name = "cgmanager",
	.chown = cgm_chown,
};
#endif

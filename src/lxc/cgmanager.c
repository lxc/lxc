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
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <ctype.h>
#include <pthread.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/inotify.h>
#include <sys/mount.h>
#include <netinet/in.h>
#include <net/if.h>
#include <poll.h>

#include "error.h"
#include "commands.h"
#include "list.h"
#include "conf.h"
#include "utils.h"
#include "bdev/bdev.h"
#include "log.h"
#include "cgroup.h"
#include "start.h"
#include "state.h"

#define CGM_SUPPORTS_GET_ABS 3
#define CGM_SUPPORTS_NAMED 4
#define CGM_SUPPORTS_MULT_CONTROLLERS 10

#ifdef HAVE_CGMANAGER
lxc_log_define(lxc_cgmanager, lxc);

#include <nih-dbus/dbus_connection.h>
#include <cgmanager/cgmanager-client.h>
#include <nih/alloc.h>
#include <nih/error.h>
#include <nih/string.h>

struct cgm_data {
	char *name;
	char *cgroup_path;
	const char *cgroup_pattern;
};

static pthread_mutex_t cgm_mutex = PTHREAD_MUTEX_INITIALIZER;

static void lock_mutex(pthread_mutex_t *l)
{
	int ret;

	if ((ret = pthread_mutex_lock(l)) != 0) {
		fprintf(stderr, "pthread_mutex_lock returned:%d %s\n", ret, strerror(ret));
		exit(1);
	}
}

static void unlock_mutex(pthread_mutex_t *l)
{
	int ret;

	if ((ret = pthread_mutex_unlock(l)) != 0) {
		fprintf(stderr, "pthread_mutex_unlock returned:%d %s\n", ret, strerror(ret));
		exit(1);
	}
}

void cgm_lock(void)
{
	lock_mutex(&cgm_mutex);
}

void cgm_unlock(void)
{
	unlock_mutex(&cgm_mutex);
}

#ifdef HAVE_PTHREAD_ATFORK
__attribute__((constructor))
static void process_lock_setup_atfork(void)
{
	pthread_atfork(cgm_lock, cgm_unlock, cgm_unlock);
}
#endif

static NihDBusProxy *cgroup_manager = NULL;
static int32_t api_version;

static struct cgroup_ops cgmanager_ops;
static int nr_subsystems;
static char **subsystems, **subsystems_inone;
static bool dbus_threads_initialized = false;
static void cull_user_controllers(void);

static void cgm_dbus_disconnect(void)
{
	if (cgroup_manager) {
		dbus_connection_flush(cgroup_manager->connection);
		dbus_connection_close(cgroup_manager->connection);
		nih_free(cgroup_manager);
	}
	cgroup_manager = NULL;
	cgm_unlock();
}

#define CGMANAGER_DBUS_SOCK "unix:path=/sys/fs/cgroup/cgmanager/sock"
static bool cgm_dbus_connect(void)
{
	DBusError dbus_error;
	static DBusConnection *connection;

	cgm_lock();
	if (!dbus_threads_initialized) {
		// tell dbus to do struct locking for thread safety
		dbus_threads_init_default();
		dbus_threads_initialized = true;
	}

	dbus_error_init(&dbus_error);

	connection = dbus_connection_open_private(CGMANAGER_DBUS_SOCK, &dbus_error);
	if (!connection) {
		DEBUG("Failed opening dbus connection: %s: %s",
				dbus_error.name, dbus_error.message);
		dbus_error_free(&dbus_error);
		cgm_unlock();
		return false;
	}
	dbus_connection_set_exit_on_disconnect(connection, FALSE);
	dbus_error_free(&dbus_error);
	cgroup_manager = nih_dbus_proxy_new(NULL, connection,
				NULL /* p2p */,
				"/org/linuxcontainers/cgmanager", NULL, NULL);
	dbus_connection_unref(connection);
	if (!cgroup_manager) {
		NihError *nerr;
		nerr = nih_error_get();
		ERROR("Error opening cgmanager proxy: %s", nerr->message);
		nih_free(nerr);
		cgm_dbus_disconnect();
		return false;
	}

	// get the api version
	if (cgmanager_get_api_version_sync(NULL, cgroup_manager, &api_version) != 0) {
		NihError *nerr;
		nerr = nih_error_get();
		ERROR("Error cgroup manager api version: %s", nerr->message);
		nih_free(nerr);
		cgm_dbus_disconnect();
		return false;
	}
	if (api_version < CGM_SUPPORTS_NAMED)
		cull_user_controllers();
	return true;
}

static bool cgm_all_controllers_same;

/*
 * Check whether we can use "all" when talking to cgmanager.
 * We check two things:
 * 1. whether cgmanager is new enough to support this.
 * 2. whether the task we are interested in is in the same
 *    cgroup for all controllers.
 * In cgm_init (before an lxc-start) we care about our own
 * cgroup.  In cgm_attach, we care about the target task's
 * cgroup.
 */
static void check_supports_multiple_controllers(pid_t pid)
{
	FILE *f;
	char *line = NULL, *prevpath = NULL;
	size_t sz = 0;
	char path[100];

	cgm_all_controllers_same = false;

	if (pid == -1)
		sprintf(path, "/proc/self/cgroup");
	else
		sprintf(path, "/proc/%d/cgroup", pid);
	f = fopen(path, "r");
	if (!f)
		return;

	cgm_all_controllers_same = true;

	while (getline(&line, &sz, f) != -1) {
		/* file format: hierarchy:subsystems:group */
		char *colon;
		if (!line[0])
			continue;

		colon = strchr(line, ':');
		if (!colon)
			continue;
		colon = strchr(colon+1, ':');
		if (!colon)
			continue;
		colon++;
		if (!prevpath) {
			prevpath = alloca(strlen(colon)+1);
			strcpy(prevpath, colon);
			continue;
		}
		if (strcmp(prevpath, colon) != 0) {
			cgm_all_controllers_same = false;
			break;
		}
	}

	fclose(f);
	free(line);
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

	if (sendmsg(sock, &msg, 0) < 0)
		return -1;
	return 0;
}

static bool lxc_cgmanager_create(const char *controller, const char *cgroup_path, int32_t *existed)
{
	bool ret = true;
	if ( cgmanager_create_sync(NULL, cgroup_manager, controller,
				       cgroup_path, existed) != 0) {
		NihError *nerr;
		nerr = nih_error_get();
		ERROR("call to cgmanager_create_sync failed: %s", nerr->message);
		nih_free(nerr);
		ERROR("Failed to create %s:%s", controller, cgroup_path);
		ret = false;
	}

	return ret;
}

/*
 * Escape to the root cgroup if we are root, so that the container will
 * be in "/lxc/c1" rather than "/user/..../c1"
 * called internally with connection already open
 */
static bool cgm_escape(void *hdata)
{
	bool ret = true, cgm_needs_disconnect = false;
	pid_t me = getpid();
	char **slist = subsystems;
	int i;

	if (!cgroup_manager) {
		if (!cgm_dbus_connect()) {
			ERROR("Error connecting to cgroup manager");
			return false;
		}
		cgm_needs_disconnect = true;
	}


	if (cgm_all_controllers_same)
		slist = subsystems_inone;

	for (i = 0; slist[i]; i++) {
		if (cgmanager_move_pid_abs_sync(NULL, cgroup_manager,
					slist[i], "/", me) != 0) {
			NihError *nerr;
			nerr = nih_error_get();
			ERROR("call to cgmanager_move_pid_abs_sync(%s) failed: %s",
					slist[i], nerr->message);
			nih_free(nerr);
			ret = false;
			break;
		}
	}

	if (cgm_needs_disconnect)
		cgm_dbus_disconnect();

	return ret;
}

struct chown_data {
	const char *cgroup_path;
	uid_t origuid;
};

static int do_chown_cgroup(const char *controller, const char *cgroup_path,
		uid_t newuid)
{
	int sv[2] = {-1, -1}, optval = 1, ret = -1;
	char buf[1];
	struct pollfd fds;

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) {
		SYSERROR("Error creating socketpair");
		goto out;
	}
	if (setsockopt(sv[1], SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval)) == -1) {
		SYSERROR("setsockopt failed");
		goto out;
	}
	if (setsockopt(sv[0], SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval)) == -1) {
		SYSERROR("setsockopt failed");
		goto out;
	}
	if ( cgmanager_chown_scm_sync(NULL, cgroup_manager, controller,
				       cgroup_path, sv[1]) != 0) {
		NihError *nerr;
		nerr = nih_error_get();
		ERROR("call to cgmanager_chown_scm_sync failed: %s", nerr->message);
		nih_free(nerr);
		goto out;
	}
	/* now send credentials */

	fds.fd = sv[0];
	fds.events = POLLIN;
	fds.revents = 0;
	if (poll(&fds, 1, -1) <= 0) {
		ERROR("Error getting go-ahead from server: %s", strerror(errno));
		goto out;
	}
	if (read(sv[0], &buf, 1) != 1) {
		ERROR("Error getting reply from server over socketpair");
		goto out;
	}
	if (send_creds(sv[0], getpid(), getuid(), getgid())) {
		SYSERROR("%s: Error sending pid over SCM_CREDENTIAL", __func__);
		goto out;
	}
	fds.fd = sv[0];
	fds.events = POLLIN;
	fds.revents = 0;
	if (poll(&fds, 1, -1) <= 0) {
		ERROR("Error getting go-ahead from server: %s", strerror(errno));
		goto out;
	}
	if (read(sv[0], &buf, 1) != 1) {
		ERROR("Error getting reply from server over socketpair");
		goto out;
	}
	if (send_creds(sv[0], getpid(), newuid, 0)) {
		SYSERROR("%s: Error sending pid over SCM_CREDENTIAL", __func__);
		goto out;
	}
	fds.fd = sv[0];
	fds.events = POLLIN;
	fds.revents = 0;
	if (poll(&fds, 1, -1) <= 0) {
		ERROR("Error getting go-ahead from server: %s", strerror(errno));
		goto out;
	}
	ret = read(sv[0], buf, 1);
out:
	close(sv[0]);
	close(sv[1]);
	if (ret == 1 && *buf == '1')
		return 0;
	return -1;
}

static int chown_cgroup_wrapper(void *data)
{
	struct chown_data *arg = data;
	char **slist = subsystems;
	int i, ret = -1;
	uid_t destuid;

	if (setresgid(0,0,0) < 0)
		SYSERROR("Failed to setgid to 0");
	if (setresuid(0,0,0) < 0)
		SYSERROR("Failed to setuid to 0");
	if (setgroups(0, NULL) < 0)
		SYSERROR("Failed to clear groups");
	cgm_dbus_disconnect();
	if (!cgm_dbus_connect()) {
		ERROR("Error connecting to cgroup manager");
		return -1;
	}
	destuid = get_ns_uid(arg->origuid);

	if (cgm_all_controllers_same)
		slist = subsystems_inone;

	for (i = 0; slist[i]; i++) {
		if (do_chown_cgroup(slist[i], arg->cgroup_path, destuid) < 0) {
			ERROR("Failed to chown %s:%s to container root",
				slist[i], arg->cgroup_path);
			goto fail;
		}
	}
	ret = 0;
fail:
	cgm_dbus_disconnect();
	return ret;
}

/* Internal helper.  Must be called with the cgmanager dbus socket open */
static bool lxc_cgmanager_chmod(const char *controller,
		const char *cgroup_path, const char *file, int mode)
{
	if (cgmanager_chmod_sync(NULL, cgroup_manager, controller,
			cgroup_path, file, mode) != 0) {
		NihError *nerr;
		nerr = nih_error_get();
		ERROR("call to cgmanager_chmod_sync failed: %s", nerr->message);
		nih_free(nerr);
		return false;
	}
	return true;
}

/* Internal helper.  Must be called with the cgmanager dbus socket open */
static bool chown_cgroup(const char *cgroup_path, struct lxc_conf *conf)
{
	struct chown_data data;
	char **slist = subsystems;
	int i;

	if (lxc_list_empty(&conf->id_map))
		/* If there's no mapping then we don't need to chown */
		return true;

	data.cgroup_path = cgroup_path;
	data.origuid = geteuid();

	/* Unpriv users can't chown it themselves, so chown from
	 * a child namespace mapping both our own and the target uid
	 */
	if (userns_exec_1(conf, chown_cgroup_wrapper, &data) < 0) {
		ERROR("Error requesting cgroup chown in new namespace");
		return false;
	}

	/*
	 * Now chmod 775 the directory else the container cannot create cgroups.
	 * This can't be done in the child namespace because it only group-owns
	 * the cgroup
	 */
	if (cgm_all_controllers_same)
		slist = subsystems_inone;

	for (i = 0; slist[i]; i++) {
		if (!lxc_cgmanager_chmod(slist[i], cgroup_path, "", 0775))
			return false;
		if (!lxc_cgmanager_chmod(slist[i], cgroup_path, "tasks", 0664))
			return false;
		if (!lxc_cgmanager_chmod(slist[i], cgroup_path, "cgroup.procs", 0664))
			return false;
	}

	return true;
}

#define CG_REMOVE_RECURSIVE 1
/* Internal helper.  Must be called with the cgmanager dbus socket open */
static void cgm_remove_cgroup(const char *controller, const char *path)
{
	int existed;
	if ( cgmanager_remove_sync(NULL, cgroup_manager, controller,
				   path, CG_REMOVE_RECURSIVE, &existed) != 0) {
		NihError *nerr;
		nerr = nih_error_get();
		ERROR("call to cgmanager_remove_sync failed: %s", nerr->message);
		nih_free(nerr);
		ERROR("Error removing %s:%s", controller, path);
	}
	if (existed == -1)
		INFO("cgroup removal attempt: %s:%s did not exist", controller, path);
}

static void *cgm_init(const char *name)
{
	struct cgm_data *d;

	d = malloc(sizeof(*d));
	if (!d)
		return NULL;

	if (!cgm_dbus_connect()) {
		ERROR("Error connecting to cgroup manager");
		goto err1;
	}

	memset(d, 0, sizeof(*d));
	d->name = strdup(name);
	if (!d->name) {
		cgm_dbus_disconnect();
		goto err1;
	}

	d->cgroup_pattern = lxc_global_config_value("lxc.cgroup.pattern");

	// cgm_create immediately gets called so keep the connection open
	return d;

err1:
	free(d);
	return NULL;
}

/* Called after a failed container startup */
static void cgm_destroy(void *hdata, struct lxc_conf *conf)
{
	struct cgm_data *d = hdata;
	char **slist = subsystems;
	int i;

	if (!d || !d->cgroup_path)
		return;
	if (!cgm_dbus_connect()) {
		ERROR("Error connecting to cgroup manager");
		return;
	}

	if (cgm_all_controllers_same)
		slist = subsystems_inone;
	for (i = 0; slist[i]; i++)
		cgm_remove_cgroup(slist[i], d->cgroup_path);

	free(d->name);
	free(d->cgroup_path);
	free(d);
	cgm_dbus_disconnect();
}

/*
 * remove all the cgroups created
 * called internally with dbus connection open
 */
static inline void cleanup_cgroups(char *path)
{
	int i;
	char **slist = subsystems;

	if (cgm_all_controllers_same)
		slist = subsystems_inone;
	for (i = 0; slist[i]; i++)
		cgm_remove_cgroup(slist[i], path);
}

static inline bool cgm_create(void *hdata)
{
	struct cgm_data *d = hdata;
	char **slist = subsystems;
	int i, index=0, baselen, ret;
	int32_t existed;
	char result[MAXPATHLEN], *tmp, *cgroup_path;

	if (!d)
		return false;
// XXX we should send a hint to the cgmanager that when these
// cgroups become empty they should be deleted.  Requires a cgmanager
// extension

	memset(result, 0, MAXPATHLEN);
	tmp = lxc_string_replace("%n", d->name, d->cgroup_pattern);
	if (!tmp)
		goto bad;
	if (strlen(tmp) >= MAXPATHLEN) {
		free(tmp);
		goto bad;
	}
	strcpy(result, tmp);
	baselen = strlen(result);
	free(tmp);
	tmp = result;
	while (*tmp == '/')
		tmp++;
again:
	if (index == 100) { // turn this into a warn later
		ERROR("cgroup error?  100 cgroups with this name already running");
		goto bad;
	}
	if (index) {
		ret = snprintf(result+baselen, MAXPATHLEN-baselen, "-%d", index);
		if (ret < 0 || ret >= MAXPATHLEN-baselen)
			goto bad;
	}
	existed = 0;

	if (cgm_all_controllers_same)
		slist = subsystems_inone;

	for (i = 0; slist[i]; i++) {
		if (!lxc_cgmanager_create(slist[i], tmp, &existed)) {
			ERROR("Error creating cgroup %s:%s", slist[i], result);
			cleanup_cgroups(tmp);
			goto bad;
		}
		if (existed == 1)
			goto next;
	}
	// success
	cgroup_path = strdup(tmp);
	if (!cgroup_path) {
		cleanup_cgroups(tmp);
		goto bad;
	}
	d->cgroup_path = cgroup_path;
	cgm_dbus_disconnect();
	return true;

next:
	index++;
	goto again;
bad:
	cgm_dbus_disconnect();
	return false;
}

/*
 * Use the cgmanager to move a task into a cgroup for a particular
 * hierarchy.
 * All the subsystems in this hierarchy are co-mounted, so we only
 * need to transition the task into one of the cgroups
 *
 * Internal helper, must be called with cgmanager dbus socket open
 */
static bool lxc_cgmanager_enter(pid_t pid, const char *controller,
		const char *cgroup_path, bool abs)
{
	int ret;

	if (abs)
		ret = cgmanager_move_pid_abs_sync(NULL, cgroup_manager,
			controller, cgroup_path, pid);
	else
		ret = cgmanager_move_pid_sync(NULL, cgroup_manager,
			controller, cgroup_path, pid);
	if (ret != 0) {
		NihError *nerr;
		nerr = nih_error_get();
		WARN("call to cgmanager_move_pid_%ssync failed: %s",
			abs ? "abs_" : "", nerr->message);
		nih_free(nerr);
		return false;
	}
	return true;
}

static inline bool cgm_enter(void *hdata, pid_t pid)
{
	struct cgm_data *d = hdata;
	char **slist = subsystems;
	bool ret = false;
	int i;

	if (!d || !d->cgroup_path)
		return false;

	if (!cgm_dbus_connect()) {
		ERROR("Error connecting to cgroup manager");
		return false;
	}

	if (cgm_all_controllers_same)
		slist = subsystems_inone;

	for (i = 0; slist[i]; i++) {
		if (!lxc_cgmanager_enter(pid, slist[i], d->cgroup_path, false))
			goto out;
	}
	ret = true;
out:
	cgm_dbus_disconnect();
	return ret;
}

static const char *cgm_get_cgroup(void *hdata, const char *subsystem)
{
	struct cgm_data *d = hdata;

	if (!d || !d->cgroup_path)
		return NULL;
	return d->cgroup_path;
}

static const char *cgm_canonical_path(void *hdata)
{
	struct cgm_data *d = hdata;

	if (!d || !d->cgroup_path)
		return NULL;
	return d->cgroup_path;
}

#if HAVE_CGMANAGER_GET_PID_CGROUP_ABS_SYNC
static inline bool abs_cgroup_supported(void) {
	return api_version >= CGM_SUPPORTS_GET_ABS;
}
#else
static inline bool abs_cgroup_supported(void) {
	return false;
}
#define cgmanager_get_pid_cgroup_abs_sync(...) -1
#endif

static char *try_get_abs_cgroup(const char *name, const char *lxcpath,
		const char *controller)
{
	char *cgroup = NULL;

	if (abs_cgroup_supported()) {
		/* get the container init pid and ask for its abs cgroup */
		pid_t pid = lxc_cmd_get_init_pid(name, lxcpath);
		if (pid < 0)
			return NULL;
		if (cgmanager_get_pid_cgroup_abs_sync(NULL, cgroup_manager,
				controller, pid, &cgroup) != 0) {
			cgroup = NULL;
			NihError *nerr;
			nerr = nih_error_get();
			nih_free(nerr);
		} else
			prune_init_scope(cgroup);
		return cgroup;
	}

	/* use the command interface to look for the cgroup */
	return lxc_cmd_get_cgroup_path(name, lxcpath, controller);
}

/*
 * nrtasks is called by the utmp helper by the container monitor.
 * cgmanager socket was closed after cgroup setup was complete, so we need
 * to reopen here.
 *
 * Return -1 on error.
 */
static int cgm_get_nrtasks(void *hdata)
{
	struct cgm_data *d = hdata;
	int32_t *pids;
	size_t pids_len;

	if (!d || !d->cgroup_path)
		return -1;

	if (!cgm_dbus_connect()) {
		ERROR("Error connecting to cgroup manager");
		return -1;
	}
	if (cgmanager_get_tasks_sync(NULL, cgroup_manager, subsystems[0],
				     d->cgroup_path, &pids, &pids_len) != 0) {
		NihError *nerr;
		nerr = nih_error_get();
		ERROR("call to cgmanager_get_tasks_sync failed: %s", nerr->message);
		nih_free(nerr);
		pids_len = -1;
		goto out;
	}
	nih_free(pids);
out:
	cgm_dbus_disconnect();
	return pids_len;
}

#if HAVE_CGMANAGER_LIST_CONTROLLERS
static bool lxc_list_controllers(char ***list)
{
	if (!cgm_dbus_connect()) {
		ERROR("Error connecting to cgroup manager");
		return false;
	}
	if (cgmanager_list_controllers_sync(NULL, cgroup_manager, list) != 0) {
		NihError *nerr;
		nerr = nih_error_get();
		ERROR("call to cgmanager_list_controllers_sync failed: %s", nerr->message);
		nih_free(nerr);
		cgm_dbus_disconnect();
		return false;
	}

	cgm_dbus_disconnect();
	return true;
}
#else
static bool lxc_list_controllers(char ***list)
{
	return false;
}
#endif

static inline void free_abs_cgroup(char *cgroup)
{
	if (!cgroup)
		return;
	if (abs_cgroup_supported())
		nih_free(cgroup);
	else
		free(cgroup);
}

static void do_cgm_get(const char *name, const char *lxcpath, const char *filename, int outp, bool sendvalue)
{
	char *controller, *key, *cgroup = NULL, *cglast;
	int len = -1;
	int ret;
	nih_local char *result = NULL;

	controller = alloca(strlen(filename)+1);
	strcpy(controller, filename);
	key = strchr(controller, '.');
	if (!key) {
		ret = write(outp, &len, sizeof(len));
		if (ret != sizeof(len))
			WARN("Failed to warn cgm_get of error; parent may hang");
		exit(1);
	}
	*key = '\0';

	if (!cgm_dbus_connect()) {
		ERROR("Error connecting to cgroup manager");
		ret = write(outp, &len, sizeof(len));
		if (ret != sizeof(len))
			WARN("Failed to warn cgm_get of error; parent may hang");
		exit(1);
	}
	cgroup = try_get_abs_cgroup(name, lxcpath, controller);
	if (!cgroup) {
		cgm_dbus_disconnect();
		ret = write(outp, &len, sizeof(len));
		if (ret != sizeof(len))
			WARN("Failed to warn cgm_get of error; parent may hang");
		exit(1);
	}
	cglast = strrchr(cgroup, '/');
	if (!cglast) {
		cgm_dbus_disconnect();
		free_abs_cgroup(cgroup);
		ret = write(outp, &len, sizeof(len));
		if (ret != sizeof(len))
			WARN("Failed to warn cgm_get of error; parent may hang");
		exit(1);
	}
	*cglast = '\0';
	if (!lxc_cgmanager_enter(getpid(), controller, cgroup, abs_cgroup_supported())) {
		WARN("Failed to enter container cgroup %s:%s", controller, cgroup);
		ret = write(outp, &len, sizeof(len));
		if (ret != sizeof(len))
			WARN("Failed to warn cgm_get of error; parent may hang");
		cgm_dbus_disconnect();
		free_abs_cgroup(cgroup);
		exit(1);
	}
	if (cgmanager_get_value_sync(NULL, cgroup_manager, controller, cglast+1, filename, &result) != 0) {
		NihError *nerr;
		nerr = nih_error_get();
		nih_free(nerr);
		free_abs_cgroup(cgroup);
		cgm_dbus_disconnect();
		ret = write(outp, &len, sizeof(len));
		if (ret != sizeof(len))
			WARN("Failed to warn cgm_get of error; parent may hang");
		exit(1);
	}
	free_abs_cgroup(cgroup);
	cgm_dbus_disconnect();
	len = strlen(result);
	ret = write(outp, &len, sizeof(len));
	if (ret != sizeof(len)) {
		WARN("Failed to send length to parent");
		exit(1);
	}
	if (!len || !sendvalue) {
		exit(0);
	}
	ret = write(outp, result, len);
	if (ret < 0)
		exit(1);
	exit(0);
}

/* cgm_get is called to get container cgroup settings, not during startup */
static int cgm_get(const char *filename, char *value, size_t len, const char *name, const char *lxcpath)
{
	pid_t pid;
	int p[2], ret, newlen, readlen;

	if (pipe(p) < 0)
		return -1;
	if ((pid = fork()) < 0) {
		close(p[0]);
		close(p[1]);
		return -1;
	}
	if (!pid) // do_cgm_get exits
		do_cgm_get(name, lxcpath, filename, p[1], len && value);
	close(p[1]);
	ret = read(p[0], &newlen, sizeof(newlen));
	if (ret != sizeof(newlen)) {
		close(p[0]);
		ret = -1;
		goto out;
	}
	if (!len || !value) {
		close(p[0]);
		ret = newlen;
		goto out;
	}
	memset(value, 0, len);
	if (newlen < 0) { // child is reporting an error
		close(p[0]);
		ret = -1;
		goto out;
	}
	if (newlen == 0) { // empty read
		close(p[0]);
		ret = 0;
		goto out;
	}
	readlen = newlen > len ? len : newlen;
	ret = read(p[0], value, readlen);
	close(p[0]);
	if (ret != readlen) {
		ret = -1;
		goto out;
	}
	if (newlen >= len) {
		value[len-1] = '\0';
		newlen = len-1;
	} else if (newlen+1 < len) {
		// cgmanager doesn't add eol to last entry
		value[newlen++] = '\n';
		value[newlen] = '\0';
	}
	ret = newlen;
out:
	if (wait_for_pid(pid))
		WARN("do_cgm_get exited with error");
	return ret;
}

static void do_cgm_set(const char *name, const char *lxcpath, const char *filename, const char *value, int outp)
{
	char *controller, *key, *cgroup = NULL;
	int retval = 0;  // value we are sending to the parent over outp
	int ret;
	char *cglast;

	controller = alloca(strlen(filename)+1);
	strcpy(controller, filename);
	key = strchr(controller, '.');
	if (!key) {
		ret = write(outp, &retval, sizeof(retval));
		if (ret != sizeof(retval))
			WARN("Failed to warn cgm_set of error; parent may hang");
		exit(1);
	}
	*key = '\0';

	if (!cgm_dbus_connect()) {
		ERROR("Error connecting to cgroup manager");
		ret = write(outp, &retval, sizeof(retval));
		if (ret != sizeof(retval))
			WARN("Failed to warn cgm_set of error; parent may hang");
		exit(1);
	}
	cgroup = try_get_abs_cgroup(name, lxcpath, controller);
	if (!cgroup) {
		cgm_dbus_disconnect();
		ret = write(outp, &retval, sizeof(retval));
		if (ret != sizeof(retval))
			WARN("Failed to warn cgm_set of error; parent may hang");
		exit(1);
	}
	cglast = strrchr(cgroup, '/');
	if (!cglast) {
		cgm_dbus_disconnect();
		free_abs_cgroup(cgroup);
		ret = write(outp, &retval, sizeof(retval));
		if (ret != sizeof(retval))
			WARN("Failed to warn cgm_set of error; parent may hang");
		exit(1);
	}
	*cglast = '\0';
	if (!lxc_cgmanager_enter(getpid(), controller, cgroup, abs_cgroup_supported())) {
		ERROR("Failed to enter container cgroup %s:%s", controller, cgroup);
		ret = write(outp, &retval, sizeof(retval));
		if (ret != sizeof(retval))
			WARN("Failed to warn cgm_set of error; parent may hang");
		cgm_dbus_disconnect();
		free_abs_cgroup(cgroup);
		exit(1);
	}
	if (cgmanager_set_value_sync(NULL, cgroup_manager, controller, cglast+1, filename, value) != 0) {
		NihError *nerr;
		nerr = nih_error_get();
		ERROR("Error setting cgroup value %s for %s:%s", filename, controller, cgroup);
		ERROR("call to cgmanager_set_value_sync failed: %s", nerr->message);
		nih_free(nerr);
		free_abs_cgroup(cgroup);
		cgm_dbus_disconnect();
		ret = write(outp, &retval, sizeof(retval));
		if (ret != sizeof(retval))
			WARN("Failed to warn cgm_set of error; parent may hang");
		exit(1);
	}
	free_abs_cgroup(cgroup);
	cgm_dbus_disconnect();
	/* tell parent that we are done */
	retval = 1;
	ret = write(outp, &retval, sizeof(retval));
	if (ret != sizeof(retval)) {
		exit(1);
	}
	exit(0);
}

/* cgm_set is called to change cgroup settings, not during startup */
static int cgm_set(const char *filename, const char *value, const char *name, const char *lxcpath)
{
	pid_t pid;
	int p[2], ret, v;

	if (pipe(p) < 0)
		return -1;
	if ((pid = fork()) < 0) {
		close(p[1]);
		close(p[0]);
		return -1;
	}
	if (!pid) // do_cgm_set exits
		do_cgm_set(name, lxcpath, filename, value, p[1]);
	close(p[1]);
	ret = read(p[0], &v, sizeof(v));
	close(p[0]);
	if (wait_for_pid(pid))
		WARN("do_cgm_set exited with error");
	if (ret != sizeof(v) || !v)
		return -1;
	return 0;
}

static void free_subsystems(void)
{
	int i;

	for (i = 0; i < nr_subsystems; i++)
		free(subsystems[i]);
	free(subsystems);
	subsystems = NULL;
	nr_subsystems = 0;
}

static void cull_user_controllers(void)
{
	int i, j;

	for (i = 0;  i < nr_subsystems; i++) {
		if (strncmp(subsystems[i], "name=", 5) != 0)
			continue;
		for (j = i;  j < nr_subsystems-1; j++)
			subsystems[j] = subsystems[j+1];
		nr_subsystems--;
	}
}

/*
 * return true if inword is in the comma-delimited list cgroup_use
 */
static bool in_comma_list(const char *inword, const char *cgroup_use)
{
	char *e;
	size_t inlen = strlen(inword), len;

	do {
		e = strchr(cgroup_use, ',');
		len = e ? e - cgroup_use : strlen(cgroup_use);
		if (len == inlen && strncmp(inword, cgroup_use, len) == 0)
			return true;
		cgroup_use = e + 1;
	} while (e);

	return false;
}

/*
 * inlist is a comma-delimited list of cgroups;  so is checklist.  Return
 * true if any member of inlist is in checklist.
 */
static bool any_in_comma_list(const char *inlist, const char *checklist)
{
	char *tmp = alloca(strlen(inlist) + 1), *tok, *saveptr = NULL;

	strcpy(tmp, inlist);
	for (tok = strtok_r(tmp, ",", &saveptr); tok; tok = strtok_r(NULL, ",", &saveptr)) {
		if (in_comma_list(tok, checklist))
			return true;
	}

	return false;
}

static bool in_subsystem_list(const char *c)
{
	int i;

	for (i = 0; i < nr_subsystems; i++) {
		if (strcmp(c, subsystems[i]) == 0)
			return true;
	}

	return false;
}

/*
 * If /etc/lxc/lxc.conf specifies lxc.cgroup.use = "freezer,memory",
 * then clear out any other subsystems, and make sure that freezer
 * and memory are both enabled
 */
static bool verify_and_prune(const char *cgroup_use)
{
	const char *p;
	char *e;
	int i, j;

	for (p = cgroup_use; p && *p; p = e + 1) {
		e = strchr(p, ',');
		if (e)
			*e = '\0';

		if (!in_subsystem_list(p)) {
			ERROR("Controller %s required by lxc.cgroup.use but not available\n", p);
			return false;
		}

		if (e)
			*e = ',';
		if (!e)
			break;
	}

	for (i = 0; i < nr_subsystems;) {
		if (in_comma_list(subsystems[i], cgroup_use)) {
			i++;
			continue;
		}
		free(subsystems[i]);
		for (j = i;  j < nr_subsystems-1; j++)
			subsystems[j] = subsystems[j+1];
		subsystems[nr_subsystems-1] = NULL;
		nr_subsystems--;
	}

	return true;
}

static void drop_subsystem(int which)
{
	int i;

	if (which < 0 || which >= nr_subsystems) {
		ERROR("code error: dropping invalid subsystem index\n");
		exit(1);
	}

	free(subsystems[which]);
	/* note - we have nr_subsystems+1 entries, last one a NULL */
	for (i = which; i < nr_subsystems; i++)
		subsystems[i] = subsystems[i+1];
	nr_subsystems -= 1;
}

/*
 * Check whether we can create the cgroups we would want
 */
static bool subsys_is_writeable(const char *controller, const char *probe)
{
	int32_t existed;
	bool ret = true;

	if ( cgmanager_create_sync(NULL, cgroup_manager, controller,
				       probe, &existed) != 0) {
		NihError *nerr;
		nerr = nih_error_get();
		ERROR("call to cgmanager_create_sync failed: %s", nerr->message);
		nih_free(nerr);
		ERROR("Failed to create %s:%s", controller, probe);
		ret = false;
	}

	return ret;
}

static char *get_last_controller_in_list(char *list)
{
	char *p;

	while ((p = strchr(list, ',')) != NULL)
		list = p + 1;

	return list;
}

/*
 * Make sure that all the controllers are writeable.
 * If any are not, then
 *   - if they are listed in lxc.cgroup.use, refuse to start
 *   - else if they are crucial subsystems, refuse to start
 *   - else warn and do not use them
 */
static bool verify_final_subsystems(const char *cgroup_use)
{
	int i;
	bool dropped_any = false;
	bool bret = false;
	const char *cgroup_pattern;
	char tmpnam[50], *probe;

	if (!cgm_dbus_connect()) {
		ERROR("Error connecting to cgroup manager");
		return false;
	}

	cgroup_pattern = lxc_global_config_value("lxc.cgroup.pattern");
	i = snprintf(tmpnam, 50, "lxcprobe-%d", getpid());
	if (i < 0 || i >= 50) {
		ERROR("Attack - format string modified?");
		return false;
	}
	probe = lxc_string_replace("%n", tmpnam, cgroup_pattern);
	if (!probe)
		goto out;

	i = 0;
	while (i < nr_subsystems) {
		char *p = get_last_controller_in_list(subsystems[i]);

		if (!subsys_is_writeable(p, probe)) {
			if (is_crucial_cgroup_subsystem(p)) {
				ERROR("Cannot write to crucial subsystem %s\n",
					subsystems[i]);
				goto out;
			}
			if (cgroup_use && any_in_comma_list(subsystems[i], cgroup_use)) {
				ERROR("Cannot write to subsystem %s which is requested in lxc.cgroup.use\n",
					subsystems[i]);
				goto out;
			}
			WARN("Cannot write to subsystem %s, continuing with out it\n",
				subsystems[i]);
			dropped_any = true;
			drop_subsystem(i);
		} else {
			cgm_remove_cgroup(subsystems[i], probe);
			i++;
		}
	}

	if (dropped_any)
		cgm_all_controllers_same = false;
	bret = true;

out:
	free(probe);
	cgm_dbus_disconnect();
	return bret;
}

static bool collect_subsystems(void)
{
	char *line = NULL;
	nih_local char **cgm_subsys_list = NULL;
	size_t sz = 0;
	FILE *f = NULL;

	if (subsystems) // already initialized
		return true;

	subsystems_inone = malloc(2 * sizeof(char *));
	if (!subsystems_inone)
		return false;
	subsystems_inone[0] = "all";
	subsystems_inone[1] = NULL;

	if (lxc_list_controllers(&cgm_subsys_list)) {
		while (cgm_subsys_list[nr_subsystems]) {
			char **tmp = NIH_MUST( realloc(subsystems,
						(nr_subsystems+2)*sizeof(char *)) );
			tmp[nr_subsystems] = NIH_MUST(
					strdup(cgm_subsys_list[nr_subsystems++]) );
			subsystems = tmp;
		}
		if (nr_subsystems)
			subsystems[nr_subsystems] = NULL;
		goto collected;
	}

	INFO("cgmanager_list_controllers failed, falling back to /proc/self/cgroups");
	f = fopen_cloexec("/proc/self/cgroup", "r");
	if (!f) {
		f = fopen_cloexec("/proc/1/cgroup", "r");
		if (!f)
			return false;
	}
	while (getline(&line, &sz, f) != -1) {
		/* file format: hierarchy:subsystems:group,
		 * with multiple subsystems being ,-separated */
		char *slist, *end, *p, *saveptr = NULL, **tmp;

		if (!line[0])
			continue;

		slist = strchr(line, ':');
		if (!slist)
			continue;
		slist++;
		end = strchr(slist, ':');
		if (!end)
			continue;
		*end = '\0';

		for (p = strtok_r(slist, ",", &saveptr);
				p;
				p = strtok_r(NULL, ",", &saveptr)) {
			tmp = realloc(subsystems, (nr_subsystems+2)*sizeof(char *));
			if (!tmp)
				goto out_free;

			subsystems = tmp;
			tmp[nr_subsystems] = strdup(p);
			tmp[nr_subsystems+1] = NULL;
			if (!tmp[nr_subsystems])
				goto out_free;
			nr_subsystems++;
		}
	}
	fclose(f);
	f = NULL;

	free(line);
	line = NULL;

collected:
	if (!nr_subsystems) {
		ERROR("No cgroup subsystems found");
		return false;
	}

	/* make sure that cgroup.use can be and is honored */
	const char *cgroup_use = lxc_global_config_value("lxc.cgroup.use");
	if (!cgroup_use && errno != 0)
		goto final_verify;
	if (cgroup_use) {
		if (!verify_and_prune(cgroup_use)) {
			free_subsystems();
			return false;
		}
		subsystems_inone[0] = NIH_MUST( strdup(cgroup_use) );
		cgm_all_controllers_same = false;
	}

final_verify:
	return verify_final_subsystems(cgroup_use);

out_free:
	free(line);
	if (f)
		fclose(f);
	free_subsystems();
	return false;
}

/*
 * called during cgroup.c:cgroup_ops_init(), at startup.  No threads.
 * We check whether we can talk to cgmanager, escape to root cgroup if
 * we are root, then close the connection.
 */
struct cgroup_ops *cgm_ops_init(void)
{
	check_supports_multiple_controllers(-1);
	if (!collect_subsystems())
		return NULL;

	if (api_version < CGM_SUPPORTS_MULT_CONTROLLERS)
		cgm_all_controllers_same = false;

	// if root, try to escape to root cgroup
	if (geteuid() == 0 && !cgm_escape(NULL)) {
		free_subsystems();
		return NULL;
	}

	return &cgmanager_ops;
}

/* unfreeze is called by the command api after killing a container.  */
static bool cgm_unfreeze(void *hdata)
{
	struct cgm_data *d = hdata;
	bool ret = true;

	if (!d || !d->cgroup_path)
		return false;

	if (!cgm_dbus_connect()) {
		ERROR("Error connecting to cgroup manager");
		return false;
	}
	if (cgmanager_set_value_sync(NULL, cgroup_manager, "freezer", d->cgroup_path,
			"freezer.state", "THAWED") != 0) {
		NihError *nerr;
		nerr = nih_error_get();
		ERROR("call to cgmanager_set_value_sync failed: %s", nerr->message);
		nih_free(nerr);
		ERROR("Error unfreezing %s", d->cgroup_path);
		ret = false;
	}
	cgm_dbus_disconnect();
	return ret;
}

static bool cgm_setup_limits(void *hdata, struct lxc_list *cgroup_settings, bool do_devices)
{
	struct cgm_data *d = hdata;
	struct lxc_list *iterator, *sorted_cgroup_settings, *next;
	struct lxc_cgroup *cg;
	bool ret = false;

	if (lxc_list_empty(cgroup_settings))
		return true;

	if (!d || !d->cgroup_path)
		return false;

	if (!cgm_dbus_connect()) {
		ERROR("Error connecting to cgroup manager");
		return false;
	}

	sorted_cgroup_settings = sort_cgroup_settings(cgroup_settings);
	if (!sorted_cgroup_settings) {
		return false;
	}

	lxc_list_for_each(iterator, sorted_cgroup_settings) {
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
		if (cgmanager_set_value_sync(NULL, cgroup_manager, controller,
					 d->cgroup_path, cg->subsystem, cg->value) != 0) {
			NihError *nerr;
			nerr = nih_error_get();
			if (do_devices) {
				WARN("call to cgmanager_set_value_sync failed: %s", nerr->message);
				nih_free(nerr);
				WARN("Error setting cgroup %s:%s limit type %s", controller,
					d->cgroup_path, cg->subsystem);
				continue;
			}

			ERROR("call to cgmanager_set_value_sync failed: %s", nerr->message);
			nih_free(nerr);
			ERROR("Error setting cgroup %s:%s limit type %s", controller,
				d->cgroup_path, cg->subsystem);
			goto out;
		}

		DEBUG("cgroup '%s' set to '%s'", cg->subsystem, cg->value);
	}

	ret = true;
	INFO("cgroup limits have been setup");
out:
	lxc_list_for_each_safe(iterator, sorted_cgroup_settings, next) {
		lxc_list_del(iterator);
		free(iterator);
	}
	free(sorted_cgroup_settings);
	cgm_dbus_disconnect();
	return ret;
}

static bool cgm_chown(void *hdata, struct lxc_conf *conf)
{
	struct cgm_data *d = hdata;

	if (!d || !d->cgroup_path)
		return false;
	if (!cgm_dbus_connect()) {
		ERROR("Error connecting to cgroup manager");
		return false;
	}
	if (!chown_cgroup(d->cgroup_path, conf))
		WARN("Failed to chown %s to container root", d->cgroup_path);
	cgm_dbus_disconnect();
	return true;
}

/*
 * TODO: this should be re-written to use the get_config_item("lxc.id_map")
 * cmd api instead of getting the idmap from c->lxc_conf.  The reason is
 * that the id_maps may be different if the container was started with a
 * -f or -s argument.
 * The reason I'm punting on that is because we'll need to parse the
 * idmap results.
 */
static bool cgm_attach(const char *name, const char *lxcpath, pid_t pid)
{
	bool pass = true;
	char *cgroup = NULL;
	char **slist = subsystems;
	int i;

	if (!cgm_dbus_connect()) {
		ERROR("Error connecting to cgroup manager");
		return false;
	}

	for (i = 0; slist[i]; i++) {
		cgroup = try_get_abs_cgroup(name, lxcpath, slist[i]);
		if (!cgroup) {
			ERROR("Failed to get cgroup for controller %s", slist[i]);
			cgm_dbus_disconnect();
			return false;
		}

		if (!lxc_cgmanager_enter(pid, slist[i], cgroup, abs_cgroup_supported())) {
			pass = false;
			break;
		}

	}
	cgm_dbus_disconnect();
	if (!pass)
		ERROR("Failed to enter group %s", cgroup);

	free_abs_cgroup(cgroup);
	return pass;
}

static bool cgm_bind_dir(const char *root, const char *dirname)
{
	nih_local char *cgpath = NULL;

	/* /sys should have been mounted by now */
	cgpath = NIH_MUST( nih_strdup(NULL, root) );
	NIH_MUST( nih_strcat(&cgpath, NULL, "/sys/fs/cgroup") );

	if (!dir_exists(cgpath)) {
		ERROR("%s does not exist", cgpath);
		return false;
	}

	/* mount a tmpfs there so we can create subdirs */
	if (safe_mount("cgroup", cgpath, "tmpfs", 0, "size=10000,mode=755", root)) {
		SYSERROR("Failed to mount tmpfs at %s", cgpath);
		return false;
	}
	NIH_MUST( nih_strcat(&cgpath, NULL, "/cgmanager") );

	if (mkdir(cgpath, 0755) < 0) {
		SYSERROR("Failed to create %s", cgpath);
		return false;
	}

	if (safe_mount(dirname, cgpath, "none", MS_BIND, 0, root)) {
		SYSERROR("Failed to bind mount %s to %s", dirname, cgpath);
		return false;
	}

	return true;
}

/*
 * cgm_mount_cgroup:
 * If /sys/fs/cgroup/cgmanager.lower/ exists, bind mount that to
 * /sys/fs/cgroup/cgmanager/ in the container.
 * Otherwise, if /sys/fs/cgroup/cgmanager exists, bind mount that.
 * Else do nothing
 */
#define CGMANAGER_LOWER_SOCK "/sys/fs/cgroup/cgmanager.lower"
#define CGMANAGER_UPPER_SOCK "/sys/fs/cgroup/cgmanager"
static bool cgm_mount_cgroup(void *hdata, const char *root, int type)
{
	if (dir_exists(CGMANAGER_LOWER_SOCK))
		return cgm_bind_dir(root, CGMANAGER_LOWER_SOCK);
	if (dir_exists(CGMANAGER_UPPER_SOCK))
		return cgm_bind_dir(root, CGMANAGER_UPPER_SOCK);
	// Host doesn't have cgmanager running?  Then how did we get here?
	return false;
}

static struct cgroup_ops cgmanager_ops = {
	.init = cgm_init,
	.destroy = cgm_destroy,
	.create = cgm_create,
	.enter = cgm_enter,
	.create_legacy = NULL,
	.get_cgroup = cgm_get_cgroup,
	.canonical_path = cgm_canonical_path,
	.escape = cgm_escape,
	.get = cgm_get,
	.set = cgm_set,
	.unfreeze = cgm_unfreeze,
	.setup_limits = cgm_setup_limits,
	.name = "cgmanager",
	.chown = cgm_chown,
	.attach = cgm_attach,
	.mount_cgroup = cgm_mount_cgroup,
	.nrtasks = cgm_get_nrtasks,
	.disconnect = NULL,
	.driver = CGMANAGER,
};
#endif

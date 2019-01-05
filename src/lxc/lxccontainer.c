/* liblxcapi
 *
 * Copyright © 2012 Serge Hallyn <serge.hallyn@ubuntu.com>.
 * Copyright © 2012 Canonical Ltd.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.

 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.

 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <libgen.h>
#include <pthread.h>
#include <sched.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../include/netns_ifaddrs.h"
#include "af_unix.h"
#include "attach.h"
#include "cgroup.h"
#include "commands.h"
#include "commands_utils.h"
#include "conf.h"
#include "config.h"
#include "confile.h"
#include "confile_utils.h"
#include "criu.h"
#include "error.h"
#include "initutils.h"
#include "log.h"
#include "lxc.h"
#include "lxccontainer.h"
#include "lxclock.h"
#include "monitor.h"
#include "namespace.h"
#include "network.h"
#include "parse.h"
#include "raw_syscalls.h"
#include "start.h"
#include "state.h"
#include "storage.h"
#include "storage/btrfs.h"
#include "storage/overlay.h"
#include "storage_utils.h"
#include "sync.h"
#include "syscall_wrappers.h"
#include "terminal.h"
#include "utils.h"
#include "version.h"

/* major()/minor() */
#ifdef MAJOR_IN_MKDEV
#include <sys/mkdev.h>
#endif

#if IS_BIONIC
#include <../include/lxcmntent.h>
#else
#include <mntent.h>
#endif

#ifndef HAVE_STRLCPY
#include "include/strlcpy.h"
#endif

/* Define faccessat() if missing from the C library */
#ifndef HAVE_FACCESSAT
static int faccessat(int __fd, const char *__file, int __type, int __flag)
{
#ifdef __NR_faccessat
	return syscall(__NR_faccessat, __fd, __file, __type, __flag);
#else
	errno = ENOSYS;
	return -1;
#endif
}
#endif

lxc_log_define(lxccontainer, lxc);

static bool do_lxcapi_destroy(struct lxc_container *c);
static const char *lxcapi_get_config_path(struct lxc_container *c);
#define do_lxcapi_get_config_path(c) lxcapi_get_config_path(c)
static bool do_lxcapi_set_config_item(struct lxc_container *c, const char *key, const char *v);
static bool container_destroy(struct lxc_container *c,
			      struct lxc_storage *storage);
static bool get_snappath_dir(struct lxc_container *c, char *snappath);
static bool lxcapi_snapshot_destroy_all(struct lxc_container *c);
static bool do_lxcapi_save_config(struct lxc_container *c, const char *alt_file);

static bool config_file_exists(const char *lxcpath, const char *cname)
{
	int ret;
	size_t len;
	char *fname;

	/* $lxcpath + '/' + $cname + '/config' + \0 */
	len = strlen(lxcpath) + strlen(cname) + 9;
	fname = alloca(len);
	ret = snprintf(fname, len, "%s/%s/config", lxcpath, cname);
	if (ret < 0 || (size_t)ret >= len)
		return false;

	return file_exists(fname);
}

/* A few functions to help detect when a container creation failed. If a
 * container creation was killed partway through, then trying to actually start
 * that container could harm the host. We detect this by creating a 'partial'
 * file under the container directory, and keeping an advisory lock. When
 * container creation completes, we remove that file.  When we load or try to
 * start a container, if we find that file, without a flock, we remove the
 * container.
 */
static int ongoing_create(struct lxc_container *c)
{
	int fd, ret;
	size_t len;
	char *path;
	struct flock lk = {0};

	len = strlen(c->config_path) + strlen(c->name) + 10;
	path = alloca(len);
	ret = snprintf(path, len, "%s/%s/partial", c->config_path, c->name);
	if (ret < 0 || (size_t)ret >= len)
		return -1;

	fd = open(path, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		if (errno != ENOENT)
			return -1;

		return 0;
	}

	lk.l_type = F_WRLCK;
	lk.l_whence = SEEK_SET;
	/* F_OFD_GETLK requires that l_pid be set to 0 otherwise the kernel
	 * will EINVAL us.
	 */
	lk.l_pid = 0;

	ret = fcntl(fd, F_OFD_GETLK, &lk);
	if (ret < 0 && errno == EINVAL) {
		ret = flock(fd, LOCK_EX | LOCK_NB);
		if (ret < 0 && errno == EWOULDBLOCK)
			ret = 0;
	}

	close(fd);

	/* F_OFD_GETLK will not send us back a pid so don't check it. */
	if (ret == 0)
		/* Create is still ongoing. */
		return 1;

	/* Create completed but partial is still there. */
	return 2;
}

static int create_partial(struct lxc_container *c)
{
	int fd, ret;
	size_t len;
	char *path;
	struct flock lk = {0};

	/* $lxcpath + '/' + $name + '/partial' + \0 */
	len = strlen(c->config_path) + strlen(c->name) + 10;
	path = alloca(len);
	ret = snprintf(path, len, "%s/%s/partial", c->config_path, c->name);
	if (ret < 0 || (size_t)ret >= len)
		return -1;

	fd = open(path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0000);
	if (fd < 0)
		return -1;

	lk.l_type = F_WRLCK;
	lk.l_whence = SEEK_SET;

	ret = fcntl(fd, F_OFD_SETLKW, &lk);
	if (ret < 0) {
		if (errno == EINVAL) {
			ret = flock(fd, LOCK_EX);
			if (ret == 0)
				return fd;
		}

		SYSERROR("Failed to lock partial file %s", path);
		close(fd);
		return -1;
	}

	return fd;
}

static void remove_partial(struct lxc_container *c, int fd)
{
	int ret;
	size_t len;
	char *path;

	close(fd);

	/* $lxcpath + '/' + $name + '/partial' + \0 */
	len = strlen(c->config_path) + strlen(c->name) + 10;
	path = alloca(len);
	ret = snprintf(path, len, "%s/%s/partial", c->config_path, c->name);
	if (ret < 0 || (size_t)ret >= len)
		return;

	ret = unlink(path);
	if (ret < 0)
		SYSERROR("Failed to remove partial file %s", path);
}

/* LOCKING
 * 1. container_mem_lock(c) protects the struct lxc_container from multiple threads.
 * 2. container_disk_lock(c) protects the on-disk container data - in particular the
 *    container configuration file.
 *    The container_disk_lock also takes the container_mem_lock.
 * 3. thread_mutex protects process data (ex: fd table) from multiple threads.
 * NOTHING mutexes two independent programs with their own struct
 * lxc_container for the same c->name, between API calls.  For instance,
 * c->config_read(); c->start();  Between those calls, data on disk
 * could change (which shouldn't bother the caller unless for instance
 * the rootfs get moved).  c->config_read(); update; c->config_write();
 * Two such updaters could race.  The callers should therefore check their
 * results.  Trying to prevent that would necessarily expose us to deadlocks
 * due to hung callers.  So I prefer to keep the locks only within our own
 * functions, not across functions.
 *
 * If you're going to clone while holding a lxccontainer, increment
 * c->numthreads (under privlock) before forking.  When deleting,
 * decrement numthreads under privlock, then if it hits 0 you can delete.
 * Do not ever use a lxccontainer whose numthreads you did not bump.
 */
static void lxc_container_free(struct lxc_container *c)
{
	if (!c)
		return;

	free(c->configfile);
	c->configfile = NULL;

	free(c->error_string);
	c->error_string = NULL;

	if (c->slock) {
		lxc_putlock(c->slock);
		c->slock = NULL;
	}

	if (c->privlock) {
		lxc_putlock(c->privlock);
		c->privlock = NULL;
	}

	free(c->name);
	c->name = NULL;

	if (c->lxc_conf) {
		lxc_conf_free(c->lxc_conf);
		c->lxc_conf = NULL;
	}

	free(c->config_path);
	c->config_path = NULL;

	free(c);
}

/* Consider the following case:
 *
 * |====================================================================|
 * | freer                         |    racing get()er                  |
 * |====================================================================|
 * | lxc_container_put()           |   lxc_container_get()              |
 * | \ lxclock(c->privlock)        |   c->numthreads < 1? (no)          |
 * | \ c->numthreads = 0           |   \ lxclock(c->privlock) -> waits  |
 * | \ lxcunlock()                 |   \                                |
 * | \ lxc_container_free()        |   \ lxclock() returns              |
 * |                               |   \ c->numthreads < 1 -> return 0  |
 * | \ \ (free stuff)              |                                    |
 * | \ \ sem_destroy(privlock)     |                                    |
 * |_______________________________|____________________________________|
 *
 * When the get()er checks numthreads the first time, one of the following
 * is true:
 * 1. freer has set numthreads = 0.  get() returns 0
 * 2. freer is between lxclock and setting numthreads to 0.  get()er will
 *    sem_wait on privlock, get lxclock after freer() drops it, then see
 *    numthreads is 0 and exit without touching lxclock again..
 * 3. freer has not yet locked privlock.  If get()er runs first, then put()er
 *    will see --numthreads = 1 and not call lxc_container_free().
*/

int lxc_container_get(struct lxc_container *c)
{
	if (!c)
		return 0;

	/* If someone else has already started freeing the container, don't try
	 * to take the lock, which may be invalid.
	 */
	if (c->numthreads < 1)
		return 0;

	if (container_mem_lock(c))
		return 0;

	/* Bail without trying to unlock, bc the privlock is now probably in
	 * freed memory.
	 */
	if (c->numthreads < 1)
		return 0;

	c->numthreads++;
	container_mem_unlock(c);

	return 1;
}

int lxc_container_put(struct lxc_container *c)
{
	if (!c)
		return -1;

	if (container_mem_lock(c))
		return -1;

	c->numthreads--;

	if (c->numthreads < 1) {
		container_mem_unlock(c);
		lxc_container_free(c);
		return 1;
	}

	container_mem_unlock(c);
	return 0;
}

static bool do_lxcapi_is_defined(struct lxc_container *c)
{
	int statret;
	struct stat statbuf;
	bool ret = false;

	if (!c)
		return false;

	if (container_mem_lock(c))
		return false;

	if (!c->configfile)
		goto on_error;

	statret = stat(c->configfile, &statbuf);
	if (statret != 0)
		goto on_error;

	ret = true;

on_error:
	container_mem_unlock(c);
	return ret;
}

#define WRAP_API(rettype, fnname)					\
static rettype fnname(struct lxc_container *c)				\
{									\
	rettype ret;							\
	bool reset_config = false;					\
									\
	if (!current_config && c && c->lxc_conf) {			\
		current_config = c->lxc_conf;				\
		reset_config = true;					\
	}								\
									\
	ret = do_##fnname(c);						\
	if (reset_config)						\
		current_config = NULL;					\
									\
	return ret;							\
}

#define WRAP_API_1(rettype, fnname, t1)					\
static rettype fnname(struct lxc_container *c, t1 a1)			\
{									\
	rettype ret;							\
	bool reset_config = false;					\
									\
	if (!current_config && c && c->lxc_conf) {			\
		current_config = c->lxc_conf;				\
		reset_config = true;					\
	}								\
									\
	ret = do_##fnname(c, a1);					\
	if (reset_config)						\
		current_config = NULL;					\
									\
	return ret;							\
}

#define WRAP_API_2(rettype, fnname, t1, t2)				\
static rettype fnname(struct lxc_container *c, t1 a1, t2 a2)		\
{									\
	rettype ret;							\
	bool reset_config = false;					\
									\
	if (!current_config && c && c->lxc_conf) {			\
		current_config = c->lxc_conf;				\
		reset_config = true;					\
	}								\
									\
	ret = do_##fnname(c, a1, a2);					\
	if (reset_config)						\
		current_config = NULL;					\
									\
	return ret;							\
}

#define WRAP_API_3(rettype, fnname, t1, t2, t3)				\
static rettype fnname(struct lxc_container *c, t1 a1, t2 a2, t3 a3)	\
{									\
	rettype ret;							\
	bool reset_config = false;					\
									\
	if (!current_config && c && c->lxc_conf) {			\
		current_config = c->lxc_conf;				\
		reset_config = true;					\
	}								\
									\
	ret = do_##fnname(c, a1, a2, a3);				\
	if (reset_config)						\
		current_config = NULL;					\
									\
	return ret;							\
}

WRAP_API(bool, lxcapi_is_defined)

static const char *do_lxcapi_state(struct lxc_container *c)
{
	lxc_state_t s;

	if (!c)
		return NULL;

	s = lxc_getstate(c->name, c->config_path);
	return lxc_state2str(s);
}

WRAP_API(const char *, lxcapi_state)

static bool is_stopped(struct lxc_container *c)
{
	lxc_state_t s;

	s = lxc_getstate(c->name, c->config_path);
	return (s == STOPPED);
}

static bool do_lxcapi_is_running(struct lxc_container *c)
{
	if (!c)
		return false;

	return !is_stopped(c);
}

WRAP_API(bool, lxcapi_is_running)

static bool do_lxcapi_freeze(struct lxc_container *c)
{
	int ret;

	if (!c)
		return false;

	ret = lxc_freeze(c->name, c->config_path);
	if (ret < 0)
		return false;

	return true;
}

WRAP_API(bool, lxcapi_freeze)

static bool do_lxcapi_unfreeze(struct lxc_container *c)
{
	int ret;

	if (!c)
		return false;

	ret = lxc_unfreeze(c->name, c->config_path);
	if (ret < 0)
		return false;

	return true;
}

WRAP_API(bool, lxcapi_unfreeze)

static int do_lxcapi_console_getfd(struct lxc_container *c, int *ttynum, int *masterfd)
{
	if (!c)
		return -1;

	return lxc_terminal_getfd(c, ttynum, masterfd);
}

WRAP_API_2(int, lxcapi_console_getfd, int *, int *)

static int lxcapi_console(struct lxc_container *c, int ttynum, int stdinfd,
			  int stdoutfd, int stderrfd, int escape)
{
	int ret;

	if (!c)
		return -1;

	current_config = c->lxc_conf;
	ret = lxc_console(c, ttynum, stdinfd, stdoutfd, stderrfd, escape);
	current_config = NULL;

	return ret;
}

static int do_lxcapi_console_log(struct lxc_container *c, struct lxc_console_log *log)
{
	int ret;

	if (!c)
		return -EINVAL;

	ret = lxc_cmd_console_log(c->name, do_lxcapi_get_config_path(c), log);
	if (ret < 0) {
		if (ret == -ENODATA)
			NOTICE("The console log is empty");
		else if (ret == -EFAULT)
			NOTICE("The container does not keep a console log");
		else if (ret == -ENOENT)
			NOTICE("The container does not keep a console log file");
		else if (ret == -EIO)
			NOTICE("Failed to write console log to log file");
		else
			ERROR("Failed to retrieve console log");
	}

	return ret;
}

WRAP_API_1(int, lxcapi_console_log, struct lxc_console_log *)

static pid_t do_lxcapi_init_pid(struct lxc_container *c)
{
	if (!c)
		return -1;

	return lxc_cmd_get_init_pid(c->name, c->config_path);
}

WRAP_API(pid_t, lxcapi_init_pid)

static bool load_config_locked(struct lxc_container *c, const char *fname)
{
	if (!c->lxc_conf)
		c->lxc_conf = lxc_conf_init();

	if (!c->lxc_conf)
		return false;

	if (lxc_config_read(fname, c->lxc_conf, false) != 0)
		return false;

	c->lxc_conf->name = c->name;
	return true;
}

static bool do_lxcapi_load_config(struct lxc_container *c, const char *alt_file)
{
	int lret;
	const char *fname;
	bool need_disklock = false, ret = false;

	if (!c)
		return false;

	fname = c->configfile;

	if (alt_file)
		fname = alt_file;

	if (!fname)
		return false;

	/* If we're reading something other than the container's config, we only
	 * need to lock the in-memory container. If loading the container's
	 * config file, take the disk lock.
	 */
	if (strcmp(fname, c->configfile) == 0)
		need_disklock = true;

	if (need_disklock)
		lret = container_disk_lock(c);
	else
		lret = container_mem_lock(c);
	if (lret)
		return false;

	ret = load_config_locked(c, fname);

	if (need_disklock)
		container_disk_unlock(c);
	else
		container_mem_unlock(c);

	return ret;
}

WRAP_API_1(bool, lxcapi_load_config, const char *)

static bool do_lxcapi_want_daemonize(struct lxc_container *c, bool state)
{
	if (!c || !c->lxc_conf)
		return false;

	if (container_mem_lock(c))
		return false;

	c->daemonize = state;

	container_mem_unlock(c);

	return true;
}

WRAP_API_1(bool, lxcapi_want_daemonize, bool)

static bool do_lxcapi_want_close_all_fds(struct lxc_container *c, bool state)
{
	if (!c || !c->lxc_conf)
		return false;

	if (container_mem_lock(c))
		return false;

	c->lxc_conf->close_all_fds = state;

	container_mem_unlock(c);

	return true;
}

WRAP_API_1(bool, lxcapi_want_close_all_fds, bool)

static bool do_lxcapi_wait(struct lxc_container *c, const char *state,
			   int timeout)
{
	int ret;

	if (!c)
		return false;

	ret = lxc_wait(c->name, state, timeout, c->config_path);
	return ret == 0;
}

WRAP_API_2(bool, lxcapi_wait, const char *, int)

static bool am_single_threaded(void)
{
	DIR *dir;
	struct dirent *direntp;
	int count = 0;

	dir = opendir("/proc/self/task");
	if (!dir)
		return false;

	while ((direntp = readdir(dir))) {
		if (strcmp(direntp->d_name, ".") == 0)
			continue;

		if (strcmp(direntp->d_name, "..") == 0)
			continue;

		count++;
		if (count > 1)
			break;
	}
	closedir(dir);

	return count == 1;
}

static void push_arg(char ***argp, char *arg, int *nargs)
{
	char *copy;
	char **argv;

	copy = must_copy_string(arg);

	do {
		argv = realloc(*argp, (*nargs + 2) * sizeof(char *));
	} while (!argv);

	*argp = argv;
	argv[*nargs] = copy;
	(*nargs)++;
	argv[*nargs] = NULL;
}

static char **split_init_cmd(const char *incmd)
{
	size_t len, retlen;
	char *copy, *p;
	char **argv;
	int nargs = 0;

	if (!incmd)
		return NULL;

	len = strlen(incmd) + 1;
	copy = alloca(len);
	retlen = strlcpy(copy, incmd, len);
	if (retlen >= len)
		return NULL;

	do {
		argv = malloc(sizeof(char *));
	} while (!argv);

	argv[0] = NULL;
	lxc_iterate_parts(p, copy, " ")
		push_arg(&argv, p, &nargs);

	if (nargs == 0) {
		free(argv);
		return NULL;
	}

	return argv;
}

static void free_init_cmd(char **argv)
{
	int i = 0;

	if (!argv)
		return;

	while (argv[i])
		free(argv[i++]);

	free(argv);
}

static int lxc_rcv_status(int state_socket)
{
	int ret;
	int state = -1;

again:
	/* Receive container state. */
	ret = lxc_abstract_unix_rcv_credential(state_socket, &state, sizeof(int));
	if (ret <= 0) {
		if (errno != EINTR)
			return -1;

		TRACE("Caught EINTR; retrying");
		goto again;
	}

	return state;
}

static bool wait_on_daemonized_start(struct lxc_handler *handler, int pid)
{
	int ret, state;

	/* Close write end of the socket pair. */
	close(handler->state_socket_pair[1]);
	handler->state_socket_pair[1] = -1;

	state = lxc_rcv_status(handler->state_socket_pair[0]);

	/* Close read end of the socket pair. */
	close(handler->state_socket_pair[0]);
	handler->state_socket_pair[0] = -1;

	/* The first child is going to fork() again and then exits. So we reap
	 * the first child here.
	 */
	ret = wait_for_pid(pid);
	if (ret < 0)
		DEBUG("Failed waiting on first child %d", pid);
	else
		DEBUG("First child %d exited", pid);

	if (state < 0) {
		SYSERROR("Failed to receive the container state");
		return false;
	}

	/* If we receive anything else then running we know that the container
	 * failed to start.
	 */
	if (state != RUNNING) {
		ERROR("Received container state \"%s\" instead of \"RUNNING\"",
		      lxc_state2str(state));
		return false;
	}

	TRACE("Container is in \"RUNNING\" state");
	return true;
}

static bool do_lxcapi_start(struct lxc_container *c, int useinit, char * const argv[])
{
	int ret;
	struct lxc_handler *handler;
	struct lxc_conf *conf;
	char *default_args[] = {
		"/sbin/init",
		NULL,
	};
	char **init_cmd = NULL;
	int keepfds[3] = {-1, -1, -1};

	/* container does exist */
	if (!c)
		return false;

	/* If anything fails before we set error_num, we want an error in there.
	 */
	c->error_num = 1;

	/* Container has not been setup. */
	if (!c->lxc_conf)
		return false;

	ret = ongoing_create(c);
	if (ret < 0) {
		ERROR("Failed checking for incomplete container creation");
		return false;
	} else if (ret == 1) {
		ERROR("Ongoing container creation detected");
		return false;
	} else if (ret == 2) {
		ERROR("Failed to create container");
		do_lxcapi_destroy(c);
		return false;
	}

	if (container_mem_lock(c))
		return false;

	conf = c->lxc_conf;

	/* initialize handler */
	handler = lxc_init_handler(c->name, conf, c->config_path, c->daemonize);

	container_mem_unlock(c);
	if (!handler)
		return false;

	if (!argv) {
		if (useinit && conf->execute_cmd)
			argv = init_cmd = split_init_cmd(conf->execute_cmd);
		else
			argv = init_cmd = split_init_cmd(conf->init_cmd);
	}

	/* ... otherwise use default_args. */
	if (!argv) {
		if (useinit) {
			ERROR("No valid init detected");
			lxc_free_handler(handler);
			return false;
		}
		argv = default_args;
	}

	/* I'm not sure what locks we want here.Any? Is liblxc's locking enough
	 * here to protect the on disk container?  We don't want to exclude
	 * things like lxc_info while the container is running.
	 */
	if (c->daemonize) {
		bool started;
		char title[2048];
		pid_t pid;

		pid = fork();
		if (pid < 0) {
			free_init_cmd(init_cmd);
			lxc_free_handler(handler);
			return false;
		}

		/* first parent */
		if (pid != 0) {
			/* Set to NULL because we don't want father unlink
			 * the PID file, child will do the free and unlink.
			 */
			c->pidfile = NULL;

			/* Wait for container to tell us whether it started
			 * successfully.
			 */
			started = wait_on_daemonized_start(handler, pid);

			free_init_cmd(init_cmd);
			lxc_free_handler(handler);
			return started;
		}

		/* first child */

		/* We don't really care if this doesn't print all the
		 * characters. All that it means is that the proctitle will be
		 * ugly. Similarly, we also don't care if setproctitle() fails.
		 */
		ret = snprintf(title, sizeof(title), "[lxc monitor] %s %s", c->config_path, c->name);
		if (ret > 0) {
			ret = setproctitle(title);
			if (ret < 0)
				INFO("Failed to set process title to %s", title);
			else
				INFO("Set process title to %s", title);
		}

		/* We fork() a second time to be reparented to init. Like
		 * POSIX's daemon() function we change to "/" and redirect
		 * std{in,out,err} to /dev/null.
		 */
		pid = fork();
		if (pid < 0) {
			SYSERROR("Failed to fork first child process");
			_exit(EXIT_FAILURE);
		}

		/* second parent */
		if (pid != 0) {
			free_init_cmd(init_cmd);
			lxc_free_handler(handler);
			_exit(EXIT_SUCCESS);
		}

		/* second child */

		/* change to / directory */
		ret = chdir("/");
		if (ret < 0) {
			SYSERROR("Failed to change to \"/\" directory");
			_exit(EXIT_FAILURE);
		}

		keepfds[0] = handler->conf->maincmd_fd;
		keepfds[1] = handler->state_socket_pair[0];
		keepfds[2] = handler->state_socket_pair[1];
		ret = lxc_check_inherited(conf, true, keepfds,
					  sizeof(keepfds) / sizeof(keepfds[0]));
		if (ret < 0)
			_exit(EXIT_FAILURE);

		/* redirect std{in,out,err} to /dev/null */
		ret = null_stdfds();
		if (ret < 0) {
			ERROR("Failed to redirect std{in,out,err} to /dev/null");
			_exit(EXIT_FAILURE);
		}

		/* become session leader */
		ret = setsid();
		if (ret < 0)
			TRACE("Process %d is already process group leader", lxc_raw_getpid());
	} else if (!am_single_threaded()) {
		ERROR("Cannot start non-daemonized container when threaded");
		free_init_cmd(init_cmd);
		lxc_free_handler(handler);
		return false;
	}

	/* We need to write PID file after daemonize, so we always write the
	 * right PID.
	 */
	if (c->pidfile) {
		int ret, w;
		char pidstr[INTTYPE_TO_STRLEN(pid_t)];

		w = snprintf(pidstr, sizeof(pidstr), "%d", lxc_raw_getpid());
		if (w < 0 || (size_t)w >= sizeof(pidstr)) {
			free_init_cmd(init_cmd);
			lxc_free_handler(handler);

			SYSERROR("Failed to write monitor pid to \"%s\"", c->pidfile);

			if (c->daemonize)
				_exit(EXIT_FAILURE);

			return false;
		}

		ret = lxc_write_to_file(c->pidfile, pidstr, w, false, 0600);
		if (ret < 0) {
			free_init_cmd(init_cmd);
			lxc_free_handler(handler);

			SYSERROR("Failed to write monitor pid to \"%s\"", c->pidfile);

			if (c->daemonize)
				_exit(EXIT_FAILURE);

			return false;
		}
	}

	conf->reboot = REBOOT_NONE;

	/* Unshare the mount namespace if requested */
	if (conf->monitor_unshare) {
		ret = unshare(CLONE_NEWNS);
		if (ret < 0) {
			SYSERROR("Failed to unshare mount namespace");
			lxc_free_handler(handler);
			ret = 1;
			goto on_error;
		}

		ret = mount(NULL, "/", NULL, MS_SLAVE|MS_REC, NULL);
		if (ret < 0) {
			SYSERROR("Failed to make / rslave at startup");
			lxc_free_handler(handler);
			ret = 1;
			goto on_error;
		}
	}

reboot:
	if (conf->reboot == REBOOT_INIT) {
		/* initialize handler */
		handler = lxc_init_handler(c->name, conf, c->config_path, c->daemonize);
		if (!handler) {
			ret = 1;
			goto on_error;
		}
	}

	keepfds[0] = handler->conf->maincmd_fd;
	keepfds[1] = handler->state_socket_pair[0];
	keepfds[2] = handler->state_socket_pair[1];
	ret = lxc_check_inherited(conf, c->daemonize, keepfds,
				  sizeof(keepfds) / sizeof(keepfds[0]));
	if (ret < 0) {
		lxc_free_handler(handler);
		ret = 1;
		goto on_error;
	}

	if (useinit)
		ret = lxc_execute(c->name, argv, 1, handler, c->config_path,
				  c->daemonize, &c->error_num);
	else
		ret = lxc_start(c->name, argv, handler, c->config_path,
				c->daemonize, &c->error_num);

	if (conf->reboot == REBOOT_REQ) {
		INFO("Container requested reboot");
		conf->reboot = REBOOT_INIT;
		goto reboot;
	}

on_error:
	if (c->pidfile) {
		unlink(c->pidfile);
		free(c->pidfile);
		c->pidfile = NULL;
	}
	free_init_cmd(init_cmd);

	if (c->daemonize && ret != 0)
		_exit(EXIT_FAILURE);
	else if (c->daemonize)
		_exit(EXIT_SUCCESS);

	if (ret != 0)
		return false;

	return true;
}

static bool lxcapi_start(struct lxc_container *c, int useinit,
			 char *const argv[])
{
	bool ret;

	current_config = c ? c->lxc_conf : NULL;
	ret = do_lxcapi_start(c, useinit, argv);
	current_config = NULL;

	return ret;
}

/* Note, there MUST be an ending NULL. */
static bool lxcapi_startl(struct lxc_container *c, int useinit, ...)
{
	va_list ap;
	char **inargs = NULL;
	bool bret = false;

	/* container exists */
	if (!c)
		return false;

	current_config = c->lxc_conf;

	va_start(ap, useinit);
	inargs = lxc_va_arg_list_to_argv(ap, 0, 1);
	va_end(ap);
	if (!inargs)
		goto on_error;

	/* pass NULL if no arguments were supplied */
	bret = do_lxcapi_start(c, useinit, *inargs ? inargs : NULL);

on_error:
	if (inargs) {
		char **arg;

		for (arg = inargs; *arg; arg++)
			free(*arg);
		free(inargs);
	}

	current_config = NULL;

	return bret;
}

static bool do_lxcapi_stop(struct lxc_container *c)
{
	int ret;

	if (!c)
		return false;

	ret = lxc_cmd_stop(c->name, c->config_path);

	return ret == 0;
}

WRAP_API(bool, lxcapi_stop)

static int do_create_container_dir(const char *path, struct lxc_conf *conf)
{
	int lasterr;
	size_t len;
	char *p;
	int ret = -1;

	mode_t mask = umask(0002);
	ret = mkdir(path, 0770);
	lasterr = errno;
	umask(mask);
	errno = lasterr;
	if (ret) {
		if (errno != EEXIST)
			return -1;

		ret = 0;
	}

	len = strlen(path);
	p = alloca(len + 1);
	(void)strlcpy(p, path, len + 1);

	if (!lxc_list_empty(&conf->id_map)) {
		ret = chown_mapped_root(p, conf);
		if (ret < 0)
			ret = -1;
	}

	return ret;
}

/* Create the standard expected container dir. */
static bool create_container_dir(struct lxc_container *c)
{
	int ret;
	size_t len;
	char *s;

	len = strlen(c->config_path) + strlen(c->name) + 2;
	s = malloc(len);
	if (!s)
		return false;

	ret = snprintf(s, len, "%s/%s", c->config_path, c->name);
	if (ret < 0 || (size_t)ret >= len) {
		free(s);
		return false;
	}

	ret = do_create_container_dir(s, c->lxc_conf);
	free(s);

	return ret == 0;
}

/* do_storage_create: thin wrapper around storage_create(). Like
 * storage_create(), it returns a mounted bdev on success, NULL on error.
 */
static struct lxc_storage *do_storage_create(struct lxc_container *c,
					     const char *type,
					     struct bdev_specs *specs)
{
	int ret;
	size_t len;
	char *dest;
	struct lxc_storage *bdev;

	/* rootfs.path or lxcpath/lxcname/rootfs */
	if (c->lxc_conf->rootfs.path &&
	    (access(c->lxc_conf->rootfs.path, F_OK) == 0)) {
		const char *rpath = c->lxc_conf->rootfs.path;
		len = strlen(rpath) + 1;
		dest = alloca(len);
		ret = snprintf(dest, len, "%s", rpath);
	} else {
		const char *lxcpath = do_lxcapi_get_config_path(c);
		len = strlen(c->name) + strlen(lxcpath) + 9;
		dest = alloca(len);
		ret = snprintf(dest, len, "%s/%s/rootfs", lxcpath, c->name);
	}
	if (ret < 0 || (size_t)ret >= len)
		return NULL;

	bdev = storage_create(dest, type, c->name, specs);
	if (!bdev) {
		ERROR("Failed to create \"%s\" storage", type);
		return NULL;
	}

	if (!c->set_config_item(c, "lxc.rootfs.path", bdev->src)) {
		ERROR("Failed to set \"lxc.rootfs.path = %s\"", bdev->src);
		return NULL;
	}

	/* If we are not root, chown the rootfs dir to root in the target user
	 * namespace.
	 */
	ret = geteuid();
	if (ret != 0 || (c->lxc_conf && !lxc_list_empty(&c->lxc_conf->id_map))) {
		ret = chown_mapped_root(bdev->dest, c->lxc_conf);
		if (ret < 0) {
			ERROR("Error chowning \"%s\" to container root", bdev->dest);
			suggest_default_idmap();
			storage_put(bdev);
			return NULL;
		}
	}

	return bdev;
}

static char *lxcbasename(char *path)
{
	char *p;

	p = path + strlen(path) - 1;
	while (*p != '/' && p > path)
		p--;

	return p;
}

static bool create_run_template(struct lxc_container *c, char *tpath,
				bool need_null_stdfds, char *const argv[])
{
	int ret;
	pid_t pid;

	if (!tpath)
		return true;

	pid = fork();
	if (pid < 0) {
		SYSERROR("Failed to fork task for container creation template");
		return false;
	}

	if (pid == 0) { /* child */
		int i, len;
		char *namearg, *patharg, *rootfsarg;
		char **newargv;
		int nargs = 0;
		struct lxc_storage *bdev = NULL;
		struct lxc_conf *conf = c->lxc_conf;
		uid_t euid;

		if (need_null_stdfds) {
			ret = null_stdfds();
			if (ret < 0)
				_exit(EXIT_FAILURE);
		}

		bdev = storage_init(c->lxc_conf);
		if (!bdev) {
			ERROR("Failed to initialize storage");
			_exit(EXIT_FAILURE);
		}

		euid = geteuid();
		if (euid == 0) {
			ret = unshare(CLONE_NEWNS);
			if (ret < 0) {
				ERROR("Failed to unshare CLONE_NEWNS");
				_exit(EXIT_FAILURE);
			}

			ret = detect_shared_rootfs();
			if (ret == 1) {
				ret = mount(NULL, "/", NULL, MS_SLAVE | MS_REC, NULL);
				if (ret < 0) {
					SYSERROR("Failed to make \"/\" rslave");
					ERROR("Continuing...");
				}
			}
		}

		if (strcmp(bdev->type, "dir") != 0 && strcmp(bdev->type, "btrfs") != 0) {
			if (euid != 0) {
				ERROR("Unprivileged users can only create "
				      "btrfs and directory-backed containers");
				_exit(EXIT_FAILURE);
			}

			if (strcmp(bdev->type, "overlay") == 0 ||
			    strcmp(bdev->type, "overlayfs") == 0) {
				/* If we create an overlay container we need to
				 * rsync the contents into
				 * <container-path>/<container-name>/rootfs.
				 * However, the overlay mount function will
				 * mount will mount
				 * <container-path>/<container-name>/delta0
				 * over
				 * <container-path>/<container-name>/rootfs
				 * which means we would rsync the rootfs into
				 * the delta directory. That doesn't make sense
				 * since the delta directory only exists to
				 * record the differences to
				 * <container-path>/<container-name>/rootfs. So
				 * let's simply bind-mount here and then rsync
				 * directly into
				 * <container-path>/<container-name>/rootfs.
				 */
				char *src;

				src = ovl_get_rootfs(bdev->src, &(size_t){0});
				if (!src) {
					ERROR("Failed to get rootfs");
					_exit(EXIT_FAILURE);
				}

				ret = mount(src, bdev->dest, "bind", MS_BIND | MS_REC, NULL);
				if (ret < 0) {
					ERROR("Failed to mount rootfs");
					_exit(EXIT_FAILURE);
				}
			} else {
				ret = bdev->ops->mount(bdev);
				if (ret < 0) {
					ERROR("Failed to mount rootfs");
					_exit(EXIT_FAILURE);
				}
			}
		} else { /* TODO come up with a better way here! */
			const char *src;
			free(bdev->dest);
			src = lxc_storage_get_path(bdev->src, bdev->type);
			bdev->dest = strdup(src);
		}

		/* Create our new array, pre-pend the template name and base
		 * args.
		 */
		if (argv)
			for (nargs = 0; argv[nargs]; nargs++)
				;

		/* template, path, rootfs and name args */
		nargs += 4;

		newargv = malloc(nargs * sizeof(*newargv));
		if (!newargv)
			_exit(EXIT_FAILURE);
		newargv[0] = lxcbasename(tpath);

		/* --path */
		len = strlen(c->config_path) + strlen(c->name) + strlen("--path=") + 2;
		patharg = malloc(len);
		if (!patharg)
			_exit(EXIT_FAILURE);

		ret = snprintf(patharg, len, "--path=%s/%s", c->config_path, c->name);
		if (ret < 0 || ret >= len)
			_exit(EXIT_FAILURE);
		newargv[1] = patharg;

		/* --name */
		len = strlen("--name=") + strlen(c->name) + 1;
		namearg = malloc(len);
		if (!namearg)
			_exit(EXIT_FAILURE);

		ret = snprintf(namearg, len, "--name=%s", c->name);
		if (ret < 0 || ret >= len)
			_exit(EXIT_FAILURE);
		newargv[2] = namearg;

		/* --rootfs */
		len = strlen("--rootfs=") + 1 + strlen(bdev->dest);
		rootfsarg = malloc(len);
		if (!rootfsarg)
			_exit(EXIT_FAILURE);

		ret = snprintf(rootfsarg, len, "--rootfs=%s", bdev->dest);
		if (ret < 0 || ret >= len)
			_exit(EXIT_FAILURE);
		newargv[3] = rootfsarg;

		/* add passed-in args */
		if (argv)
			for (i = 4; i < nargs; i++)
				newargv[i] = argv[i - 4];

		/* add trailing NULL */
		nargs++;
		newargv = realloc(newargv, nargs * sizeof(*newargv));
		if (!newargv)
			_exit(EXIT_FAILURE);
		newargv[nargs - 1] = NULL;

		/* If we're running the template in a mapped userns, then we
		 * prepend the template command with: lxc-usernsexec <-m map1>
		 * ... <-m mapn> -- and we append "--mapped-uid x", where x is
		 * the mapped uid for our geteuid()
		 */
		if (!lxc_list_empty(&conf->id_map)) {
			int extraargs, hostuid_mapped, hostgid_mapped;
			char **n2;
			char txtuid[20], txtgid[20];
			struct lxc_list *it;
			struct id_map *map;
			int n2args = 1;

			n2 = malloc(n2args * sizeof(*n2));
			if (!n2)
				_exit(EXIT_FAILURE);

			newargv[0] = tpath;
			tpath = "lxc-usernsexec";
			n2[0] = "lxc-usernsexec";

			lxc_list_for_each(it, &conf->id_map) {
				map = it->elem;
				n2args += 2;
				n2 = realloc(n2, n2args * sizeof(char *));
				if (!n2)
					_exit(EXIT_FAILURE);

				n2[n2args - 2] = "-m";
				n2[n2args - 1] = malloc(200);
				if (!n2[n2args - 1])
					_exit(EXIT_FAILURE);

				ret = snprintf(n2[n2args - 1], 200, "%c:%lu:%lu:%lu",
					       map->idtype == ID_TYPE_UID ? 'u' : 'g',
					       map->nsid, map->hostid, map->range);
				if (ret < 0 || ret >= 200)
					_exit(EXIT_FAILURE);
			}

			hostuid_mapped = mapped_hostid(geteuid(), conf, ID_TYPE_UID);
			extraargs = hostuid_mapped >= 0 ? 1 : 3;

			n2 = realloc(n2, (nargs + n2args + extraargs) * sizeof(char *));
			if (!n2)
				_exit(EXIT_FAILURE);

			if (hostuid_mapped < 0) {
				hostuid_mapped = find_unmapped_nsid(conf, ID_TYPE_UID);
				n2[n2args++] = "-m";
				if (hostuid_mapped < 0) {
					ERROR("Failed to find free uid to map");
					_exit(EXIT_FAILURE);
				}

				n2[n2args++] = malloc(200);
				if (!n2[n2args - 1]) {
					SYSERROR("out of memory");
					_exit(EXIT_FAILURE);
				}

				ret = snprintf(n2[n2args - 1], 200, "u:%d:%d:1",
					       hostuid_mapped, geteuid());
				if (ret < 0 || ret >= 200)
					_exit(EXIT_FAILURE);
			}

			hostgid_mapped = mapped_hostid(getegid(), conf, ID_TYPE_GID);
			extraargs = hostgid_mapped >= 0 ? 1 : 3;

			n2 = realloc(n2, (nargs + n2args + extraargs) * sizeof(char *));
			if (!n2)
				_exit(EXIT_FAILURE);

			if (hostgid_mapped < 0) {
				hostgid_mapped = find_unmapped_nsid(conf, ID_TYPE_GID);
				n2[n2args++] = "-m";
				if (hostgid_mapped < 0) {
					ERROR("Failed to find free gid to map");
					_exit(EXIT_FAILURE);
				}

				n2[n2args++] = malloc(200);
				if (!n2[n2args - 1]) {
					SYSERROR("out of memory");
					_exit(EXIT_FAILURE);
				}

				ret = snprintf(n2[n2args - 1], 200, "g:%d:%d:1",
					       hostgid_mapped, getegid());
				if (ret < 0 || ret >= 200)
					_exit(EXIT_FAILURE);
			}

			n2[n2args++] = "--";

			for (i = 0; i < nargs; i++)
				n2[i + n2args] = newargv[i];
			n2args += nargs;

			/* Finally add "--mapped-uid $uid" to tell template what
			 * to chown cached images to.
			 */
			n2args += 4;
			n2 = realloc(n2, n2args * sizeof(char *));
			if (!n2)
				_exit(EXIT_FAILURE);

			/* note n2[n2args-1] is NULL */
			n2[n2args - 5] = "--mapped-uid";

			ret = snprintf(txtuid, 20, "%d", hostuid_mapped);
			if (ret < 0 || ret >= 20) {
				free(newargv);
				free(n2);
				_exit(EXIT_FAILURE);
			}

			n2[n2args - 4] = txtuid;
			n2[n2args - 3] = "--mapped-gid";

			ret = snprintf(txtgid, 20, "%d", hostgid_mapped);
			if (ret < 0 || ret >= 20) {
				free(newargv);
				free(n2);
				_exit(EXIT_FAILURE);
			}

			n2[n2args - 2] = txtgid;
			n2[n2args - 1] = NULL;
			free(newargv);
			newargv = n2;
		}

		execvp(tpath, newargv);
		SYSERROR("Failed to execute template %s", tpath);
		_exit(EXIT_FAILURE);
	}

	ret = wait_for_pid(pid);
	if (ret != 0) {
		ERROR("Failed to create container from template");
		return false;
	}

	return true;
}

static bool prepend_lxc_header(char *path, const char *t, char *const argv[])
{
	long flen;
	size_t len;
	char *contents;
	FILE *f;
	int ret = -1;
#if HAVE_LIBGNUTLS
	int i;
	unsigned char md_value[SHA_DIGEST_LENGTH];
	char *tpath;
#endif

	f = fopen(path, "r");
	if (f == NULL)
		return false;

	ret = fseek(f, 0, SEEK_END);
	if (ret < 0)
		goto out_error;

	ret = -1;
	flen = ftell(f);
	if (flen < 0)
		goto out_error;

	ret = fseek(f, 0, SEEK_SET);
	if (ret < 0)
		goto out_error;

	ret = fseek(f, 0, SEEK_SET);
	if (ret < 0)
		goto out_error;

	ret = -1;
	contents = malloc(flen + 1);
	if (!contents)
		goto out_error;

	len = fread(contents, 1, flen, f);
	if (len != flen)
		goto out_free_contents;

	contents[flen] = '\0';

	ret = fclose(f);
	f = NULL;
	if (ret < 0)
		goto out_free_contents;

#if HAVE_LIBGNUTLS
	tpath = get_template_path(t);
	if (!tpath) {
		ERROR("Invalid template \"%s\" specified", t);
		goto out_free_contents;
	}

	ret = sha1sum_file(tpath, md_value);
	if (ret < 0) {
		ERROR("Failed to get sha1sum of %s", tpath);
		free(tpath);
		goto out_free_contents;
	}
	free(tpath);
#endif

	f = fopen(path, "w");
	if (f == NULL) {
		SYSERROR("Reopening config for writing");
		free(contents);
		return false;
	}

	fprintf(f, "# Template used to create this container: %s\n", t);
	if (argv) {
		fprintf(f, "# Parameters passed to the template:");
		while (*argv) {
			fprintf(f, " %s", *argv);
			argv++;
		}
		fprintf(f, "\n");
	}

#if HAVE_LIBGNUTLS
	fprintf(f, "# Template script checksum (SHA-1): ");
	for (i=0; i<SHA_DIGEST_LENGTH; i++)
		fprintf(f, "%02x", md_value[i]);
	fprintf(f, "\n");
#endif
	fprintf(f, "# For additional config options, please look at lxc.container.conf(5)\n");
	fprintf(f, "\n# Uncomment the following line to support nesting containers:\n");
	fprintf(f, "#lxc.include = " LXCTEMPLATECONFIG "/nesting.conf\n");
	fprintf(f, "# (Be aware this has security implications)\n\n");
	if (fwrite(contents, 1, flen, f) != flen) {
		SYSERROR("Writing original contents");
		free(contents);
		fclose(f);
		return false;
	}

	ret = 0;

out_free_contents:
	free(contents);

out_error:
	if (f) {
		int newret;
		newret = fclose(f);
		if (ret == 0)
			ret = newret;
	}

	if (ret < 0) {
		SYSERROR("Error prepending header");
		return false;
	}

	return true;
}

static void lxcapi_clear_config(struct lxc_container *c)
{
	if (!c || !c->lxc_conf)
		return;

	lxc_conf_free(c->lxc_conf);
	c->lxc_conf = NULL;
}

#define do_lxcapi_clear_config(c) lxcapi_clear_config(c)

/*
 * lxcapi_create:
 * create a container with the given parameters.
 * @c: container to be created.  It has the lxcpath, name, and a starting
 *     configuration already set
 * @t: the template to execute to instantiate the root filesystem and
 *     adjust the configuration.
 * @bdevtype: backing store type to use.  If NULL, dir will be used.
 * @specs: additional parameters for the backing store, i.e. LVM vg to
 *         use.
 *
 * @argv: the arguments to pass to the template, terminated by NULL.  If no
 * arguments, you can just pass NULL.
 */
static bool do_lxcapi_create(struct lxc_container *c, const char *t,
			     const char *bdevtype, struct bdev_specs *specs,
			     int flags, char *const argv[])
{
	int partial_fd;
	mode_t mask;
	pid_t pid;
	bool ret = false;
	char *tpath = NULL;

	if (!c)
		return false;

	if (t) {
		tpath = get_template_path(t);
		if (!tpath) {
			ERROR("Unknown template \"%s\"", t);
			goto out;
		}
	}

	/* If a template is passed in, and the rootfs already is defined in the
	 * container config and exists, then the caller is trying to create an
	 * existing container. Return an error, but do NOT delete the container.
	 */
	if (do_lxcapi_is_defined(c) && c->lxc_conf && c->lxc_conf->rootfs.path &&
	    access(c->lxc_conf->rootfs.path, F_OK) == 0 && tpath) {
		ERROR("Container \"%s\" already exists in \"%s\"", c->name,
		      c->config_path);
		goto free_tpath;
	}

	if (!c->lxc_conf) {
		if (!do_lxcapi_load_config(c, lxc_global_config_value("lxc.default_config"))) {
			ERROR("Error loading default configuration file %s",
			      lxc_global_config_value("lxc.default_config"));
			goto free_tpath;
		}
	}

	if (!create_container_dir(c))
		goto free_tpath;

	/* If both template and rootfs.path are set, template is setup as
	 * rootfs.path. The container is already created if we have a config and
	 * rootfs.path is accessible
	 */
	if (!c->lxc_conf->rootfs.path && !tpath) {
		/* No template passed in and rootfs does not exist. */
		if (!c->save_config(c, NULL)) {
			ERROR("Failed to save initial config for \"%s\"", c->name);
			goto out;
		}
		ret = true;
		goto out;
	}

	/* Rootfs passed into configuration, but does not exist. */
	if (c->lxc_conf->rootfs.path && access(c->lxc_conf->rootfs.path, F_OK) != 0)
		goto out;

	if (do_lxcapi_is_defined(c) && c->lxc_conf->rootfs.path && !tpath) {
		/* Rootfs already existed, user just wanted to save the loaded
		 * configuration.
		 */
		if (!c->save_config(c, NULL))
			ERROR("Failed to save initial config for \"%s\"", c->name);

		ret = true;
		goto out;
	}

	/* Mark that this container is being created */
	partial_fd = create_partial(c);
	if (partial_fd < 0)
		goto out;

	/* No need to get disk lock bc we have the partial lock. */

	mask = umask(0022);

	/* Create the storage.
	 * Note we can't do this in the same task as we use to execute the
	 * template because of the way zfs works.
	 * After you 'zfs create', zfs mounts the fs only in the initial
	 * namespace.
	 */
	pid = fork();
	if (pid < 0) {
		SYSERROR("Failed to fork task for container creation template");
		goto out_unlock;
	}

	if (pid == 0) { /* child */
		struct lxc_storage *bdev = NULL;

		bdev = do_storage_create(c, bdevtype, specs);
		if (!bdev) {
			ERROR("Failed to create %s storage for %s",
			      bdevtype ? bdevtype : "(none)", c->name);
			_exit(EXIT_FAILURE);
		}

		/* Save config file again to store the new rootfs location. */
		if (!do_lxcapi_save_config(c, NULL)) {
			ERROR("Failed to save initial config for %s", c->name);
			/* Parent task won't see the storage driver in the
			 * config so we delete it.
			 */
			bdev->ops->umount(bdev);
			bdev->ops->destroy(bdev);
			_exit(EXIT_FAILURE);
		}

		_exit(EXIT_SUCCESS);
	}

	if (wait_for_pid(pid) != 0)
		goto out_unlock;

	/* Reload config to get the rootfs. */
	lxc_conf_free(c->lxc_conf);
	c->lxc_conf = NULL;

	if (!load_config_locked(c, c->configfile))
		goto out_unlock;

	if (!create_run_template(c, tpath, !!(flags & LXC_CREATE_QUIET), argv))
		goto out_unlock;

	/* Now clear out the lxc_conf we have, reload from the created
	 * container.
	 */
	do_lxcapi_clear_config(c);

	if (t) {
		if (!prepend_lxc_header(c->configfile, tpath, argv)) {
			ERROR("Failed to prepend header to config file");
			goto out_unlock;
		}
	}

	ret = load_config_locked(c, c->configfile);

out_unlock:
	umask(mask);
	remove_partial(c, partial_fd);

out:
	if (!ret)
		container_destroy(c, NULL);

free_tpath:
	free(tpath);
	return ret;
}

static bool lxcapi_create(struct lxc_container *c, const char *t,
			  const char *bdevtype, struct bdev_specs *specs,
			  int flags, char *const argv[])
{
	bool ret;

	current_config = c ? c->lxc_conf : NULL;

	ret = do_lxcapi_create(c, t, bdevtype, specs, flags, argv);
	current_config = NULL;
	return ret;
}

static bool do_lxcapi_reboot(struct lxc_container *c)
{
	int ret;
	pid_t pid;
	int rebootsignal = SIGINT;

	if (!c)
		return false;

	if (!do_lxcapi_is_running(c))
		return false;

	pid = do_lxcapi_init_pid(c);
	if (pid <= 0)
		return false;

	if (c->lxc_conf && c->lxc_conf->rebootsignal)
		rebootsignal = c->lxc_conf->rebootsignal;

	ret = kill(pid, rebootsignal);
	if (ret < 0) {
		WARN("Failed to send signal %d to pid %d", rebootsignal, pid);
		return false;
	}

	return true;
}

WRAP_API(bool, lxcapi_reboot)

static bool do_lxcapi_reboot2(struct lxc_container *c, int timeout)
{
	int killret, ret;
	pid_t pid;
	int rebootsignal = SIGINT, state_client_fd = -1;
	lxc_state_t states[MAX_STATE] = {0};

	if (!c)
		return false;

	if (!do_lxcapi_is_running(c))
		return true;

	pid = do_lxcapi_init_pid(c);
	if (pid <= 0)
		return true;

	if (c->lxc_conf && c->lxc_conf->rebootsignal)
		rebootsignal = c->lxc_conf->rebootsignal;

	/* Add a new state client before sending the shutdown signal so that we
	 * don't miss a state.
	 */
	if (timeout != 0) {
		states[RUNNING] = 2;
		ret = lxc_cmd_add_state_client(c->name, c->config_path, states,
					       &state_client_fd);
		if (ret < 0)
			return false;

		if (state_client_fd < 0)
			return false;

		if (ret == RUNNING)
			return true;

		if (ret < MAX_STATE)
			return false;
	}

	/* Send reboot signal to container. */
	killret = kill(pid, rebootsignal);
	if (killret < 0) {
		if (state_client_fd >= 0)
			close(state_client_fd);

		WARN("Failed to send signal %d to pid %d", rebootsignal, pid);
		return false;
	}
	TRACE("Sent signal %d to pid %d", rebootsignal, pid);

	if (timeout == 0)
		return true;

	ret = lxc_cmd_sock_rcv_state(state_client_fd, timeout);
	close(state_client_fd);
	if (ret < 0)
		return false;

	TRACE("Received state \"%s\"", lxc_state2str(ret));
	if (ret != RUNNING)
		return false;

	return true;
}

WRAP_API_1(bool, lxcapi_reboot2, int)

static bool do_lxcapi_shutdown(struct lxc_container *c, int timeout)
{
	int killret, ret;
	pid_t pid;
	int haltsignal = SIGPWR, state_client_fd = -EBADF;
	lxc_state_t states[MAX_STATE] = {0};

	if (!c)
		return false;

	if (!do_lxcapi_is_running(c))
		return true;

	pid = do_lxcapi_init_pid(c);
	if (pid <= 0)
		return true;

	/* Detect whether we should send SIGRTMIN + 3 (e.g. systemd). */
	if (c->lxc_conf && c->lxc_conf->haltsignal)
		haltsignal = c->lxc_conf->haltsignal;
	else if (task_blocks_signal(pid, (SIGRTMIN + 3)))
		haltsignal = (SIGRTMIN + 3);

	/* Add a new state client before sending the shutdown signal so that we
	 * don't miss a state.
	 */
	if (timeout != 0) {
		states[STOPPED] = 1;
		ret = lxc_cmd_add_state_client(c->name, c->config_path, states,
					       &state_client_fd);
		if (ret < 0)
			return false;

		if (state_client_fd < 0)
			return false;

		if (ret == STOPPED)
			return true;

		if (ret < MAX_STATE)
			return false;
	}

	/* Send shutdown signal to container. */
	killret = kill(pid, haltsignal);
	if (killret < 0) {
		if (state_client_fd >= 0)
			close(state_client_fd);

		WARN("Failed to send signal %d to pid %d", haltsignal, pid);
		return false;
	}
	TRACE("Sent signal %d to pid %d", haltsignal, pid);

	if (timeout == 0)
		return true;

	ret = lxc_cmd_sock_rcv_state(state_client_fd, timeout);
	close(state_client_fd);
	if (ret < 0)
		return false;

	TRACE("Received state \"%s\"", lxc_state2str(ret));
	if (ret != STOPPED)
		return false;

	return true;
}

WRAP_API_1(bool, lxcapi_shutdown, int)

static bool lxcapi_createl(struct lxc_container *c, const char *t,
		const char *bdevtype, struct bdev_specs *specs, int flags, ...)
{
	bool bret = false;
	char **args = NULL;
	va_list ap;

	if (!c)
		return false;

	current_config = c->lxc_conf;

	/*
	 * since we're going to wait for create to finish, I don't think we
	 * need to get a copy of the arguments.
	 */
	va_start(ap, flags);
	args = lxc_va_arg_list_to_argv(ap, 0, 0);
	va_end(ap);
	if (!args) {
		ERROR("Failed to allocate memory");
		goto out;
	}

	bret = do_lxcapi_create(c, t, bdevtype, specs, flags, args);

out:
	free(args);
	current_config = NULL;
	return bret;
}

static void do_clear_unexp_config_line(struct lxc_conf *conf, const char *key)
{
	if (!strcmp(key, "lxc.cgroup"))
		return clear_unexp_config_line(conf, key, true);

	if (!strcmp(key, "lxc.network"))
		return clear_unexp_config_line(conf, key, true);

	if (!strcmp(key, "lxc.net"))
		return clear_unexp_config_line(conf, key, true);

	/* Clear a network with a specific index. */
	if (!strncmp(key, "lxc.net.", 8)) {
		int ret;
		const char *idx;

		idx = key + 8;
		ret = lxc_safe_uint(idx, &(unsigned int){0});
		if (!ret)
			return clear_unexp_config_line(conf, key, true);
	}

	if (!strcmp(key, "lxc.hook"))
		return clear_unexp_config_line(conf, key, true);

	return clear_unexp_config_line(conf, key, false);
}

static bool do_lxcapi_clear_config_item(struct lxc_container *c,
					const char *key)
{
	int ret = 1;
	struct lxc_config_t *config;

	if (!c || !c->lxc_conf)
		return false;

	if (container_mem_lock(c))
		return false;

	config = lxc_get_config(key);
	/* Verify that the config key exists and that it has a callback
	 * implemented.
	 */
	if (config && config->clr)
		ret = config->clr(key, c->lxc_conf, NULL);

	if (!ret)
		do_clear_unexp_config_line(c->lxc_conf, key);

	container_mem_unlock(c);
	return ret == 0;
}

WRAP_API_1(bool, lxcapi_clear_config_item, const char *)

static inline bool enter_net_ns(struct lxc_container *c)
{
	pid_t pid = do_lxcapi_init_pid(c);

	if ((geteuid() != 0 || (c->lxc_conf && !lxc_list_empty(&c->lxc_conf->id_map))) &&
	    (access("/proc/self/ns/user", F_OK) == 0))
		if (!switch_to_ns(pid, "user"))
			return false;

	return switch_to_ns(pid, "net");
}

/* Used by qsort and bsearch functions for comparing names. */
static inline int string_cmp(char **first, char **second)
{
	return strcmp(*first, *second);
}

/* Used by qsort and bsearch functions for comparing container names. */
static inline int container_cmp(struct lxc_container **first,
				struct lxc_container **second)
{
	return strcmp((*first)->name, (*second)->name);
}

static bool add_to_array(char ***names, char *cname, int pos)
{
	char **newnames = realloc(*names, (pos+1) * sizeof(char *));
	if (!newnames) {
		ERROR("Out of memory");
		return false;
	}

	*names = newnames;
	newnames[pos] = strdup(cname);
	if (!newnames[pos])
		return false;

	/* Sort the array as we will use binary search on it. */
	qsort(newnames, pos + 1, sizeof(char *),
	      (int (*)(const void *, const void *))string_cmp);

	return true;
}

static bool add_to_clist(struct lxc_container ***list, struct lxc_container *c,
			 int pos, bool sort)
{
	struct lxc_container **newlist = realloc(*list, (pos + 1) * sizeof(struct lxc_container *));
	if (!newlist) {
		ERROR("Out of memory");
		return false;
	}

	*list = newlist;
	newlist[pos] = c;

	/* Sort the array as we will use binary search on it. */
	if (sort)
		qsort(newlist, pos + 1, sizeof(struct lxc_container *),
		      (int (*)(const void *, const void *))container_cmp);

	return true;
}

static char** get_from_array(char ***names, char *cname, int size)
{
	return (char **)bsearch(&cname, *names, size, sizeof(char *), (int (*)(const void *, const void *))string_cmp);
}

static bool array_contains(char ***names, char *cname, int size)
{
	if(get_from_array(names, cname, size) != NULL)
		return true;

	return false;
}

static bool remove_from_array(char ***names, char *cname, int size)
{
	char **result = get_from_array(names, cname, size);
	if (result != NULL) {
		free(result);
		return true;
	}

	return false;
}

static char **do_lxcapi_get_interfaces(struct lxc_container *c)
{
	pid_t pid;
	int i, count = 0, pipefd[2];
	char **interfaces = NULL;
	char interface[IFNAMSIZ];

	if (pipe2(pipefd, O_CLOEXEC) < 0)
		return NULL;

	pid = fork();
	if (pid < 0) {
		SYSERROR("Failed to fork task to get interfaces information");
		close(pipefd[0]);
		close(pipefd[1]);
		return NULL;
	}

	if (pid == 0) { /* child */
		int ret = 1, nbytes;
		struct netns_ifaddrs *interfaceArray = NULL, *tempIfAddr = NULL;

		/* close the read-end of the pipe */
		close(pipefd[0]);

		if (!enter_net_ns(c)) {
			SYSERROR("Failed to enter network namespace");
			goto out;
		}

		/* Grab the list of interfaces */
		if (netns_getifaddrs(&interfaceArray, -1, &(bool){false})) {
			SYSERROR("Failed to get interfaces list");
			goto out;
		}

		/* Iterate through the interfaces */
		for (tempIfAddr = interfaceArray; tempIfAddr != NULL;
		     tempIfAddr = tempIfAddr->ifa_next) {
			nbytes = lxc_write_nointr(pipefd[1], tempIfAddr->ifa_name, IFNAMSIZ);
			if (nbytes < 0)
				goto out;

			count++;
		}

		ret = 0;

	out:
		if (interfaceArray)
			netns_freeifaddrs(interfaceArray);

		/* close the write-end of the pipe, thus sending EOF to the reader */
		close(pipefd[1]);
		_exit(ret);
	}

	/* close the write-end of the pipe */
	close(pipefd[1]);

	while (lxc_read_nointr(pipefd[0], &interface, IFNAMSIZ) == IFNAMSIZ) {
		interface[IFNAMSIZ - 1] = '\0';

		if (array_contains(&interfaces, interface, count))
			continue;

		if (!add_to_array(&interfaces, interface, count))
			ERROR("Failed to add \"%s\" to array", interface);

		count++;
	}

	if (wait_for_pid(pid) != 0) {
		for (i = 0; i < count; i++)
			free(interfaces[i]);

		free(interfaces);
		interfaces = NULL;
	}

	/* close the read-end of the pipe */
	close(pipefd[0]);

	/* Append NULL to the array */
	if (interfaces)
		interfaces = (char **)lxc_append_null_to_array((void **)interfaces, count);

	return interfaces;
}

WRAP_API(char **, lxcapi_get_interfaces)

static char **do_lxcapi_get_ips(struct lxc_container *c, const char *interface,
				const char *family, int scope)
{
	int i, ret;
	pid_t pid;
	int pipefd[2];
	char address[INET6_ADDRSTRLEN];
	int count = 0;
	char **addresses = NULL;

	ret = pipe2(pipefd, O_CLOEXEC);
	if (ret < 0) {
		SYSERROR("Failed to create pipe");
		return NULL;
	}

	pid = fork();
	if (pid < 0) {
		SYSERROR("Failed to create new process");
		close(pipefd[0]);
		close(pipefd[1]);
		return NULL;
	}

	if (pid == 0) {
		ssize_t nbytes;
		char addressOutputBuffer[INET6_ADDRSTRLEN];
		int ret = 1;
		char *address = NULL;
		void *tempAddrPtr = NULL;
		struct netns_ifaddrs *interfaceArray = NULL, *tempIfAddr = NULL;

		/* close the read-end of the pipe */
		close(pipefd[0]);

		if (!enter_net_ns(c)) {
			SYSERROR("Failed to attach to network namespace");
			goto out;
		}

		/* Grab the list of interfaces */
		if (netns_getifaddrs(&interfaceArray, -1, &(bool){false})) {
			SYSERROR("Failed to get interfaces list");
			goto out;
		}

		/* Iterate through the interfaces */
		for (tempIfAddr = interfaceArray; tempIfAddr;
		     tempIfAddr = tempIfAddr->ifa_next) {
			if (tempIfAddr->ifa_addr == NULL)
				continue;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"

			if (tempIfAddr->ifa_addr->sa_family == AF_INET) {
				if (family && strcmp(family, "inet"))
					continue;

				tempAddrPtr = &((struct sockaddr_in *)tempIfAddr->ifa_addr)->sin_addr;
			} else {
				if (family && strcmp(family, "inet6"))
					continue;

				if (((struct sockaddr_in6 *)tempIfAddr->ifa_addr)->sin6_scope_id != scope)
					continue;

				tempAddrPtr = &((struct sockaddr_in6 *)tempIfAddr->ifa_addr)->sin6_addr;
			}

#pragma GCC diagnostic pop

			if (interface && strcmp(interface, tempIfAddr->ifa_name))
				continue;
			else if (!interface && strcmp("lo", tempIfAddr->ifa_name) == 0)
				continue;

			address = (char *)inet_ntop(tempIfAddr->ifa_addr->sa_family,
						    tempAddrPtr, addressOutputBuffer,
						    sizeof(addressOutputBuffer));
			if (!address)
				continue;

			nbytes = lxc_write_nointr(pipefd[1], address, INET6_ADDRSTRLEN);
			if (nbytes != INET6_ADDRSTRLEN) {
				SYSERROR("Failed to send ipv6 address \"%s\"",
					 address);
				goto out;
			}

			count++;
		}

		ret = 0;

	out:
		if (interfaceArray)
			netns_freeifaddrs(interfaceArray);

		/* close the write-end of the pipe, thus sending EOF to the reader */
		close(pipefd[1]);
		_exit(ret);
	}

	/* close the write-end of the pipe */
	close(pipefd[1]);

	while (lxc_read_nointr(pipefd[0], &address, INET6_ADDRSTRLEN) == INET6_ADDRSTRLEN) {
		address[INET6_ADDRSTRLEN - 1] = '\0';

		if (!add_to_array(&addresses, address, count))
			ERROR("PARENT: add_to_array failed");

		count++;
	}

	if (wait_for_pid(pid) != 0) {
		for (i = 0; i < count; i++)
			free(addresses[i]);

		free(addresses);
		addresses = NULL;
	}

	/* close the read-end of the pipe */
	close(pipefd[0]);

	/* Append NULL to the array */
	if (addresses)
		addresses = (char **)lxc_append_null_to_array((void **)addresses, count);

	return addresses;
}

WRAP_API_3(char **, lxcapi_get_ips, const char *, const char *, int)

static int do_lxcapi_get_config_item(struct lxc_container *c, const char *key, char *retv, int inlen)
{
	int ret = -1;
	struct lxc_config_t *config;

	if (!c || !c->lxc_conf)
		return -1;

	if (container_mem_lock(c))
		return -1;

	config = lxc_get_config(key);
	/* Verify that the config key exists and that it has a callback
	 * implemented.
	 */
	if (config && config->get)
		ret = config->get(key, retv, inlen, c->lxc_conf, NULL);

	container_mem_unlock(c);
	return ret;
}

WRAP_API_3(int, lxcapi_get_config_item, const char *, char *, int)

static char* do_lxcapi_get_running_config_item(struct lxc_container *c, const char *key)
{
	char *ret;

	if (!c || !c->lxc_conf)
		return NULL;

	if (container_mem_lock(c))
		return NULL;

	ret = lxc_cmd_get_config_item(c->name, key, do_lxcapi_get_config_path(c));
	container_mem_unlock(c);
	return ret;
}

WRAP_API_1(char *, lxcapi_get_running_config_item, const char *)

static int do_lxcapi_get_keys(struct lxc_container *c, const char *key, char *retv, int inlen)
{
	int ret = -1;

	/* List all config items. */
	if (!key)
		return lxc_list_config_items(retv, inlen);

	if (!c || !c->lxc_conf)
		return -1;

	if (container_mem_lock(c))
		return -1;

	/* Support 'lxc.net.<idx>', i.e. 'lxc.net.0'
	 * This is an intelligent result to show which keys are valid given the
	 * type of nic it is.
	 */
	if (strncmp(key, "lxc.net.", 8) == 0)
		ret = lxc_list_net(c->lxc_conf, key, retv, inlen);
	else
		ret = lxc_list_subkeys(c->lxc_conf, key, retv, inlen);

	container_mem_unlock(c);
	return ret;
}

WRAP_API_3(int, lxcapi_get_keys, const char *, char *, int)

static bool do_lxcapi_save_config(struct lxc_container *c, const char *alt_file)
{
	int fd, lret;
	bool ret = false, need_disklock = false;

	if (!alt_file)
		alt_file = c->configfile;

	if (!alt_file)
		return false;

	/* If we haven't yet loaded a config, load the stock config. */
	if (!c->lxc_conf) {
		if (!do_lxcapi_load_config(c, lxc_global_config_value("lxc.default_config"))) {
			ERROR("Error loading default configuration file %s "
			      "while saving %s",
			      lxc_global_config_value("lxc.default_config"),
			      c->name);
			return false;
		}
	}

	if (!create_container_dir(c))
		return false;

	/* If we're writing to the container's config file, take the disk lock.
	 * Otherwise just take the memlock to protect the struct lxc_container
	 * while we're traversing it.
	 */
	if (strcmp(c->configfile, alt_file) == 0)
		need_disklock = true;

	if (need_disklock)
		lret = container_disk_lock(c);
	else
		lret = container_mem_lock(c);
	if (lret)
		return false;

	fd = open(alt_file, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
		  S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
	if (fd < 0)
		goto on_error;

	lret = write_config(fd, c->lxc_conf);
	close(fd);
	if (lret < 0)
		goto on_error;

	ret = true;

on_error:
	if (need_disklock)
		container_disk_unlock(c);
	else
		container_mem_unlock(c);

	return ret;
}

WRAP_API_1(bool, lxcapi_save_config, const char *)


static bool mod_rdep(struct lxc_container *c0, struct lxc_container *c, bool inc)
{
	FILE *f1;
	struct stat fbuf;
	void *buf = NULL;
	char *del = NULL;
	char path[PATH_MAX];
	char newpath[PATH_MAX];
	int fd, ret, n = 0, v = 0;
	bool bret = false;
	size_t len = 0, bytes = 0;

	if (container_disk_lock(c0))
		return false;

	ret = snprintf(path, PATH_MAX, "%s/%s/lxc_snapshots", c0->config_path, c0->name);
	if (ret < 0 || ret > PATH_MAX)
		goto out;

	ret = snprintf(newpath, PATH_MAX, "%s\n%s\n", c->config_path, c->name);
	if (ret < 0 || ret > PATH_MAX)
		goto out;

	/* If we find an lxc-snapshot file using the old format only listing the
	 * number of snapshots we will keep using it. */
	f1 = fopen(path, "r");
	if (f1) {
		n = fscanf(f1, "%d", &v);
		fclose(f1);
		if (n == 1 && v == 0) {
			ret = remove(path);
			if (ret < 0)
				SYSERROR("Failed to remove \"%s\"", path);

			n = 0;
		}
	}

	if (n == 1) {
		v += inc ? 1 : -1;
		f1 = fopen(path, "w");
		if (!f1)
			goto out;

		if (fprintf(f1, "%d\n", v) < 0) {
			ERROR("Error writing new snapshots value");
			fclose(f1);
			goto out;
		}

		ret = fclose(f1);
		if (ret != 0) {
			SYSERROR("Error writing to or closing snapshots file");
			goto out;
		}
	} else {
		/* Here we know that we have or can use an lxc-snapshot file
		 * using the new format. */
		if (inc) {
			f1 = fopen(path, "a");
			if (!f1)
				goto out;

			if (fprintf(f1, "%s", newpath) < 0) {
				ERROR("Error writing new snapshots entry");
				ret = fclose(f1);
				if (ret != 0)
					SYSERROR("Error writing to or closing snapshots file");
				goto out;
			}

			ret = fclose(f1);
			if (ret != 0) {
				SYSERROR("Error writing to or closing snapshots file");
				goto out;
			}
		} else if (!inc) {
			if ((fd = open(path, O_RDWR | O_CLOEXEC)) < 0)
				goto out;

			if (fstat(fd, &fbuf) < 0) {
				close(fd);
				goto out;
			}

			if (fbuf.st_size != 0) {
				buf = lxc_strmmap(NULL, fbuf.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
				if (buf == MAP_FAILED) {
					SYSERROR("Failed to create mapping %s", path);
					close(fd);
					goto out;
				}

				len = strlen(newpath);
				while ((del = strstr((char *)buf, newpath))) {
					memmove(del, del + len, strlen(del) - len + 1);
					bytes += len;
				}

				lxc_strmunmap(buf, fbuf.st_size);
				if (ftruncate(fd, fbuf.st_size - bytes) < 0) {
					SYSERROR("Failed to truncate file %s", path);
					close(fd);
					goto out;
				}
			}

			close(fd);
		}

		/* If the lxc-snapshot file is empty, remove it. */
		if (stat(path, &fbuf) < 0)
			goto out;

		if (!fbuf.st_size) {
			ret = remove(path);
			if (ret < 0)
				SYSERROR("Failed to remove \"%s\"", path);
		}
	}

	bret = true;

out:
	container_disk_unlock(c0);
	return bret;
}

void mod_all_rdeps(struct lxc_container *c, bool inc)
{
	struct lxc_container *p;
	char *lxcpath = NULL, *lxcname = NULL, path[PATH_MAX];
	size_t pathlen = 0, namelen = 0;
	FILE *f;
	int ret;

	ret = snprintf(path, PATH_MAX, "%s/%s/lxc_rdepends",
		c->config_path, c->name);
	if (ret < 0 || ret >= PATH_MAX) {
		ERROR("Path name too long");
		return;
	}

	f = fopen(path, "r");
	if (f == NULL)
		return;

	while (getline(&lxcpath, &pathlen, f) != -1) {
		if (getline(&lxcname, &namelen, f) == -1) {
			ERROR("badly formatted file %s", path);
			goto out;
		}

		remove_trailing_newlines(lxcpath);
		remove_trailing_newlines(lxcname);

		if ((p = lxc_container_new(lxcname, lxcpath)) == NULL) {
			ERROR("Unable to find dependent container %s:%s",
				lxcpath, lxcname);
			continue;
		}

		if (!mod_rdep(p, c, inc))
			ERROR("Failed to update snapshots file for %s:%s",
				lxcpath, lxcname);

		lxc_container_put(p);
	}

out:
	free(lxcpath);
	free(lxcname);
	fclose(f);
}

static bool has_fs_snapshots(struct lxc_container *c)
{
	FILE *f;
	char path[PATH_MAX];
	int ret, v;
	struct stat fbuf;
	bool bret = false;

	ret = snprintf(path, PATH_MAX, "%s/%s/lxc_snapshots", c->config_path,
			c->name);
	if (ret < 0 || ret > PATH_MAX)
		goto out;

	/* If the file doesn't exist there are no snapshots. */
	if (stat(path, &fbuf) < 0)
		goto out;

	v = fbuf.st_size;
	if (v != 0) {
		f = fopen(path, "r");
		if (!f)
			goto out;

		ret = fscanf(f, "%d", &v);
		fclose(f);
		/* TODO: Figure out what to do with the return value of fscanf. */
		if (ret != 1)
			INFO("Container uses new lxc-snapshots format %s", path);
	}

	bret = v != 0;

out:
	return bret;
}

static bool has_snapshots(struct lxc_container *c)
{
	char path[PATH_MAX];
	struct dirent *direntp;
	int count=0;
	DIR *dir;

	if (!get_snappath_dir(c, path))
		return false;

	dir = opendir(path);
	if (!dir)
		return false;

	while ((direntp = readdir(dir))) {
		if (!strcmp(direntp->d_name, "."))
			continue;

		if (!strcmp(direntp->d_name, ".."))
			continue;
		count++;
		break;
	}

	closedir(dir);
	return count > 0;
}

static bool do_destroy_container(struct lxc_conf *conf) {
	int ret;

	if (am_guest_unpriv()) {
		ret = userns_exec_full(conf, storage_destroy_wrapper, conf,
				       "storage_destroy_wrapper");
		if (ret < 0)
			return false;

		return true;
	}

	return storage_destroy(conf);
}

static int lxc_rmdir_onedev_wrapper(void *data)
{
	char *arg = (char *) data;
	return lxc_rmdir_onedev(arg, "snaps");
}

static int lxc_unlink_exec_wrapper(void *data)
{
	char *arg = data;
	return unlink(arg);
}

static bool container_destroy(struct lxc_container *c,
			      struct lxc_storage *storage)
{
	const char *p1;
	size_t len;
	struct lxc_conf *conf;
	char *path = NULL;
	bool bret = false;
	int ret = 0;

	if (!c || !do_lxcapi_is_defined(c))
		return false;

	conf = c->lxc_conf;
	if (container_disk_lock(c))
		return false;

	if (!is_stopped(c)) {
		/* We should queue some sort of error - in c->error_string? */
		ERROR("container %s is not stopped", c->name);
		goto out;
	}

	if (conf && !lxc_list_empty(&conf->hooks[LXCHOOK_DESTROY])) {
		/* Start of environment variable setup for hooks */
		if (setenv("LXC_NAME", c->name, 1))
			SYSERROR("Failed to set environment variable for container name");

		if (conf->rcfile && setenv("LXC_CONFIG_FILE", conf->rcfile, 1))
			SYSERROR("Failed to set environment variable for config path");

		if (conf->rootfs.mount && setenv("LXC_ROOTFS_MOUNT", conf->rootfs.mount, 1))
			SYSERROR("Failed to set environment variable for rootfs mount");

		if (conf->rootfs.path && setenv("LXC_ROOTFS_PATH", conf->rootfs.path, 1))
			SYSERROR("Failed to set environment variable for rootfs mount");

		if (conf->console.path && setenv("LXC_CONSOLE", conf->console.path, 1))
			SYSERROR("Failed to set environment variable for console path");

		if (conf->console.log_path && setenv("LXC_CONSOLE_LOGPATH", conf->console.log_path, 1))
			SYSERROR("Failed to set environment variable for console log");
		/* End of environment variable setup for hooks */

		if (run_lxc_hooks(c->name, "destroy", conf, NULL)) {
			ERROR("Failed to execute clone hook for \"%s\"", c->name);
			goto out;
		}
	}

	if (current_config && conf == current_config) {
		current_config = NULL;

		if (conf->logfd != -1) {
			close(conf->logfd);
			conf->logfd = -1;
		}
	}

	if (conf && conf->rootfs.path && conf->rootfs.mount) {
		if (!do_destroy_container(conf)) {
			ERROR("Error destroying rootfs for %s", c->name);
			goto out;
		}
		INFO("Destroyed rootfs for %s", c->name);
	}

	mod_all_rdeps(c, false);

	p1 = do_lxcapi_get_config_path(c);
	/* strlen(p1)
	 * +
	 * /
	 * +
	 * strlen(c->name)
	 * +
	 * /
	 * +
	 * strlen("config") = 6
	 * +
	 * \0
	 */
	len = strlen(p1) + 1 + strlen(c->name) + 1 + 6 + 1;
	path = malloc(len);
	if (!path) {
		ERROR("Failed to allocate memory");
		goto out;
	}

	/* For an overlay container the rootfs is considered immutable and
	 * cannot be removed when restoring from a snapshot.
	 */
	if (storage && (!strcmp(storage->type, "overlay") ||
			!strcmp(storage->type, "overlayfs")) &&
	    (storage->flags & LXC_STORAGE_INTERNAL_OVERLAY_RESTORE)) {
		ret = snprintf(path, len, "%s/%s/config", p1, c->name);
		if (ret < 0 || (size_t)ret >= len)
			goto out;

		if (am_guest_unpriv())
			ret = userns_exec_1(conf, lxc_unlink_exec_wrapper, path,
					    "lxc_unlink_exec_wrapper");
		else
			ret = unlink(path);
		if (ret < 0) {
			SYSERROR("Failed to destroy config file \"%s\" for \"%s\"",
			         path, c->name);
			goto out;
		}
		INFO("Destroyed config file \"%s\" for \"%s\"", path, c->name);

		bret = true;
		goto out;
	}

	ret = snprintf(path, len, "%s/%s", p1, c->name);
	if (ret < 0 || (size_t)ret >= len)
		goto out;

	if (am_guest_unpriv())
		ret = userns_exec_full(conf, lxc_rmdir_onedev_wrapper, path,
				       "lxc_rmdir_onedev_wrapper");
	else
		ret = lxc_rmdir_onedev(path, "snaps");
	if (ret < 0) {
		ERROR("Failed to destroy directory \"%s\" for \"%s\"", path,
		      c->name);
		goto out;
	}
	INFO("Destroyed directory \"%s\" for \"%s\"", path, c->name);

	bret = true;

out:
	if (path)
		free(path);

	container_disk_unlock(c);
	return bret;
}

static bool do_lxcapi_destroy(struct lxc_container *c)
{
	if (!c || !lxcapi_is_defined(c))
		return false;

	if (has_snapshots(c)) {
		ERROR("Container %s has snapshots;  not removing", c->name);
		return false;
	}

	if (has_fs_snapshots(c)) {
		ERROR("container %s has snapshots on its rootfs", c->name);
		return false;
	}

	return container_destroy(c, NULL);
}

WRAP_API(bool, lxcapi_destroy)

static bool do_lxcapi_destroy_with_snapshots(struct lxc_container *c)
{
	if (!c || !lxcapi_is_defined(c))
		return false;

	if (!lxcapi_snapshot_destroy_all(c)) {
		ERROR("Error deleting all snapshots");
		return false;
	}

	return lxcapi_destroy(c);
}

WRAP_API(bool, lxcapi_destroy_with_snapshots)

int lxc_set_config_item_locked(struct lxc_conf *conf, const char *key,
			       const char *v)
{
	int ret;
	struct lxc_config_t *config;
	bool bret = true;

	config = lxc_get_config(key);
	if (!config)
		return -EINVAL;

	ret = config->set(key, v, conf, NULL);
	if (ret < 0)
		return -EINVAL;

	if (lxc_config_value_empty(v))
		do_clear_unexp_config_line(conf, key);
	else
		bret = do_append_unexp_config_line(conf, key, v);
	if (!bret)
		return -ENOMEM;

	return 0;
}

static bool do_set_config_item_locked(struct lxc_container *c, const char *key,
				      const char *v)
{
	int ret;

	if (!c->lxc_conf)
		c->lxc_conf = lxc_conf_init();

	if (!c->lxc_conf)
		return false;

	ret = lxc_set_config_item_locked(c->lxc_conf, key, v);
	if (ret < 0)
		return false;

	return true;
}

static bool do_lxcapi_set_config_item(struct lxc_container *c, const char *key, const char *v)
{
	bool b = false;

	if (!c)
		return false;

	if (container_mem_lock(c))
		return false;

	b = do_set_config_item_locked(c, key, v);

	container_mem_unlock(c);
	return b;
}

WRAP_API_2(bool, lxcapi_set_config_item, const char *, const char *)

static char *lxcapi_config_file_name(struct lxc_container *c)
{
	if (!c || !c->configfile)
		return NULL;

	return strdup(c->configfile);
}

static const char *lxcapi_get_config_path(struct lxc_container *c)
{
	if (!c || !c->config_path)
		return NULL;

	return (const char *)(c->config_path);
}

/*
 * not for export
 * Just recalculate the c->configfile based on the
 * c->config_path, which must be set.
 * The lxc_container must be locked or not yet public.
 */
static bool set_config_filename(struct lxc_container *c)
{
	char *newpath;
	int len, ret;

	if (!c->config_path)
		return false;

	/* $lxc_path + "/" + c->name + "/" + "config" + '\0' */
	len = strlen(c->config_path) + strlen(c->name) + strlen("config") + 3;
	newpath = malloc(len);
	if (!newpath)
		return false;

	ret = snprintf(newpath, len, "%s/%s/config", c->config_path, c->name);
	if (ret < 0 || ret >= len) {
		fprintf(stderr, "Error printing out config file name\n");
		free(newpath);
		return false;
	}

	free(c->configfile);
	c->configfile = newpath;

	return true;
}

static bool do_lxcapi_set_config_path(struct lxc_container *c, const char *path)
{
	char *p;
	bool b = false;
	char *oldpath = NULL;

	if (!c)
		return b;

	if (container_mem_lock(c))
		return b;

	p = strdup(path);
	if (!p) {
		ERROR("Out of memory setting new lxc path");
		goto err;
	}

	b = true;
	if (c->config_path)
		oldpath = c->config_path;
	c->config_path = p;

	/* Since we've changed the config path, we have to change the
	 * config file name too */
	if (!set_config_filename(c)) {
		ERROR("Out of memory setting new config filename");
		b = false;
		free(c->config_path);
		c->config_path = oldpath;
		oldpath = NULL;
	}

err:
	free(oldpath);
	container_mem_unlock(c);
	return b;
}

WRAP_API_1(bool, lxcapi_set_config_path, const char *)

static bool do_lxcapi_set_cgroup_item(struct lxc_container *c, const char *subsys, const char *value)
{
	int ret;
	struct cgroup_ops *cgroup_ops;

	if (!c)
		return false;

	if (is_stopped(c))
		return false;

	cgroup_ops = cgroup_init(NULL);
	if (!cgroup_ops)
		return false;

	ret = cgroup_ops->set(cgroup_ops, subsys, value, c->name, c->config_path);

	cgroup_exit(cgroup_ops);

	return ret == 0;
}

WRAP_API_2(bool, lxcapi_set_cgroup_item, const char *, const char *)

static int do_lxcapi_get_cgroup_item(struct lxc_container *c, const char *subsys, char *retv, int inlen)
{
	int ret;
	struct cgroup_ops *cgroup_ops;

	if (!c)
		return -1;

	if (is_stopped(c))
		return -1;

	cgroup_ops = cgroup_init(NULL);
	if (!cgroup_ops)
		return -1;

	ret = cgroup_ops->get(cgroup_ops, subsys, retv, inlen, c->name,
			      c->config_path);

	cgroup_exit(cgroup_ops);

	return ret;
}

WRAP_API_3(int, lxcapi_get_cgroup_item, const char *, char *, int)

const char *lxc_get_global_config_item(const char *key)
{
	return lxc_global_config_value(key);
}

const char *lxc_get_version(void)
{
	return LXC_VERSION;
}

static int copy_file(const char *old, const char *new)
{
	int in, out;
	ssize_t len, ret;
	char buf[8096];
	struct stat sbuf;

	if (file_exists(new)) {
		ERROR("copy destination %s exists", new);
		return -1;
	}

	ret = stat(old, &sbuf);
	if (ret < 0) {
		INFO("Error stat'ing %s", old);
		return -1;
	}

	in = open(old, O_RDONLY);
	if (in < 0) {
		SYSERROR("Error opening original file %s", old);
		return -1;
	}

	out = open(new, O_CREAT | O_EXCL | O_WRONLY, 0644);
	if (out < 0) {
		SYSERROR("Error opening new file %s", new);
		close(in);
		return -1;
	}

	while (1) {
		len = lxc_read_nointr(in, buf, 8096);
		if (len < 0) {
			SYSERROR("Error reading old file %s", old);
			goto err;
		}

		if (len == 0)
			break;

		ret = lxc_write_nointr(out, buf, len);
		if (ret < len) { /* should we retry? */
			SYSERROR("Error: write to new file %s was interrupted", new);
			goto err;
		}
	}

	close(in);
	close(out);

	/* We set mode, but not owner/group. */
	ret = chmod(new, sbuf.st_mode);
	if (ret) {
		SYSERROR("Error setting mode on %s", new);
		return -1;
	}

	return 0;

err:
	close(in);
	close(out);
	return -1;
}

static int copyhooks(struct lxc_container *oldc, struct lxc_container *c)
{
	int i, len, ret;
	struct lxc_list *it;
	char *cpath;

	len = strlen(oldc->config_path) + strlen(oldc->name) + 3;
	cpath = alloca(len);
	ret = snprintf(cpath, len, "%s/%s/", oldc->config_path, oldc->name);
	if (ret < 0 || ret >= len)
		return -1;

	for (i=0; i<NUM_LXC_HOOKS; i++) {
		lxc_list_for_each(it, &c->lxc_conf->hooks[i]) {
			char *hookname = it->elem;
			char *fname = strrchr(hookname, '/');
			char tmppath[PATH_MAX];
			if (!fname) /* relative path - we don't support, but maybe we should */
				return 0;

			if (strncmp(hookname, cpath, len - 1) != 0) {
				/* this hook is public - ignore */
				continue;
			}

			/* copy the script, and change the entry in confile */
			ret = snprintf(tmppath, PATH_MAX, "%s/%s/%s",
					c->config_path, c->name, fname+1);
			if (ret < 0 || ret >= PATH_MAX)
				return -1;

			ret = copy_file(it->elem, tmppath);
			if (ret < 0)
				return -1;

			free(it->elem);

			it->elem = strdup(tmppath);
			if (!it->elem) {
				ERROR("out of memory copying hook path");
				return -1;
			}
		}
	}

	if (!clone_update_unexp_hooks(c->lxc_conf, oldc->config_path,
			c->config_path, oldc->name, c->name)) {
		ERROR("Error saving new hooks in clone");
		return -1;
	}

	do_lxcapi_save_config(c, NULL);
	return 0;
}


static int copy_fstab(struct lxc_container *oldc, struct lxc_container *c)
{
	char newpath[PATH_MAX];
	char *oldpath = oldc->lxc_conf->fstab;
	int ret;

	if (!oldpath)
		return 0;

	clear_unexp_config_line(c->lxc_conf, "lxc.mount.fstab", false);

	char *p = strrchr(oldpath, '/');
	if (!p)
		return -1;

	ret = snprintf(newpath, PATH_MAX, "%s/%s%s",
			c->config_path, c->name, p);
	if (ret < 0 || ret >= PATH_MAX) {
		ERROR("error printing new path for %s", oldpath);
		return -1;
	}

	if (file_exists(newpath)) {
		ERROR("error: fstab file %s exists", newpath);
		return -1;
	}

	if (copy_file(oldpath, newpath) < 0) {
		ERROR("error: copying %s to %s", oldpath, newpath);
		return -1;
	}

	free(c->lxc_conf->fstab);

	c->lxc_conf->fstab = strdup(newpath);
	if (!c->lxc_conf->fstab) {
		ERROR("error: allocating pathname");
		return -1;
	}

	if (!do_append_unexp_config_line(c->lxc_conf, "lxc.mount.fstab", newpath)) {
		ERROR("error saving new lxctab");
		return -1;
	}

	return 0;
}

static void copy_rdepends(struct lxc_container *c, struct lxc_container *c0)
{
	char path0[PATH_MAX], path1[PATH_MAX];
	int ret;

	ret = snprintf(path0, PATH_MAX, "%s/%s/lxc_rdepends", c0->config_path,
		c0->name);
	if (ret < 0 || ret >= PATH_MAX) {
		WARN("Error copying reverse dependencies");
		return;
	}

	ret = snprintf(path1, PATH_MAX, "%s/%s/lxc_rdepends", c->config_path,
		c->name);
	if (ret < 0 || ret >= PATH_MAX) {
		WARN("Error copying reverse dependencies");
		return;
	}

	if (copy_file(path0, path1) < 0) {
		INFO("Error copying reverse dependencies");
		return;
	}
}

static bool add_rdepends(struct lxc_container *c, struct lxc_container *c0)
{
	int ret;
	char path[PATH_MAX];
	FILE *f;
	bool bret;

	ret = snprintf(path, PATH_MAX, "%s/%s/lxc_rdepends", c->config_path,
		c->name);
	if (ret < 0 || ret >= PATH_MAX)
		return false;

	f = fopen(path, "a");
	if (!f)
		return false;

	bret = true;

	/* If anything goes wrong, just return an error. */
	if (fprintf(f, "%s\n%s\n", c0->config_path, c0->name) < 0)
		bret = false;

	if (fclose(f) != 0)
		bret = false;

	return bret;
}

/*
 * If the fs natively supports snapshot clones with no penalty,
 * then default to those even if not requested.
 * Currently we only do this for btrfs.
 */
bool should_default_to_snapshot(struct lxc_container *c0,
				struct lxc_container *c1)
{
	int ret;
	size_t l0 = strlen(c0->config_path) + strlen(c0->name) + 2;
	size_t l1 = strlen(c1->config_path) + strlen(c1->name) + 2;
	char *p0 = alloca(l0 + 1);
	char *p1 = alloca(l1 + 1);
	char *rootfs = c0->lxc_conf->rootfs.path;

	ret = snprintf(p0, l0, "%s/%s", c0->config_path, c0->name);
	if (ret < 0 || ret >= l0)
		return false;

	ret = snprintf(p1, l1, "%s/%s", c1->config_path, c1->name);
	if (ret < 0 || ret >= l1)
		return false;

	if (!is_btrfs_fs(p0) || !is_btrfs_fs(p1))
		return false;

	if (is_btrfs_subvol(rootfs) <= 0)
		return false;

	return btrfs_same_fs(p0, p1) == 0;
}

static int copy_storage(struct lxc_container *c0, struct lxc_container *c,
			const char *newtype, int flags, const char *bdevdata,
			uint64_t newsize)
{
	struct lxc_storage *bdev;
	bool need_rdep;

	if (should_default_to_snapshot(c0, c))
		flags |= LXC_CLONE_SNAPSHOT;

	bdev = storage_copy(c0, c->name, c->config_path, newtype, flags,
			    bdevdata, newsize, &need_rdep);
	if (!bdev) {
		ERROR("Error copying storage.");
		return -1;
	}

	/* Set new rootfs. */
	free(c->lxc_conf->rootfs.path);
	c->lxc_conf->rootfs.path = strdup(bdev->src);
	storage_put(bdev);

	if (!c->lxc_conf->rootfs.path) {
		ERROR("Out of memory while setting storage path.");
		return -1;
	}

	/* Append a new lxc.rootfs.path entry to the unexpanded config. */
	clear_unexp_config_line(c->lxc_conf, "lxc.rootfs.path", false);
	if (!do_append_unexp_config_line(c->lxc_conf, "lxc.rootfs.path",
					 c->lxc_conf->rootfs.path)) {
		ERROR("Error saving new rootfs to cloned config.");
		return -1;
	}

	if (flags & LXC_CLONE_SNAPSHOT)
		copy_rdepends(c, c0);

	if (need_rdep) {
		if (!add_rdepends(c, c0))
			WARN("Error adding reverse dependency from %s to %s",
			     c->name, c0->name);
	}

	mod_all_rdeps(c, true);

	return 0;
}

struct clone_update_data {
	struct lxc_container *c0;
	struct lxc_container *c1;
	int flags;
	char **hookargs;
};

static int clone_update_rootfs(struct clone_update_data *data)
{
	struct lxc_container *c0 = data->c0;
	struct lxc_container *c = data->c1;
	int flags = data->flags;
	char **hookargs = data->hookargs;
	int ret = -1;
	char path[PATH_MAX];
	struct lxc_storage *bdev;
	FILE *fout;
	struct lxc_conf *conf = c->lxc_conf;

	/* update hostname in rootfs */
	/* we're going to mount, so run in a clean namespace to simplify cleanup */

	if (setgid(0) < 0) {
		ERROR("Failed to setgid to 0");
		return -1;
	}

	if (setuid(0) < 0) {
		ERROR("Failed to setuid to 0");
		return -1;
	}

	if (setgroups(0, NULL) < 0)
		WARN("Failed to clear groups");

	if (unshare(CLONE_NEWNS) < 0)
		return -1;

	bdev = storage_init(c->lxc_conf);
	if (!bdev)
		return -1;

	if (strcmp(bdev->type, "dir") != 0) {
		if (unshare(CLONE_NEWNS) < 0) {
			ERROR("error unsharing mounts");
			storage_put(bdev);
			return -1;
		}

		if (detect_shared_rootfs()) {
			if (mount(NULL, "/", NULL, MS_SLAVE|MS_REC, NULL)) {
				SYSERROR("Failed to make / rslave");
				ERROR("Continuing...");
			}
		}

		if (bdev->ops->mount(bdev) < 0) {
			storage_put(bdev);
			return -1;
		}
	} else { /* TODO come up with a better way */
		free(bdev->dest);
		bdev->dest = strdup(bdev->src);
	}

	if (!lxc_list_empty(&conf->hooks[LXCHOOK_CLONE])) {
		/* Start of environment variable setup for hooks */
		if (c0->name && setenv("LXC_SRC_NAME", c0->name, 1))
			SYSERROR("failed to set environment variable for source container name");

		if (setenv("LXC_NAME", c->name, 1))
			SYSERROR("failed to set environment variable for container name");

		if (conf->rcfile && setenv("LXC_CONFIG_FILE", conf->rcfile, 1))
			SYSERROR("failed to set environment variable for config path");

		if (bdev->dest && setenv("LXC_ROOTFS_MOUNT", bdev->dest, 1))
			SYSERROR("failed to set environment variable for rootfs mount");

		if (conf->rootfs.path && setenv("LXC_ROOTFS_PATH", conf->rootfs.path, 1))
			SYSERROR("failed to set environment variable for rootfs mount");

		if (run_lxc_hooks(c->name, "clone", conf, hookargs)) {
			ERROR("Error executing clone hook for %s", c->name);
			storage_put(bdev);
			return -1;
		}
	}

	if (!(flags & LXC_CLONE_KEEPNAME)) {
		ret = snprintf(path, PATH_MAX, "%s/etc/hostname", bdev->dest);
		storage_put(bdev);

		if (ret < 0 || ret >= PATH_MAX)
			return -1;

		if (!file_exists(path))
			return 0;

		if (!(fout = fopen(path, "w"))) {
			SYSERROR("unable to open %s: ignoring", path);
			return 0;
		}

		if (fprintf(fout, "%s", c->name) < 0) {
			fclose(fout);
			return -1;
		}

		if (fclose(fout) < 0)
			return -1;
	} else {
		storage_put(bdev);
	}

	return 0;
}

static int clone_update_rootfs_wrapper(void *data)
{
	struct clone_update_data *arg = (struct clone_update_data *) data;
	return clone_update_rootfs(arg);
}

/*
 * We want to support:
sudo lxc-clone -o o1 -n n1 -s -L|-fssize fssize -v|--vgname vgname \
        -p|--lvprefix lvprefix -t|--fstype fstype  -B backingstore

-s [ implies overlay]
-s -B overlay

only rootfs gets converted (copied/snapshotted) on clone.
*/

static int create_file_dirname(char *path, struct lxc_conf *conf)
{
	char *p = strrchr(path, '/');
	int ret = -1;

	if (!p)
		return -1;

	*p = '\0';
	ret = do_create_container_dir(path, conf);
	*p = '/';

	return ret;
}

static struct lxc_container *do_lxcapi_clone(struct lxc_container *c, const char *newname,
		const char *lxcpath, int flags,
		const char *bdevtype, const char *bdevdata, uint64_t newsize,
		char **hookargs)
{
	char newpath[PATH_MAX];
	int fd, ret;
	struct clone_update_data data;
	size_t saved_unexp_len;
	pid_t pid;
	int storage_copied = 0;
	char *origroot = NULL, *saved_unexp_conf = NULL;
	struct lxc_container *c2 = NULL;

	if (!c || !do_lxcapi_is_defined(c))
		return NULL;

	if (container_mem_lock(c))
		return NULL;

	if (!is_stopped(c)) {
		ERROR("error: Original container (%s) is running", c->name);
		goto out;
	}

	/* Make sure the container doesn't yet exist. */
	if (!newname)
		newname = c->name;

	if (!lxcpath)
		lxcpath = do_lxcapi_get_config_path(c);

	ret = snprintf(newpath, PATH_MAX, "%s/%s/config", lxcpath, newname);
	if (ret < 0 || ret >= PATH_MAX) {
		SYSERROR("clone: failed making config pathname");
		goto out;
	}

	if (file_exists(newpath)) {
		ERROR("error: clone: %s exists", newpath);
		goto out;
	}

	ret = create_file_dirname(newpath, c->lxc_conf);
	if (ret < 0 && errno != EEXIST) {
		ERROR("Error creating container dir for %s", newpath);
		goto out;
	}

	/* Copy the configuration. Tweak it as needed. */
	if (c->lxc_conf->rootfs.path) {
		origroot = c->lxc_conf->rootfs.path;
		c->lxc_conf->rootfs.path = NULL;
	}

	fd = open(newpath, O_WRONLY | O_CREAT | O_CLOEXEC,
		  S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
	if (fd < 0) {
		SYSERROR("Failed to open \"%s\"", newpath);
		goto out;
	}

	saved_unexp_conf = c->lxc_conf->unexpanded_config;
	saved_unexp_len = c->lxc_conf->unexpanded_len;
	c->lxc_conf->unexpanded_config = strdup(saved_unexp_conf);
	if (!c->lxc_conf->unexpanded_config) {
		close(fd);
		goto out;
	}

	clear_unexp_config_line(c->lxc_conf, "lxc.rootfs.path", false);
	write_config(fd, c->lxc_conf);
	close(fd);

	c->lxc_conf->rootfs.path = origroot;

	free(c->lxc_conf->unexpanded_config);
	c->lxc_conf->unexpanded_config = saved_unexp_conf;
	saved_unexp_conf = NULL;
	c->lxc_conf->unexpanded_len = saved_unexp_len;

	ret = snprintf(newpath, PATH_MAX, "%s/%s/rootfs", lxcpath, newname);
	if (ret < 0 || ret >= PATH_MAX) {
		SYSERROR("clone: failed making rootfs pathname");
		goto out;
	}

	ret = mkdir(newpath, 0755);
	if (ret < 0) {
		/* For an overlay container the rootfs is considered immutable
		 * and will not have been removed when restoring from a
		 * snapshot.
		 */
		if (errno != ENOENT &&
		    !(flags & LXC_STORAGE_INTERNAL_OVERLAY_RESTORE)) {
			SYSERROR("Failed to create directory \"%s\"", newpath);
			goto out;
		}
	}

	if (am_guest_unpriv()) {
		if (chown_mapped_root(newpath, c->lxc_conf) < 0) {
			ERROR("Error chowning %s to container root", newpath);
			goto out;
		}
	}

	c2 = lxc_container_new(newname, lxcpath);
	if (!c2) {
		ERROR("clone: failed to create new container (%s %s)", newname,
				lxcpath);
		goto out;
	}

	/* copy/snapshot rootfs's */
	ret = copy_storage(c, c2, bdevtype, flags, bdevdata, newsize);
	if (ret < 0)
		goto out;

	/* update utsname */
	if (!(flags & LXC_CLONE_KEEPNAME)) {
		clear_unexp_config_line(c2->lxc_conf, "lxc.utsname", false);
		clear_unexp_config_line(c2->lxc_conf, "lxc.uts.name", false);

		if (!do_set_config_item_locked(c2, "lxc.uts.name", newname)) {
			ERROR("Error setting new hostname");
			goto out;
		}
	}

	/* copy hooks */
	ret = copyhooks(c, c2);
	if (ret < 0) {
		ERROR("error copying hooks");
		goto out;
	}

	if (copy_fstab(c, c2) < 0) {
		ERROR("error copying fstab");
		goto out;
	}

	/* update macaddrs */
	if (!(flags & LXC_CLONE_KEEPMACADDR)) {
		if (!network_new_hwaddrs(c2->lxc_conf)) {
			ERROR("Error updating mac addresses");
			goto out;
		}
	}

	/* Update absolute paths for overlay mount directories. */
	if (ovl_update_abs_paths(c2->lxc_conf, c->config_path, c->name, lxcpath, newname) < 0)
		goto out;

	/* We've now successfully created c2's storage, so clear it out if we
	 * fail after this.
	 */
	storage_copied = 1;

	if (!c2->save_config(c2, NULL))
		goto out;

	if ((pid = fork()) < 0) {
		SYSERROR("fork");
		goto out;
	}

	if (pid > 0) {
		ret = wait_for_pid(pid);
		if (ret)
			goto out;

		container_mem_unlock(c);
		return c2;
	}

	data.c0 = c;
	data.c1 = c2;
	data.flags = flags;
	data.hookargs = hookargs;

	if (am_guest_unpriv())
		ret = userns_exec_full(c->lxc_conf, clone_update_rootfs_wrapper,
				       &data, "clone_update_rootfs_wrapper");
	else
		ret = clone_update_rootfs(&data);
	if (ret < 0)
		_exit(EXIT_FAILURE);

	container_mem_unlock(c);
	_exit(EXIT_SUCCESS);

out:
	container_mem_unlock(c);
	if (c2) {
		if (!storage_copied)
			c2->lxc_conf->rootfs.path = NULL;

		c2->destroy(c2);
		lxc_container_put(c2);
	}

	return NULL;
}

static struct lxc_container *lxcapi_clone(struct lxc_container *c, const char *newname,
		const char *lxcpath, int flags,
		const char *bdevtype, const char *bdevdata, uint64_t newsize,
		char **hookargs)
{
	struct lxc_container * ret;

	current_config = c ? c->lxc_conf : NULL;
	ret = do_lxcapi_clone(c, newname, lxcpath, flags, bdevtype, bdevdata, newsize, hookargs);
	current_config = NULL;

	return ret;
}

static bool do_lxcapi_rename(struct lxc_container *c, const char *newname)
{
	struct lxc_storage *bdev;
	struct lxc_container *newc;

	if (!c || !c->name || !c->config_path || !c->lxc_conf)
		return false;

	if (has_fs_snapshots(c) || has_snapshots(c)) {
		ERROR("Renaming a container with snapshots is not supported");
		return false;
	}

	bdev = storage_init(c->lxc_conf);
	if (!bdev) {
		ERROR("Failed to find original backing store type");
		return false;
	}

	newc = lxcapi_clone(c, newname, c->config_path, LXC_CLONE_KEEPMACADDR, NULL, bdev->type, 0, NULL);
	storage_put(bdev);
	if (!newc) {
		lxc_container_put(newc);
		return false;
	}

	if (newc && lxcapi_is_defined(newc))
		lxc_container_put(newc);

	if (!container_destroy(c, NULL)) {
		ERROR("Could not destroy existing container %s", c->name);
		return false;
	}

	return true;
}

WRAP_API_1(bool, lxcapi_rename, const char *)

static int lxcapi_attach(struct lxc_container *c, lxc_attach_exec_t exec_function, void *exec_payload, lxc_attach_options_t *options, pid_t *attached_process)
{
	int ret;

	if (!c)
		return -1;

	current_config = c->lxc_conf;

	ret = lxc_attach(c->name, c->config_path, exec_function, exec_payload, options, attached_process);
	current_config = NULL;
	return ret;
}

static int do_lxcapi_attach_run_wait(struct lxc_container *c, lxc_attach_options_t *options, const char *program, const char * const argv[])
{
	lxc_attach_command_t command;
	pid_t pid;
	int r;

	if (!c)
		return -1;

	command.program = (char*)program;
	command.argv = (char**)argv;

	r = lxc_attach(c->name, c->config_path, lxc_attach_run_command, &command, options, &pid);
	if (r < 0) {
		ERROR("ups");
		return r;
	}

	return lxc_wait_for_pid_status(pid);
}

static int lxcapi_attach_run_wait(struct lxc_container *c, lxc_attach_options_t *options, const char *program, const char * const argv[])
{
	int ret;

	current_config = c ? c->lxc_conf : NULL;
	ret = do_lxcapi_attach_run_wait(c, options, program, argv);
	current_config = NULL;

	return ret;
}

static int get_next_index(const char *lxcpath, char *cname)
{
	char *fname;
	struct stat sb;
	int i = 0, ret;

	fname = alloca(strlen(lxcpath) + 20);

	while (1) {
		sprintf(fname, "%s/snap%d", lxcpath, i);

		ret = stat(fname, &sb);
		if (ret != 0)
			return i;

		i++;
	}
}

static bool get_snappath_dir(struct lxc_container *c, char *snappath)
{
	int ret;

	/*
	 * If the old style snapshot path exists, use it
	 * /var/lib/lxc -> /var/lib/lxcsnaps
	 */
	ret = snprintf(snappath, PATH_MAX, "%ssnaps", c->config_path);
	if (ret < 0 || ret >= PATH_MAX)
		return false;

	if (dir_exists(snappath)) {
		ret = snprintf(snappath, PATH_MAX, "%ssnaps/%s", c->config_path, c->name);
		if (ret < 0 || ret >= PATH_MAX)
			return false;

		return true;
	}

	/*
	 * Use the new style path
	 * /var/lib/lxc -> /var/lib/lxc + c->name + /snaps + \0
	 */
	ret = snprintf(snappath, PATH_MAX, "%s/%s/snaps", c->config_path, c->name);
	if (ret < 0 || ret >= PATH_MAX)
		return false;

	return true;
}

static int do_lxcapi_snapshot(struct lxc_container *c, const char *commentfile)
{
	int i, flags, ret;
	time_t timer;
	struct tm tm_info;
	struct lxc_container *c2;
	char snappath[PATH_MAX], newname[20];
	char buffer[25];
	FILE *f;

	if (!c || !lxcapi_is_defined(c))
		return -1;

	if (!storage_can_backup(c->lxc_conf)) {
		ERROR("%s's backing store cannot be backed up", c->name);
		ERROR("Your container must use another backing store type");
		return -1;
	}

	if (!get_snappath_dir(c, snappath))
		return -1;

	i = get_next_index(snappath, c->name);

	if (mkdir_p(snappath, 0755) < 0) {
		ERROR("Failed to create snapshot directory %s", snappath);
		return -1;
	}

	ret = snprintf(newname, 20, "snap%d", i);
	if (ret < 0 || ret >= 20)
		return -1;

	/*
	 * We pass LXC_CLONE_SNAPSHOT to make sure that a rdepends file entry is
	 * created in the original container
	 */
	flags = LXC_CLONE_SNAPSHOT | LXC_CLONE_KEEPMACADDR | LXC_CLONE_KEEPNAME |
		LXC_CLONE_KEEPBDEVTYPE | LXC_CLONE_MAYBE_SNAPSHOT;
	if (storage_is_dir(c->lxc_conf)) {
		ERROR("Snapshot of directory-backed container requested");
		ERROR("Making a copy-clone.  If you do want snapshots, then");
		ERROR("please create overlay clone first, snapshot that");
		ERROR("and keep the original container pristine");
		flags &= ~LXC_CLONE_SNAPSHOT | LXC_CLONE_MAYBE_SNAPSHOT;
	}

	c2 = do_lxcapi_clone(c, newname, snappath, flags, NULL, NULL, 0, NULL);
	if (!c2) {
		ERROR("Failed to clone of %s:%s", c->config_path, c->name);
		return -1;
	}

	lxc_container_put(c2);

	/* Now write down the creation time. */
	time(&timer);

	if (!localtime_r(&timer, &tm_info)) {
		ERROR("Failed to get localtime");
		return -1;
	}

	strftime(buffer, 25, "%Y:%m:%d %H:%M:%S", &tm_info);

	char *dfnam = alloca(strlen(snappath) + strlen(newname) + 5);
	sprintf(dfnam, "%s/%s/ts", snappath, newname);
	f = fopen(dfnam, "w");
	if (!f) {
		ERROR("Failed to open %s", dfnam);
		return -1;
	}

	if (fprintf(f, "%s", buffer) < 0) {
		SYSERROR("Writing timestamp");
		fclose(f);
		return -1;
	}

	ret = fclose(f);
	if (ret != 0) {
		SYSERROR("Writing timestamp");
		return -1;
	}

	if (commentfile) {
		/* $p / $name / comment \0 */
		int len = strlen(snappath) + strlen(newname) + 10;
		char *path = alloca(len);

		sprintf(path, "%s/%s/comment", snappath, newname);
		return copy_file(commentfile, path) < 0 ? -1 : i;
	}

	return i;
}

WRAP_API_1(int, lxcapi_snapshot, const char *)

static void lxcsnap_free(struct lxc_snapshot *s)
{
	free(s->name);
	free(s->comment_pathname);
	free(s->timestamp);
	free(s->lxcpath);
}

static char *get_snapcomment_path(char* snappath, char *name)
{
	/* $snappath/$name/comment */
	int ret, len = strlen(snappath) + strlen(name) + 10;
	char *s = malloc(len);

	if (s) {
		ret = snprintf(s, len, "%s/%s/comment", snappath, name);
		if (ret < 0 || ret >= len) {
			free(s);
			s = NULL;
		}
	}

	return s;
}

static char *get_timestamp(char* snappath, char *name)
{
	char path[PATH_MAX], *s = NULL;
	int ret, len;
	FILE *fin;

	ret = snprintf(path, PATH_MAX, "%s/%s/ts", snappath, name);
	if (ret < 0 || ret >= PATH_MAX)
		return NULL;

	fin = fopen(path, "r");
	if (!fin)
		return NULL;

	(void) fseek(fin, 0, SEEK_END);
	len = ftell(fin);
	(void) fseek(fin, 0, SEEK_SET);
	if (len > 0) {
		s = malloc(len+1);
		if (s) {
			s[len] = '\0';
			if (fread(s, 1, len, fin) != len) {
				SYSERROR("reading timestamp");
				free(s);
				s = NULL;
			}
		}
	}

	fclose(fin);
	return s;
}

static int do_lxcapi_snapshot_list(struct lxc_container *c, struct lxc_snapshot **ret_snaps)
{
	char snappath[PATH_MAX], path2[PATH_MAX];
	int count = 0, ret;
	struct dirent *direntp;
	struct lxc_snapshot *snaps =NULL, *nsnaps;
	DIR *dir;

	if (!c || !lxcapi_is_defined(c))
		return -1;

	if (!get_snappath_dir(c, snappath)) {
		ERROR("path name too long");
		return -1;
	}

	dir = opendir(snappath);
	if (!dir) {
		INFO("Failed to open %s - assuming no snapshots", snappath);
		return 0;
	}

	while ((direntp = readdir(dir))) {
		if (!strcmp(direntp->d_name, "."))
			continue;

		if (!strcmp(direntp->d_name, ".."))
			continue;

		ret = snprintf(path2, PATH_MAX, "%s/%s/config", snappath, direntp->d_name);
		if (ret < 0 || ret >= PATH_MAX) {
			ERROR("pathname too long");
			goto out_free;
		}

		if (!file_exists(path2))
			continue;

		nsnaps = realloc(snaps, (count + 1)*sizeof(*snaps));
		if (!nsnaps) {
			SYSERROR("Out of memory");
			goto out_free;
		}

		snaps = nsnaps;
		snaps[count].free = lxcsnap_free;
		snaps[count].name = strdup(direntp->d_name);
		if (!snaps[count].name)
			goto out_free;

		snaps[count].lxcpath = strdup(snappath);
		if (!snaps[count].lxcpath) {
			free(snaps[count].name);
			goto out_free;
		}

		snaps[count].comment_pathname = get_snapcomment_path(snappath, direntp->d_name);
		snaps[count].timestamp = get_timestamp(snappath, direntp->d_name);
		count++;
	}

	if (closedir(dir))
		WARN("Failed to close directory");

	*ret_snaps = snaps;
	return count;

out_free:
	if (snaps) {
		int i;

		for (i=0; i<count; i++)
			lxcsnap_free(&snaps[i]);

		free(snaps);
	}

	if (closedir(dir))
		WARN("Failed to close directory");

	return -1;
}

WRAP_API_1(int, lxcapi_snapshot_list, struct lxc_snapshot **)

static bool do_lxcapi_snapshot_restore(struct lxc_container *c, const char *snapname, const char *newname)
{
	char clonelxcpath[PATH_MAX];
	int flags = 0;
	struct lxc_container *snap, *rest;
	struct lxc_storage *bdev;
	bool b = false;

	if (!c || !c->name || !c->config_path)
		return false;

	if (has_fs_snapshots(c)) {
		ERROR("container rootfs has dependent snapshots");
		return false;
	}

	bdev = storage_init(c->lxc_conf);
	if (!bdev) {
		ERROR("Failed to find original backing store type");
		return false;
	}

	/* For an overlay container the rootfs is considered immutable
	 * and cannot be removed when restoring from a snapshot. We pass this
	 * internal flag along to communicate this to various parts of the
	 * codebase.
	 */
	if (!strcmp(bdev->type, "overlay") || !strcmp(bdev->type, "overlayfs"))
		bdev->flags |= LXC_STORAGE_INTERNAL_OVERLAY_RESTORE;

	if (!newname)
		newname = c->name;

	if (!get_snappath_dir(c, clonelxcpath)) {
		storage_put(bdev);
		return false;
	}
	/* how should we lock this? */

	snap = lxc_container_new(snapname, clonelxcpath);
	if (!snap || !lxcapi_is_defined(snap)) {
		ERROR("Could not open snapshot %s", snapname);

		if (snap)
			lxc_container_put(snap);

		storage_put(bdev);
		return false;
	}

	if (!strcmp(c->name, newname)) {
		if (!container_destroy(c, bdev)) {
			ERROR("Could not destroy existing container %s", newname);
			lxc_container_put(snap);
			storage_put(bdev);
			return false;
		}
	}

	if (strcmp(bdev->type, "dir") != 0 && strcmp(bdev->type, "loop") != 0)
		flags = LXC_CLONE_SNAPSHOT | LXC_CLONE_MAYBE_SNAPSHOT;

	if (!strcmp(bdev->type, "overlay") || !strcmp(bdev->type, "overlayfs"))
		flags |= LXC_STORAGE_INTERNAL_OVERLAY_RESTORE;

	rest = lxcapi_clone(snap, newname, c->config_path, flags, bdev->type,
			    NULL, 0, NULL);
	storage_put(bdev);
	if (rest && lxcapi_is_defined(rest))
		b = true;

	if (rest)
		lxc_container_put(rest);

	lxc_container_put(snap);
	return b;
}

WRAP_API_2(bool, lxcapi_snapshot_restore, const char *, const char *)

static bool do_snapshot_destroy(const char *snapname, const char *clonelxcpath)
{
	struct lxc_container *snap = NULL;
	bool bret = false;

	snap = lxc_container_new(snapname, clonelxcpath);
	if (!snap) {
		ERROR("Could not find snapshot %s", snapname);
		goto err;
	}

	if (!do_lxcapi_destroy(snap)) {
		ERROR("Could not destroy snapshot %s", snapname);
		goto err;
	}

	bret = true;

err:
	if (snap)
		lxc_container_put(snap);

	return bret;
}

static bool remove_all_snapshots(const char *path)
{
	DIR *dir;
	struct dirent *direntp;
	bool bret = true;

	dir = opendir(path);
	if (!dir) {
		SYSERROR("opendir on snapshot path %s", path);
		return false;
	}

	while ((direntp = readdir(dir))) {
		if (!strcmp(direntp->d_name, "."))
			continue;

		if (!strcmp(direntp->d_name, ".."))
			continue;

		if (!do_snapshot_destroy(direntp->d_name, path)) {
			bret = false;
			continue;
		}
	}

	closedir(dir);

	if (rmdir(path))
		SYSERROR("Error removing directory %s", path);

	return bret;
}

static bool do_lxcapi_snapshot_destroy(struct lxc_container *c, const char *snapname)
{
	char clonelxcpath[PATH_MAX];

	if (!c || !c->name || !c->config_path || !snapname)
		return false;

	if (!get_snappath_dir(c, clonelxcpath))
		return false;

	return do_snapshot_destroy(snapname, clonelxcpath);
}

WRAP_API_1(bool, lxcapi_snapshot_destroy, const char *)

static bool do_lxcapi_snapshot_destroy_all(struct lxc_container *c)
{
	char clonelxcpath[PATH_MAX];

	if (!c || !c->name || !c->config_path)
		return false;

	if (!get_snappath_dir(c, clonelxcpath))
		return false;

	return remove_all_snapshots(clonelxcpath);
}

WRAP_API(bool, lxcapi_snapshot_destroy_all)

static bool do_lxcapi_may_control(struct lxc_container *c)
{
	if (!c)
		return false;

	return lxc_try_cmd(c->name, c->config_path) == 0;
}

WRAP_API(bool, lxcapi_may_control)

static bool do_add_remove_node(pid_t init_pid, const char *path, bool add,
			       struct stat *st)
{
	int ret;
	char *tmp;
	pid_t pid;
	char chrootpath[PATH_MAX];
	char *directory_path = NULL;

	pid = fork();
	if (pid < 0) {
		SYSERROR("Failed to fork()");
		return false;
	}

	if (pid) {
		ret = wait_for_pid(pid);
		if (ret != 0) {
			ERROR("Failed to create device node");
			return false;
		}

		return true;
	}

	/* prepare the path */
	ret = snprintf(chrootpath, PATH_MAX, "/proc/%d/root", init_pid);
	if (ret < 0 || ret >= PATH_MAX)
		return false;

	ret = chroot(chrootpath);
	if (ret < 0)
		_exit(EXIT_FAILURE);

	ret = chdir("/");
	if (ret < 0)
		_exit(EXIT_FAILURE);

	/* remove path if it exists */
	ret = faccessat(AT_FDCWD, path, F_OK, AT_SYMLINK_NOFOLLOW);
	if(ret == 0) {
		ret = unlink(path);
		if (ret < 0) {
			SYSERROR("Failed to remove \"%s\"", path);
			_exit(EXIT_FAILURE);
		}
	}

	if (!add)
		_exit(EXIT_SUCCESS);

	/* create any missing directories */
	tmp = strdup(path);
	if (!tmp)
		_exit(EXIT_FAILURE);

	directory_path = dirname(tmp);
	ret = mkdir_p(directory_path, 0755);
	if (ret < 0 && errno != EEXIST) {
		SYSERROR("Failed to create path \"%s\"", directory_path);
		free(tmp);
		_exit(EXIT_FAILURE);
	}

	/* create the device node */
	ret = mknod(path, st->st_mode, st->st_rdev);
	free(tmp);
	if (ret < 0) {
		SYSERROR("Failed to create device node at \"%s\"", path);
		_exit(EXIT_FAILURE);
	}

	_exit(EXIT_SUCCESS);
}

static bool add_remove_device_node(struct lxc_container *c, const char *src_path, const char *dest_path, bool add)
{
	int ret;
	struct stat st;
	char value[LXC_MAX_BUFFER];
	const char *p;

	/* make sure container is running */
	if (!do_lxcapi_is_running(c)) {
		ERROR("container is not running");
		return false;
	}

	/* use src_path if dest_path is NULL otherwise use dest_path */
	p = dest_path ? dest_path : src_path;

	/* make sure we can access p */
	if(access(p, F_OK) < 0 || stat(p, &st) < 0)
		return false;

	/* continue if path is character device or block device */
	if (S_ISCHR(st.st_mode))
		ret = snprintf(value, LXC_MAX_BUFFER, "c %d:%d rwm", major(st.st_rdev), minor(st.st_rdev));
	else if (S_ISBLK(st.st_mode))
		ret = snprintf(value, LXC_MAX_BUFFER, "b %d:%d rwm", major(st.st_rdev), minor(st.st_rdev));
	else
		return false;

	/* check snprintf return code */
	if (ret < 0 || ret >= LXC_MAX_BUFFER)
		return false;

	if (!do_add_remove_node(do_lxcapi_init_pid(c), p, add, &st))
		return false;

	/* add or remove device to/from cgroup access list */
	if (add) {
		if (!do_lxcapi_set_cgroup_item(c, "devices.allow", value)) {
			ERROR("set_cgroup_item failed while adding the device node");
			return false;
		}
	} else {
		if (!do_lxcapi_set_cgroup_item(c, "devices.deny", value)) {
			ERROR("set_cgroup_item failed while removing the device node");
			return false;
		}
	}

	return true;
}

static bool do_lxcapi_add_device_node(struct lxc_container *c, const char *src_path, const char *dest_path)
{
	// cannot mknod if we're not privileged wrt init_user_ns
	if (am_host_unpriv()) {
		ERROR(LXC_UNPRIV_EOPNOTSUPP, __FUNCTION__);
		return false;
	}

	return add_remove_device_node(c, src_path, dest_path, true);
}

WRAP_API_2(bool, lxcapi_add_device_node, const char *, const char *)

static bool do_lxcapi_remove_device_node(struct lxc_container *c, const char *src_path, const char *dest_path)
{
	if (am_guest_unpriv()) {
		ERROR(LXC_UNPRIV_EOPNOTSUPP, __FUNCTION__);
		return false;
	}

	return add_remove_device_node(c, src_path, dest_path, false);
}

WRAP_API_2(bool, lxcapi_remove_device_node, const char *, const char *)

static bool do_lxcapi_attach_interface(struct lxc_container *c,
				       const char *ifname,
				       const char *dst_ifname)
{
	pid_t init_pid;
	int ret = 0;

	if (am_guest_unpriv()) {
		ERROR(LXC_UNPRIV_EOPNOTSUPP, __FUNCTION__);
		return false;
	}

	if (!ifname) {
		ERROR("No source interface name given");
		return false;
	}

	ret = lxc_netdev_isup(ifname);
	if (ret > 0) {
		/* netdev of ifname is up. */
		ret = lxc_netdev_down(ifname);
		if (ret)
			goto err;
	}

	init_pid = do_lxcapi_init_pid(c);
	ret = lxc_netdev_move_by_name(ifname, init_pid, dst_ifname);
	if (ret)
		goto err;

	INFO("Moved network device \"%s\" to network namespace of %d", ifname, init_pid);
	return true;

err:
	return false;
}

WRAP_API_2(bool, lxcapi_attach_interface, const char *, const char *)

static bool do_lxcapi_detach_interface(struct lxc_container *c,
				       const char *ifname,
				       const char *dst_ifname)
{
	int ret;
	pid_t pid, pid_outside;

	/*
	 * TODO - if this is a physical device, then we need am_host_unpriv.
	 * But for other types guest privilege suffices.
	 */
	if (am_guest_unpriv()) {
		ERROR(LXC_UNPRIV_EOPNOTSUPP, __FUNCTION__);
		return false;
	}

	if (!ifname) {
		ERROR("No source interface name given");
		return false;
	}

	pid_outside = lxc_raw_getpid();
	pid = fork();
	if (pid < 0) {
		ERROR("Failed to fork");
		return false;
	}

	if (pid == 0) { /* child */
		pid_t init_pid;

		init_pid = do_lxcapi_init_pid(c);
		if (!switch_to_ns(init_pid, "net")) {
			ERROR("Failed to enter network namespace");
			_exit(EXIT_FAILURE);
		}

		ret = lxc_netdev_isup(ifname);
		if (ret < 0) {
			ERROR("Failed to determine whether network device \"%s\" is up", ifname);
			_exit(EXIT_FAILURE);
		}

		/* netdev of ifname is up. */
		if (ret) {
			ret = lxc_netdev_down(ifname);
			if (ret) {
				ERROR("Failed to set network device \"%s\" down", ifname);
				_exit(EXIT_FAILURE);
			}
		}

		ret = lxc_netdev_move_by_name(ifname, pid_outside, dst_ifname);
		/* -EINVAL means there is no netdev named as ifname. */
		if (ret < 0) {
			if (ret == -EINVAL)
				ERROR("Network device \"%s\" not found", ifname);
			else
				ERROR("Failed to remove network device \"%s\"", ifname);

			_exit(EXIT_FAILURE);
		}

		_exit(EXIT_SUCCESS);
	}

	ret = wait_for_pid(pid);
	if (ret != 0)
		return false;

	INFO("Moved network device \"%s\" to network namespace of %d", ifname, pid_outside);
	return true;
}

WRAP_API_2(bool, lxcapi_detach_interface, const char *, const char *)

static int do_lxcapi_migrate(struct lxc_container *c, unsigned int cmd,
			     struct migrate_opts *opts, unsigned int size)
{
	int ret = -1;
	struct migrate_opts *valid_opts = opts;
	uint64_t features_to_check = 0;

	/* If the caller has a bigger (newer) struct migrate_opts, let's make
	 * sure that the stuff on the end is zero, i.e. that they didn't ask us
	 * to do anything special.
	 */
	if (size > sizeof(*opts)) {
		unsigned char *addr;
		unsigned char *end;

		addr = (void *)opts + sizeof(*opts);
		end  = (void *)opts + size;

		for (; addr < end; addr++)
			if (*addr)
				return -E2BIG;
	}

	/* If the caller has a smaller struct, let's zero out the end for them
	 * so we don't accidentally use bits of it that they didn't know about
	 * to initialize.
	 */
	if (size < sizeof(*opts)) {
		valid_opts = malloc(sizeof(*opts));
		if (!valid_opts)
			return -ENOMEM;

		memset(valid_opts, 0, sizeof(*opts));
		memcpy(valid_opts, opts, size);
	}

	switch (cmd) {
	case MIGRATE_PRE_DUMP:
		if (!do_lxcapi_is_running(c)) {
			ERROR("container is not running");
			goto on_error;
		}

		ret = !__criu_pre_dump(c, valid_opts);
		break;
	case MIGRATE_DUMP:
		if (!do_lxcapi_is_running(c)) {
			ERROR("container is not running");
			goto on_error;
		}

		ret = !__criu_dump(c, valid_opts);
		break;
	case MIGRATE_RESTORE:
		if (do_lxcapi_is_running(c)) {
			ERROR("container is already running");
			goto on_error;
		}

		ret = !__criu_restore(c, valid_opts);
		break;
	case MIGRATE_FEATURE_CHECK:
		features_to_check = valid_opts->features_to_check;
		ret = !__criu_check_feature(&features_to_check);
		if (ret) {
			/* Something went wrong. Let's let the caller
			 * know which feature checks failed. */
			valid_opts->features_to_check = features_to_check;
		}
		break;
	default:
		ERROR("invalid migrate command %u", cmd);
		ret = -EINVAL;
	}

on_error:
	if (size < sizeof(*opts))
		free(valid_opts);

	return ret;
}

WRAP_API_3(int, lxcapi_migrate, unsigned int, struct migrate_opts *, unsigned int)

static bool do_lxcapi_checkpoint(struct lxc_container *c, char *directory, bool stop, bool verbose)
{
	struct migrate_opts opts;

	memset(&opts, 0, sizeof(opts));

	opts.directory = directory;
	opts.stop = stop;
	opts.verbose = verbose;

	return !do_lxcapi_migrate(c, MIGRATE_DUMP, &opts, sizeof(opts));
}

WRAP_API_3(bool, lxcapi_checkpoint, char *, bool, bool)

static bool do_lxcapi_restore(struct lxc_container *c, char *directory, bool verbose)
{
	struct migrate_opts opts;

	memset(&opts, 0, sizeof(opts));

	opts.directory = directory;
	opts.verbose = verbose;

	return !do_lxcapi_migrate(c, MIGRATE_RESTORE, &opts, sizeof(opts));
}

WRAP_API_2(bool, lxcapi_restore, char *, bool)

static int lxcapi_attach_run_waitl(struct lxc_container *c, lxc_attach_options_t *options, const char *program, const char *arg, ...)
{
	va_list ap;
	const char **argv;
	int ret;

	if (!c)
		return -1;

	current_config = c->lxc_conf;

	va_start(ap, arg);
	argv = lxc_va_arg_list_to_argv_const(ap, 1);
	va_end(ap);

	if (!argv) {
		ERROR("Memory allocation error.");
		ret = -1;
		goto out;
	}
	argv[0] = arg;

	ret = do_lxcapi_attach_run_wait(c, options, program, (const char * const *)argv);
	free((void*)argv);

out:
	current_config = NULL;
	return ret;
}

struct lxc_container *lxc_container_new(const char *name, const char *configpath)
{
	struct lxc_container *c;
	size_t len;

	if (!name)
		return NULL;

	c = malloc(sizeof(*c));
	if (!c) {
		fprintf(stderr, "Failed to allocate memory for %s\n", name);
		return NULL;
	}
	memset(c, 0, sizeof(*c));

	if (configpath)
		c->config_path = strdup(configpath);
	else
		c->config_path = strdup(lxc_global_config_value("lxc.lxcpath"));
	if (!c->config_path) {
		fprintf(stderr, "Failed to allocate memory for %s\n", name);
		goto err;
	}

	remove_trailing_slashes(c->config_path);

	len = strlen(name);
	c->name = malloc(len + 1);
	if (!c->name) {
		fprintf(stderr, "Failed to allocate memory for %s\n", name);
		goto err;
	}
	(void)strlcpy(c->name, name, len + 1);

	c->numthreads = 1;
	c->slock = lxc_newlock(c->config_path, name);
	if (!c->slock) {
		fprintf(stderr, "Failed to create lock for %s\n", name);
		goto err;
	}

	c->privlock = lxc_newlock(NULL, NULL);
	if (!c->privlock) {
		fprintf(stderr, "Failed to create private lock for %s\n", name);
		goto err;
	}

	if (!set_config_filename(c)) {
		fprintf(stderr, "Failed to create config file name for %s\n", name);
		goto err;
	}

	if (file_exists(c->configfile) && !lxcapi_load_config(c, NULL)) {
		fprintf(stderr, "Failed to load config for %s\n", name);
		goto err;
	}

	if (ongoing_create(c) == 2) {
		ERROR("Failed to complete container creation for %s", c->name);
		container_destroy(c, NULL);
		lxcapi_clear_config(c);
	}

	c->daemonize = true;
	c->pidfile = NULL;

	/* Assign the member functions. */
	c->is_defined = lxcapi_is_defined;
	c->state = lxcapi_state;
	c->is_running = lxcapi_is_running;
	c->freeze = lxcapi_freeze;
	c->unfreeze = lxcapi_unfreeze;
	c->console = lxcapi_console;
	c->console_getfd = lxcapi_console_getfd;
	c->init_pid = lxcapi_init_pid;
	c->load_config = lxcapi_load_config;
	c->want_daemonize = lxcapi_want_daemonize;
	c->want_close_all_fds = lxcapi_want_close_all_fds;
	c->start = lxcapi_start;
	c->startl = lxcapi_startl;
	c->stop = lxcapi_stop;
	c->config_file_name = lxcapi_config_file_name;
	c->wait = lxcapi_wait;
	c->set_config_item = lxcapi_set_config_item;
	c->destroy = lxcapi_destroy;
	c->destroy_with_snapshots = lxcapi_destroy_with_snapshots;
	c->rename = lxcapi_rename;
	c->save_config = lxcapi_save_config;
	c->get_keys = lxcapi_get_keys;
	c->create = lxcapi_create;
	c->createl = lxcapi_createl;
	c->shutdown = lxcapi_shutdown;
	c->reboot = lxcapi_reboot;
	c->reboot2 = lxcapi_reboot2;
	c->clear_config = lxcapi_clear_config;
	c->clear_config_item = lxcapi_clear_config_item;
	c->get_config_item = lxcapi_get_config_item;
	c->get_running_config_item = lxcapi_get_running_config_item;
	c->get_cgroup_item = lxcapi_get_cgroup_item;
	c->set_cgroup_item = lxcapi_set_cgroup_item;
	c->get_config_path = lxcapi_get_config_path;
	c->set_config_path = lxcapi_set_config_path;
	c->clone = lxcapi_clone;
	c->get_interfaces = lxcapi_get_interfaces;
	c->get_ips = lxcapi_get_ips;
	c->attach = lxcapi_attach;
	c->attach_run_wait = lxcapi_attach_run_wait;
	c->attach_run_waitl = lxcapi_attach_run_waitl;
	c->snapshot = lxcapi_snapshot;
	c->snapshot_list = lxcapi_snapshot_list;
	c->snapshot_restore = lxcapi_snapshot_restore;
	c->snapshot_destroy = lxcapi_snapshot_destroy;
	c->snapshot_destroy_all = lxcapi_snapshot_destroy_all;
	c->may_control = lxcapi_may_control;
	c->add_device_node = lxcapi_add_device_node;
	c->remove_device_node = lxcapi_remove_device_node;
	c->attach_interface = lxcapi_attach_interface;
	c->detach_interface = lxcapi_detach_interface;
	c->checkpoint = lxcapi_checkpoint;
	c->restore = lxcapi_restore;
	c->migrate = lxcapi_migrate;
	c->console_log = lxcapi_console_log;

	return c;

err:
	lxc_container_free(c);
	return NULL;
}

int lxc_get_wait_states(const char **states)
{
	int i;

	if (states)
		for (i=0; i<MAX_STATE; i++)
			states[i] = lxc_state2str(i);

	return MAX_STATE;
}

/*
 * These next two could probably be done smarter with reusing a common function
 * with different iterators and tests...
 */
int list_defined_containers(const char *lxcpath, char ***names, struct lxc_container ***cret)
{
	DIR *dir;
	int i, cfound = 0, nfound = 0;
	struct dirent *direntp;
	struct lxc_container *c;

	if (!lxcpath)
		lxcpath = lxc_global_config_value("lxc.lxcpath");

	dir = opendir(lxcpath);
	if (!dir) {
		SYSERROR("opendir on lxcpath");
		return -1;
	}

	if (cret)
		*cret = NULL;

	if (names)
		*names = NULL;

	while ((direntp = readdir(dir))) {
		/* Ignore '.', '..' and any hidden directory. */
		if (!strncmp(direntp->d_name, ".", 1))
			continue;

		if (!config_file_exists(lxcpath, direntp->d_name))
			continue;

		if (names)
			if (!add_to_array(names, direntp->d_name, cfound))
				goto free_bad;

		cfound++;

		if (!cret) {
			nfound++;
			continue;
		}

		c = lxc_container_new(direntp->d_name, lxcpath);
		if (!c) {
			INFO("Container %s:%s has a config but could not be loaded",
				lxcpath, direntp->d_name);

			if (names)
				if(!remove_from_array(names, direntp->d_name, cfound--))
					goto free_bad;

			continue;
		}

		if (!do_lxcapi_is_defined(c)) {
			INFO("Container %s:%s has a config but is not defined",
				lxcpath, direntp->d_name);

			if (names)
				if(!remove_from_array(names, direntp->d_name, cfound--))
					goto free_bad;

			lxc_container_put(c);
			continue;
		}

		if (!add_to_clist(cret, c, nfound, true)) {
			lxc_container_put(c);
			goto free_bad;
		}

		nfound++;
	}

	closedir(dir);
	return nfound;

free_bad:
	if (names && *names) {
		for (i=0; i<cfound; i++)
			free((*names)[i]);
		free(*names);
	}

	if (cret && *cret) {
		for (i=0; i<nfound; i++)
			lxc_container_put((*cret)[i]);
		free(*cret);
	}

	closedir(dir);
	return -1;
}

int list_active_containers(const char *lxcpath, char ***nret,
			   struct lxc_container ***cret)
{
	int i, ret = -1, cret_cnt = 0, ct_name_cnt = 0;
	int lxcpath_len;
	char *line = NULL;
	char **ct_name = NULL;
	size_t len = 0;
	struct lxc_container *c = NULL;
	bool is_hashed;

	if (!lxcpath)
		lxcpath = lxc_global_config_value("lxc.lxcpath");
	lxcpath_len = strlen(lxcpath);

	if (cret)
		*cret = NULL;

	if (nret)
		*nret = NULL;

	FILE *f = fopen("/proc/net/unix", "r");
	if (!f)
		return -1;

	while (getline(&line, &len, f) != -1) {
		char *p = strrchr(line, ' '), *p2;
		if (!p)
			continue;
		p++;

		if (*p != 0x40)
			continue;
		p++;

		is_hashed = false;

		if (strncmp(p, lxcpath, lxcpath_len) == 0) {
			p += lxcpath_len;
		} else if (strncmp(p, "lxc/", 4) == 0) {
			p += 4;
			is_hashed = true;
		} else {
			continue;
		}

		while (*p == '/')
			p++;

		/* Now p is the start of lxc_name. */
		p2 = strchr(p, '/');
		if (!p2 || strncmp(p2, "/command", 8) != 0)
			continue;
		*p2 = '\0';

		if (is_hashed) {
			char *recvpath = lxc_cmd_get_lxcpath(p);
			if (!recvpath)
				continue;

			if (strncmp(lxcpath, recvpath, lxcpath_len) != 0) {
				free(recvpath);
				continue;
			}
			free(recvpath);

			p = lxc_cmd_get_name(p);
			if (!p)
				continue;
		}

		if (array_contains(&ct_name, p, ct_name_cnt)) {
			if (is_hashed)
				free(p);
			continue;
		}

		if (!add_to_array(&ct_name, p, ct_name_cnt)) {
			if (is_hashed)
				free(p);
			goto free_cret_list;
		}

		ct_name_cnt++;

		if (!cret) {
			if (is_hashed)
				free(p);
			continue;
		}

		c = lxc_container_new(p, lxcpath);
		if (!c) {
			INFO("Container %s:%s is running but could not be loaded",
				lxcpath, p);

			remove_from_array(&ct_name, p, ct_name_cnt--);
			if (is_hashed)
				free(p);

			continue;
		}

		if (is_hashed)
			free(p);

		/*
		 * If this is an anonymous container, then is_defined *can*
		 * return false.  So we don't do that check.  Count on the
		 * fact that the command socket exists.
		 */

		if (!add_to_clist(cret, c, cret_cnt, true)) {
			lxc_container_put(c);
			goto free_cret_list;
		}

		cret_cnt++;
	}

	if (nret && cret && cret_cnt != ct_name_cnt) {
		if (c)
			lxc_container_put(c);
		goto free_cret_list;
	}

	ret = ct_name_cnt;
	if (nret)
		*nret = ct_name;
	else
		goto free_ct_name;

	goto out;

free_cret_list:
	if (cret && *cret) {
		for (i = 0; i < cret_cnt; i++)
			lxc_container_put((*cret)[i]);
		free(*cret);
	}

free_ct_name:
	if (ct_name) {
		for (i = 0; i < ct_name_cnt; i++)
			free(ct_name[i]);
		free(ct_name);
	}

out:
	free(line);
	fclose(f);
	return ret;
}

int list_all_containers(const char *lxcpath, char ***nret,
			struct lxc_container ***cret)
{
	int i, ret, active_cnt, ct_cnt, ct_list_cnt;
	char **active_name;
	char **ct_name;
	struct lxc_container **ct_list = NULL;

	ct_cnt = list_defined_containers(lxcpath, &ct_name, NULL);
	if (ct_cnt < 0)
		return ct_cnt;

	active_cnt = list_active_containers(lxcpath, &active_name, NULL);
	if (active_cnt < 0) {
		ret = active_cnt;
		goto free_ct_name;
	}

	for (i = 0; i < active_cnt; i++) {
		if (!array_contains(&ct_name, active_name[i], ct_cnt)) {
			if (!add_to_array(&ct_name, active_name[i], ct_cnt)) {
				ret = -1;
				goto free_active_name;
			}

			ct_cnt++;
		}

		free(active_name[i]);
		active_name[i] = NULL;
	}

	free(active_name);
	active_name = NULL;
	active_cnt = 0;

	for (i = 0, ct_list_cnt = 0; i < ct_cnt && cret; i++) {
		struct lxc_container *c;

		c = lxc_container_new(ct_name[i], lxcpath);
		if (!c) {
			WARN("Container %s:%s could not be loaded", lxcpath, ct_name[i]);
			remove_from_array(&ct_name, ct_name[i], ct_cnt--);
			continue;
		}

		if (!add_to_clist(&ct_list, c, ct_list_cnt, false)) {
			lxc_container_put(c);
			ret = -1;
			goto free_ct_list;
		}

		ct_list_cnt++;
	}

	if (cret)
		*cret = ct_list;

	if (nret) {
		*nret = ct_name;
	} else {
		ret = ct_cnt;
		goto free_ct_name;
	}

	return ct_cnt;

free_ct_list:
	for (i = 0; i < ct_list_cnt; i++) {
		lxc_container_put(ct_list[i]);
	}
	free(ct_list);

free_active_name:
	for (i = 0; i < active_cnt; i++) {
		free(active_name[i]);
	}
	free(active_name);

free_ct_name:
	for (i = 0; i < ct_cnt; i++) {
		free(ct_name[i]);
	}
	free(ct_name);
	return ret;
}

bool lxc_config_item_is_supported(const char *key)
{
	return !!lxc_get_config(key);
}

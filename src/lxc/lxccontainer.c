/* liblxcapi
 *
 * Copyright © 2012 Serge Hallyn <serge.hallyn@ubuntu.com>.
 * Copyright © 2012 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _GNU_SOURCE
#include <stdarg.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include "config.h"
#include "lxc.h"
#include "state.h"
#include "lxccontainer.h"
#include "conf.h"
#include "confile.h"
#include "console.h"
#include "cgroup.h"
#include "commands.h"
#include "version.h"
#include "log.h"
#include "bdev.h"
#include "utils.h"
#include "attach.h"
#include <lxc/utils.h>
#include <lxc/monitor.h>
#include <sched.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

lxc_log_define(lxc_container, lxc);

static bool file_exists(char *f)
{
	struct stat statbuf;

	return stat(f, &statbuf) == 0;
}

/*
 * A few functions to help detect when a container creation failed.
 * If a container creation was killed partway through, then trying
 * to actually start that container could harm the host.  We detect
 * this by creating a 'partial' file under the container directory,
 * and keeping an advisory lock.  When container creation completes,
 * we remove that file.  When we load or try to start a container, if
 * we find that file, without a flock, we remove the container.
 */
int ongoing_create(struct lxc_container *c)
{
	int len = strlen(c->config_path) + strlen(c->name) + 10;
	char *path = alloca(len);
	int fd, ret;
	struct flock lk;

	ret = snprintf(path, len, "%s/%s/partial", c->config_path, c->name);
	if (ret < 0 || ret >= len) {
		ERROR("Error writing partial pathname");
		return -1;
	}

	if (!file_exists(path))
		return 0;
	if (process_lock())
		return -1;
	if ((fd = open(path, O_RDWR)) < 0) {
		// give benefit of the doubt
		SYSERROR("Error opening partial file");
		process_unlock();
		return 0;
	}
	lk.l_type = F_WRLCK;
	lk.l_whence = SEEK_SET;
	lk.l_start = 0;
	lk.l_len = 0;
	lk.l_pid = -1;
	if (fcntl(fd, F_GETLK, &lk) == 0 && lk.l_pid != -1) {
		// create is still ongoing
		close(fd);
		process_unlock();
		return 1;
	}
	// create completed but partial is still there.
	close(fd);
	process_unlock();
	return 2;
}

int create_partial(struct lxc_container *c)
{
	// $lxcpath + '/' + $name + '/partial' + \0
	int len = strlen(c->config_path) + strlen(c->name) + 10;
	char *path = alloca(len);
	int fd, ret;
	struct flock lk;

	ret = snprintf(path, len, "%s/%s/partial", c->config_path, c->name);
	if (ret < 0 || ret >= len) {
		ERROR("Error writing partial pathname");
		return -1;
	}
	if (process_lock())
		return -1;
	if ((fd=open(path, O_RDWR | O_CREAT | O_EXCL, 0755)) < 0) {
		SYSERROR("Erorr creating partial file");
		process_unlock();
		return -1;
	}
	lk.l_type = F_WRLCK;
	lk.l_whence = SEEK_SET;
	lk.l_start = 0;
	lk.l_len = 0;
	if (fcntl(fd, F_SETLKW, &lk) < 0) {
		SYSERROR("Error locking partial file %s", path);
		close(fd);
		process_unlock();
		return -1;
	}
	process_unlock();

	return fd;
}

void remove_partial(struct lxc_container *c, int fd)
{
	// $lxcpath + '/' + $name + '/partial' + \0
	int len = strlen(c->config_path) + strlen(c->name) + 10;
	char *path = alloca(len);
	int ret;

	close(fd);
	ret = snprintf(path, len, "%s/%s/partial", c->config_path, c->name);
	if (ret < 0 || ret >= len) {
		ERROR("Error writing partial pathname");
		return;
	}
	if (process_lock())
		return;
	if (unlink(path) < 0)
		SYSERROR("Error unlink partial file %s", path);
	process_unlock();
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

	if (c->configfile) {
		free(c->configfile);
		c->configfile = NULL;
	}
	if (c->error_string) {
		free(c->error_string);
		c->error_string = NULL;
	}
	if (c->slock) {
		lxc_putlock(c->slock);
		c->slock = NULL;
	}
	if (c->privlock) {
		lxc_putlock(c->privlock);
		c->privlock = NULL;
	}
	if (c->name) {
		free(c->name);
		c->name = NULL;
	}
	if (c->lxc_conf) {
		lxc_conf_free(c->lxc_conf);
		c->lxc_conf = NULL;
	}
	if (c->config_path) {
		free(c->config_path);
		c->config_path = NULL;
	}
	free(c);
}

/*
 * Consider the following case:
freer                         |    racing get()er
==================================================================
lxc_container_put()           |   lxc_container_get()
\ lxclock(c->privlock)        |   c->numthreads < 1? (no)
\ c->numthreads = 0           |   \ lxclock(c->privlock) -> waits
\ lxcunlock()                 |   \
\ lxc_container_free()        |   \ lxclock() returns
                              |   \ c->numthreads < 1 -> return 0
\ \ (free stuff)              |
\ \ sem_destroy(privlock)     |

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

	// if someone else has already started freeing the container, don't
	// try to take the lock, which may be invalid
	if (c->numthreads < 1)
		return 0;

	if (container_mem_lock(c))
		return 0;
	if (c->numthreads < 1) {
		// bail without trying to unlock, bc the privlock is now probably
		// in freed memory
		return 0;
	}
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
	if (--c->numthreads < 1) {
		container_mem_unlock(c);
		lxc_container_free(c);
		return 1;
	}
	container_mem_unlock(c);
	return 0;
}

static bool lxcapi_is_defined(struct lxc_container *c)
{
	struct stat statbuf;
	bool ret = false;
	int statret;

	if (!c)
		return false;

	if (container_mem_lock(c))
		return false;
	if (!c->configfile)
		goto out;
	statret = stat(c->configfile, &statbuf);
	if (statret != 0)
		goto out;
	ret = true;

out:
	container_mem_unlock(c);
	return ret;
}

static const char *lxcapi_state(struct lxc_container *c)
{
	lxc_state_t s;

	if (!c)
		return NULL;
	s = lxc_getstate(c->name, c->config_path);
	return lxc_state2str(s);
}

static bool is_stopped(struct lxc_container *c)
{
	lxc_state_t s;
	s = lxc_getstate(c->name, c->config_path);
	return (s == STOPPED);
}

static bool lxcapi_is_running(struct lxc_container *c)
{
	const char *s;

	if (!c)
		return false;
	s = lxcapi_state(c);
	if (!s || strcmp(s, "STOPPED") == 0)
		return false;
	return true;
}

static bool lxcapi_freeze(struct lxc_container *c)
{
	int ret;
	if (!c)
		return false;

	ret = lxc_freeze(c->name, c->config_path);
	if (ret)
		return false;
	return true;
}

static bool lxcapi_unfreeze(struct lxc_container *c)
{
	int ret;
	if (!c)
		return false;

	ret = lxc_unfreeze(c->name, c->config_path);
	if (ret)
		return false;
	return true;
}

static int lxcapi_console_getfd(struct lxc_container *c, int *ttynum, int *masterfd)
{
	int ttyfd;
	if (!c)
		return -1;

	ttyfd = lxc_console_getfd(c, ttynum, masterfd);
	return ttyfd;
}

static int lxcapi_console(struct lxc_container *c, int ttynum, int stdinfd,
			  int stdoutfd, int stderrfd, int escape)
{
	return lxc_console(c, ttynum, stdinfd, stdoutfd, stderrfd, escape);
}

static pid_t lxcapi_init_pid(struct lxc_container *c)
{
	if (!c)
		return -1;

	return lxc_cmd_get_init_pid(c->name, c->config_path);
}

static bool load_config_locked(struct lxc_container *c, const char *fname)
{
	if (!c->lxc_conf)
		c->lxc_conf = lxc_conf_init();
	if (c->lxc_conf && !lxc_config_read(fname, c->lxc_conf))
		return true;
	return false;
}

static bool lxcapi_load_config(struct lxc_container *c, const char *alt_file)
{
	bool ret = false, need_disklock = false;
	int lret;
	const char *fname;
	if (!c)
		return false;

	fname = c->configfile;
	if (alt_file)
		fname = alt_file;
	if (!fname)
		return false;
	/*
	 * If we're reading something other than the container's config,
	 * we only need to lock the in-memory container.  If loading the
	 * container's config file, take the disk lock.
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

static void lxcapi_want_daemonize(struct lxc_container *c)
{
	if (!c)
		return;
	if (container_mem_lock(c)) {
		ERROR("Error getting mem lock");
		return;
	}
	c->daemonize = 1;
	container_mem_unlock(c);
}

static bool lxcapi_wait(struct lxc_container *c, const char *state, int timeout)
{
	int ret;

	if (!c)
		return false;

	ret = lxc_wait(c->name, state, timeout, c->config_path);
	return ret == 0;
}


static bool wait_on_daemonized_start(struct lxc_container *c)
{
	/* we'll probably want to make this timeout configurable? */
	int timeout = 5, ret, status;

	/*
	 * our child is going to fork again, then exit.  reap the
	 * child
	 */
	ret = wait(&status);
	if (ret == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
		DEBUG("failed waiting for first dual-fork child");
	return lxcapi_wait(c, "RUNNING", timeout);
}

/*
 * I can't decide if it'd be more convenient for callers if we accept '...',
 * or a null-terminated array (i.e. execl vs execv)
 */
static bool lxcapi_start(struct lxc_container *c, int useinit, char * const argv[])
{
	int ret;
	struct lxc_conf *conf;
	int daemonize = 0;
	char *default_args[] = {
		"/sbin/init",
		'\0',
	};

	/* container exists */
	if (!c)
		return false;
	/* container has been setup */
	if (!c->lxc_conf)
		return false;

	if ((ret = ongoing_create(c)) < 0) {
		ERROR("Error checking for incomplete creation");
		return false;
	}
	if (ret == 2) {
		ERROR("Error: %s creation was not completed", c->name);
		c->destroy(c);
		return false;
	} else if (ret == 1) {
		ERROR("Error: creation of %s is ongoing", c->name);
		return false;
	}

	/* is this app meant to be run through lxcinit, as in lxc-execute? */
	if (useinit && !argv)
		return false;

	if (container_mem_lock(c))
		return false;
	conf = c->lxc_conf;
	daemonize = c->daemonize;
	container_mem_unlock(c);

	if (useinit) {
		ret = lxc_execute(c->name, argv, 1, conf, c->config_path);
		return ret == 0 ? true : false;
	}

	if (!argv)
		argv = default_args;

	/*
	* say, I'm not sure - what locks do we want here?  Any?
	* Is liblxc's locking enough here to protect the on disk
	* container?  We don't want to exclude things like lxc_info
	* while container is running...
	*/
	if (daemonize) {
		if (!lxc_container_get(c))
			return false;
		lxc_monitord_spawn(c->config_path);

		if (process_lock())
			return false;
		pid_t pid = fork();
		if (pid < 0) {
			lxc_container_put(c);
			process_unlock();
			return false;
		}
		if (pid != 0) {
			ret = wait_on_daemonized_start(c);
			process_unlock();
			return ret;
		}
		process_unlock();
		/* second fork to be reparented by init */
		pid = fork();
		if (pid < 0) {
			SYSERROR("Error doing dual-fork");
			return false;
		}
		if (pid != 0)
			exit(0);
		/* like daemon(), chdir to / and redirect 0,1,2 to /dev/null */
		if (chdir("/")) {
			SYSERROR("Error chdir()ing to /.");
			return false;
		}
		close(0);
		close(1);
		close(2);
		open("/dev/zero", O_RDONLY);
		open("/dev/null", O_RDWR);
		open("/dev/null", O_RDWR);
		setsid();
	}

reboot:
	conf->reboot = 0;
	ret = lxc_start(c->name, argv, conf, c->config_path);

	if (conf->reboot) {
		INFO("container requested reboot");
		conf->reboot = 0;
		goto reboot;
	}

	if (daemonize) {
		lxc_container_put(c);
		exit (ret == 0 ? true : false);
	} else {
		return (ret == 0 ? true : false);
	}
}

/*
 * note there MUST be an ending NULL
 */
static bool lxcapi_startl(struct lxc_container *c, int useinit, ...)
{
	va_list ap;
	char **inargs = NULL;
	bool bret = false;

	/* container exists */
	if (!c)
		return false;

	va_start(ap, useinit);
	inargs = lxc_va_arg_list_to_argv(ap, 0, 1);
	va_end(ap);

	if (!inargs) {
		ERROR("Memory allocation error.");
		goto out;
	}

	/* pass NULL if no arguments were supplied */
	bret = lxcapi_start(c, useinit, *inargs ? inargs : NULL);

out:
	if (inargs) {
		char *arg;
		for (arg = *inargs; arg; arg++)
			free(arg);
		free(inargs);
	}

	return bret;
}

static bool lxcapi_stop(struct lxc_container *c)
{
	int ret;

	if (!c)
		return false;

	ret = lxc_cmd_stop(c->name, c->config_path);

	return ret == 0;
}

/*
 * create the standard expected container dir
 */
static bool create_container_dir(struct lxc_container *c)
{
	char *s;
	int len, ret;

	len = strlen(c->config_path) + strlen(c->name) + 2;
	s = malloc(len);
	if (!s)
		return false;
	ret = snprintf(s, len, "%s/%s", c->config_path, c->name);
	if (ret < 0 || ret >= len) {
		free(s);
		return false;
	}
	ret = mkdir(s, 0755);
	if (ret) {
		if (errno == EEXIST)
			ret = 0;
		else
			SYSERROR("failed to create container path for %s\n", c->name);
	}
	free(s);
	return ret == 0;
}

static const char *lxcapi_get_config_path(struct lxc_container *c);
static bool lxcapi_set_config_item(struct lxc_container *c, const char *key, const char *v);

/*
 * do_bdev_create: thin wrapper around bdev_create().  Like bdev_create(),
 * it returns a mounted bdev on success, NULL on error.
 */
static struct bdev *do_bdev_create(struct lxc_container *c, const char *type,
			 struct bdev_specs *specs)
{
	char *dest;
	const char *lxcpath = lxcapi_get_config_path(c);
	size_t len;
	struct bdev *bdev;
	int ret;

	/* lxcpath/lxcname/rootfs */
	len = strlen(c->name) + strlen(lxcpath) + 9;
	dest = alloca(len);
	ret = snprintf(dest, len, "%s/%s/rootfs", lxcpath, c->name);
	if (ret < 0 || ret >= len)
		return NULL;

	bdev = bdev_create(dest, type, c->name, specs);
	if (!bdev)
		return NULL;
	lxcapi_set_config_item(c, "lxc.rootfs", bdev->src);
	return bdev;
}

/*
 * Given the '-t' template option to lxc-create, figure out what to
 * do.  If the template is a full executable path, use that.  If it
 * is something like 'sshd', then return $templatepath/lxc-sshd.  If
 * no template was passed in, return NULL  (this is ok).
 * On error return (char *) -1.
 */
char *get_template_path(const char *t)
{
	int ret, len;
	char *tpath;

	if (!t)
		return NULL;

	if (t[0] == '/' && access(t, X_OK) == 0) {
		tpath = strdup(t);
		if (!tpath)
			return (char *) -1;
		return tpath;
	}

	len = strlen(LXCTEMPLATEDIR) + strlen(t) + strlen("/lxc-") + 1;
	tpath = malloc(len);
	if (!tpath)
		return (char *) -1;
	ret = snprintf(tpath, len, "%s/lxc-%s", LXCTEMPLATEDIR, t);
	if (ret < 0 || ret >= len) {
		free(tpath);
		return (char *) -1;
	}
	if (access(tpath, X_OK) < 0) {
		SYSERROR("bad template: %s\n", t);
		free(tpath);
		return (char *) -1;
	}

	return tpath;
}

static char *lxcbasename(char *path)
{
	char *p = path + strlen(path) - 1;
	while (*p != '/' && p > path)
		p--;
	return p;
}

static bool create_run_template(struct lxc_container *c, char *tpath, bool quiet,
				char *const argv[])
{
	pid_t pid;

	if (!tpath)
		return true;

	pid = fork();
	if (pid < 0) {
		SYSERROR("failed to fork task for container creation template\n");
		return false;
	}

	if (pid == 0) { // child
		char *patharg, *namearg, *rootfsarg, *src;
		struct bdev *bdev = NULL;
		int i;
		int ret, len, nargs = 0;
		char **newargv;

		if (quiet) {
			close(0);
			close(1);
			close(2);
			open("/dev/zero", O_RDONLY);
			open("/dev/null", O_RDWR);
			open("/dev/null", O_RDWR);
		}
		if (unshare(CLONE_NEWNS) < 0) {
			ERROR("error unsharing mounts");
			exit(1);
		}

		src = c->lxc_conf->rootfs.path;
		/*
		 * for an overlayfs create, what the user wants is the template to fill
		 * in what will become the readonly lower layer.  So don't mount for
		 * the template
		 */
		if (strncmp(src, "overlayfs:", 10) == 0) {
			src = overlayfs_getlower(src+10);
		}
		bdev = bdev_init(src, c->lxc_conf->rootfs.mount, NULL);
		if (!bdev) {
			ERROR("Error opening rootfs");
			exit(1);
		}

		if (bdev->ops->mount(bdev) < 0) {
			ERROR("Error mounting rootfs");
			exit(1);
		}

		/*
		 * create our new array, pre-pend the template name and
		 * base args
		 */
		if (argv)
			for (nargs = 0; argv[nargs]; nargs++) ;
		nargs += 4;  // template, path, rootfs and name args
		newargv = malloc(nargs * sizeof(*newargv));
		if (!newargv)
			exit(1);
		newargv[0] = lxcbasename(tpath);

		len = strlen(c->config_path) + strlen(c->name) + strlen("--path=") + 2;
		patharg = malloc(len);
		if (!patharg)
			exit(1);
		ret = snprintf(patharg, len, "--path=%s/%s", c->config_path, c->name);
		if (ret < 0 || ret >= len)
			exit(1);
		newargv[1] = patharg;
		len = strlen("--name=") + strlen(c->name) + 1;
		namearg = malloc(len);
		if (!namearg)
			exit(1);
		ret = snprintf(namearg, len, "--name=%s", c->name);
		if (ret < 0 || ret >= len)
			exit(1);
		newargv[2] = namearg;

		len = strlen("--rootfs=") + 1 + strlen(bdev->dest);
		rootfsarg = malloc(len);
		if (!rootfsarg)
			exit(1);
		ret = snprintf(rootfsarg, len, "--rootfs=%s", bdev->dest);
		if (ret < 0 || ret >= len)
			exit(1);
		newargv[3] = rootfsarg;

		/* add passed-in args */
		if (argv)
			for (i = 4; i < nargs; i++)
				newargv[i] = argv[i-4];

		/* add trailing NULL */
		nargs++;
		newargv = realloc(newargv, nargs * sizeof(*newargv));
		if (!newargv)
			exit(1);
		newargv[nargs - 1] = NULL;

		/* execute */
		execv(tpath, newargv);
		SYSERROR("failed to execute template %s", tpath);
		exit(1);
	}

	if (wait_for_pid(pid) != 0) {
		ERROR("container creation template for %s failed\n", c->name);
		return false;
	}

	return true;
}

bool prepend_lxc_header(char *path, const char *t, char *const argv[])
{
	size_t flen;
	char *contents, *tpath;
	FILE *f;
#if HAVE_LIBGNUTLS
	int i, ret;
	unsigned char md_value[SHA_DIGEST_LENGTH];
	bool have_tpath = false;
#endif

	if ((f = fopen(path, "r")) == NULL) {
		SYSERROR("Opening old config");
		return false;
	}
	if (fseek(f, 0, SEEK_END) < 0) {
		SYSERROR("Seeking to end of old config file");
		fclose(f);
		return false;
	}
	if ((flen = ftell(f)) < 0) {
		SYSERROR("telling size of old config");
		fclose(f);
		return false;
	}
	if (fseek(f, 0, SEEK_SET) < 0) {
		SYSERROR("rewinding old config");
		fclose(f);
		return false;
	}
	if ((contents = malloc(flen + 1)) == NULL) {
		SYSERROR("out of memory");
		fclose(f);
		return false;
	}
	if (fread(contents, 1, flen, f) != flen) {
		SYSERROR("Reading old config");
		free(contents);
		fclose(f);
		return false;
	}
	contents[flen] = '\0';
	if (fclose(f) < 0) {
		SYSERROR("closing old config");
		free(contents);
		return false;
	}

	if ((tpath = get_template_path(t)) < 0) {
		ERROR("bad template: %s\n", t);
		free(contents);
		return false;
	}

#if HAVE_LIBGNUTLS
	if (tpath) {
		have_tpath = true;
		ret = sha1sum_file(tpath, md_value);
		if (ret < 0) {
			ERROR("Error getting sha1sum of %s", tpath);
			free(contents);
			return false;
		}
		free(tpath);
	}
#endif

	if ((f = fopen(path, "w")) == NULL) {
		SYSERROR("reopening config for writing");
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
	if (have_tpath) {
		fprintf(f, "# Template script checksum (SHA-1): ");
		for (i=0; i<SHA_DIGEST_LENGTH; i++)
			fprintf(f, "%02x", md_value[i]);
		fprintf(f, "\n");
	}
#endif
	if (fwrite(contents, 1, flen, f) != flen) {
		SYSERROR("Writing original contents");
		free(contents);
		fclose(f);
		return false;
	}
	free(contents);
	if (fclose(f) < 0) {
		SYSERROR("Closing config file after write");
		return false;
	}
	return true;
}

static bool lxcapi_destroy(struct lxc_container *c);
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
static bool lxcapi_create(struct lxc_container *c, const char *t,
		const char *bdevtype, struct bdev_specs *specs, int flags,
		char *const argv[])
{
	bool bret = false;
	pid_t pid;
	char *tpath;
	int partial_fd;

	if (!c)
		return false;

	if ((tpath = get_template_path(t)) < 0) {
		ERROR("bad template: %s\n", t);
		goto out;
	}

	if (!c->save_config(c, NULL)) {
		ERROR("failed to save starting configuration for %s\n", c->name);
		goto out;
	}

	/* container is already created if we have a config and rootfs.path is accessible */
	if (lxcapi_is_defined(c) && c->lxc_conf && c->lxc_conf->rootfs.path && access(c->lxc_conf->rootfs.path, F_OK) == 0)
		goto out;

	/* Mark that this container is being created */
	if ((partial_fd = create_partial(c)) < 0)
		goto out;

	/* no need to get disk lock bc we have the partial locked */

	/*
	 * Create the backing store
	 * Note we can't do this in the same task as we use to execute the
	 * template because of the way zfs works.
	 * After you 'zfs create', zfs mounts the fs only in the initial
	 * namespace.
	 */
	pid = fork();
	if (pid < 0) {
		SYSERROR("failed to fork task for container creation template\n");
		goto out_unlock;
	}

	if (pid == 0) { // child
		struct bdev *bdev = NULL;

		if (!(bdev = do_bdev_create(c, bdevtype, specs))) {
			ERROR("Error creating backing store type %s for %s",
				bdevtype ? bdevtype : "(none)", c->name);
			exit(1);
		}

		/* save config file again to store the new rootfs location */
		if (!c->save_config(c, NULL)) {
			ERROR("failed to save starting configuration for %s\n", c->name);
			// parent task won't see bdev in config so we delete it
			bdev->ops->umount(bdev);
			bdev->ops->destroy(bdev);
			exit(1);
		}
		exit(0);
	}
	if (wait_for_pid(pid) != 0)
		goto out;

	/* reload config to get the rootfs */
	if (c->lxc_conf)
		lxc_conf_free(c->lxc_conf);
	c->lxc_conf = NULL;
	if (!load_config_locked(c, c->configfile))
		goto out;

	if (!create_run_template(c, tpath, !!(flags & LXC_CREATE_QUIET), argv))
		goto out_unlock;

	// now clear out the lxc_conf we have, reload from the created
	// container
	if (c->lxc_conf)
		lxc_conf_free(c->lxc_conf);
	c->lxc_conf = NULL;

	if (!prepend_lxc_header(c->configfile, tpath, argv)) {
		ERROR("Error prepending header to configuration file");
		goto out_unlock;
	}
	bret = load_config_locked(c, c->configfile);

out_unlock:
	if (partial_fd >= 0)
		remove_partial(c, partial_fd);
out:
	if (tpath)
		free(tpath);
	if (!bret && c)
		lxcapi_destroy(c);
	return bret;
}

static bool lxcapi_reboot(struct lxc_container *c)
{
	pid_t pid;

	if (!c)
		return false;
	if (!c->is_running(c))
		return false;
	pid = c->init_pid(c);
	if (pid <= 0)
		return false;
	if (kill(pid, SIGINT) < 0)
		return false;
	return true;

}

static bool lxcapi_shutdown(struct lxc_container *c, int timeout)
{
	bool retv;
	pid_t pid;

	if (!c)
		return false;

	if (!timeout)
		timeout = -1;
	if (!c->is_running(c))
		return true;
	pid = c->init_pid(c);
	if (pid <= 0)
		return true;
	kill(pid, SIGPWR);
	retv = c->wait(c, "STOPPED", timeout);
	if (!retv && timeout > 0) {
		c->stop(c);
		retv = c->wait(c, "STOPPED", 0); // 0 means don't wait
	}
	return retv;
}

static bool lxcapi_createl(struct lxc_container *c, const char *t,
		const char *bdevtype, struct bdev_specs *specs, int flags, ...)
{
	bool bret = false;
	char **args = NULL;
	va_list ap;

	if (!c)
		return false;

	/*
	 * since we're going to wait for create to finish, I don't think we
	 * need to get a copy of the arguments.
	 */
	va_start(ap, flags);
	args = lxc_va_arg_list_to_argv(ap, 0, 0);
	va_end(ap);
	if (!args) {
		ERROR("Memory allocation error.");
		goto out;
	}

	bret = c->create(c, t, bdevtype, specs, flags, args);

out:
	free(args);
	return bret;
}

static bool lxcapi_clear_config_item(struct lxc_container *c, const char *key)
{
	int ret;

	if (!c || !c->lxc_conf)
		return false;
	if (container_mem_lock(c))
		return false;
	ret = lxc_clear_config_item(c->lxc_conf, key);
	container_mem_unlock(c);
	return ret == 0;
}

char** lxcapi_get_ips(struct lxc_container *c, char* interface, char* family, int scope)
{
	int count = 0;
	struct ifaddrs *interfaceArray = NULL, *tempIfAddr = NULL;
	char addressOutputBuffer[INET6_ADDRSTRLEN];
	void *tempAddrPtr = NULL;
	char **addresses = NULL, **temp;
	char *address = NULL;
	char new_netns_path[MAXPATHLEN];
	int old_netns = -1, new_netns = -1, ret = 0;

	if (!c->is_running(c))
		goto out;

	/* Save reference to old netns */
	old_netns = open("/proc/self/ns/net", O_RDONLY);
	if (old_netns < 0) {
		SYSERROR("failed to open /proc/self/ns/net");
		goto out;
	}

	/* Switch to new netns */
	ret = snprintf(new_netns_path, MAXPATHLEN, "/proc/%d/ns/net", c->init_pid(c));
	if (ret < 0 || ret >= MAXPATHLEN)
		goto out;

	new_netns = open(new_netns_path, O_RDONLY);
	if (new_netns < 0) {
		SYSERROR("failed to open %s", new_netns_path);
		goto out;
	}

	if (setns(new_netns, CLONE_NEWNET)) {
		SYSERROR("failed to setns");
		goto out;
	}

	/* Grab the list of interfaces */
	if (getifaddrs(&interfaceArray)) {
		SYSERROR("failed to get interfaces list");
		goto out;
	}

	/* Iterate through the interfaces */
	for (tempIfAddr = interfaceArray; tempIfAddr != NULL; tempIfAddr = tempIfAddr->ifa_next) {
		if(tempIfAddr->ifa_addr->sa_family == AF_INET) {
			if (family && strcmp(family, "inet"))
				continue;
			tempAddrPtr = &((struct sockaddr_in *)tempIfAddr->ifa_addr)->sin_addr;
		}
		else {
			if (family && strcmp(family, "inet6"))
				continue;

			if (((struct sockaddr_in6 *)tempIfAddr->ifa_addr)->sin6_scope_id != scope)
				continue;

			tempAddrPtr = &((struct sockaddr_in6 *)tempIfAddr->ifa_addr)->sin6_addr;
		}

		if (interface && strcmp(interface, tempIfAddr->ifa_name))
			continue;
		else if (!interface && strcmp("lo", tempIfAddr->ifa_name) == 0)
			continue;

		address = (char *)inet_ntop(tempIfAddr->ifa_addr->sa_family,
					   tempAddrPtr,
					   addressOutputBuffer,
					   sizeof(addressOutputBuffer));
		if (!address)
			continue;

		count += 1;
		temp = realloc(addresses, count * sizeof(*addresses));
		if (!temp) {
			count--;
			goto out;
		}
		addresses = temp;
		addresses[count - 1] = strdup(address);
	}

out:
	if(interfaceArray)
		freeifaddrs(interfaceArray);

	/* Switch back to original netns */
	if (old_netns >= 0 && setns(old_netns, CLONE_NEWNET))
		SYSERROR("failed to setns");
	if (new_netns >= 0)
		close(new_netns);
	if (old_netns >= 0)
		close(old_netns);

	/* Append NULL to the array */
	if (count) {
		count++;
		temp = realloc(addresses, count * sizeof(*addresses));
		if (!temp) {
			int i;
			for (i = 0; i < count-1; i++)
				free(addresses[i]);
			free(addresses);
			return NULL;
		}
		addresses = temp;
		addresses[count - 1] = NULL;
	}

	return addresses;
}

static int lxcapi_get_config_item(struct lxc_container *c, const char *key, char *retv, int inlen)
{
	int ret;

	if (!c || !c->lxc_conf)
		return -1;
	if (container_mem_lock(c))
		return -1;
	ret = lxc_get_config_item(c->lxc_conf, key, retv, inlen);
	container_mem_unlock(c);
	return ret;
}

static int lxcapi_get_keys(struct lxc_container *c, const char *key, char *retv, int inlen)
{
	if (!key)
		return lxc_listconfigs(retv, inlen);
	/*
	 * Support 'lxc.network.<idx>', i.e. 'lxc.network.0'
	 * This is an intelligent result to show which keys are valid given
	 * the type of nic it is
	 */
	if (!c || !c->lxc_conf)
		return -1;
	if (container_mem_lock(c))
		return -1;
	int ret = -1;
	if (strncmp(key, "lxc.network.", 12) == 0)
		ret =  lxc_list_nicconfigs(c->lxc_conf, key, retv, inlen);
	container_mem_unlock(c);
	return ret;
}

static bool lxcapi_save_config(struct lxc_container *c, const char *alt_file)
{
	FILE *fout;
	bool ret = false, need_disklock = false;
	int lret;

	if (!alt_file)
		alt_file = c->configfile;
	if (!alt_file)
		return false;  // should we write to stdout if no file is specified?

	// If we haven't yet loaded a config, load the stock config
	if (!c->lxc_conf) {
		if (!c->load_config(c, LXC_DEFAULT_CONFIG)) {
			ERROR("Error loading default configuration file %s while saving %s\n", LXC_DEFAULT_CONFIG, c->name);
			return false;
		}
	}

	if (!create_container_dir(c))
		return false;

	/*
	 * If we're writing to the container's config file, take the
	 * disk lock.  Otherwise just take the memlock to protect the
	 * struct lxc_container while we're traversing it.
	 */
	if (strcmp(c->configfile, alt_file) == 0)
		need_disklock = true;

	if (need_disklock)
		lret = container_disk_lock(c);
	else
		lret = container_mem_lock(c);

	if (lret)
		return false;

	fout = fopen(alt_file, "w");
	if (!fout)
		goto out;
	write_config(fout, c->lxc_conf);
	fclose(fout);
	ret = true;

out:
	if (need_disklock)
		container_disk_unlock(c);
	else
		container_mem_unlock(c);
	return ret;
}

// do we want the api to support --force, or leave that to the caller?
static bool lxcapi_destroy(struct lxc_container *c)
{
	struct bdev *r = NULL;
	bool ret = false;

	if (!c || !lxcapi_is_defined(c))
		return false;

	if (container_disk_lock(c))
		return false;

	if (!is_stopped(c)) {
		// we should queue some sort of error - in c->error_string?
		ERROR("container %s is not stopped", c->name);
		goto out;
	}

	if (c->lxc_conf && c->lxc_conf->rootfs.path && c->lxc_conf->rootfs.mount)
		r = bdev_init(c->lxc_conf->rootfs.path, c->lxc_conf->rootfs.mount, NULL);
	if (r) {
		if (r->ops->destroy(r) < 0) {
			ERROR("Error destroying rootfs for %s", c->name);
			goto out;
		}
	}

	const char *p1 = lxcapi_get_config_path(c);
	char *path = alloca(strlen(p1) + strlen(c->name) + 2);
	sprintf(path, "%s/%s", p1, c->name);
	if (lxc_rmdir_onedev(path) < 0) {
		ERROR("Error destroying container directory for %s", c->name);
		goto out;
	}
	ret = true;

out:
	container_disk_unlock(c);
	return ret;
}

static bool set_config_item_locked(struct lxc_container *c, const char *key, const char *v)
{
	struct lxc_config_t *config;

	if (!c->lxc_conf)
		c->lxc_conf = lxc_conf_init();
	if (!c->lxc_conf)
		return false;
	config = lxc_getconfig(key);
	if (!config)
		return false;
	return (0 == config->cb(key, v, c->lxc_conf));
}

static bool lxcapi_set_config_item(struct lxc_container *c, const char *key, const char *v)
{
	bool b = false;

	if (!c)
		return false;

	if (container_mem_lock(c))
		return false;

	b = set_config_item_locked(c, key, v);

	container_mem_unlock(c);
	return b;
}

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

	if (c->configfile)
		free(c->configfile);
	c->configfile = newpath;

	return true;
}

static bool lxcapi_set_config_path(struct lxc_container *c, const char *path)
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
	if (oldpath)
		free(oldpath);
	container_mem_unlock(c);
	return b;
}


static bool lxcapi_set_cgroup_item(struct lxc_container *c, const char *subsys, const char *value)
{
	int ret;

	if (!c)
		return false;

	if (is_stopped(c))
		return false;

	if (container_disk_lock(c))
		return false;

	ret = lxc_cgroup_set(c->name, subsys, value, c->config_path);

	container_disk_unlock(c);
	return ret == 0;
}

static int lxcapi_get_cgroup_item(struct lxc_container *c, const char *subsys, char *retv, int inlen)
{
	int ret;

	if (!c || !c->lxc_conf)
		return -1;

	if (is_stopped(c))
		return -1;

	if (container_disk_lock(c))
		return -1;

	ret = lxc_cgroup_get(c->name, subsys, retv, inlen, c->config_path);

	container_disk_unlock(c);
	return ret;
}

const char *lxc_get_default_config_path(void)
{
	return default_lxc_path();
}

const char *lxc_get_default_lvm_vg(void)
{
	return default_lvm_vg();
}

const char *lxc_get_default_zfs_root(void)
{
	return default_zfs_root();
}

const char *lxc_get_version(void)
{
	return lxc_version();
}

static int copy_file(char *old, char *new)
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
		SYSERROR("stat'ing %s", old);
		return -1;
	}

	in = open(old, O_RDONLY);
	if (in < 0) {
		SYSERROR("opening original file %s", old);
		return -1;
	}
	out = open(new, O_CREAT | O_EXCL | O_WRONLY, 0644);
	if (out < 0) {
		SYSERROR("opening new file %s", new);
		close(in);
		return -1;
	}

	while (1) {
		len = read(in, buf, 8096);
		if (len < 0) {
			SYSERROR("reading old file %s", old);
			goto err;
		}
		if (len == 0)
			break;
		ret = write(out, buf, len);
		if (ret < len) {  // should we retry?
			SYSERROR("write to new file %s was interrupted", new);
			goto err;
		}
	}
	close(in);
	close(out);

	// we set mode, but not owner/group
	ret = chmod(new, sbuf.st_mode);
	if (ret) {
		SYSERROR("setting mode on %s", new);
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
	int i;
	int ret;
	struct lxc_list *it;

	for (i=0; i<NUM_LXC_HOOKS; i++) {
		lxc_list_for_each(it, &c->lxc_conf->hooks[i]) {
			char *hookname = it->elem;
			char *fname = rindex(hookname, '/');
			char tmppath[MAXPATHLEN];
			if (!fname) // relative path - we don't support, but maybe we should
				return 0;
			// copy the script, and change the entry in confile
			ret = snprintf(tmppath, MAXPATHLEN, "%s/%s/%s",
					c->config_path, c->name, fname+1);
			if (ret < 0 || ret >= MAXPATHLEN)
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

	c->save_config(c, NULL);
	return 0;
}

static void new_hwaddr(char *hwaddr)
{
	FILE *f = fopen("/dev/urandom", "r");
	if (f) {
		unsigned int seed;
		int ret = fread(&seed, sizeof(seed), 1, f);
		if (ret != 1)
			seed = time(NULL);
		fclose(f);
		srand(seed);
	} else
		srand(time(NULL));
	snprintf(hwaddr, 18, "00:16:3e:%02x:%02x:%02x",
			rand() % 255, rand() % 255, rand() % 255);
}

static void network_new_hwaddrs(struct lxc_container *c)
{
	struct lxc_list *it;

	lxc_list_for_each(it, &c->lxc_conf->network) {
		struct lxc_netdev *n = it->elem;
		if (n->hwaddr)
			new_hwaddr(n->hwaddr);
	}
}

static int copy_fstab(struct lxc_container *oldc, struct lxc_container *c)
{
	char newpath[MAXPATHLEN];
	char *oldpath = oldc->lxc_conf->fstab;
	int ret;

	if (!oldpath)
		return 0;

	char *p = rindex(oldpath, '/');
	if (!p)
		return -1;
	ret = snprintf(newpath, MAXPATHLEN, "%s/%s%s",
			c->config_path, c->name, p);
	if (ret < 0 || ret >= MAXPATHLEN) {
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

	return 0;
}

static int copy_storage(struct lxc_container *c0, struct lxc_container *c,
		const char *newtype, int flags, const char *bdevdata, unsigned long newsize)
{
	struct bdev *bdev;

	bdev = bdev_copy(c0->lxc_conf->rootfs.path, c0->name, c->name,
			c0->config_path, c->config_path, newtype, !!(flags & LXC_CLONE_SNAPSHOT),
			bdevdata, newsize);
	if (!bdev) {
		ERROR("error copying storage");
		return -1;
	}
	free(c->lxc_conf->rootfs.path);
	c->lxc_conf->rootfs.path = strdup(bdev->src);
	bdev_put(bdev);
	if (!c->lxc_conf->rootfs.path)
		return -1;
	// here we could also update all lxc.mount.entries or even
	// items in the lxc.mount fstab list.  As discussed on m-l,
	// we could do either any source paths starting with the
	// lxcpath/oldname, or simply anythign which is not a virtual
	// fs or a bind mount.
	return 0;
}

static int clone_update_rootfs(struct lxc_container *c0,
			       struct lxc_container *c, int flags,
			       char **hookargs)
{
	int ret = -1;
	char path[MAXPATHLEN];
	struct bdev *bdev;
	FILE *fout;
	pid_t pid;
	struct lxc_conf *conf = c->lxc_conf;

	/* update hostname in rootfs */
	/* we're going to mount, so run in a clean namespace to simplify cleanup */

	pid = fork();
	if (pid < 0)
		return -1;
	if (pid > 0)
		return wait_for_pid(pid);

	if (unshare(CLONE_NEWNS) < 0) {
		ERROR("error unsharing mounts");
		exit(1);
	}
	bdev = bdev_init(c->lxc_conf->rootfs.path, c->lxc_conf->rootfs.mount, NULL);
	if (!bdev)
		exit(1);
	if (bdev->ops->mount(bdev) < 0)
		exit(1);

	if (!lxc_list_empty(&conf->hooks[LXCHOOK_CLONE])) {
		/* Start of environment variable setup for hooks */
		if (setenv("LXC_SRC_NAME", c0->name, 1)) {
			SYSERROR("failed to set environment variable for source container name");
		}
		if (setenv("LXC_NAME", c->name, 1)) {
			SYSERROR("failed to set environment variable for container name");
		}
		if (setenv("LXC_CONFIG_FILE", conf->rcfile, 1)) {
			SYSERROR("failed to set environment variable for config path");
		}
		if (setenv("LXC_ROOTFS_MOUNT", conf->rootfs.mount, 1)) {
			SYSERROR("failed to set environment variable for rootfs mount");
		}
		if (setenv("LXC_ROOTFS_PATH", conf->rootfs.path, 1)) {
			SYSERROR("failed to set environment variable for rootfs mount");
		}

		if (run_lxc_hooks(c->name, "clone", conf, c->get_config_path(c), hookargs)) {
			ERROR("Error executing clone hook for %s", c->name);
			exit(1);
		}
	}

	if (!(flags & LXC_CLONE_KEEPNAME)) {
		ret = snprintf(path, MAXPATHLEN, "%s/etc/hostname", bdev->dest);
		if (ret < 0 || ret >= MAXPATHLEN)
			exit(1);
		if (!file_exists(path))
			exit(0);
		if (!(fout = fopen(path, "w"))) {
			SYSERROR("unable to open %s: ignoring\n", path);
			exit(0);
		}
		if (fprintf(fout, "%s", c->name) < 0)
			exit(1);
		if (fclose(fout) < 0)
			exit(1);
	}
	exit(0);
}

/*
 * We want to support:
sudo lxc-clone -o o1 -n n1 -s -L|-fssize fssize -v|--vgname vgname \
        -p|--lvprefix lvprefix -t|--fstype fstype  -B backingstore

-s [ implies overlayfs]
-s -B overlayfs
-s -B aufs

only rootfs gets converted (copied/snapshotted) on clone.
*/

static int create_file_dirname(char *path)
{
	char *p = rindex(path, '/');
	int ret;

	if (!p)
		return -1;
	*p = '\0';
	ret = mkdir(path, 0755);
	if (ret && errno != EEXIST)
		SYSERROR("creating container path %s\n", path);
	*p = '/';
	return ret;
}

struct lxc_container *lxcapi_clone(struct lxc_container *c, const char *newname,
		const char *lxcpath, int flags,
		const char *bdevtype, const char *bdevdata, unsigned long newsize,
		char **hookargs)
{
	struct lxc_container *c2 = NULL;
	char newpath[MAXPATHLEN];
	int ret, storage_copied = 0;
	const char *n, *l;
	FILE *fout;

	if (!c || !c->is_defined(c))
		return NULL;

	if (container_mem_lock(c))
		return NULL;

	if (!is_stopped(c)) {
		ERROR("error: Original container (%s) is running", c->name);
		goto out;
	}

	// Make sure the container doesn't yet exist.
	n = newname ? newname : c->name;
	l = lxcpath ? lxcpath : c->get_config_path(c);
	ret = snprintf(newpath, MAXPATHLEN, "%s/%s/config", l, n);
	if (ret < 0  || ret >= MAXPATHLEN) {
		SYSERROR("clone: failed making config pathname");
		goto out;
	}
	if (file_exists(newpath)) {
		ERROR("error: clone: %s exists", newpath);
		goto out;
	}

	ret = create_file_dirname(newpath);
	if (ret < 0 && errno != EEXIST) {
		ERROR("Error creating container dir for %s", newpath);
		goto out;
	}

	// copy the configuration, tweak it as needed,
	fout = fopen(newpath, "w");
	if (!fout) {
		SYSERROR("open %s", newpath);
		goto out;
	}
	write_config(fout, c->lxc_conf);
	fclose(fout);

	sprintf(newpath, "%s/%s/rootfs", l, n);
	if (mkdir(newpath, 0755) < 0) {
		SYSERROR("error creating %s", newpath);
		goto out;
	}

	c2 = lxc_container_new(n, l);
	if (!c2) {
		ERROR("clone: failed to create new container (%s %s)", n, l);
		goto out;
	}

	// update utsname
	if (!set_config_item_locked(c2, "lxc.utsname", newname)) {
		ERROR("Error setting new hostname");
		goto out;
	}


	// copy hooks if requested
	if (flags & LXC_CLONE_COPYHOOKS) {
		ret = copyhooks(c, c2);
		if (ret < 0) {
			ERROR("error copying hooks");
			goto out;
		}
	}

	if (copy_fstab(c, c2) < 0) {
		ERROR("error copying fstab");
		goto out;
	}

	// update macaddrs
	if (!(flags & LXC_CLONE_KEEPMACADDR))
		network_new_hwaddrs(c2);

	// copy/snapshot rootfs's
	ret = copy_storage(c, c2, bdevtype, flags, bdevdata, newsize);
	if (ret < 0)
		goto out;

	// We've now successfully created c2's storage, so clear it out if we
	// fail after this
	storage_copied = 1;

	if (!c2->save_config(c2, NULL))
		goto out;

	if (clone_update_rootfs(c, c2, flags, hookargs) < 0)
		goto out;

	// TODO: update c's lxc.snapshot = count
	container_mem_unlock(c);
	return c2;

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

static int lxcapi_attach(struct lxc_container *c, lxc_attach_exec_t exec_function, void *exec_payload, lxc_attach_options_t *options, pid_t *attached_process)
{
	if (!c)
		return -1;

	return lxc_attach(c->name, c->config_path, exec_function, exec_payload, options, attached_process);
}

static int lxcapi_attach_run_wait(struct lxc_container *c, lxc_attach_options_t *options, const char *program, const char * const argv[])
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

static int lxcapi_attach_run_waitl(struct lxc_container *c, lxc_attach_options_t *options, const char *program, const char *arg, ...)
{
	va_list ap;
	const char **argv;
	int ret;

	if (!c)
		return -1;

	va_start(ap, arg);
	argv = lxc_va_arg_list_to_argv_const(ap, 1);
	va_end(ap);

	if (!argv) {
		ERROR("Memory allocation error.");
		return -1;
	}
	argv[0] = arg;

	ret = lxcapi_attach_run_wait(c, options, program, (const char * const *)argv);
	free((void*)argv);
	return ret;
}

struct lxc_container *lxc_container_new(const char *name, const char *configpath)
{
	struct lxc_container *c;

	c = malloc(sizeof(*c));
	if (!c) {
		fprintf(stderr, "failed to malloc lxc_container\n");
		return NULL;
	}
	memset(c, 0, sizeof(*c));

	if (configpath)
		c->config_path = strdup(configpath);
	else
		c->config_path = strdup(default_lxc_path());

	if (!c->config_path) {
		fprintf(stderr, "Out of memory");
		goto err;
	}

	c->name = malloc(strlen(name)+1);
	if (!c->name) {
		fprintf(stderr, "Error allocating lxc_container name\n");
		goto err;
	}
	strcpy(c->name, name);

	c->numthreads = 1;
	if (!(c->slock = lxc_newlock(c->config_path, name))) {
		fprintf(stderr, "failed to create lock\n");
		goto err;
	}

	if (!(c->privlock = lxc_newlock(NULL, NULL))) {
		fprintf(stderr, "failed to alloc privlock\n");
		goto err;
	}

	if (!set_config_filename(c)) {
		fprintf(stderr, "Error allocating config file pathname\n");
		goto err;
	}

	if (file_exists(c->configfile))
		lxcapi_load_config(c, NULL);

	if (ongoing_create(c) == 2) {
		ERROR("Error: %s creation was not completed", c->name);
		lxcapi_destroy(c);
		lxc_conf_free(c->lxc_conf);
		c->lxc_conf = NULL;
	}

	// assign the member functions
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
	c->start = lxcapi_start;
	c->startl = lxcapi_startl;
	c->stop = lxcapi_stop;
	c->config_file_name = lxcapi_config_file_name;
	c->wait = lxcapi_wait;
	c->set_config_item = lxcapi_set_config_item;
	c->destroy = lxcapi_destroy;
	c->save_config = lxcapi_save_config;
	c->get_keys = lxcapi_get_keys;
	c->create = lxcapi_create;
	c->createl = lxcapi_createl;
	c->shutdown = lxcapi_shutdown;
	c->reboot = lxcapi_reboot;
	c->clear_config_item = lxcapi_clear_config_item;
	c->get_config_item = lxcapi_get_config_item;
	c->get_cgroup_item = lxcapi_get_cgroup_item;
	c->set_cgroup_item = lxcapi_set_cgroup_item;
	c->get_config_path = lxcapi_get_config_path;
	c->set_config_path = lxcapi_set_config_path;
	c->clone = lxcapi_clone;
	c->get_ips = lxcapi_get_ips;
	c->attach = lxcapi_attach;
	c->attach_run_wait = lxcapi_attach_run_wait;
	c->attach_run_waitl = lxcapi_attach_run_waitl;

	/* we'll allow the caller to update these later */
	if (lxc_log_init(NULL, "none", NULL, "lxc_container", 0, c->config_path)) {
		fprintf(stderr, "failed to open log\n");
		goto err;
	}

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

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

#include "lxc.h"
#include "state.h"
#include "lxccontainer.h"
#include "conf.h"
#include "config.h"
#include "confile.h"
#include "cgroup.h"
#include "commands.h"
#include "version.h"
#include "log.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <lxc/utils.h>

lxc_log_define(lxc_container, lxc);

/* LOCKING
 * c->privlock protects the struct lxc_container from multiple threads.
 * c->slock protects the on-disk container data
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
 * If you're going to fork while holding a lxccontainer, increment
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
		sem_close(c->slock);
		c->slock = NULL;
	}
	if (c->privlock) {
		sem_destroy(c->privlock);
		free(c->privlock);
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

int lxc_container_get(struct lxc_container *c)
{
	if (!c)
		return 0;

	if (lxclock(c->privlock, 0))
		return 0;
	if (c->numthreads < 1) {
		// bail without trying to unlock, bc the privlock is now probably
		// in freed memory
		return 0;
	}
	c->numthreads++;
	lxcunlock(c->privlock);
	return 1;
}

int lxc_container_put(struct lxc_container *c)
{
	if (!c)
		return -1;
	if (lxclock(c->privlock, 0))
		return -1;
	if (--c->numthreads < 1) {
		lxcunlock(c->privlock);
		lxc_container_free(c);
		return 1;
	}
	lxcunlock(c->privlock);
	return 0;
}

static bool file_exists(char *f)
{
	struct stat statbuf;

	return stat(f, &statbuf) == 0;
}

static bool lxcapi_is_defined(struct lxc_container *c)
{
	struct stat statbuf;
	bool ret = false;
	int statret;

	if (!c)
		return false;

	if (lxclock(c->privlock, 0))
		return false;
	if (!c->configfile)
		goto out;
	statret = stat(c->configfile, &statbuf);
	if (statret != 0)
		goto out;
	ret = true;

out:
	lxcunlock(c->privlock);
	return ret;
}

static const char *lxcapi_state(struct lxc_container *c)
{
	const char *ret;
	lxc_state_t s;

	if (!c)
		return NULL;
	if (lxclock(c->slock, 0))
		return NULL;
	s = lxc_getstate(c->name, c->config_path);
	ret = lxc_state2str(s);
	lxcunlock(c->slock);

	return ret;
}

static bool is_stopped_nolock(struct lxc_container *c)
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

	if (lxclock(c->slock, 0))
		return false;
	ret = lxc_freeze(c->name, c->config_path);
	lxcunlock(c->slock);
	if (ret)
		return false;
	return true;
}

static bool lxcapi_unfreeze(struct lxc_container *c)
{
	int ret;
	if (!c)
		return false;

	if (lxclock(c->slock, 0))
		return false;
	ret = lxc_unfreeze(c->name, c->config_path);
	lxcunlock(c->slock);
	if (ret)
		return false;
	return true;
}

static pid_t lxcapi_init_pid(struct lxc_container *c)
{
	pid_t ret;
	if (!c)
		return -1;

	if (lxclock(c->slock, 0))
		return -1;
	ret = get_init_pid(c->name, c->config_path);
	lxcunlock(c->slock);
	return ret;
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
	bool ret = false;
	const char *fname;
	if (!c)
		return false;

	fname = c->configfile;
	if (alt_file)
		fname = alt_file;
	if (!fname)
		return false;
	if (lxclock(c->slock, 0))
		return false;
	ret = load_config_locked(c, fname);
	lxcunlock(c->slock);
	return ret;
}

static void lxcapi_want_daemonize(struct lxc_container *c)
{
	if (!c)
		return;
	c->daemonize = 1;
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

	/* is this app meant to be run through lxcinit, as in lxc-execute? */
	if (useinit && !argv)
		return false;

	if (lxclock(c->privlock, 0))
		return false;
	conf = c->lxc_conf;
	daemonize = c->daemonize;
	lxcunlock(c->privlock);

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
		pid_t pid = fork();
		if (pid < 0) {
			lxc_container_put(c);
			return false;
		}
		if (pid != 0)
			return wait_on_daemonized_start(c);
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
		open("/dev/null", O_RDONLY);
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
	char **inargs = NULL, **temp;
	int n_inargs = 0;
	bool bret = false;

	/* container exists */
	if (!c)
		return false;

	/* build array of arguments if any */
	va_start(ap, useinit);
	while (1) {
		char *arg;
		arg = va_arg(ap, char *);
		if (!arg)
			break;
		n_inargs++;
		temp = realloc(inargs, n_inargs * sizeof(*inargs));
		if (!temp)
			goto out;
		inargs = temp;
		inargs[n_inargs - 1] = strdup(arg);  // not sure if it's safe not to copy
	}
	va_end(ap);

	/* add trailing NULL */
	if (n_inargs) {
		n_inargs++;
		temp = realloc(inargs, n_inargs * sizeof(*inargs));
		if (!temp)
			goto out;
		inargs = temp;
		inargs[n_inargs - 1] = NULL;
	}

	bret = lxcapi_start(c, useinit, inargs);

out:
	if (inargs) {
		int i;
		for (i = 0; i < n_inargs; i++) {
			if (inargs[i])
				free(inargs[i]);
		}
		free(inargs);
	}

	return bret;
}

static bool lxcapi_stop(struct lxc_container *c)
{
	int ret;

	if (!c)
		return false;

	ret = lxc_stop(c->name, c->config_path);

	return ret == 0;
}

static bool valid_template(char *t)
{
	struct stat statbuf;
	int statret;

	statret = stat(t, &statbuf);
	if (statret == 0)
		return true;
	return false;
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

/*
 * backing stores not (yet) supported
 * for ->create, argv contains the arguments to pass to the template,
 * terminated by NULL.  If no arguments, you can just pass NULL.
 */
static bool lxcapi_create(struct lxc_container *c, char *t, char *const argv[])
{
	bool bret = false;
	pid_t pid;
	int ret, status;
	char *tpath = NULL;
	int len, nargs = 0;
	char **newargv;

	if (!c)
		return false;

	len = strlen(LXCTEMPLATEDIR) + strlen(t) + strlen("/lxc-") + 1;
	tpath = malloc(len);
	if (!tpath)
		return false;
	ret = snprintf(tpath, len, "%s/lxc-%s", LXCTEMPLATEDIR, t);
	if (ret < 0 || ret >= len)
		goto out;
	if (!valid_template(tpath)) {
		ERROR("bad template: %s\n", t);
		goto out;
	}

	if (!c->save_config(c, NULL)) {
		ERROR("failed to save starting configuration for %s\n", c->name);
		goto out;
	}

	/* container is already created if we have a config and rootfs.path is accessible */
	if (lxcapi_is_defined(c) && c->lxc_conf && c->lxc_conf->rootfs.path && access(c->lxc_conf->rootfs.path, F_OK) == 0) 
		return false;

	/* we're going to fork.  but since we'll wait for our child, we
	   don't need to lxc_container_get */

	if (lxclock(c->slock, 0)) {
		ERROR("failed to grab global container lock for %s\n", c->name);
		goto out;
	}

	pid = fork();
	if (pid < 0) {
		SYSERROR("failed to fork task for container creation template\n");
		goto out_unlock;
	}

	if (pid == 0) { // child
		char *patharg, *namearg;
		int i;

		close(0);
		close(1);
		close(2);
		open("/dev/null", O_RDONLY);
		open("/dev/null", O_RDWR);
		open("/dev/null", O_RDWR);

		/*
		 * create our new array, pre-pend the template name and
		 * base args
		 */
		if (argv)
			for (; argv[nargs]; nargs++) ;
		nargs += 3;  // template, path and name args
		newargv = malloc(nargs * sizeof(*newargv));
		if (!newargv)
			exit(1);
		newargv[0] = t;

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

		/* add passed-in args */
		if (argv)
			for (i = 3; i < nargs; i++)
				newargv[i] = argv[i-3];

		/* add trailing NULL */
		nargs++;
		newargv = realloc(newargv, nargs * sizeof(*newargv));
		if (!newargv)
			exit(1);
		newargv[nargs - 1] = NULL;

		/* execute */
		ret = execv(tpath, newargv);
		SYSERROR("failed to execute template %s", tpath);
		exit(1);
	}

again:
	ret = waitpid(pid, &status, 0);
	if (ret == -1) {
		if (errno == -EINTR)
			goto again;
		SYSERROR("waitpid failed");
		goto out_unlock;
	}
	if (ret != pid)
		goto again;
	if (!WIFEXITED(status))  { // did not exit normally
		// we could set an error code and string inside the
		// container_struct here if we like
		ERROR("container creation template exited abnormally\n");
		goto out_unlock;
	}

	if (WEXITSTATUS(status) != 0) {
		ERROR("container creation template for %s exited with %d\n",
		      c->name, WEXITSTATUS(status));
		goto out_unlock;
	}

	// now clear out the lxc_conf we have, reload from the created
	// container
	if (c->lxc_conf)
		lxc_conf_free(c->lxc_conf);
	c->lxc_conf = NULL;
	bret = load_config_locked(c, c->configfile);

out_unlock:
	lxcunlock(c->slock);
out:
	if (tpath)
		free(tpath);
	return bret;
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

static bool lxcapi_createl(struct lxc_container *c, char *t, ...)
{
	bool bret = false;
	char **args = NULL, **temp;
	va_list ap;
	int nargs = 0;

	if (!c)
		return false;

	/*
	 * since we're going to wait for create to finish, I don't think we
	 * need to get a copy of the arguments.
	 */
	va_start(ap, t);
	while (1) {
		char *arg;
		arg = va_arg(ap, char *);
		if (!arg)
			break;
		nargs++;
		temp = realloc(args, (nargs+1) * sizeof(*args));
		if (!temp)
			goto out;
		args = temp;
		args[nargs - 1] = arg;
	}
	va_end(ap);
	if (args)
		args[nargs] = NULL;

	bret = c->create(c, t, args);

out:
	if (args)
		free(args);
	return bret;
}

static bool lxcapi_clear_config_item(struct lxc_container *c, const char *key)
{
	int ret;

	if (!c || !c->lxc_conf)
		return false;
	if (lxclock(c->privlock, 0)) {
		return false;
	}
	ret = lxc_clear_config_item(c->lxc_conf, key);
	lxcunlock(c->privlock);
	return ret == 0;
}

static int lxcapi_get_config_item(struct lxc_container *c, const char *key, char *retv, int inlen)
{
	int ret;

	if (!c || !c->lxc_conf)
		return -1;
	if (lxclock(c->privlock, 0)) {
		return -1;
	}
	ret = lxc_get_config_item(c->lxc_conf, key, retv, inlen);
	lxcunlock(c->privlock);
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
	if (lxclock(c->privlock, 0))
		return -1;
	int ret = -1;
	if (strncmp(key, "lxc.network.", 12) == 0)
		ret =  lxc_list_nicconfigs(c->lxc_conf, key, retv, inlen);
	lxcunlock(c->privlock);
	return ret;
}


/* default config file - should probably come through autoconf */
#define LXC_DEFAULT_CONFIG "/etc/lxc/default.conf"
static bool lxcapi_save_config(struct lxc_container *c, const char *alt_file)
{
	if (!alt_file)
		alt_file = c->configfile;
	if (!alt_file)
		return false;  // should we write to stdout if no file is specified?
	if (!c->lxc_conf)
		if (!c->load_config(c, LXC_DEFAULT_CONFIG)) {
			ERROR("Error loading default configuration file %s while saving %s\n", LXC_DEFAULT_CONFIG, c->name);
			return false;
		}

	if (!create_container_dir(c))
		return false;

	FILE *fout = fopen(alt_file, "w");
	if (!fout)
		return false;
	if (lxclock(c->privlock, 0)) {
		fclose(fout);
		return false;
	}
	write_config(fout, c->lxc_conf);
	fclose(fout);
	lxcunlock(c->privlock);
	return true;
}

static bool lxcapi_destroy(struct lxc_container *c)
{
	pid_t pid;
	int ret, status;

	if (!c)
		return false;

	/* container is already destroyed if we don't have a config and rootfs.path is not accessible */
	if (!lxcapi_is_defined(c) && (!c->lxc_conf || !c->lxc_conf->rootfs.path || access(c->lxc_conf->rootfs.path, F_OK) != 0)) 
		return false;

	pid = fork();
	if (pid < 0)
		return false;
	if (pid == 0) { // child
		ret = execlp("lxc-destroy", "lxc-destroy", "-n", c->name, "-P", c->config_path, NULL);
		perror("execl");
		exit(1);
	}

again:
	ret = waitpid(pid, &status, 0);
	if (ret == -1) {
		if (errno == -EINTR)
			goto again;
		perror("waitpid");
		return false;
	}
	if (ret != pid)
		goto again;
	if (!WIFEXITED(status))  { // did not exit normally
		// we could set an error code and string inside the
		// container_struct here if we like
		return false;
	}

	return WEXITSTATUS(status) == 0;
}

static bool lxcapi_set_config_item(struct lxc_container *c, const char *key, const char *v)
{
	int ret;
	bool b = false;
	struct lxc_config_t *config;

	if (!c)
		return false;

	if (lxclock(c->privlock, 0))
		return false;

	if (!c->lxc_conf)
		c->lxc_conf = lxc_conf_init();
	if (!c->lxc_conf)
		goto err;
	config = lxc_getconfig(key);
	if (!config)
		goto err;
	ret = config->cb(key, v, c->lxc_conf);
	if (!ret)
		b = true;

err:
	lxcunlock(c->privlock);
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

	if (lxclock(c->privlock, 0))
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
	lxcunlock(c->privlock);
	return b;
}


static bool lxcapi_set_cgroup_item(struct lxc_container *c, const char *subsys, const char *value)
{
	int ret;
	bool b = false;

	if (!c)
		return false;

	if (lxclock(c->privlock, 0))
		return false;

	if (is_stopped_nolock(c))
		goto err;

	ret = lxc_cgroup_set(c->name, subsys, value, c->config_path);
	if (!ret)
		b = true;
err:
	lxcunlock(c->privlock);
	return b;
}

static int lxcapi_get_cgroup_item(struct lxc_container *c, const char *subsys, char *retv, int inlen)
{
	int ret = -1;

	if (!c || !c->lxc_conf)
		return -1;

	if (lxclock(c->privlock, 0))
		return -1;

	if (is_stopped_nolock(c))
		goto out;

	ret = lxc_cgroup_get(c->name, subsys, retv, inlen, c->config_path);

out:
	lxcunlock(c->privlock);
	return ret;
}

const char *lxc_get_default_config_path(void)
{
	return default_lxc_path();
}

const char *lxc_get_version(void)
{
	return lxc_version();
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
	c->slock = lxc_newlock(name);
	if (!c->slock) {
		fprintf(stderr, "failed to create lock\n");
		goto err;
	}

	c->privlock = lxc_newlock(NULL);
	if (!c->privlock) {
		fprintf(stderr, "failed to alloc privlock\n");
		goto err;
	}

	if (!set_config_filename(c)) {
		fprintf(stderr, "Error allocating config file pathname\n");
		goto err;
	}

	if (file_exists(c->configfile))
		lxcapi_load_config(c, NULL);

	// assign the member functions
	c->is_defined = lxcapi_is_defined;
	c->state = lxcapi_state;
	c->is_running = lxcapi_is_running;
	c->freeze = lxcapi_freeze;
	c->unfreeze = lxcapi_unfreeze;
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
	c->clear_config_item = lxcapi_clear_config_item;
	c->get_config_item = lxcapi_get_config_item;
	c->get_cgroup_item = lxcapi_get_cgroup_item;
	c->set_cgroup_item = lxcapi_set_cgroup_item;
	c->get_config_path = lxcapi_get_config_path;
	c->set_config_path = lxcapi_set_config_path;

	/* we'll allow the caller to update these later */
	if (lxc_log_init(NULL, "none", NULL, "lxc_container", 0)) {
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

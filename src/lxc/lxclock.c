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

#include <pthread.h>
#include "lxclock.h"
#include <malloc.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#define _GNU_SOURCE
#include <stdlib.h>
#include <lxc/utils.h>
#include <lxc/log.h>
#include <lxc/lxccontainer.h>

#define OFLAG (O_CREAT | O_RDWR)
#define SEMMODE 0660
#define SEMVALUE 1
#define SEMVALUE_LOCKED 0

lxc_log_define(lxc_lock, lxc);

pthread_mutex_t thread_mutex = PTHREAD_MUTEX_INITIALIZER;

static char *lxclock_name(const char *p, const char *n)
{
	int ret;
	int len;
	char *dest;
	const char *rundir;
	struct stat sb;

	/* lockfile will be:
	 * "/run" + "/lock/lxc/$lxcpath/$lxcname + '\0' if root
	 * or
	 * $XDG_RUNTIME_DIR + "/lock/lxc/$lxcpath/$lxcname + '\0' if non-root
	 */

	/* length of "/lock/lxc/" + $lxcpath + "/" + $lxcname + '\0' */
	len = strlen("/lock/lxc/") + strlen(n) + strlen(p) + 2;
	rundir = getenv("XDG_RUNTIME_DIR");
	if (geteuid() == 0 || rundir == NULL)
		rundir = "/run";

	len += strlen(rundir);

	if ((dest = malloc(len)) == NULL)
		return NULL;

	ret = snprintf(dest, len, "%s/lock/lxc/%s", rundir, p);
	if (ret < 0 || ret >= len) {
		free(dest);
		return NULL;
	}
	process_lock();
	ret = mkdir_p(dest, 0755);
	process_unlock();
	if (ret < 0) {
		free(dest);
		return NULL;
	}

	ret = stat(p, &sb);
	if (ret == 0) {
		// best effort.  If this fails, ignore it
		if (chown(dest, sb.st_uid, sb.st_gid) < 0)
			ERROR("Failed ot set owner for lockdir %s\n", dest);
		if (chmod(dest, sb.st_mode) < 0)
			ERROR("Failed to set mode for lockdir %s\n", dest);
	}

	ret = snprintf(dest, len, "%s/lock/lxc/%s/%s", rundir, p, n);
	if (ret < 0 || ret >= len) {
		free(dest);
		return NULL;
	}
	return dest;
}

static sem_t *lxc_new_unnamed_sem(void)
{
	sem_t *s;
	int ret;

	s = malloc(sizeof(*s));
	if (!s)
		return NULL;
	ret = sem_init(s, 0, 1);
	if (ret) {
		free(s);
		return NULL;
	}
	return s;
}

struct lxc_lock *lxc_newlock(const char *lxcpath, const char *name)
{
	struct lxc_lock *l;

	l = malloc(sizeof(*l));
	if (!l)
		goto out;

	if (!name) {
		l->type = LXC_LOCK_ANON_SEM;
		l->u.sem = lxc_new_unnamed_sem();
		if (!l->u.sem) {
			free(l);
			l = NULL;
		}
		goto out;
	}

	l->type = LXC_LOCK_FLOCK;
	l->u.f.fname = lxclock_name(lxcpath, name);
	if (!l->u.f.fname) {
		free(l);
		l = NULL;
		goto out;
	}
	l->u.f.fd = -1;

out:
	return l;
}

int lxclock(struct lxc_lock *l, int timeout)
{
	int ret = -1, saved_errno = errno;
	struct flock lk;

	switch(l->type) {
	case LXC_LOCK_ANON_SEM:
		if (!timeout) {
			ret = sem_wait(l->u.sem);
			if (ret == -1)
				saved_errno = errno;
		} else {
			struct timespec ts;
			if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
				ret = -2;
				goto out;
			}
			ts.tv_sec += timeout;
			ret = sem_timedwait(l->u.sem, &ts);
			if (ret == -1)
				saved_errno = errno;
		}
		break;
	case LXC_LOCK_FLOCK:
		ret = -2;
		if (timeout) {
			ERROR("Error: timeout not supported with flock");
			ret = -2;
			goto out;
		}
		if (!l->u.f.fname) {
			ERROR("Error: filename not set for flock");
			ret = -2;
			goto out;
		}
		process_lock();
		if (l->u.f.fd == -1) {
			l->u.f.fd = open(l->u.f.fname, O_RDWR|O_CREAT,
					S_IWUSR | S_IRUSR);
			if (l->u.f.fd == -1) {
				process_unlock();
				ERROR("Error opening %s", l->u.f.fname);
				goto out;
			}
		}
		lk.l_type = F_WRLCK;
		lk.l_whence = SEEK_SET;
		lk.l_start = 0;
		lk.l_len = 0;
		ret = fcntl(l->u.f.fd, F_SETLKW, &lk);
		process_unlock();
		if (ret == -1)
			saved_errno = errno;
		break;
	}

out:
	errno = saved_errno;
	return ret;
}

int lxcunlock(struct lxc_lock *l)
{
	int ret = 0, saved_errno = errno;
	struct flock lk;

	switch(l->type) {
	case LXC_LOCK_ANON_SEM:
		if (!l->u.sem)
			ret = -2;
		else {
			ret = sem_post(l->u.sem);
			saved_errno = errno;
		}
		break;
	case LXC_LOCK_FLOCK:
		process_lock();
		if (l->u.f.fd != -1) {
			lk.l_type = F_UNLCK;
			lk.l_whence = SEEK_SET;
			lk.l_start = 0;
			lk.l_len = 0;
			ret = fcntl(l->u.f.fd, F_SETLK, &lk);
			if (ret < 0)
				saved_errno = errno;
			close(l->u.f.fd);
			l->u.f.fd = -1;
		} else
			ret = -2;
		process_unlock();
		break;
	}

	errno = saved_errno;
	return ret;
}

/*
 * lxc_putlock() is only called when a container_new() fails,
 * or during container_put(), which is already guaranteed to
 * only be done by one task.
 * So the only exclusion we need to provide here is for regular
 * thread safety (i.e. file descriptor table changes).
 */
void lxc_putlock(struct lxc_lock *l)
{
	if (!l)
		return;
	switch(l->type) {
	case LXC_LOCK_ANON_SEM:
		if (l->u.sem) {
			sem_close(l->u.sem);
			free(l->u.sem);
			l->u.sem = NULL;
		}
		break;
	case LXC_LOCK_FLOCK:
		process_lock();
		if (l->u.f.fd != -1) {
			close(l->u.f.fd);
			l->u.f.fd = -1;
		}
		process_unlock();
		if (l->u.f.fname) {
			free(l->u.f.fname);
			l->u.f.fname = NULL;
		}
		break;
	}
	free(l);
}

int process_lock(void)
{
	int ret;
	ret = pthread_mutex_lock(&thread_mutex);
	if (ret != 0)
		ERROR("pthread_mutex_lock returned:%d %s", ret, strerror(ret));
	return ret;
}

void process_unlock(void)
{
	pthread_mutex_unlock(&thread_mutex);
}

int container_mem_lock(struct lxc_container *c)
{
	return lxclock(c->privlock, 0);
}

void container_mem_unlock(struct lxc_container *c)
{
	lxcunlock(c->privlock);
}

int container_disk_lock(struct lxc_container *c)
{
	int ret;

	if ((ret = lxclock(c->privlock, 0)))
		return ret;
	if ((ret = lxclock(c->slock, 0))) {
		lxcunlock(c->privlock);
		return ret;
	}
	return 0;
}

void container_disk_unlock(struct lxc_container *c)
{
	lxcunlock(c->slock);
	lxcunlock(c->privlock);
}

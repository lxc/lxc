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

#define _GNU_SOURCE
#include "lxclock.h"
#include <malloc.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <pthread.h>

#include <lxc/lxccontainer.h>

#include "utils.h"
#include "log.h"

#ifdef MUTEX_DEBUGGING
#include <execinfo.h>
#endif

#define MAX_STACKDEPTH 25

#define OFLAG (O_CREAT | O_RDWR)
#define SEMMODE 0660
#define SEMVALUE 1
#define SEMVALUE_LOCKED 0

lxc_log_define(lxc_lock, lxc);

#ifdef MUTEX_DEBUGGING
static pthread_mutex_t thread_mutex = PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP;

static inline void dump_stacktrace(void)
{
	void *array[MAX_STACKDEPTH];
	size_t size;
	char **strings;
	size_t i;

	size = backtrace(array, MAX_STACKDEPTH);
	strings = backtrace_symbols(array, size);

	// Using fprintf here as our logging module is not thread safe
	fprintf(stderr, "\tObtained %zd stack frames.\n", size);

	for (i = 0; i < size; i++)
		fprintf(stderr, "\t\t%s\n", strings[i]);

	free (strings);
}
#else
static pthread_mutex_t thread_mutex = PTHREAD_MUTEX_INITIALIZER;

static inline void dump_stacktrace(void) {;}
#endif

static void lock_mutex(pthread_mutex_t *l)
{
	int ret;

	if ((ret = pthread_mutex_lock(l)) != 0) {
		fprintf(stderr, "pthread_mutex_lock returned:%d %s\n", ret, strerror(ret));
		dump_stacktrace();
		exit(1);
	}
}

static void unlock_mutex(pthread_mutex_t *l)
{
	int ret;

	if ((ret = pthread_mutex_unlock(l)) != 0) {
		fprintf(stderr, "pthread_mutex_unlock returned:%d %s\n", ret, strerror(ret));
		dump_stacktrace();
		exit(1);
	}
}

static char *lxclock_name(const char *p, const char *n)
{
	int ret;
	int len;
	char *dest;
	char *rundir;

	/* lockfile will be:
	 * "/run" + "/lxc/lock/$lxcpath/$lxcname + '\0' if root
	 * or
	 * $XDG_RUNTIME_DIR + "/lxc/lock/$lxcpath/$lxcname + '\0' if non-root
	 */

	/* length of "/lxc/lock/" + $lxcpath + "/" + "." + $lxcname + '\0' */
	len = strlen("/lxc/lock/") + strlen(n) + strlen(p) + 3;
	rundir = get_rundir();
	if (!rundir)
		return NULL;
	len += strlen(rundir);

	if ((dest = malloc(len)) == NULL) {
		free(rundir);
		return NULL;
	}

	ret = snprintf(dest, len, "%s/lxc/lock/%s", rundir, p);
	if (ret < 0 || ret >= len) {
		free(dest);
		free(rundir);
		return NULL;
	}
	ret = mkdir_p(dest, 0755);
	if (ret < 0) {
		free(dest);
		free(rundir);
		return NULL;
	}

	ret = snprintf(dest, len, "%s/lxc/lock/%s/.%s", rundir, p, n);
	free(rundir);
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
		if (l->u.f.fd == -1) {
			l->u.f.fd = open(l->u.f.fname, O_RDWR|O_CREAT,
					S_IWUSR | S_IRUSR);
			if (l->u.f.fd == -1) {
				ERROR("Error opening %s", l->u.f.fname);
				goto out;
			}
		}
		lk.l_type = F_WRLCK;
		lk.l_whence = SEEK_SET;
		lk.l_start = 0;
		lk.l_len = 0;
		ret = fcntl(l->u.f.fd, F_SETLKW, &lk);
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
			sem_destroy(l->u.sem);
			free(l->u.sem);
			l->u.sem = NULL;
		}
		break;
	case LXC_LOCK_FLOCK:
		if (l->u.f.fd != -1) {
			close(l->u.f.fd);
			l->u.f.fd = -1;
		}
		free(l->u.f.fname);
		l->u.f.fname = NULL;
		break;
	}
	free(l);
}

void process_lock(void)
{
	lock_mutex(&thread_mutex);
}

void process_unlock(void)
{
	unlock_mutex(&thread_mutex);
}

/* One thread can do fork() while another one is holding a mutex.
 * There is only one thread in child just after the fork(), so no one will ever release that mutex.
 * We setup a "child" fork handler to unlock the mutex just after the fork().
 * For several mutex types, unlocking an unlocked mutex can lead to undefined behavior.
 * One way to deal with it is to setup "prepare" fork handler
 * to lock the mutex before fork() and both "parent" and "child" fork handlers
 * to unlock the mutex.
 * This forbids doing fork() while explicitly holding the lock.
 */
#ifdef HAVE_PTHREAD_ATFORK
__attribute__((constructor))
static void process_lock_setup_atfork(void)
{
	pthread_atfork(process_lock, process_unlock, process_unlock);
}
#endif

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

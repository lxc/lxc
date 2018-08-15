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
#include <errno.h>
#include <fcntl.h>
#include <malloc.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/file.h>
#include <unistd.h>

#include <lxc/lxccontainer.h>

#include "lxclock.h"
#include "utils.h"
#include "log.h"

#ifdef MUTEX_DEBUGGING
#include <execinfo.h>
#endif

#define MAX_STACKDEPTH 25

lxc_log_define(lxclock, lxc);

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

	/* Using fprintf here as our logging module is not thread safe. */
	fprintf(stderr, "\tObtained %zu stack frames\n", size);

	for (i = 0; i < size; i++)
		fprintf(stderr, "\t\t%s\n", strings[i]);

	free(strings);
}
#else
static pthread_mutex_t thread_mutex = PTHREAD_MUTEX_INITIALIZER;

static inline void dump_stacktrace(void) {;}
#endif

static void lock_mutex(pthread_mutex_t *l)
{
	int ret;

	ret = pthread_mutex_lock(l);
	if (ret != 0) {
		SYSERROR("Failed to acquire mutex");
		dump_stacktrace();
		_exit(EXIT_FAILURE);
	}
}

static void unlock_mutex(pthread_mutex_t *l)
{
	int ret;

	ret = pthread_mutex_unlock(l);
	if (ret != 0) {
		SYSERROR("Failed to release mutex");
		dump_stacktrace();
		_exit(EXIT_FAILURE);
	}
}

static char *lxclock_name(const char *p, const char *n)
{
	int ret;
	size_t len;
	char *dest, *rundir;

	/* lockfile will be:
	 * "/run" + "/lxc/lock/$lxcpath/$lxcname + '\0' if root
	 * or
	 * $XDG_RUNTIME_DIR + "/lxc/lock/$lxcpath/$lxcname + '\0' if non-root
	 */

	/* length of "/lxc/lock/" + $lxcpath + "/" + "." + $lxcname + '\0' */
	len = (sizeof("/lxc/lock/") - 1) + strlen(n) + strlen(p) + 3;

	rundir = get_rundir();
	if (!rundir)
		return NULL;

	len += strlen(rundir);

	dest = malloc(len);
	if (!dest) {
		free(rundir);
		return NULL;
	}

	ret = snprintf(dest, len, "%s/lxc/lock/%s", rundir, p);
	if (ret < 0 || (size_t)ret >= len) {
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
	if (ret < 0 || (size_t)ret >= len) {
		free(dest);
		return NULL;
	}

	return dest;
}

static sem_t *lxc_new_unnamed_sem(void)
{
	int ret;
	sem_t *s;

	s = malloc(sizeof(*s));
	if (!s)
		return NULL;

	ret = sem_init(s, 0, 1);
	if (ret < 0) {
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
		goto on_error;

	if (!name) {
		l->type = LXC_LOCK_ANON_SEM;
		l->u.sem = lxc_new_unnamed_sem();
		if (!l->u.sem) {
			free(l);
			l = NULL;
		}

		goto on_error;
	}

	l->type = LXC_LOCK_FLOCK;
	l->u.f.fname = lxclock_name(lxcpath, name);
	if (!l->u.f.fname) {
		free(l);
		l = NULL;
		goto on_error;
	}

	l->u.f.fd = -1;

on_error:
	return l;
}

int lxclock(struct lxc_lock *l, int timeout)
{
	struct flock lk;
	int ret = -1, saved_errno = errno;

	switch(l->type) {
	case LXC_LOCK_ANON_SEM:
		if (!timeout) {
			ret = sem_wait(l->u.sem);
			if (ret < 0)
				saved_errno = errno;
		} else {
			struct timespec ts;

			ret = clock_gettime(CLOCK_REALTIME, &ts);
			if (ret < 0) {
				ret = -2;
				goto on_error;
			}

			ts.tv_sec += timeout;
			ret = sem_timedwait(l->u.sem, &ts);
			if (ret < 0)
				saved_errno = errno;
		}

		break;
	case LXC_LOCK_FLOCK:
		ret = -2;
		if (timeout) {
			ERROR("Timeouts are not supported with file locks");
			goto on_error;
		}

		if (!l->u.f.fname) {
			ERROR("No filename set for file lock");
			goto on_error;
		}

		if (l->u.f.fd == -1) {
			l->u.f.fd = open(l->u.f.fname, O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NOCTTY, S_IWUSR | S_IRUSR);
			if (l->u.f.fd == -1) {
				SYSERROR("Failed to open \"%s\"", l->u.f.fname);
				saved_errno = errno;
				goto on_error;
			}
		}

		memset(&lk, 0, sizeof(struct flock));

		lk.l_type = F_WRLCK;
		lk.l_whence = SEEK_SET;

		ret = fcntl(l->u.f.fd, F_OFD_SETLKW, &lk);
		if (ret < 0) {
			if (errno == EINVAL)
				ret = flock(l->u.f.fd, LOCK_EX);
			saved_errno = errno;
		}

		break;
	}

on_error:
	errno = saved_errno;
	return ret;
}

int lxcunlock(struct lxc_lock *l)
{
	struct flock lk;
	int ret = 0, saved_errno = errno;

	switch (l->type) {
	case LXC_LOCK_ANON_SEM:
		if (!l->u.sem) {
			ret = -2;
		} else {
			ret = sem_post(l->u.sem);
			saved_errno = errno;
		}

		break;
	case LXC_LOCK_FLOCK:
		if (l->u.f.fd != -1) {
			memset(&lk, 0, sizeof(struct flock));

			lk.l_type = F_UNLCK;
			lk.l_whence = SEEK_SET;

			ret = fcntl(l->u.f.fd, F_OFD_SETLK, &lk);
			if (ret < 0) {
				if (errno == EINVAL)
					ret = flock(l->u.f.fd, LOCK_EX | LOCK_NB);
				saved_errno = errno;
			}

			close(l->u.f.fd);
			l->u.f.fd = -1;
		} else {
			ret = -2;
		}

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

	ret = lxclock(c->privlock, 0);
	if (ret < 0)
		return ret;

	ret = lxclock(c->slock, 0);
	if (ret < 0) {
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

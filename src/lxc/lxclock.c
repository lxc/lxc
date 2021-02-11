/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <errno.h>
#include <fcntl.h>
#include <malloc.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/file.h>
#include <unistd.h>

#include <lxc/lxccontainer.h>

#include "config.h"
#include "log.h"
#include "lxclock.h"
#include "memory_utils.h"
#include "utils.h"

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

	size = backtrace(array, MAX_STACKDEPTH);
	strings = backtrace_symbols(array, size);

	/* Using fprintf here as our logging module is not thread safe. */
	fprintf(stderr, "\tObtained %zu stack frames\n", size);

	for (int i = 0; i < size; i++)
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
	__do_free char *dest = NULL, *rundir = NULL;
	int ret;
	size_t len;

	/* lockfile will be:
	 * "/run" + "/lxc/lock/$lxcpath/$lxcname + '\0' if root
	 * or
	 * $XDG_RUNTIME_DIR + "/lxc/lock/$lxcpath/$lxcname + '\0' if non-root
	 */

	/* length of "/lxc/lock/" + $lxcpath + "/" + "." + $lxcname + '\0' */
	len = STRLITERALLEN("/lxc/lock/") + strlen(n) + strlen(p) + 3;

	rundir = get_rundir();
	if (!rundir)
		return NULL;

	len += strlen(rundir);

	dest = malloc(len);
	if (!dest)
		return NULL;

	ret = strnprintf(dest, len, "%s/lxc/lock/%s", rundir, p);
	if (ret < 0)
		return NULL;

	ret = mkdir_p(dest, 0755);
	if (ret < 0)
		return NULL;

	ret = strnprintf(dest, len, "%s/lxc/lock/%s/.%s", rundir, p, n);
	if (ret < 0)
		return NULL;

	return move_ptr(dest);
}

static sem_t *lxc_new_unnamed_sem(void)
{
	__do_free sem_t *s = NULL;
	int ret;

	s = malloc(sizeof(*s));
	if (!s)
		return ret_set_errno(NULL, ENOMEM);

	ret = sem_init(s, 0, 1);
	if (ret < 0)
		return NULL;

	return move_ptr(s);
}

struct lxc_lock *lxc_newlock(const char *lxcpath, const char *name)
{
	__do_free struct lxc_lock *l = NULL;

	l = zalloc(sizeof(*l));
	if (!l)
		return ret_set_errno(NULL, ENOMEM);

	if (name) {
		l->type = LXC_LOCK_FLOCK;
		l->u.f.fname = lxclock_name(lxcpath, name);
		if (!l->u.f.fname)
			return ret_set_errno(NULL, ENOMEM);
		l->u.f.fd = -EBADF;
	} else {
		l->type = LXC_LOCK_ANON_SEM;
		l->u.sem = lxc_new_unnamed_sem();
		if (!l->u.sem)
			return ret_set_errno(NULL, ENOMEM);
	}

	return move_ptr(l);
}

int lxclock(struct lxc_lock *l, int timeout)
{
	int ret = -1;
	struct flock lk;

	switch (l->type) {
	case LXC_LOCK_ANON_SEM:
		if (!timeout) {
			ret = sem_wait(l->u.sem);
		} else {
			struct timespec ts;

			ret = clock_gettime(CLOCK_REALTIME, &ts);
			if (ret < 0)
				return -2;

			ts.tv_sec += timeout;
			ret = sem_timedwait(l->u.sem, &ts);
		}

		break;
	case LXC_LOCK_FLOCK:
		if (timeout)
			return log_error(-2, "Timeouts are not supported with file locks");

		if (!l->u.f.fname)
			return log_error(-2, "No filename set for file lock");

		if (l->u.f.fd < 0) {
			l->u.f.fd = open(l->u.f.fname, O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NOCTTY, S_IWUSR | S_IRUSR);
			if (l->u.f.fd < 0)
				return log_error_errno(-2, errno, "Failed to open \"%s\"", l->u.f.fname);
		}

		memset(&lk, 0, sizeof(struct flock));

		lk.l_type = F_WRLCK;
		lk.l_whence = SEEK_SET;

		ret = fcntl(l->u.f.fd, F_OFD_SETLKW, &lk);
		if (ret < 0 && errno == EINVAL)
			ret = flock(l->u.f.fd, LOCK_EX);
		break;
	default:
		return ret_set_errno(-1, EINVAL);
	}

	return ret;
}

int lxcunlock(struct lxc_lock *l)
{
	struct flock lk;
	int ret = 0;

	switch (l->type) {
	case LXC_LOCK_ANON_SEM:
		if (!l->u.sem)
			return -2;

		ret = sem_post(l->u.sem);
		break;
	case LXC_LOCK_FLOCK:
		if (l->u.f.fd < 0)
			return -2;

		memset(&lk, 0, sizeof(struct flock));

		lk.l_type = F_UNLCK;
		lk.l_whence = SEEK_SET;

		ret = fcntl(l->u.f.fd, F_OFD_SETLK, &lk);
		if (ret < 0 && errno == EINVAL)
			ret = flock(l->u.f.fd, LOCK_EX | LOCK_NB);

		close_prot_errno_disarm(l->u.f.fd);
		break;
	default:
		return ret_set_errno(-1, EINVAL);
	}

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

	switch (l->type) {
	case LXC_LOCK_ANON_SEM:
		if (l->u.sem) {
			sem_destroy(l->u.sem);
			free_disarm(l->u.sem);
		}
		break;
	case LXC_LOCK_FLOCK:
		close_prot_errno_disarm(l->u.f.fd);
		free_disarm(l->u.f.fname);
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

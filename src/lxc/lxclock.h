#ifndef __LXCLOCK_H
#define __LXCLOCK_H
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

#include <fcntl.h>           /* For O_* constants */
#include <sys/stat.h>        /* For mode constants */
#include <sys/file.h>
#include <semaphore.h>
#include <string.h>
#include <time.h>

#define LXC_LOCK_ANON_SEM 1
#define LXC_LOCK_FLOCK 2
struct lxc_lock {
	short type;
	union {
		sem_t *sem; // an anonymous semaphore
		struct {
			int fd; // fd on which a lock is held (if not -1)
			char *fname;
		} f;
	} u;
};

/*
 * lxc_newlock: Create a new (unlocked) lock.
 *
 * if name is not given, create an unnamed semaphore.  We use these
 * to protect against racing threads.
 * Note that an unnamed sem was malloced by us and needs to be freed.
 *
 * sem is initialized to value of 1
 * A sem_t * which can be passed to lxclock() and lxcunlock()
 * will be placed in l->u.sem
 *
 * If lxcpath and name are given (both must be given if either is
 * given) then a lockfile is created, $lxcpath/$lxcname/locks/$name.
 * We use that to protect the containers as represented on disk.
 * lxc_newlock() for the named lock only allocates the pathname in
 * memory so we can quickly open+lock it at lxclock.
 * l->u.f.fname will contain the malloc'ed name (which must be
 * freed when the container is freed), and u.f.fd = -1.
 *
 * return lxclock on success, NULL on failure.
 */
extern struct lxc_lock *lxc_newlock(const char *lxcpath, const char *name);

/*
 * lxclock: take an existing lock.  If timeout is 0, wait
 * indefinately.  Otherwise use given timeout.
 * return 0 if we got the lock, -2 on failure to set timeout, or -1
 * otherwise in which case errno will be set by sem_wait()).
 *
 * Note that timeout is (currently?) only supported for privlock, not
 * for slock.  Since currently there is not a single use of the timeout
 * (except in the test case) I may remove the support for it in sem as
 * well.
 */
extern int lxclock(struct lxc_lock *lock, int timeout);

/*
 * lxcunlock: unlock given sem.  Return 0 on success, or -2 if we did not
 * have the lock.  Otherwise returns -1 with errno saved from flock
 * or sem_post function.
 */
extern int lxcunlock(struct lxc_lock *lock);

extern void lxc_putlock(struct lxc_lock *l);

extern int process_lock(void);
extern void process_unlock(void);
struct lxc_container;
extern int container_mem_lock(struct lxc_container *c);
extern void container_mem_unlock(struct lxc_container *c);
extern int container_disk_lock(struct lxc_container *c);
extern void container_disk_unlock(struct lxc_container *c);
#endif

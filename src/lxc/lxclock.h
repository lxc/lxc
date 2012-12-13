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

#include <fcntl.h>           /* For O_* constants */
#include <sys/stat.h>        /* For mode constants */
#include <semaphore.h>
#include <string.h>
#include <time.h>

/*
 * lxc_newlock:
 * if name is not given, create an unnamed semaphore.  We use these
 * to protect against racing threads.
 * Note that an unnamed sem was malloced by us and needs to be freed.
 *
 * If name is given, it is prepended with '/lxcapi.', and used as the
 * name for a system-wide (well, ipcns-wide) semaphore.  We use that
 * to protect the containers as represented on disk.
 * A named sem should not be freed.
 *
 * XXX TODO
 * We should probably introduce a lxclock_close() which detecs the type
 * of lock and calls sem_close() or sem_destroy()+free() not as appropriate.
 * For now, it is up to the caller to do so.
 *
 * sem is initialized to value of 1
 *
 * return NULL on failure, else a sem_t * which can be passed to
 * lxclock() and lxcunlock().
 */
extern sem_t *lxc_newlock(const char *name);

/*
 * lxclock: take an existing lock.  If timeout is 0, wait
 * indefinately.  Otherwise use given timeout.
 * return 0 if we got the lock, -2 on failure to set timeout, or -1
 * otherwise in which case errno will be set by sem_wait()).
 */
extern int lxclock(sem_t *sem, int timeout);

/*
 * lxcunlock: unlock given sem.  Return 0 on success.  Otherwise returns
 * -1 and sem_post will leave errno set.
 */
extern int lxcunlock(sem_t *lock);

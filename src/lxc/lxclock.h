/*! \file
 *
 * liblxcapi
 *
 * Copyright © 2012 Serge Hallyn <serge.hallyn@ubuntu.com>.
 * Copyright © 2012 Canonical Ltd.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef __LXC_LXCLOCK_H
#define __LXC_LXCLOCK_H

#include <fcntl.h>           /* For O_* constants */
#include <sys/stat.h>        /* For mode constants */
#include <sys/file.h>
#include <semaphore.h>
#include <string.h>
#include <time.h>

#define LXC_LOCK_ANON_SEM 1 /*!< Anonymous semaphore lock */
#define LXC_LOCK_FLOCK    2 /*!< flock(2) lock */

// private
/*!
 * LXC Lock
*/
struct lxc_lock {
	short type; //!< Lock type

	union {
		sem_t *sem; //!< Anonymous semaphore (LXC_LOCK_ANON_SEM)
		/*! LXC_LOCK_FLOCK details */
		struct {
			int   fd; //!< fd on which a lock is held (if not -1)
			char *fname; //!< Name of lock
		} f;
	} u; //!< Container for lock type elements
};

/*!
 * \brief Create a new (unlocked) lock.
 *
 * \param lxcpath lxcpath lock should relate to.
 * \param name Name for lock.
 *
 * \return Newly-allocated lxclock on success, \c NULL on failure.

 * \note If \p name is not given, create an unnamed semaphore
 *  (used to protect against racing threads).
 *
 * \note Note that an unnamed sem was malloced by us and needs to be freed.
 *
 * \internal \ref sem is initialized to a value of \c 1.
 * A 'sem_t *' which can be passed to \ref lxclock() and \ref lxcunlock()
 * will be placed in \c l->u.sem.
 *
 * If \ref lxcpath and \ref name are given (both must be given if either is
 * given) then a lockfile is created as \c $lxcpath/$lxcname/locks/$name.
 * The lock is used to protect the containers on-disk representation.
 *
 * \internal This function allocates the pathname for the given lock in memory
 * such that it can be can quickly opened and locked by \ref lxclock().
 * \c l->u.f.fname will contain the malloc'ed name (which must be
 * freed when the container is freed), and \c u.f.fd = -1.
 *
 */
extern struct lxc_lock *lxc_newlock(const char *lxcpath, const char *name);

/*!
 * \brief Take an existing lock.
 *
 * \param lock Lock to operate on.
 * \param timeout Seconds to wait to take lock (\c 0 signifies an
 * indefinite wait).
 *
 * \return \c 0 if lock obtained, \c -2 on failure to set timeout,
 *  or \c -1 on any other error (\c errno will be set by \c sem_wait(3)).
 *
 * \note \p timeout is (currently?) only supported for privlock, not
 * for slock.  Since currently there is not a single use of the timeout
 * (except in the test case) I may remove the support for it in sem as
 * well.
 */
extern int lxclock(struct lxc_lock *lock, int timeout);

/*!
 * \brief Unlock specified lock previously locked using \ref lxclock().
 *
 * \param lock \ref lxc_lock.
 *
 * \return \c 0 on success, \c -2 if provided lock was not already held,
 * otherwise \c -1 with \c errno saved from \c flock(2) or sem_post function.
 */
extern int lxcunlock(struct lxc_lock *lock);

/*!
 * \brief Free a lock created by \ref lxc_newlock().
 *
 * \param lock Lock.
 */
extern void lxc_putlock(struct lxc_lock *lock);

/*!
 * \brief Lock the current process.
 */
extern void process_lock(void);

/*!
 * \brief Unlock the current process.
 */
extern void process_unlock(void);

struct lxc_container;

/*!
 * \brief Lock the containers memory.
 *
 * \param c Container.
 *
 * \return As for \ref lxclock().
 */
extern int container_mem_lock(struct lxc_container *c);

/*!
 * \brief Unlock the containers memory.
 *
 * \param c Container.
 */
extern void container_mem_unlock(struct lxc_container *c);

/*!
 * \brief Lock the containers disk data.
 *
 * \param c Container.
 *
 * \return \c 0 on success, or an \ref lxclock() error return
 * values on error.
 */
extern int container_disk_lock(struct lxc_container *c);

/*!
 * \brief Unlock the containers disk data.
 */
extern void container_disk_unlock(struct lxc_container *c);

#endif

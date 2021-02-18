/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_LXCLOCK_H
#define __LXC_LXCLOCK_H

#include <fcntl.h>
#include <semaphore.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "compiler.h"

#ifndef F_OFD_GETLK
#define F_OFD_GETLK	36
#endif

#ifndef F_OFD_SETLK
#define F_OFD_SETLK	37
#endif

#ifndef F_OFD_SETLKW
#define F_OFD_SETLKW	38
#endif

#define LXC_LOCK_ANON_SEM 1 /*!< Anonymous semaphore lock */
#define LXC_LOCK_FLOCK    2 /*!< flock(2) lock */

/* private */
/*!
 * LXC Lock
*/
struct lxc_lock {
	short type; /*!< Lock type */

	union {
		sem_t *sem; /*!< Anonymous semaphore (LXC_LOCK_ANON_SEM) */
		/*! LXC_LOCK_FLOCK details */
		struct {
			int   fd; /*!< fd on which a lock is held (if not -1) */
			char *fname; /*!< Name of lock */
		} f;
	} u; /*!< Container for lock type elements */
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
 * given) then a lockfile is created as \c /run/lxc/lock/$lxcpath/.$name if root,
 * or \c $XDG_RUNTIME_DIR/lxc/lock/$lxcpath/.$name if non-root.
 * The lock is used to protect the containers on-disk representation.
 *
 * \internal This function allocates the pathname for the given lock in memory
 * such that it can be can quickly opened and locked by \ref lxclock().
 * \c l->u.f.fname will contain the malloc'ed name (which must be
 * freed when the container is freed), and \c u.f.fd = -1.
 *
 */
__hidden extern struct lxc_lock *lxc_newlock(const char *lxcpath, const char *name);

/*!
 * \brief Take an existing lock.
 *
 * \param lock Lock to operate on.
 * \param timeout Seconds to wait to take lock (\c 0 signifies an
 * indefinite wait).
 *
 * \return \c 0 if lock obtained, \c -2 on failure to set timeout,
 *  or \c -1 on any other error (\c errno will be set by \c sem_wait(3)
 * or \c fcntl(2)).
 *
 * \note \p timeout is (currently?) only supported for privlock, not
 * for slock.  Since currently there is not a single use of the timeout
 * (except in the test case) I may remove the support for it in sem as
 * well.
 */
__hidden extern int lxclock(struct lxc_lock *lock, int timeout);

/*!
 * \brief Unlock specified lock previously locked using \ref lxclock().
 *
 * \param lock \ref lxc_lock.
 *
 * \return \c 0 on success, \c -2 if provided lock was not already held,
 * otherwise \c -1 with \c errno saved from \c fcntl(2) or sem_post function.
 */
__hidden extern int lxcunlock(struct lxc_lock *lock);

/*!
 * \brief Free a lock created by \ref lxc_newlock().
 *
 * \param lock Lock.
 */
__hidden extern void lxc_putlock(struct lxc_lock *lock);

/*!
 * \brief Lock the current process.
 */
__hidden extern void process_lock(void);

/*!
 * \brief Unlock the current process.
 */
__hidden extern void process_unlock(void);

struct lxc_container;

/*!
 * \brief Lock the containers memory.
 *
 * \param c Container.
 *
 * \return As for \ref lxclock().
 */
__hidden extern int container_mem_lock(struct lxc_container *c);

/*!
 * \brief Unlock the containers memory.
 *
 * \param c Container.
 */
__hidden extern void container_mem_unlock(struct lxc_container *c);

/*!
 * \brief Lock the containers disk data.
 *
 * \param c Container.
 *
 * \return \c 0 on success, or an \ref lxclock() error return
 * values on error.
 */
__hidden extern int container_disk_lock(struct lxc_container *c);

/*!
 * \brief Unlock the containers disk data.
 *
 * \param c Container.
 *
 */
__hidden extern void container_disk_unlock(struct lxc_container *c);

#endif

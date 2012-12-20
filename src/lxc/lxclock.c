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

#include "lxclock.h"
#include <malloc.h>
#include <stdio.h>

#define OFLAG (O_CREAT | O_RDWR)
#define SEMMODE 0660
#define SEMVALUE 1
#define SEMVALUE_LOCKED 0
#define LXCLOCK_PREFIX "/lxcapi."


static char *lxclock_name(const char *container)
{
	int ret;
	int len = strlen(container) + strlen(LXCLOCK_PREFIX) + 1;
	char *dest = malloc(len);
	if (!dest)
		return NULL;
	ret = snprintf(dest, len, "%s%s", LXCLOCK_PREFIX, container);
	if (ret < 0 || ret >= len) {
		free(dest);
		return NULL;
	}
	return dest;
}

static void lxcfree_name(char *name)
{
	if (name)
		free(name);
}

static sem_t *lxc_new_unnamed_sem(void)
{
    sem_t *s;
    int ret;

    s = malloc(sizeof(*s));
    if (!s)
        return NULL;
    ret = sem_init(s, 0, 1);
    if (ret)
        return NULL;
    return s;
}

sem_t *lxc_newlock(const char *name)
{
	char *lname;
	sem_t *lock;

	if (!name)
		return lxc_new_unnamed_sem();

	lname = lxclock_name(name);
	if (!lname)
		return NULL;
	lock = sem_open(lname, OFLAG, SEMMODE, SEMVALUE);
	lxcfree_name(lname);
    if (lock == SEM_FAILED)
        return NULL;
	return lock;
}

int lxclock(sem_t *sem, int timeout)
{
	int ret;

	if (!timeout) {
		ret = sem_wait(sem);
	} else {
		struct timespec ts;
		if (clock_gettime(CLOCK_REALTIME, &ts) == -1)
		       return -2;
		ts.tv_sec += timeout;
		ret = sem_timedwait(sem, &ts);
	}

	return ret;
}

int lxcunlock(sem_t *sem)
{
	if (!sem)
		return -2;
	return sem_post(sem);
}

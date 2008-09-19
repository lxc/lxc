/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2008
 *
 * Authors:
 * Daniel Lezcano <dlezcano at fr.ibm.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */
#define _GNU_SOURCE
#include <stdio.h>
#undef _GNU_SOURCE
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/file.h>
#include <netinet/in.h>
#include <net/if.h>

#include <lxc.h>


#if __i386__
#    define __NR_checkpoint 334
static inline long sys_checkpoint(pid_t pid, int fd, unsigned long flags)
{
	return syscall(__NR_checkpoint, pid, fd, flags);
}
#else
#    warning "Architecture not supported for checkpoint"
static inline long sys_checkpoint(pid_t pid, int fd, unsigned long flags)
{
	errno = ENOSYS;
	return -1;
}

#endif

int lxc_checkpoint(const char *name, int cfd, unsigned long flags)
{
	char init[MAXPATHLEN];
	char val[MAXPIDLEN];
	int fd, lock, ret = -1;
	size_t pid;

	lock = lxc_get_lock(name);
	if (lock > 0) {
		lxc_log_error("'%s' is not running", name);
		lxc_put_lock(lock);
		return -1;
	}

	if (lock < 0) {
		lxc_log_error("failed to acquire the lock on '%s':%s", 
			      name, strerror(-lock));
		return -1;
	}

	snprintf(init, MAXPATHLEN, LXCPATH "/%s/init", name);
	fd = open(init, O_RDONLY);
	if (fd < 0) {
		lxc_log_syserror("failed to open init file for %s", name);
		goto out_unlock;
	}
	
	if (read(fd, val, sizeof(val)) < 0) {
		lxc_log_syserror("failed to read %s", init);
		goto out_close;
	}

	pid = atoi(val);

	if (sys_checkpoint(pid, cfd, flags) < 0) {
		lxc_log_syserror("failed to checkpoint %zd", pid);
		goto out_close;
	}

	ret = 0;

out_close:
	close(fd);
out_unlock:
	lxc_put_lock(lock);
	return ret;
}

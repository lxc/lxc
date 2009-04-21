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

#include "error.h"
#include <lxc.h>
#include <lxc/log.h>

lxc_log_define(lxc_columbia, lxc);



#if __i386__
#    define __NR_checkpoint 333
#    define __NR_restart 334
static inline long sys_checkpoint(pid_t pid, int fd, unsigned long flags)
{
	return syscall(__NR_checkpoint, pid, fd, flags);
}
static inline long sys_restart(pid_t pid, int fd, unsigned long flags)
{
	return syscall(__NR_restart, pid, fd, flags);
}
#elif __x86_64__
#    define __NR_checkpoint 295
#    define __NR_restart 296
static inline long sys_checkpoint(pid_t pid, int fd, unsigned long flags)
{
        return syscall(__NR_checkpoint, pid, fd, flags);
}
static inline long sys_restart(pid_t pid, int fd, unsigned long flags)
{
        return syscall(__NR_restart, pid, fd, flags);
}
#else
#    warning "Architecture not supported for checkpoint"
static inline long sys_checkpoint(pid_t pid, int fd, unsigned long flags)
{
	errno = ENOSYS;
	return -1;
}
static inline long sys_restart(pid_t pid, int fd, unsigned long flags)
{
	errno = ENOSYS;
	return -1;
}
#    warning "Architecture not supported for restart syscall"

#endif


int lxc_plugin_checkpoint(pid_t pid, const char *statefile, unsigned long flags)
{
	int fd, ret;

	fd = open(statefile, O_RDWR);
	if (fd < 0) {
		SYSERROR("failed to open init file for %s", statefile);
		return -1;
	}
	
	ret = sys_checkpoint(pid, fd, flags);
	if (ret < 0) {
		SYSERROR("failed to checkpoint %d", pid);
		goto out_close;
	}

	ret = 0;

out_close:
	close(fd);
	return ret;
}

int lxc_plugin_restart(pid_t pid, const char *statefile, unsigned long flags)
{
	int fd;

	fd = open(statefile, O_RDONLY);
	if (fd < 0) {
		SYSERROR("failed to open init file for %s", statefile);
		return -1;
	}
	
	sys_restart(pid, fd, flags);
	SYSERROR("failed to restart %d", pid);
	close(fd);
	return -1;
}

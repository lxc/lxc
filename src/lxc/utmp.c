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

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/inotify.h>

#include "conf.h"
#include "cgroup.h"
#include "start.h"
#include "mainloop.h"
#include "lxc.h"
#include "log.h"
#define __USE_GNU
#include <utmpx.h>
#undef __USE_GNU

lxc_log_define(lxc_utmp, lxc);

static int utmp_handler(int fd, void *data, struct lxc_epoll_descr *descr)
{
	struct inotify_event ie;
	struct utmpx *utmpx;
	struct lxc_handler *handler = (struct lxc_handler *)data;
	struct lxc_conf *conf = handler->conf;
	char prevrun_level = 'N', currun_level = 'N';
	int ntasks, ret;
	char path[MAXPATHLEN];

	if (read(fd, &ie, sizeof(ie)) < 0) {
		SYSERROR("failed to read utmp notification");
		return -1;
	}

	if (snprintf(path, MAXPATHLEN, "%s/var/run/utmp", conf->rootfs) >
	    MAXPATHLEN) {
		ERROR("path is too long");
		return -1;
	}

	if (utmpxname(path)) {
		SYSERROR("failed to 'utmpxname'");
		return -1;
	}

	setutxent();

	while ((utmpx = getutxent())) {

		if (utmpx->ut_type == RUN_LVL) {
			prevrun_level = utmpx->ut_pid / 256;
			currun_level = utmpx->ut_pid % 256;
		}
	}

	ntasks = lxc_cgroup_nrtasks(handler->name);
	if (ntasks < 0) {
		ERROR("failed to get the number of tasks");
		goto out;
	}

	if (ntasks == 1 && prevrun_level == '3') {

		DEBUG("run level is %c/%c", prevrun_level, currun_level);
		DEBUG("there is %d tasks remaining", ntasks);

		if (currun_level == '0') {
			INFO("container has shutdown");
			kill(handler->pid, SIGKILL);
		}

		if (currun_level == '6') {
			INFO("container has rebooted");
			conf->reboot = 1;
			kill(handler->pid, SIGKILL);
		}
	}

	ret = 0;
out:
	endutxent();

	return ret;
}

int lxc_utmp_mainloop_add(struct lxc_epoll_descr *descr,
			  struct lxc_handler *handler)
{
	struct lxc_conf *conf = handler->conf;
	char path[MAXPATHLEN];
	int fd, wd;

	if (!conf->rootfs)
		return 0;

	if (snprintf(path, MAXPATHLEN, "%s/var/run/utmp", conf->rootfs) >
	    MAXPATHLEN) {
		ERROR("path is too long");
		return -1;
	}

	if (access(path, F_OK)) {
		WARN("'%s' not found", path);
		return 0;
	}

	fd = inotify_init();
	if (fd < 0) {
		SYSERROR("failed to inotify_init");
		return -1;
	}

	if (fcntl(fd, F_SETFD, FD_CLOEXEC)) {
		SYSERROR("failed to set inotify fd to close-on-exec");
		close(fd);
		return -1;
	}

	wd = inotify_add_watch(fd, path, IN_MODIFY);
	if (wd < 0) {
		SYSERROR("failed to add watch for '%s'", path);
		close(fd);
		return -1;
	}

	if (lxc_mainloop_add_handler(descr, fd, utmp_handler, handler)) {
		SYSERROR("failed to add mainloop");
		close(fd);
		return -1;
	}

	return 0;
}

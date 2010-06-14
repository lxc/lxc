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
#include <sys/ioctl.h>
#include <sys/timerfd.h>

#include "conf.h"
#include "cgroup.h"
#include "start.h"
#include "mainloop.h"
#include "lxc.h"
#include "log.h"
#define __USE_GNU
#include <utmpx.h>
#undef __USE_GNU

/* This file watches the /var/run/utmp file in the container
 * (that should probably be configurable)
 * We use inotify to put a watch on the /var/run directory for
 * create and modify events. These can trigger a read of the
 * utmp file looking for runlevel changes. If a runlevel change
 * to reboot or halt states is detected, we set up an itimer to
 * regularly check for the container shutdown, and reboot or halt
 * as appropriate when we get down to 1 task remaining.
 */

lxc_log_define(lxc_utmp, lxc);

struct lxc_utmp {
	struct lxc_handler *handler;
#define CONTAINER_STARTING  0
#define CONTAINER_REBOOTING 1
#define CONTAINER_HALTING   2
#define CONTAINER_RUNNING   4
	char container_state;
	int timer_fd;
	int prev_runlevel, curr_runlevel;
};

typedef void (*lxc_mainloop_timer_t) (void *data);

static int utmp_get_runlevel(struct lxc_utmp *utmp_data);
static int utmp_get_ntasks(struct lxc_handler *handler);
static int utmp_shutdown_handler(int fd, void *data,
				 struct lxc_epoll_descr *descr);
static int lxc_utmp_add_timer(struct lxc_epoll_descr *descr,
			      lxc_mainloop_callback_t callback, void *data);
static int lxc_utmp_del_timer(struct lxc_epoll_descr *descr,
			      struct lxc_utmp *utmp_data);

static int utmp_handler(int fd, void *data, struct lxc_epoll_descr *descr)
{
	struct inotify_event *ie;
	int size, ret, length;

	struct lxc_utmp *utmp_data = (struct lxc_utmp *)data;

	/* we're monitoring a directory. ie->name is not included in sizeof(struct inotify_event)
	 * if we don't read it all at once, read gives us EINVAL, so we read and cast to struct ie
	 */
	char buffer[MAXPATHLEN];

	if (ioctl(fd, FIONREAD, &size) < 0) {
		SYSERROR("cannot determine the size of this notification");
		return -1;
	}

	if (read(fd, buffer, size) < 0) {
		SYSERROR("failed to read notification");
		return -1;
	}

	ie = (struct inotify_event *)buffer;

	if (ie->len <= 0) {
		SYSERROR("inotify event with no name");
		return -1;
	}

	ret = 0;

	DEBUG("got inotify event %d for %s", ie->mask, ie->name);

	length = (4 < ie->len) ? 4 : ie->len;

	/* only care about utmp */

	if (strncmp(ie->name, "utmp", length))
		return 0;

	if (ie->mask & (IN_MODIFY | IN_CREATE))
		ret = utmp_get_runlevel(utmp_data);

	if (ret < 0)
		goto out;

	/* container halting, from running or starting state */
	if (utmp_data->curr_runlevel == '0'
	    && ((utmp_data->container_state == CONTAINER_RUNNING)
		|| (utmp_data->container_state == CONTAINER_STARTING))) {
		utmp_data->container_state = CONTAINER_HALTING;
		if (utmp_data->timer_fd == -1)
			lxc_utmp_add_timer(descr, utmp_shutdown_handler, data);
		DEBUG("Container halting");
		goto out;
	}

	/* container rebooting, from running or starting state */
	if (utmp_data->curr_runlevel == '6'
	    && ((utmp_data->container_state == CONTAINER_RUNNING)
		|| (utmp_data->container_state == CONTAINER_STARTING))) {
		utmp_data->container_state = CONTAINER_REBOOTING;
		if (utmp_data->timer_fd == -1)
			lxc_utmp_add_timer(descr, utmp_shutdown_handler, data);
		DEBUG("Container rebooting");
		goto out;
	}

	/* normal operation, running, from starting state. */
	if (utmp_data->curr_runlevel > '0' && utmp_data->curr_runlevel < '6') {
		utmp_data->container_state = CONTAINER_RUNNING;
		if (utmp_data->timer_fd > 0)
			lxc_utmp_del_timer(descr, utmp_data);
		DEBUG("Container running");
		goto out;
	}

out:
	return 0;
}

static int utmp_get_runlevel(struct lxc_utmp *utmp_data)
{
	struct utmpx *utmpx;
	char path[MAXPATHLEN];
	struct lxc_handler *handler = utmp_data->handler;
	struct lxc_conf *conf = handler->conf;

	if (snprintf(path, MAXPATHLEN, "%s/var/run/utmp", conf->rootfs.path) >
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
			utmp_data->prev_runlevel = utmpx->ut_pid / 256;
			utmp_data->curr_runlevel = utmpx->ut_pid % 256;
			DEBUG("utmp handler - run level is %c/%c",
			      utmp_data->prev_runlevel,
			      utmp_data->curr_runlevel);
		}
	}

	endutxent();

	return 0;
}

static int utmp_get_ntasks(struct lxc_handler *handler)
{
	int ntasks;

	ntasks = lxc_cgroup_nrtasks(handler->name);

	if (ntasks < 0) {
		ERROR("failed to get the number of tasks");
		return -1;
	}

	DEBUG("there are %d tasks running", ntasks);

	return ntasks;
}

int lxc_utmp_mainloop_add(struct lxc_epoll_descr *descr,
			  struct lxc_handler *handler)
{
	struct lxc_conf *conf = handler->conf;
	char path[MAXPATHLEN];
	int fd, wd;
	struct lxc_utmp *utmp_data;

	if (!conf->rootfs.path)
		return 0;

	/* We set up a watch for the /var/run directory. We're only interested in
	 * utmp at the moment, but want to watch for delete and create events as well.
	 */
	if (snprintf(path, MAXPATHLEN, "%s/var/run", conf->rootfs.path) >
	    MAXPATHLEN) {
		ERROR("path is too long");
		return -1;
	}

	if (access(path, F_OK)) {
		WARN("'%s' not found", path);
		return 0;
	}

	utmp_data = (struct lxc_utmp *)malloc(sizeof(struct lxc_utmp));

	if (NULL == utmp_data) {
		SYSERROR("failed to malloc handler utmp_data");
		return -1;
	}

	memset(utmp_data, 0, sizeof(struct lxc_utmp));

	fd = inotify_init();
	if (fd < 0) {
		SYSERROR("failed to inotify_init");
		goto out;
	}

	if (fcntl(fd, F_SETFD, FD_CLOEXEC)) {
		SYSERROR("failed to set inotify fd to close-on-exec");
		goto out_close;

	}

	wd = inotify_add_watch(fd, path, IN_MODIFY | IN_CREATE);
	if (wd < 0) {
		SYSERROR("failed to add watch for '%s'", path);
		goto out_close;
	}

	utmp_data->handler = handler;
	utmp_data->container_state = CONTAINER_STARTING;
	utmp_data->timer_fd = -1;
	utmp_data->prev_runlevel = 'N';
	utmp_data->curr_runlevel = 'N';

	if (lxc_mainloop_add_handler
	    (descr, fd, utmp_handler, (void *)utmp_data)) {
		SYSERROR("failed to add mainloop");
		goto out_close;
	}

	DEBUG("Added '%s' to inotifywatch", path);

	return 0;
out_close:
	close(fd);
out:
	free(utmp_data);
	return -1;
}

static int utmp_shutdown_handler(int fd, void *data,
				 struct lxc_epoll_descr *descr)
{
	int ntasks;
	struct lxc_utmp *utmp_data = (struct lxc_utmp *)data;
	struct lxc_handler *handler = utmp_data->handler;
	struct lxc_conf *conf = handler->conf;
	uint64_t expirations;

	/* read and clear notifications */
	read(fd, &expirations, sizeof(expirations));

	ntasks = utmp_get_ntasks(handler);

	if (ntasks == 1 && (utmp_data->container_state == CONTAINER_HALTING)) {
		INFO("container has shutdown");
		/* shutdown timer */
		lxc_utmp_del_timer(descr, utmp_data);

		kill(handler->pid, SIGKILL);
	}

	if (ntasks == 1 && (utmp_data->container_state == CONTAINER_REBOOTING)) {
		INFO("container has rebooted");
		conf->reboot = 1;
		/* shutdown timer */
		lxc_utmp_del_timer(descr, utmp_data);
		/* this seems a bit rough. */
		kill(handler->pid, SIGKILL);
	}
	return 0;

}

int lxc_utmp_add_timer(struct lxc_epoll_descr *descr,
		       lxc_mainloop_callback_t callback, void *data)
{
	int fd, result;
	struct itimerspec timeout;
	struct lxc_utmp *utmp_data = (struct lxc_utmp *)data;

	fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
	if (fd < 0) {
		SYSERROR("failed to create timer");
		return -1;
	}

	DEBUG("Setting up utmp shutdown timer");

	/* set a one second timeout. Repeated. */
	timeout.it_value.tv_sec = 1;
	timeout.it_value.tv_nsec = 0;

	timeout.it_interval.tv_sec = 1;
	timeout.it_interval.tv_nsec = 0;

	result = timerfd_settime(fd, 0, &timeout, NULL);

	if (result < 0) {
		SYSERROR("timerfd_settime:");
		return -1;
	}

	if (lxc_mainloop_add_handler(descr, fd, callback, utmp_data)) {
		SYSERROR("failed to add utmp timer to mainloop");
		close(fd);
		return -1;
	}

	utmp_data->timer_fd = fd;

	return 0;
}

int lxc_utmp_del_timer(struct lxc_epoll_descr *descr,
		       struct lxc_utmp *utmp_data)
{
	int result;

	DEBUG("Clearing utmp shutdown timer");

	result = lxc_mainloop_del_handler(descr, utmp_data->timer_fd);
	if (result < 0)
		SYSERROR("failed to del utmp timer from mainloop");

	/* shutdown timer_fd */
	close(utmp_data->timer_fd);
	utmp_data->timer_fd = -1;

	if (result < 0)
		return -1;
	else
		return 0;
}

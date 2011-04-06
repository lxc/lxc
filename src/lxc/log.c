/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2008
 *
 * Authors:
 * Cedric Le Goater <legoater@free.fr>
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
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>

#define __USE_GNU /* for *_CLOEXEC */

#include <fcntl.h>
#include <stdlib.h>

#include "log.h"
#include "caps.h"

#define LXC_LOG_PREFIX_SIZE	32
#define LXC_LOG_BUFFER_SIZE	512

int lxc_log_fd = -1;
static char log_prefix[LXC_LOG_PREFIX_SIZE] = "lxc";

lxc_log_define(lxc_log, lxc);

/*---------------------------------------------------------------------------*/
static int log_append_stderr(const struct lxc_log_appender *appender,
			     struct lxc_log_event *event)
{
	if (event->priority < LXC_LOG_PRIORITY_ERROR)
		return 0;

	fprintf(stderr, "%s: ", log_prefix);
	vfprintf(stderr, event->fmt, *event->vap);
	fprintf(stderr, "\n");
	return 0;
}

/*---------------------------------------------------------------------------*/
static int log_append_logfile(const struct lxc_log_appender *appender,
			      struct lxc_log_event *event)
{
	char buffer[LXC_LOG_BUFFER_SIZE];
	int n;

	if (lxc_log_fd == -1)
		return 0;

	n = snprintf(buffer, sizeof(buffer),
		     "%15s %10ld.%03ld %-8s %s - ",
		     log_prefix,
		     event->timestamp.tv_sec,
		     event->timestamp.tv_usec / 1000,
		     lxc_log_priority_to_string(event->priority),
		     event->category);

	n += vsnprintf(buffer + n, sizeof(buffer) - n, event->fmt,
		       *event->vap);

	if (n >= sizeof(buffer) - 1) {
		WARN("truncated next event from %d to %zd bytes", n,
		     sizeof(buffer));
		n = sizeof(buffer) - 1;
	}

	buffer[n] = '\n';

	return write(lxc_log_fd, buffer, n + 1);
}

static struct lxc_log_appender log_appender_stderr = {
	.name		= "stderr",
	.append		= log_append_stderr,
	.next		= NULL,
};

static struct lxc_log_appender log_appender_logfile = {
	.name		= "logfile",
	.append		= log_append_logfile,
	.next		= NULL,
};

static struct lxc_log_category log_root = {
	.name		= "root",
	.priority	= LXC_LOG_PRIORITY_ERROR,
	.appender	= NULL,
	.parent		= NULL,
};

struct lxc_log_category lxc_log_category_lxc = {
	.name		= "lxc",
	.priority	= LXC_LOG_PRIORITY_ERROR,
	.appender	= &log_appender_stderr,
	.parent		= &log_root
};

/*---------------------------------------------------------------------------*/
extern void lxc_log_setprefix(const char *prefix)
{
	strncpy(log_prefix, prefix, sizeof(log_prefix));
	log_prefix[sizeof(log_prefix) - 1] = 0;
}

/*---------------------------------------------------------------------------*/
static int log_open(const char *name)
{
	int fd;
	int newfd;

	fd = lxc_unpriv(open(name, O_CREAT | O_WRONLY |
			     O_APPEND | O_CLOEXEC, 0666));
	if (fd == -1) {
		ERROR("failed to open log file \"%s\" : %s", name,
		      strerror(errno));
		return -1;
	}

	if (fd > 2)
		return fd;

	newfd = fcntl(fd, F_DUPFD_CLOEXEC, 3);
	if (newfd == -1)
		ERROR("failed to dup log fd %d : %s", fd, strerror(errno));

	close(fd);
	return newfd;
}

/*---------------------------------------------------------------------------*/
extern int lxc_log_init(const char *file, const char *priority,
			const char *prefix, int quiet)
{
	int lxc_priority = LXC_LOG_PRIORITY_ERROR;

	if (priority) {
		lxc_priority = lxc_log_priority_to_int(priority);

		if (lxc_priority == LXC_LOG_PRIORITY_NOTSET) {
			ERROR("invalid log priority %s", priority);
			return -1;
		}
	}

	lxc_log_category_lxc.priority = lxc_priority;
	lxc_log_category_lxc.appender = &log_appender_logfile;

	if (!quiet)
		lxc_log_category_lxc.appender->next = &log_appender_stderr;

	if (prefix)
		lxc_log_setprefix(prefix);

	if (file) {
		int fd;

		fd = log_open(file);
		if (fd == -1) {
			ERROR("failed to initialize log service");
			return -1;
		}

		lxc_log_fd = fd;
	}

	return 0;
}

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
static int lxc_loglevel_specified = 0;
// if logfile was specifed on command line, it won't be overridden by lxc.logfile
static int lxc_log_specified = 0;

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

static int build_dir(const char *name)
{
	char *n = strdup(name);  // because we'll be modifying it
	char *p, *e;
	int ret;

	if (!n) {
		ERROR("Out of memory while creating directory '%s'.", name);
		return -1;
	}

	e = &n[strlen(n)];
	for (p = n+1; p < e; p++) {
		if (*p != '/')
			continue;
		*p = '\0';
		if (access(n, F_OK)) {
			ret = lxc_unpriv(mkdir(n, 0755));
			if (ret && errno != -EEXIST) {
				SYSERROR("failed to create directory '%s'.", n);
				free(n);
				return -1;
			}
		}
		*p = '/';
	}
	free(n);
	return 0;
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

static char *build_log_path(const char *name)
{
	char *p;
	int len, ret;

	/*
	 * '$logpath' + '/' + '$name' + '.log' + '\0'
	 * or
	 * '$logpath' + '/' + '$name' + '/' + '$name' + '.log' + '\0'
	 * sizeof(LOGPATH) includes its \0
	 */
	len = sizeof(LOGPATH) + strlen(name) + 6;
#if USE_CONFIGPATH_LOGS
	len += strlen(name) + 1;  /* add "/$container_name/" */
#endif
	p = malloc(len);
	if (!p)
		return p;
#if USE_CONFIGPATH_LOGS
	ret = snprintf(p, len, "%s/%s/%s.log", LOGPATH, name, name);
#else
	ret = snprintf(p, len, "%s/%s.log", LOGPATH, name);
#endif
	if (ret < 0 || ret >= len) {
		free(p);
		return NULL;
	}
	return p;
}

int do_lxc_log_set_file(const char *fname, int from_default);

/*---------------------------------------------------------------------------*/
extern int lxc_log_init(const char *name, const char *file,
			const char *priority, const char *prefix, int quiet)
{
	int lxc_priority = LXC_LOG_PRIORITY_ERROR;
	int ret;
	char *tmpfile = NULL;
	int want_lxc_log_specified = 0;

	if (lxc_log_fd != -1)
		return 0;

	if (priority) {
		lxc_loglevel_specified = 1;
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

	if (file && strcmp(file, "none") == 0) {
		want_lxc_log_specified = 1;
		return 0;
	}

	if (!file) {
		tmpfile = build_log_path(name);
		if (!tmpfile) {
			ERROR("could not build log path");
			return -1;
		}
	} else {
		want_lxc_log_specified = 1;
	}

	ret = do_lxc_log_set_file(tmpfile ? tmpfile : file, !want_lxc_log_specified);

	if (want_lxc_log_specified)
		lxc_log_specified = 1;
	/*
	 * If !want_lxc_log_specified, that is, if the user did not request
	 * this logpath, then ignore failures and continue logging to console
	 */
	if (!want_lxc_log_specified && ret != 0) {
		INFO("Ignoring failure to open default logfile.");
		ret = 0;
	}

	if (tmpfile)
		free(tmpfile);

	return ret;
}

/*
 * This is called when we read a lxc.loglevel entry in a lxc.conf file.  This
 * happens after processing command line arguments, which override the .conf
 * settings.  So only set the level if previously unset.
 */
extern int lxc_log_set_level(int level)
{
	if (lxc_loglevel_specified)
		return 0;
	if (level < 0 || level >= LXC_LOG_PRIORITY_NOTSET) {
		ERROR("invalid log priority %d", level);
		return -1;
	}
	lxc_log_category_lxc.priority = level;
	return 0;
}

char *log_fname;  // default to NULL, set in lxc_log_set_file.
/*
 * This can be called:
 *   1. when a program calls lxc_log_init with no logfile parameter (in which
 *      case the default is used).  In this case lxc.logfile can override this.
 *   2. when a program calls lxc_log_init with a logfile parameter.  In this
 *	case we don't want lxc.logfile to override this.
 *   3. When a lxc.logfile entry is found in config file.
 */
int do_lxc_log_set_file(const char *fname, int from_default)
{
	if (lxc_log_specified) {
		INFO("lxc.logfile overriden by command line");
		return 0;
	}
	if (lxc_log_fd != -1) {
		// we are overriding the default.
		close(lxc_log_fd);
		free(log_fname);
	}

#if USE_CONFIGPATH_LOGS
	// we don't build_dir for the default if the default is
	// i.e. /var/lib/lxc/$container/$container.log
	if (!from_default)
#endif
	if (build_dir(fname)) {
		ERROR("failed to create dir for log file \"%s\" : %s", fname,
		      strerror(errno));
		return -1;
	}

	lxc_log_fd = log_open(fname);
	if (lxc_log_fd == -1)
		return -1;

	log_fname = strdup(fname);
	return 0;
}

extern int lxc_log_set_file(const char *fname)
{
	return do_lxc_log_set_file(fname, 0);
}

extern int lxc_log_get_level(void)
{
	if (!lxc_loglevel_specified)
		return LXC_LOG_PRIORITY_NOTSET;
	return lxc_log_category_lxc.priority;
}

extern const char *lxc_log_get_file(void)
{
	return log_fname;
}

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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
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
#include "utils.h"

#define LXC_LOG_PREFIX_SIZE	32
#define LXC_LOG_BUFFER_SIZE	512

int lxc_log_fd = -1;
static char log_prefix[LXC_LOG_PREFIX_SIZE] = "lxc";
static char *log_fname = NULL;
/* command line values for logfile or logpriority should always override
 * values from the configuration file or defaults
 */
static int lxc_logfile_specified = 0;
static int lxc_loglevel_specified = 0;

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
	int ms;

	if (lxc_log_fd == -1)
		return 0;

	ms = event->timestamp.tv_usec / 1000;
	n = snprintf(buffer, sizeof(buffer),
		     "%15s %10ld.%03d %-8s %s - ",
		     log_prefix,
		     event->timestamp.tv_sec,
		     ms,
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

/*
 * Build the path to the log file
 * @name     : the name of the container
 * @lxcpath  : the lxcpath to use as a basename or NULL to use LOGPATH
 * Returns malloced path on sucess, or NULL on failure
 */
static char *build_log_path(const char *name, const char *lxcpath)
{
	char *p;
	int len, ret, use_dir;

#if USE_CONFIGPATH_LOGS
	use_dir = 1;
#else
	use_dir = 0;
#endif

	/*
	 * If USE_CONFIGPATH_LOGS is true or lxcpath is given, the resulting
	 * path will be:
	 * '$logpath' + '/' + '$name' + '/' + '$name' + '.log' + '\0'
	 *
	 * If USE_CONFIGPATH_LOGS is false the resulting path will be:
	 * '$logpath' + '/' + '$name' + '.log' + '\0'
	 */
	len = strlen(name) + 6; /* 6 == '/' + '.log' + '\0' */
	if (lxcpath)
		use_dir = 1;
	else
		lxcpath = LOGPATH;

	if (use_dir)
		len += strlen(lxcpath) + 1 + strlen(name) + 1;  /* add "/$container_name/" */
	else
		len += strlen(lxcpath) + 1;
	p = malloc(len);
	if (!p)
		return p;

	if (use_dir)
		ret = snprintf(p, len, "%s/%s/%s.log", lxcpath, name, name);
	else
		ret = snprintf(p, len, "%s/%s.log", lxcpath, name);

	if (ret < 0 || ret >= len) {
		free(p);
		return NULL;
	}
	return p;
}

/*
 * This can be called:
 *   1. when a program calls lxc_log_init with no logfile parameter (in which
 *      case the default is used).  In this case lxc.logfile can override this.
 *   2. when a program calls lxc_log_init with a logfile parameter.  In this
 *	case we don't want lxc.logfile to override this.
 *   3. When a lxc.logfile entry is found in config file.
 */
static int __lxc_log_set_file(const char *fname, int create_dirs)
{
	if (lxc_log_fd != -1) {
		// we are overriding the default.
		close(lxc_log_fd);
		free(log_fname);
	}

#if USE_CONFIGPATH_LOGS
	// we don't build_dir for the default if the default is
	// i.e. /var/lib/lxc/$container/$container.log
	if (create_dirs)
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

static int _lxc_log_set_file(const char *name, const char *lxcpath, int create_dirs)
{
	char *logfile;
	int ret;

	logfile = build_log_path(name, lxcpath);
	if (!logfile) {
		ERROR("could not build log path");
		return -1;
	}
	ret = __lxc_log_set_file(logfile, create_dirs);
	free(logfile);
	return ret;
}

extern int lxc_log_init(const char *name, const char *file,
			const char *priority, const char *prefix, int quiet,
			const char *lxcpath)
{
	int lxc_priority = LXC_LOG_PRIORITY_ERROR;
	int ret;

	if (lxc_log_fd != -1) {
		WARN("lxc_log_init called with log already initialized");
		return 0;
	}

	if (priority) {
		if (lxc_priority == LXC_LOG_PRIORITY_NOTSET) {
			ERROR("invalid log priority %s", priority);
			return -1;
		}

		lxc_loglevel_specified = 1;
		lxc_priority = lxc_log_priority_to_int(priority);
	}

	lxc_log_category_lxc.priority = lxc_priority;
	lxc_log_category_lxc.appender = &log_appender_logfile;

	if (!quiet)
		lxc_log_category_lxc.appender->next = &log_appender_stderr;

	if (prefix)
		lxc_log_set_prefix(prefix);

	if (file) {
		if (strcmp(file, "none") == 0)
			return 0;
		lxc_logfile_specified = 1;
		ret = __lxc_log_set_file(file, 1);
	} else {
		ret = -1;

		if (!lxcpath)
			lxcpath = LOGPATH;

		/* try LOGPATH if lxcpath is the default */
		if (strcmp(lxcpath, default_lxc_path()) == 0)
			ret = _lxc_log_set_file(name, NULL, 0);

		/* try in lxcpath */
		if (ret < 0)
			ret = _lxc_log_set_file(name, lxcpath, 1);

		/* try LOGPATH in case its writable by the caller */
		if (ret < 0)
			ret = _lxc_log_set_file(name, NULL, 0);
	}

	/*
	 * If !file, that is, if the user did not request this logpath, then
	 * ignore failures and continue logging to console
	 */
	if (!file && ret != 0) {
		INFO("Ignoring failure to open default logfile.");
		ret = 0;
	}

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
	lxc_loglevel_specified = 1;
	lxc_log_category_lxc.priority = level;
	return 0;
}

extern int lxc_log_get_level(void)
{
	if (!lxc_loglevel_specified)
		return LXC_LOG_PRIORITY_NOTSET;
	return lxc_log_category_lxc.priority;
}

extern bool lxc_log_has_valid_level(void)
{
	int log_level = lxc_log_get_level();
	if (log_level < 0 || log_level >= LXC_LOG_PRIORITY_NOTSET)
		return false;
	return true;
}

/*
 * This is called when we read a lxc.logfile entry in a lxc.conf file.  This
 * happens after processing command line arguments, which override the .conf
 * settings.  So only set the file if previously unset.
 */
extern int lxc_log_set_file(const char *fname)
{
	if (lxc_logfile_specified)
		return 0;
	lxc_logfile_specified = 1;
	return __lxc_log_set_file(fname, 0);
}

extern const char *lxc_log_get_file(void)
{
	return log_fname;
}

extern void lxc_log_set_prefix(const char *prefix)
{
	strncpy(log_prefix, prefix, sizeof(log_prefix));
	log_prefix[sizeof(log_prefix) - 1] = 0;
}

extern const char *lxc_log_get_prefix(void)
{
	return log_prefix;
}

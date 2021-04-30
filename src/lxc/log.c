/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#define __STDC_FORMAT_MACROS /* Required for PRIu64 to work. */
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#include "caps.h"
#include "config.h"
#include "file_utils.h"
#include "log.h"
#include "lxccontainer.h"
#include "memory_utils.h"
#include "utils.h"

#ifndef HAVE_STRLCPY
#include "include/strlcpy.h"
#endif

#if HAVE_DLOG
#include <dlog.h>

#undef LOG_TAG
#define LOG_TAG "LXC"
#endif

/* We're logging in seconds and nanoseconds. Assuming that the underlying
 * datatype is currently at maximum a 64bit integer, we have a date string that
 * is of maximum length (2^64 - 1) * 2 = (21 + 21) = 42.
 */
#define LXC_LOG_TIME_SIZE ((INTTYPE_TO_STRLEN(uint64_t)) * 2)

int lxc_log_fd = -EBADF;
static bool wants_syslog = false;
static int lxc_quiet_specified;
bool lxc_log_use_global_fd = false;
static int lxc_loglevel_specified;

static char log_prefix[LXC_LOG_PREFIX_SIZE] = "lxc";
static char *log_fname = NULL;
static char *log_vmname = NULL;

lxc_log_define(log, lxc);

static int lxc_log_priority_to_syslog(int priority)
{
	switch (priority) {
	case LXC_LOG_LEVEL_FATAL:
		return LOG_EMERG;
	case LXC_LOG_LEVEL_ALERT:
		return LOG_ALERT;
	case LXC_LOG_LEVEL_CRIT:
		return LOG_CRIT;
	case LXC_LOG_LEVEL_ERROR:
		return LOG_ERR;
	case LXC_LOG_LEVEL_WARN:
		return LOG_WARNING;
	case LXC_LOG_LEVEL_NOTICE:
	case LXC_LOG_LEVEL_NOTSET:
		return LOG_NOTICE;
	case LXC_LOG_LEVEL_INFO:
		return LOG_INFO;
	case LXC_LOG_LEVEL_TRACE:
	case LXC_LOG_LEVEL_DEBUG:
		return LOG_DEBUG;
	}

	/* Not reached */
	return LOG_NOTICE;
}

static const char *lxc_log_get_container_name(void)
{
#ifndef NO_LXC_CONF
	if (current_config && !log_vmname)
		return current_config->name;
#endif

	return log_vmname;
}

int lxc_log_get_fd(void)
{
	int fd_log = -EBADF;

#ifndef NO_LXC_CONF
	if (current_config && !lxc_log_use_global_fd)
		fd_log = current_config->logfd;
#endif
	if (fd_log < 0)
		fd_log = lxc_log_fd;

	return fd_log;
}

static char *lxc_log_get_va_msg(struct lxc_log_event *event)
{
	__do_free char *msg = NULL;
	int rc, len;
	va_list args;

	if (!event)
		return ret_set_errno(NULL, EINVAL);

	va_copy(args, *event->vap);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
	len = vsnprintf(NULL, 0, event->fmt, args) + 1;
#pragma GCC diagnostic pop
	va_end(args);

	msg = malloc(len * sizeof(char));
	if (!msg)
		return ret_set_errno(NULL, ENOMEM);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
	rc = vsnprintf(msg, len, event->fmt, *event->vap);
#pragma GCC diagnostic pop
	if (rc < 0 || rc >= len)
		return ret_set_errno(NULL, EIO);

	return move_ptr(msg);
}

static int log_append_syslog(const struct lxc_log_appender *appender,
			     struct lxc_log_event *event)
{
	__do_free char *msg = NULL;
	const char *log_container_name;

	if (!wants_syslog)
		return 0;

	log_container_name = lxc_log_get_container_name();

	msg = lxc_log_get_va_msg(event);
	if (!msg)
		return 0;

	syslog(lxc_log_priority_to_syslog(event->priority),
	       "%s%s %s - %s:%s:%d - %s" ,
	       log_container_name ? log_container_name : "",
	       log_container_name ? ":" : "",
	       event->category,
	       event->locinfo->file, event->locinfo->func,
	       event->locinfo->line,
	       msg);

	return 0;
}

static int log_append_stderr(const struct lxc_log_appender *appender,
			     struct lxc_log_event *event)
{
	const char *log_container_name;

	if (event->priority < LXC_LOG_LEVEL_ERROR)
		return 0;

	log_container_name = lxc_log_get_container_name();

	fprintf(stderr, "%s: %s%s", log_prefix,
	        log_container_name ? log_container_name : "",
	        log_container_name ? ": " : "");
	fprintf(stderr, "%s: %s: %d ", event->locinfo->file,
	        event->locinfo->func, event->locinfo->line);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
	vfprintf(stderr, event->fmt, *event->vap);
#pragma GCC diagnostic pop
	fprintf(stderr, "\n");

	return 0;
}

static int lxc_unix_epoch_to_utc(char *buf, size_t bufsize, const struct timespec *time)
{
	int64_t epoch_to_days, z, era, doe, yoe, year, doy, mp, day, month,
	    d_in_s, hours, h_in_s, minutes, seconds;
	char nanosec[INTTYPE_TO_STRLEN(int64_t)];
	int ret;

	/*
	 * See https://howardhinnant.github.io/date_algorithms.html for an
	 * explanation of the algorithm used here.
	 */

	/* Convert Epoch in seconds to number of days. */
	epoch_to_days = time->tv_sec / 86400;

	/* Shift the Epoch from 1970-01-01 to 0000-03-01. */
	z = epoch_to_days + 719468;

	/*
	 * Compute the era from the serial date by simply dividing by the number
	 * of days in an era (146097).
	 */
	era = (z >= 0 ? z : z - 146096) / 146097;

	/*
	 * The day-of-era (doe) can then be found by subtracting the era number
	 * times the number of days per era, from the serial date.
	 */
	doe = (z - era * 146097);

	/*
	 * From the day-of-era (doe), the year-of-era (yoe, range [0, 399]) can
	 * be computed.
	 */
	yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;

	/* Given year-of-era, and era, one can now compute the year. */
	year = yoe + era * 400;

	/*
	 * Also the day-of-year, again with the year beginning on Mar. 1, can be
	 * computed from the day-of-era and year-of-era.
	 */
	doy = doe - (365 * yoe + yoe / 4 - yoe / 100);

	/* Given day-of-year, find the month number. */
	mp = (5 * doy + 2) / 153;

	/*
	 * From day-of-year and month-of-year we can now easily compute
	 * day-of-month.
	 */
	day = doy - (153 * mp + 2) / 5 + 1;

	/*
	 * Transform the month number from the [0, 11] / [Mar, Feb] system to
	 * the civil system: [1, 12] to find the correct month.
	 */
	month = mp + (mp < 10 ? 3 : -9);

	/*
	 * The algorithm assumes that a year begins on 1 March, so add 1 before
	 * that.
	 */
	if (month < 3)
		year++;

	/* Transform days in the epoch to seconds. */
	d_in_s = epoch_to_days * 86400;

	/*
	 * To find the current hour simply substract the Epoch_to_days from the
	 * total Epoch and divide by the number of seconds in an hour.
	 */
	hours = (time->tv_sec - d_in_s) / 3600;

	/* Transform hours to seconds. */
	h_in_s = hours * 3600;

	/*
	 * Calculate minutes by subtracting the seconds for all days in the
	 * epoch and for all hours in the epoch and divide by the number of
	 * minutes in an hour.
	 */
	minutes = (time->tv_sec - d_in_s - h_in_s) / 60;

	/*
	 * Calculate the seconds by subtracting the seconds for all days in the
	 * epoch, hours in the epoch and minutes in the epoch.
	 */
	seconds = (time->tv_sec - d_in_s - h_in_s - (minutes * 60));

	/* Make string from nanoseconds. */
	ret = strnprintf(nanosec, sizeof(nanosec), "%"PRId64, (int64_t)time->tv_nsec);
	if (ret < 0)
		return ret_errno(EIO);

	/*
	 * Create final timestamp for the log and shorten nanoseconds to 3
	 * digit precision.
	 */
	ret = strnprintf(buf, bufsize,
		       "%" PRId64 "%02" PRId64 "%02" PRId64 "%02" PRId64
		       "%02" PRId64 "%02" PRId64 ".%.3s",
		       year, month, day, hours, minutes, seconds, nanosec);
	if (ret < 0)
		return ret_errno(EIO);

	return 0;
}

/*
 * This function needs to make extra sure that it is thread-safe. We had some
 * problems with that before. This especially involves time-conversion
 * functions. I don't want to find any localtime() or gmtime() functions or
 * relatives in here. Not even localtime_r() or gmtime_r() or relatives. They
 * all fiddle with global variables and locking in various libcs. They cause
 * deadlocks when liblxc is used multi-threaded and no matter how smart you
 * think you are, you __will__ cause trouble using them.
 * (As a short example how this can cause trouble: LXD uses forkstart to fork
 * off a new process that runs the container. At the same time the go runtime
 * LXD relies on does its own multi-threading thing which we can't control. The
 * fork()ing + threading then seems to mess with the locking states in these
 * time functions causing deadlocks.)
 * The current solution is to be good old unix people and use the Epoch as our
 * reference point and simply use the seconds and nanoseconds that have past
 * since then. This relies on clock_gettime() which is explicitly marked MT-Safe
 * with no restrictions! This way, anyone who is really strongly invested in
 * getting the actual time the log entry was created, can just convert it for
 * themselves. Our logging is mostly done for debugging purposes so don't try
 * to make it pretty. Pretty might cost you thread-safety.
 */
static int log_append_logfile(const struct lxc_log_appender *appender,
			      struct lxc_log_event *event)
{
	int fd_to_use = -EBADF;
	char buffer[LXC_LOG_BUFFER_SIZE];
	char date_time[LXC_LOG_TIME_SIZE];
	int n;
	ssize_t ret;
	const char *log_container_name;

#ifndef NO_LXC_CONF
	if (current_config && !lxc_log_use_global_fd)
		fd_to_use = current_config->logfd;
#endif

	log_container_name = lxc_log_get_container_name();

	if (fd_to_use < 0)
		fd_to_use = lxc_log_fd;

	if (fd_to_use < 0)
		return 0;

	ret = lxc_unix_epoch_to_utc(date_time, LXC_LOG_TIME_SIZE, &event->timestamp);
	if (ret)
		return ret;

	/*
	 * We allow truncation here which is why we use snprintf() directly
	 * instead of strnprintf().
	 */
	n = snprintf(buffer, sizeof(buffer),
		     "%s%s%s %s %-8s %s - %s:%s:%d - ",
		     log_prefix,
		     log_container_name ? " " : "",
		     log_container_name ? log_container_name : "",
		     date_time,
		     lxc_log_priority_to_string(event->priority),
		     event->category,
		     event->locinfo->file, event->locinfo->func,
		     event->locinfo->line);
	if (n < 0)
		return ret_errno(EIO);

	if ((size_t)n < STRARRAYLEN(buffer)) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
		ret = vsnprintf(buffer + n, sizeof(buffer) - n, event->fmt, *event->vap);
#pragma GCC diagnostic pop
		if (ret < 0)
			return 0;

		n += ret;
	}

	if ((size_t)n >= sizeof(buffer))
		n = STRARRAYLEN(buffer);

	buffer[n] = '\n';

	return lxc_write_nointr(fd_to_use, buffer, n + 1);
}

#if HAVE_DLOG
static int log_append_dlog(const struct lxc_log_appender *appender,
			     struct lxc_log_event *event)
{
	__do_free char *msg = NULL;
	const char *log_container_name;

	log_container_name = lxc_log_get_container_name();
	msg = lxc_log_get_va_msg(event);

	switch (event->priority) {
	case LXC_LOG_LEVEL_TRACE:
	case LXC_LOG_LEVEL_DEBUG:
		print_log(DLOG_DEBUG, LOG_TAG, "%s: %s(%d) > [%s] %s",
		          event->locinfo->file, event->locinfo->func, event->locinfo->line,
		          log_container_name ? log_container_name : "-",
		          msg ? msg : "-");
		break;
	case LXC_LOG_LEVEL_INFO:
		print_log(DLOG_INFO, LOG_TAG, "%s: %s(%d) > [%s] %s",
		          event->locinfo->file, event->locinfo->func, event->locinfo->line,
		          log_container_name ? log_container_name : "-",
		          msg ? msg : "-");
		break;
	case LXC_LOG_LEVEL_NOTICE:
	case LXC_LOG_LEVEL_WARN:
		print_log(DLOG_WARN, LOG_TAG, "%s: %s(%d) > [%s] %s",
		          event->locinfo->file, event->locinfo->func, event->locinfo->line,
		          log_container_name ? log_container_name : "-",
		          msg ? msg : "-");
		break;
	case LXC_LOG_LEVEL_ERROR:
		print_log(DLOG_ERROR, LOG_TAG, "%s: %s(%d) > [%s] %s",
		          event->locinfo->file, event->locinfo->func, event->locinfo->line,
		          log_container_name ? log_container_name : "-",
		          msg ? msg : "-");
		break;
	case LXC_LOG_LEVEL_CRIT:
	case LXC_LOG_LEVEL_ALERT:
	case LXC_LOG_LEVEL_FATAL:
		print_log(DLOG_FATAL, LOG_TAG, "%s: %s(%d) > [%s] %s",
		          event->locinfo->file, event->locinfo->func, event->locinfo->line,
		          log_container_name ? log_container_name : "-",
		          msg ? msg : "-");
		break;
	default:
		break;
	}

	return 0;
}
#endif

static struct lxc_log_appender log_appender_syslog = {
	.name		= "syslog",
	.append		= log_append_syslog,
	.next		= NULL,
};

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

#if HAVE_DLOG
static struct lxc_log_appender log_appender_dlog = {
	.name		= "dlog",
	.append		= log_append_dlog,
	.next		= NULL,
};
#endif

static struct lxc_log_category log_root = {
	.name		= "root",
	.priority	= LXC_LOG_LEVEL_ERROR,
	.appender	= NULL,
	.parent		= NULL,
};

#if HAVE_DLOG
struct lxc_log_category lxc_log_category_lxc = {
	.name		= "lxc",
	.priority	= LXC_LOG_LEVEL_TRACE,
	.appender	= &log_appender_dlog,
	.parent		= &log_root
};
#else
struct lxc_log_category lxc_log_category_lxc = {
	.name		= "lxc",
	.priority	= LXC_LOG_LEVEL_ERROR,
	.appender	= &log_appender_logfile,
	.parent		= &log_root
};
#endif

static int build_dir(const char *name)
{
	__do_free char *n = NULL;
	char *e, *p;

	if (is_empty_string(name))
		return ret_errno(EINVAL);

	/* Make copy of the string since we'll be modifying it. */
	n = strdup(name);
	if (!n)
		return ret_errno(ENOMEM);

	e = &n[strlen(n)];
	for (p = n + 1; p < e; p++) {
		int ret;

		if (*p != '/')
			continue;
		*p = '\0';

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
		ret = lxc_unpriv(mkdir(n, 0755));
#else
		if (RUN_ON_OSS_FUZZ || is_in_comm("fuzz-lxc-") > 0)
			ret = errno = EEXIST;
		else
			ret = lxc_unpriv(mkdir(n, 0755));
#endif /*!FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */
		*p = '/';
		if (ret && errno != EEXIST)
			return log_error_errno(-errno, errno, "Failed to create directory \"%s\"", n);
	}

	return 0;
}

static int log_open(const char *name)
{
	int newfd = -EBADF;
	__do_close int fd = -EBADF;

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
	fd = lxc_unpriv(open(name, O_CREAT | O_WRONLY | O_APPEND | O_CLOEXEC, 0660));
#else
	if (!RUN_ON_OSS_FUZZ && is_in_comm("fuzz-lxc-") <= 0)
		fd = lxc_unpriv(open(name, O_CREAT | O_WRONLY | O_APPEND | O_CLOEXEC, 0660));
#endif /* !FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */
	if (fd < 0)
		return log_error_errno(-errno, errno, "Failed to open log file \"%s\"", name);

	if (fd > 2)
		return move_fd(fd);

	newfd = fcntl(fd, F_DUPFD_CLOEXEC, STDERR_FILENO);
	if (newfd < 0)
		return log_error_errno(-errno, errno, "Failed to dup log fd %d", fd);
	return newfd;
}

/*
 * Build the path to the log file
 * @name     : the name of the container
 * @lxcpath  : the lxcpath to use as a basename or NULL to use LOGPATH
 * Returns malloced path on success, or NULL on failure
 */
static char *build_log_path(const char *name, const char *lxcpath)
{
	__do_free char *p = NULL;
	int ret;
	size_t len;
	bool use_dir;

	if (!name)
		return ret_set_errno(NULL, EINVAL);

#if USE_CONFIGPATH_LOGS
	use_dir = true;
#else
	use_dir = false;
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
		use_dir = true;
	else
		lxcpath = LOGPATH;

	if (use_dir)
		len += strlen(lxcpath) + 1 + strlen(name) + 1;  /* add "/$container_name/" */
	else
		len += strlen(lxcpath) + 1;

	p = malloc(len);
	if (!p)
		return ret_set_errno(NULL, ENOMEM);

	if (use_dir)
		ret = strnprintf(p, len, "%s/%s/%s.log", lxcpath, name, name);
	else
		ret = strnprintf(p, len, "%s/%s.log", lxcpath, name);
	if (ret < 0)
		return ret_set_errno(NULL, EIO);

	return move_ptr(p);
}

/*
 * This can be called:
 *   1. when a program calls lxc_log_init with no logfile parameter (in which
 *      case the default is used).  In this case lxc.loge can override this.
 *   2. when a program calls lxc_log_init with a logfile parameter.  In this
 *	case we don't want lxc.log to override this.
 *   3. When a lxc.log entry is found in config file.
 */
static int __lxc_log_set_file(const char *fname, int create_dirs)
{
	/* we are overriding the default. */
	if (lxc_log_fd >= 0)
		lxc_log_close();

	if (is_empty_string(fname))
		return ret_errno(EINVAL);

	if (strlen(fname) == 0) {
		log_fname = NULL;
		return ret_errno(EINVAL);
	}

#if USE_CONFIGPATH_LOGS
	/* We don't build_dir for the default if the default is i.e.
	 * /var/lib/lxc/$container/$container.log.
	 */
	if (create_dirs)
#endif
	if (build_dir(fname))
		return log_error_errno(-errno, errno, "Failed to create dir for log file \"%s\"", fname);

	lxc_log_fd = log_open(fname);
	if (lxc_log_fd < 0)
		return lxc_log_fd;

	log_fname = strdup(fname);
	return 0;
}

static int _lxc_log_set_file(const char *name, const char *lxcpath, int create_dirs)
{
	__do_free char *logfile = NULL;

	logfile = build_log_path(name, lxcpath);
	if (!logfile)
		return log_error_errno(-errno, errno, "Could not build log path");

	return __lxc_log_set_file(logfile, create_dirs);
}

/*
 * lxc_log_init:
 * Called from lxc front-end programs (like lxc-create, lxc-start) to
 * initialize the log defaults.
 */
int lxc_log_init(struct lxc_log *log)
{
	int ret;
	int lxc_priority = LXC_LOG_LEVEL_ERROR;

	if (!log)
		return ret_errno(EINVAL);

	if (lxc_log_fd >= 0)
		return log_warn_errno(0, EOPNOTSUPP, "Log already initialized");

	if (log->level)
		lxc_priority = lxc_log_priority_to_int(log->level);

	if (!lxc_loglevel_specified) {
		lxc_log_category_lxc.priority = lxc_priority;
		lxc_loglevel_specified = 1;
	}

	if (!lxc_quiet_specified)
		if (!log->quiet)
			lxc_log_category_lxc.appender->next = &log_appender_stderr;

	if (log->prefix)
		lxc_log_set_prefix(log->prefix);

	if (log->name)
		log_vmname = strdup(log->name);

	if (log->file) {
		if (strequal(log->file, "none"))
			return 0;

		ret = __lxc_log_set_file(log->file, 1);
		if (ret < 0)
			return log_error_errno(-1, errno, "Failed to enable logfile");

		lxc_log_use_global_fd = true;
	} else {
		/* if no name was specified, there nothing to do */
		if (!log->name)
			return 0;

		ret = -1;

		if (!log->lxcpath)
			log->lxcpath = LOGPATH;

		/* try LOGPATH if lxcpath is the default for the privileged containers */
		if (!geteuid() && strequal(LXCPATH, log->lxcpath))
			ret = _lxc_log_set_file(log->name, NULL, 0);

		/* try in lxcpath */
		if (ret < 0)
			ret = _lxc_log_set_file(log->name, log->lxcpath, 1);

		/* try LOGPATH in case its writable by the caller */
		if (ret < 0)
			ret = _lxc_log_set_file(log->name, NULL, 0);
	}

	/*
	 * If !file, that is, if the user did not request this logpath, then
	 * ignore failures and continue logging to console
	 */
	if (!log->file && ret != 0) {
		INFO("Ignoring failure to open default logfile");
		ret = 0;
	}

	if (lxc_log_fd >= 0) {
		lxc_log_category_lxc.appender = &log_appender_logfile;
		lxc_log_category_lxc.appender->next = &log_appender_stderr;
	}

	return ret;
}

void lxc_log_close(void)
{
	closelog();

	free_disarm(log_vmname);

	close_prot_errno_disarm(lxc_log_fd);

	free_disarm(log_fname);
}

int lxc_log_syslog(int facility)
{
	struct lxc_log_appender *appender;

	openlog(log_prefix, LOG_PID, facility);
	if (!lxc_log_category_lxc.appender) {
		lxc_log_category_lxc.appender = &log_appender_syslog;
		return 0;
	}

	appender = lxc_log_category_lxc.appender;
	/* Check if syslog was already added, to avoid creating a loop */
	while (appender) {
		/* not an error: openlog re-opened the connection */
		if (appender == &log_appender_syslog)
			return 0;
		appender = appender->next;
	}

	appender = lxc_log_category_lxc.appender;
	while (appender->next != NULL)
		appender = appender->next;
	appender->next = &log_appender_syslog;

	return 0;
}

void lxc_log_syslog_enable(void)
{
	wants_syslog = true;
}

void lxc_log_syslog_disable(void)
{
	wants_syslog = false;
}

/*
 * This is called when we read a lxc.log.level entry in a lxc.conf file.  This
 * happens after processing command line arguments, which override the .conf
 * settings.  So only set the level if previously unset.
 */
int lxc_log_set_level(int *dest, int level)
{
	if (level < 0 || level >= LXC_LOG_LEVEL_NOTSET)
		return log_error_errno(-EINVAL, EINVAL, "Invalid log priority %d", level);

	*dest = level;
	return 0;
}

int lxc_log_get_level(void)
{
	int level = LXC_LOG_LEVEL_NOTSET;

#ifndef NO_LXC_CONF
	if (current_config)
		level = current_config->loglevel;
#endif
	if (level == LXC_LOG_LEVEL_NOTSET)
		level = lxc_log_category_lxc.priority;

	return level;
}

bool lxc_log_has_valid_level(void)
{
	int log_level;

	log_level = lxc_log_get_level();
	if (log_level < 0 || log_level >= LXC_LOG_LEVEL_NOTSET)
		return ret_set_errno(false, EINVAL);

	return true;
}

/*
 * This is called when we read a lxc.logfile entry in a lxc.conf file.  This
 * happens after processing command line arguments, which override the .conf
 * settings.  So only set the file if previously unset.
 */
int lxc_log_set_file(int *fd, const char *fname)
{
	if (*fd >= 0)
		close_prot_errno_disarm(*fd);

	if (is_empty_string(fname))
		return ret_errno(EINVAL);

	if (build_dir(fname))
		return -errno;

	*fd = log_open(fname);
	if (*fd < 0)
		return -errno;
	return 0;
}

inline const char *lxc_log_get_file(void)
{
	return log_fname;
}

inline void lxc_log_set_prefix(const char *prefix)
{
	/* We don't care if the prefix is truncated. */
	(void)strlcpy(log_prefix, prefix, sizeof(log_prefix));
}

inline const char *lxc_log_get_prefix(void)
{
	return log_prefix;
}

inline void lxc_log_options_no_override(void)
{
	lxc_quiet_specified = 1;
	lxc_loglevel_specified = 1;
}

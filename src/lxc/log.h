/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2008
 *
 * Authors:
 * Daniel Lezcano <daniel.lezcano at free.fr>
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
#ifndef __LXC_LOG_H
#define __LXC_LOG_H

#include "config.h"

#include <stdarg.h>
#include <stdio.h>
#include <sys/time.h>
#include <string.h>
#include <strings.h>
#include <stdbool.h>

#include "conf.h"

#ifndef O_CLOEXEC
#define O_CLOEXEC 02000000
#endif

#ifndef F_DUPFD_CLOEXEC
#define F_DUPFD_CLOEXEC 1030
#endif

#define LXC_LOG_PREFIX_SIZE	32
#define LXC_LOG_BUFFER_SIZE	1024

/* This attribute is required to silence clang warnings */
#if defined(__GNUC__)
#define ATTR_UNUSED __attribute__ ((unused))
#else
#define ATTR_UNUSED
#endif

/* predefined priorities. */
enum lxc_loglevel {
	LXC_LOG_PRIORITY_TRACE,
	LXC_LOG_PRIORITY_DEBUG,
	LXC_LOG_PRIORITY_INFO,
	LXC_LOG_PRIORITY_NOTICE,
	LXC_LOG_PRIORITY_WARN,
	LXC_LOG_PRIORITY_ERROR,
	LXC_LOG_PRIORITY_CRIT,
	LXC_LOG_PRIORITY_ALERT,
	LXC_LOG_PRIORITY_FATAL,
	LXC_LOG_PRIORITY_NOTSET,
};

/* location information of the logging event */
struct lxc_log_locinfo {
	const char	*file;
	const char	*func;
	int		line;
};

#define LXC_LOG_LOCINFO_INIT						\
	{ .file = __FILE__, .func = __func__, .line = __LINE__	}

/* brief logging event object */
struct lxc_log_event {
	const char*		category;
	int			priority;
	struct timeval		timestamp;
	struct lxc_log_locinfo	*locinfo;
	const char		*fmt;
	va_list			*vap;
};

/* log appender object */
struct lxc_log_appender {
	const char*	name;
	int (*append)(const struct lxc_log_appender *, struct lxc_log_event *);

	/*
	 * appenders can be stacked
	 */
	struct lxc_log_appender	*next;
};

/* log category object */
struct lxc_log_category {
	const char			*name;
	int				priority;
	struct lxc_log_appender		*appender;
	const struct lxc_log_category	*parent;
};

#ifndef NO_LXC_CONF
extern int lxc_log_use_global_fd;
#endif

/*
 * Returns true if the chained priority is equal to or higher than
 * given priority.
 */
static inline int
lxc_log_priority_is_enabled(const struct lxc_log_category* category,
			   int priority)
{
	while (category->priority == LXC_LOG_PRIORITY_NOTSET &&
	       category->parent)
		category = category->parent;

	int cmp_prio = category->priority;
#ifndef NO_LXC_CONF
	if (!lxc_log_use_global_fd && current_config &&
			current_config->loglevel != LXC_LOG_PRIORITY_NOTSET)
		cmp_prio = current_config->loglevel;
#endif

	return priority >= cmp_prio;
}

/*
 * converts a priority to a literal string
 */
static inline const char* lxc_log_priority_to_string(int priority)
{
	switch (priority) {
	case LXC_LOG_PRIORITY_TRACE:	return "TRACE";
	case LXC_LOG_PRIORITY_DEBUG:	return "DEBUG";
	case LXC_LOG_PRIORITY_INFO:	return "INFO";
	case LXC_LOG_PRIORITY_NOTICE:	return "NOTICE";
	case LXC_LOG_PRIORITY_WARN:	return "WARN";
	case LXC_LOG_PRIORITY_ERROR:	return "ERROR";
	case LXC_LOG_PRIORITY_CRIT:	return "CRIT";
	case LXC_LOG_PRIORITY_ALERT:	return "ALERT";
	case LXC_LOG_PRIORITY_FATAL:	return "FATAL";
	default:
		return "NOTSET";
	}
}
/*
 * converts a literal priority to an int
 */
static inline int lxc_log_priority_to_int(const char* name)
{
	if (!strcasecmp("TRACE",  name)) return LXC_LOG_PRIORITY_TRACE;
	if (!strcasecmp("DEBUG",  name)) return LXC_LOG_PRIORITY_DEBUG;
	if (!strcasecmp("INFO",   name)) return LXC_LOG_PRIORITY_INFO;
	if (!strcasecmp("NOTICE", name)) return LXC_LOG_PRIORITY_NOTICE;
	if (!strcasecmp("WARN",   name)) return LXC_LOG_PRIORITY_WARN;
	if (!strcasecmp("ERROR",  name)) return LXC_LOG_PRIORITY_ERROR;
	if (!strcasecmp("CRIT",   name)) return LXC_LOG_PRIORITY_CRIT;
	if (!strcasecmp("ALERT",  name)) return LXC_LOG_PRIORITY_ALERT;
	if (!strcasecmp("FATAL",  name)) return LXC_LOG_PRIORITY_FATAL;

	return LXC_LOG_PRIORITY_NOTSET;
}

static inline void
__lxc_log_append(const struct lxc_log_appender *appender,
		struct lxc_log_event* event)
{
	va_list va, *va_keep;
	va_keep = event->vap;

	while (appender) {
		va_copy(va, *va_keep);
		event->vap = &va;
		appender->append(appender, event);
		appender = appender->next;
		va_end(va);
	}
}

static inline void
__lxc_log(const struct lxc_log_category* category,
	  struct lxc_log_event* event)
{
	while (category) {
		__lxc_log_append(category->appender, event);
		category = category->parent;
	}
}

/*
 * Helper macro to define log functions.
 */
#define lxc_log_priority_define(acategory, PRIORITY)			\
									\
ATTR_UNUSED static inline void LXC_##PRIORITY(struct lxc_log_locinfo *,		\
	const char *, ...) __attribute__ ((format (printf, 2, 3)));	\
									\
ATTR_UNUSED static inline void LXC_##PRIORITY(struct lxc_log_locinfo* locinfo,	\
				  const char* format, ...)		\
{									\
	if (lxc_log_priority_is_enabled(acategory, 			\
					LXC_LOG_PRIORITY_##PRIORITY)) {	\
		struct lxc_log_event evt = {				\
			.category	= (acategory)->name,		\
			.priority	= LXC_LOG_PRIORITY_##PRIORITY,	\
			.fmt		= format,			\
			.locinfo	= locinfo			\
		};							\
		va_list va_ref;						\
									\
		gettimeofday(&evt.timestamp, NULL);			\
									\
		va_start(va_ref, format);				\
		evt.vap = &va_ref;					\
		__lxc_log(acategory, &evt);				\
		va_end(va_ref);						\
	}								\
}

/*
 * Helper macro to define and use static categories.
 */
#define lxc_log_category_define(name, parent)				\
	extern struct lxc_log_category lxc_log_category_##parent;	\
	struct lxc_log_category lxc_log_category_##name = {		\
		#name,							\
		LXC_LOG_PRIORITY_NOTSET,				\
		NULL,							\
		&lxc_log_category_##parent				\
	};

#define lxc_log_define(name, parent)					\
	lxc_log_category_define(name, parent)				\
									\
	lxc_log_priority_define(&lxc_log_category_##name, TRACE)	\
	lxc_log_priority_define(&lxc_log_category_##name, DEBUG)	\
	lxc_log_priority_define(&lxc_log_category_##name, INFO)		\
	lxc_log_priority_define(&lxc_log_category_##name, NOTICE)	\
	lxc_log_priority_define(&lxc_log_category_##name, WARN)		\
	lxc_log_priority_define(&lxc_log_category_##name, ERROR)	\
	lxc_log_priority_define(&lxc_log_category_##name, CRIT)		\
	lxc_log_priority_define(&lxc_log_category_##name, ALERT)	\
	lxc_log_priority_define(&lxc_log_category_##name, FATAL)

#define lxc_log_category_priority(name) 				\
	(lxc_log_priority_to_string(lxc_log_category_##name.priority))

/*
 * top categories
 */
#define TRACE(format, ...) do {						\
	struct lxc_log_locinfo locinfo = LXC_LOG_LOCINFO_INIT;		\
	LXC_TRACE(&locinfo, format, ##__VA_ARGS__);			\
} while (0)

#define DEBUG(format, ...) do {						\
	struct lxc_log_locinfo locinfo = LXC_LOG_LOCINFO_INIT;		\
	LXC_DEBUG(&locinfo, format, ##__VA_ARGS__);			\
} while (0)

#define INFO(format, ...) do {						\
	struct lxc_log_locinfo locinfo = LXC_LOG_LOCINFO_INIT;		\
	LXC_INFO(&locinfo, format, ##__VA_ARGS__);			\
} while (0)

#define NOTICE(format, ...) do {					\
	struct lxc_log_locinfo locinfo = LXC_LOG_LOCINFO_INIT;		\
	LXC_NOTICE(&locinfo, format, ##__VA_ARGS__);			\
} while (0)

#define WARN(format, ...) do {						\
	struct lxc_log_locinfo locinfo = LXC_LOG_LOCINFO_INIT;		\
	LXC_WARN(&locinfo, format, ##__VA_ARGS__);			\
} while (0)

#define ERROR(format, ...) do {						\
	struct lxc_log_locinfo locinfo = LXC_LOG_LOCINFO_INIT;		\
	LXC_ERROR(&locinfo, format, ##__VA_ARGS__);			\
} while (0)

#define CRIT(format, ...) do {						\
	struct lxc_log_locinfo locinfo = LXC_LOG_LOCINFO_INIT;		\
	LXC_CRIT(&locinfo, format, ##__VA_ARGS__);			\
} while (0)

#define ALERT(format, ...) do {						\
	struct lxc_log_locinfo locinfo = LXC_LOG_LOCINFO_INIT;		\
	LXC_ALERT(&locinfo, format, ##__VA_ARGS__);			\
} while (0)

#define FATAL(format, ...) do {						\
	struct lxc_log_locinfo locinfo = LXC_LOG_LOCINFO_INIT;		\
	LXC_FATAL(&locinfo, format, ##__VA_ARGS__);			\
} while (0)



#define SYSERROR(format, ...) do {				    	\
	ERROR("%s - " format, strerror(errno), ##__VA_ARGS__);		\
} while (0)

extern int lxc_log_fd;

extern int lxc_log_init(const char *name, const char *file,
			const char *priority, const char *prefix, int quiet,
			const char *lxcpath);

extern int lxc_log_set_file(int *fd, const char *fname);
extern int lxc_log_set_level(int *dest, int level);
extern void lxc_log_set_prefix(const char *prefix);
extern const char *lxc_log_get_file(void);
extern int lxc_log_get_level(void);
extern bool lxc_log_has_valid_level(void);
extern const char *lxc_log_get_prefix(void);
extern void lxc_log_options_no_override();
#endif

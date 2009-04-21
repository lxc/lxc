#ifndef _log_h
#define _log_h

#include <stdarg.h>
#include <stdio.h>
#include <sys/time.h>
#include <string.h>

/* predefined priorities. */
enum {
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
	va_list 		va;
};

/* log appender object */
struct lxc_log_appender {
	const char*	name;
	int (*append)(const struct lxc_log_appender *,
		      const struct lxc_log_event *);

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

	return priority >= category->priority;
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
		const struct lxc_log_event* event)
{
	while (appender) {
		appender->append(appender, event);
		appender = appender->next;
	}
}

static inline void
__lxc_log(const struct lxc_log_category* category,
	 const struct lxc_log_event* event)
{
	while (category) {
		__lxc_log_append(category->appender, event);
		category = category->parent;
	}
}

/*
 * Helper macro to define log fonctions.
 */
#define lxc_log_priority_define(acategory, PRIORITY)			\
									\
static inline void LXC_##PRIORITY(struct lxc_log_locinfo *,		\
	const char *, ...) __attribute__ ((format (printf, 2, 3)));	\
									\
static inline void LXC_##PRIORITY(struct lxc_log_locinfo* locinfo,	\
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
									\
		gettimeofday(&evt.timestamp, NULL);			\
									\
		va_start(evt.va, format);				\
		__lxc_log(acategory, &evt);				\
		va_end(evt.va);						\
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
extern struct lxc_log_category lxc_log_category_lxc;

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
	ERROR("%s - " format "\n", strerror(errno), ##__VA_ARGS__); 	\
} while (0)


#define lxc_log(format, level, ...) do {			       \
		fprintf(stderr, "[%s] \t%s:%d - " format "\n", \
			level, __FUNCTION__, __LINE__, ##__VA_ARGS__); \
	} while (0)

#define lxc_log_error(format, ...) lxc_log(format, "error", ##__VA_ARGS__);
#define lxc_log_warning(format, ...) lxc_log(format, "warning", ##__VA_ARGS__);
#define lxc_log_info(format, ...) lxc_log(format, "info", ##__VA_ARGS__);
#define lxc_log_debug(format, ...) lxc_log(format, "debug", ##__VA_ARGS__);
#define lxc_log_trace(format, ...) lxc_log(format, "trace", ##__VA_ARGS__);
#define lxc_log_syserror(format, ...) do { \
		fprintf(stderr, "[syserr] \t%s:%d: %s - " format "\n", \
			__FUNCTION__, __LINE__, strerror(errno), \
			##__VA_ARGS__);					\
	} while (0)

#endif

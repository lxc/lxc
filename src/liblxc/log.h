#ifndef _log_h
#define _log_h

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
		fprintf(stderr, "[SYSERROR][%s] \t%s:%d - " format "\n", \
			strerror(errno),__FUNCTION__, __LINE__, \
			##__VA_ARGS__);					\
	} while (0)

#endif

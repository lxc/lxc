/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_CAPS_H
#define __LXC_CAPS_H

#include <stdbool.h>

#include "config.h"
#include "compiler.h"

#if HAVE_LIBCAP
#include <linux/types.h> /* workaround for libcap < 2.17 bug */
#include <sys/capability.h>

__hidden extern int lxc_caps_down(void);
__hidden extern int lxc_caps_up(void);
__hidden extern int lxc_ambient_caps_up(void);
__hidden extern int lxc_ambient_caps_down(void);
__hidden extern int lxc_caps_init(void);
__hidden extern int lxc_caps_last_cap(void);
__hidden extern bool lxc_proc_cap_is_set(cap_value_t cap, cap_flag_t flag);
__hidden extern bool lxc_file_cap_is_set(const char *path, cap_value_t cap, cap_flag_t flag);
#else
static inline int lxc_caps_down(void)
{
	return 0;
}

static inline int lxc_caps_up(void)
{
	return 0;
}

static inline int lxc_ambient_caps_up(void)
{
	return 0;
}

static inline int lxc_ambient_caps_down(void)
{
	return 0;
}

static inline int lxc_caps_init(void)
{
	return 0;
}

static inline int lxc_caps_last_cap(void)
{
	return 0;
}

typedef int cap_value_t;
typedef int cap_flag_t;
static inline bool lxc_proc_cap_is_set(cap_value_t cap, cap_flag_t flag)
{
	return false;
}

static inline bool lxc_file_cap_is_set(const char *path, cap_value_t cap,
				       cap_flag_t flag)
{
	return false;
}
#endif

#define lxc_priv(__lxc_function)                          \
	({                                                \
		__label__ out;                            \
		int __ret, __ret2, ___errno = 0;          \
		__ret = lxc_caps_up();                    \
		if (__ret)                                \
			goto out;                         \
		__ret = __lxc_function;                   \
		if (__ret)                                \
			___errno = errno;                 \
		__ret2 = lxc_caps_down();                 \
	out:                                              \
		__ret ? errno = ___errno, __ret : __ret2; \
	})

#define lxc_unpriv(__lxc_function)                        \
	({                                                \
		__label__ out;                            \
		int __ret, __ret2, ___errno = 0;          \
		__ret = lxc_caps_down();                  \
		if (__ret)                                \
			goto out;                         \
		__ret = __lxc_function;                   \
		if (__ret)                                \
			___errno = errno;                 \
		__ret2 = lxc_caps_up();                   \
	out:                                              \
		__ret ? errno = ___errno, __ret : __ret2; \
	})
#endif

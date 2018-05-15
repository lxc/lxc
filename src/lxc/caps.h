/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2008
 *
 * Authors:
 * Daniel Lezcano <daniel.lezcano at free.fr>
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

#ifndef __LXC_CAPS_H
#define __LXC_CAPS_H

#include "config.h"
#include <stdbool.h>

#if HAVE_LIBCAP
#include <linux/types.h> /* workaround for libcap < 2.17 bug */
#include <sys/capability.h>

extern int lxc_caps_down(void);
extern int lxc_caps_up(void);
extern int lxc_ambient_caps_up(void);
extern int lxc_ambient_caps_down(void);
extern int lxc_caps_init(void);
extern int lxc_caps_last_cap(void);
extern bool lxc_proc_cap_is_set(cap_value_t cap, cap_flag_t flag);
extern bool lxc_file_cap_is_set(const char *path, cap_value_t cap,
				cap_flag_t flag);
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

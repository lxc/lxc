/* liblxcapi
 *
 * Copyright © 2018 Christian Brauner <christian.brauner@ubuntu.com>.
 * Copyright © 2018 Canonical Ltd.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.

 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef __LXC_COMPILER_H
#define __LXC_COMPILER_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include "config.h"

#ifndef thread_local
#if __STDC_VERSION__ >= 201112L &&    \
    !(defined(__STDC_NO_THREADS__) || \
      (defined(__GNU_LIBRARY__) && __GLIBC__ == 2 && __GLIBC_MINOR__ < 16))
#define thread_local _Thread_local
#else
#define thread_local __thread
#endif
#endif

#ifndef __fallthrough
#define __fallthrough /* fall through */
#endif

#ifndef __noreturn
#	if __STDC_VERSION__ >= 201112L
#		if !IS_BIONIC
#			define __noreturn _Noreturn
#		else
#			define __noreturn __attribute__((__noreturn__))
#		endif
#	elif IS_BIONIC
#		define __noreturn __attribute__((__noreturn__))
#	else
#		define __noreturn __attribute__((noreturn))
#	endif
#endif

#ifndef __hot
#	define __hot __attribute__((hot))
#endif

#define __cgfsng_ops

#endif /* __LXC_COMPILER_H */

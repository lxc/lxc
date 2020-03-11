/* SPDX-License-Identifier: LGPL-2.1+ */

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

#ifndef __returns_twice
#define __returns_twice __attribute__((returns_twice))
#endif

/* This attribute is required to silence clang warnings */
#if defined(__GNUC__)
#define __lxc_unused __attribute__ ((unused))
#else
#define __lxc_unused
#endif

/* Indicates taking ownership */
#define __owns

#define __cgfsng_ops

#endif /* __LXC_COMPILER_H */

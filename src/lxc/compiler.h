/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_COMPILER_H
#define __LXC_COMPILER_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <stdbool.h>
#include <linux/types.h>

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

#if __GNUC__ >= 7
#define __fallthrough __attribute__((__fallthrough__))
#else
#define __fallthrough /* fall through */
#endif

#if defined(__GNUC__) && !defined(__clang__)
	#if GCC_VERSION >= 50100
	#define COMPILER_HAS_GENERIC_BUILTIN_OVERFLOW 1
	#endif
#endif

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define __must_check __attribute__((__warn_unused_result__))

static inline bool __must_check __must_check_overflow(bool overflow)
{
	return unlikely(overflow);
}

#define is_signed_type(type)       (((type)(-1)) < (type)1)
#define __type_half_max(type) ((type)1 << (8*sizeof(type) - 1 - is_signed_type(type)))
#define type_max(T) ((T)((__type_half_max(T) - 1) + __type_half_max(T)))
#define type_min(T) ((T)((T)-type_max(T)-(T)1))

/*
 * Avoids triggering -Wtype-limits compilation warning,
 * while using unsigned data types to check a < 0.
 */
#define is_non_negative(a) ((a) > 0 || (a) == 0)
#define is_negative(a) (!(is_non_negative(a)))

#ifdef COMPILER_HAS_GENERIC_BUILTIN_OVERFLOW
/*
 * For simplicity and code hygiene, the fallback code below insists on
 * a, b and *d having the same type (similar to the min() and max()
 * macros), whereas gcc's type-generic overflow checkers accept
 * different types. Hence we don't just make check_add_overflow an
 * alias for __builtin_add_overflow, but add type checks similar to
 * below.
 */
#define check_add_overflow(a, b, d) __must_check_overflow(({	\
	typeof(a) __a = (a);			\
	typeof(b) __b = (b);			\
	typeof(d) __d = (d);			\
	(void) (&__a == &__b);			\
	(void) (&__a == __d);			\
	__builtin_add_overflow(__a, __b, __d);	\
}))

#define check_sub_overflow(a, b, d) __must_check_overflow(({	\
	typeof(a) __a = (a);			\
	typeof(b) __b = (b);			\
	typeof(d) __d = (d);			\
	(void) (&__a == &__b);			\
	(void) (&__a == __d);			\
	__builtin_sub_overflow(__a, __b, __d);	\
}))

#define check_mul_overflow(a, b, d) __must_check_overflow(({	\
	typeof(a) __a = (a);			\
	typeof(b) __b = (b);			\
	typeof(d) __d = (d);			\
	(void) (&__a == &__b);			\
	(void) (&__a == __d);			\
	__builtin_mul_overflow(__a, __b, __d);	\
}))
#else /* !COMPILER_HAS_GENERIC_BUILTIN_OVERFLOW */

/* Checking for unsigned overflow is relatively easy without causing UB. */
#define __unsigned_add_overflow(a, b, d) ({	\
	typeof(a) __a = (a);			\
	typeof(b) __b = (b);			\
	typeof(d) __d = (d);			\
	(void) (&__a == &__b);			\
	(void) (&__a == __d);			\
	*__d = __a + __b;			\
	*__d < __a;				\
})
#define __unsigned_sub_overflow(a, b, d) ({	\
	typeof(a) __a = (a);			\
	typeof(b) __b = (b);			\
	typeof(d) __d = (d);			\
	(void) (&__a == &__b);			\
	(void) (&__a == __d);			\
	*__d = __a - __b;			\
	__a < __b;				\
})

/*
 * If one of a or b is a compile-time constant, this avoids a division.
 */
#define __unsigned_mul_overflow(a, b, d) ({		\
	typeof(a) __a = (a);				\
	typeof(b) __b = (b);				\
	typeof(d) __d = (d);				\
	(void) (&__a == &__b);				\
	(void) (&__a == __d);				\
	*__d = __a * __b;				\
	__builtin_constant_p(__b) ?			\
	  __b > 0 && __a > type_max(typeof(__a)) / __b : \
	  __a > 0 && __b > type_max(typeof(__b)) / __a;	 \
})

/*
 * For signed types, detecting overflow is much harder, especially if
 * we want to avoid UB. But the interface of these macros is such that
 * we must provide a result in *d, and in fact we must produce the
 * result promised by gcc's builtins, which is simply the possibly
 * wrapped-around value. Fortunately, we can just formally do the
 * operations in the widest relevant unsigned type (u64) and then
 * truncate the result - gcc is smart enough to generate the same code
 * with and without the (u64) casts.
 */

/*
 * Adding two signed integers can overflow only if they have the same
 * sign, and overflow has happened iff the result has the opposite
 * sign.
 */
#define __signed_add_overflow(a, b, d) ({	\
	typeof(a) __a = (a);			\
	typeof(b) __b = (b);			\
	typeof(d) __d = (d);			\
	(void) (&__a == &__b);			\
	(void) (&__a == __d);			\
	*__d = (__u64)__a + (__u64)__b;		\
	(((~(__a ^ __b)) & (*__d ^ __a))	\
		& type_min(typeof(__a))) != 0;	\
})

/*
 * Subtraction is similar, except that overflow can now happen only
 * when the signs are opposite. In this case, overflow has happened if
 * the result has the opposite sign of a.
 */
#define __signed_sub_overflow(a, b, d) ({	\
	typeof(a) __a = (a);			\
	typeof(b) __b = (b);			\
	typeof(d) __d = (d);			\
	(void) (&__a == &__b);			\
	(void) (&__a == __d);			\
	*__d = (__u64)__a - (__u64)__b;		\
	((((__a ^ __b)) & (*__d ^ __a))		\
		& type_min(typeof(__a))) != 0;	\
})

/*
 * Signed multiplication is rather hard. gcc always follows C99, so
 * division is truncated towards 0. This means that we can write the
 * overflow check like this:
 *
 * (a > 0 && (b > MAX/a || b < MIN/a)) ||
 * (a < -1 && (b > MIN/a || b < MAX/a) ||
 * (a == -1 && b == MIN)
 *
 * The redundant casts of -1 are to silence an annoying -Wtype-limits
 * (included in -Wextra) warning: When the type is u8 or u16, the
 * __b_c_e in check_mul_overflow obviously selects
 * __unsigned_mul_overflow, but unfortunately gcc still parses this
 * code and warns about the limited range of __b.
 */

#define __signed_mul_overflow(a, b, d) ({				\
	typeof(a) __a = (a);						\
	typeof(b) __b = (b);						\
	typeof(d) __d = (d);						\
	typeof(a) __tmax = type_max(typeof(a));				\
	typeof(a) __tmin = type_min(typeof(a));				\
	(void) (&__a == &__b);						\
	(void) (&__a == __d);						\
	*__d = (__u64)__a * (__u64)__b;					\
	(__b > 0   && (__a > __tmax/__b || __a < __tmin/__b)) ||	\
	(__b < (typeof(__b))-1  && (__a > __tmin/__b || __a < __tmax/__b)) || \
	(__b == (typeof(__b))-1 && __a == __tmin);			\
})


#define check_add_overflow(a, b, d)	__must_check_overflow(		\
	__builtin_choose_expr(is_signed_type(typeof(a)),		\
			__signed_add_overflow(a, b, d),			\
			__unsigned_add_overflow(a, b, d)))

#define check_sub_overflow(a, b, d)	__must_check_overflow(		\
	__builtin_choose_expr(is_signed_type(typeof(a)),		\
			__signed_sub_overflow(a, b, d),			\
			__unsigned_sub_overflow(a, b, d)))

#define check_mul_overflow(a, b, d)	__must_check_overflow(		\
	__builtin_choose_expr(is_signed_type(typeof(a)),		\
			__signed_mul_overflow(a, b, d),			\
			__unsigned_mul_overflow(a, b, d)))

#endif /* COMPILER_HAS_GENERIC_BUILTIN_OVERFLOW */

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

/* access attribute */
#define __access_r_nosize(x)
#define __access_r(x, y)
#define __access_w(x, y)
#define __access_rw(x, y)

#ifdef __has_attribute
#if __has_attribute(access)
#undef __access_r
#define __access_r(x, y) __attribute__((access(read_only, x, y)))

#undef __access_r_nosize
#define __access_r_nosize(x) __attribute__((access(read_only, x)))

#undef __access_w
#define __access_w(x, y) __attribute__((access(write_only, x, y)))

#undef __access_rw
#define __access_rw(x, y) __attribute__((access(read_write, x, y)))
#endif
#endif

#ifndef __hidden
#define __hidden __attribute__((visibility("hidden")))
#endif

#ifndef __public
#define __public __attribute__((visibility("default")))
#endif

#endif /* __LXC_COMPILER_H */

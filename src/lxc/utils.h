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
#ifndef _utils_h
#define _utils_h

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include "config.h"

/* returns 1 on success, 0 if there were any failures */
extern int lxc_rmdir_onedev(char *path);
extern int lxc_setup_fs(void);
extern int get_u16(unsigned short *val, const char *arg, int base);
extern int mkdir_p(const char *dir, mode_t mode);
/*
 * Return a buffer containing the default container path.
 * Caller must NOT free this buffer, since it may be static.
 */
extern const char *lxc_global_config_value(const char *option_name);
extern const char *default_lxc_path(void);
extern const char *default_zfs_root(void);
extern const char *default_lvm_vg(void);

/* Define getline() if missing from the C library */
#ifndef HAVE_GETLINE
#ifdef HAVE_FGETLN
#include <../include/getline.h>
#endif
#endif

/* Define setns() if missing from the C library */
#ifndef HAVE_SETNS
static inline int setns(int fd, int nstype)
{
#ifdef __NR_setns
	return syscall(__NR_setns, fd, nstype);
#else
	errno = ENOSYS;
	return -1;
#endif
}
#endif

/* Define unshare() if missing from the C library */
#ifndef HAVE_UNSHARE
static inline int unshare(int flags)
{
#ifdef __NR_unshare
	return syscall(__NR_unshare, flags);
#else
	errno = ENOSYS;
	return -1;
#endif
}
#else
int unshare(int);
#endif

/* Define signalfd() if missing from the C library */
#ifdef HAVE_SYS_SIGNALFD_H
#  include <sys/signalfd.h>
#else
/* assume kernel headers are too old */
#include <stdint.h>
struct signalfd_siginfo
{
	uint32_t ssi_signo;
	int32_t ssi_errno;
	int32_t ssi_code;
	uint32_t ssi_pid;
	uint32_t ssi_uid;
	int32_t ssi_fd;
	uint32_t ssi_tid;
	uint32_t ssi_band;
	uint32_t ssi_overrun;
	uint32_t ssi_trapno;
	int32_t ssi_status;
	int32_t ssi_int;
	uint64_t ssi_ptr;
	uint64_t ssi_utime;
	uint64_t ssi_stime;
	uint64_t ssi_addr;
	uint8_t __pad[48];
};

#  ifndef __NR_signalfd4
/* assume kernel headers are too old */
#    if __i386__
#      define __NR_signalfd4 327
#    elif __x86_64__
#      define __NR_signalfd4 289
#    elif __powerpc__
#      define __NR_signalfd4 313
#    elif __s390x__
#      define __NR_signalfd4 322
#    elif __arm__
#      define __NR_signalfd4 355
#    endif
#endif

#  ifndef __NR_signalfd
/* assume kernel headers are too old */
#    if __i386__
#      define __NR_signalfd 321
#    elif __x86_64__
#      define __NR_signalfd 282
#    elif __powerpc__
#      define __NR_signalfd 305
#    elif __s390x__
#      define __NR_signalfd 316
#    elif __arm__
#      define __NR_signalfd 349
#    endif
#endif

static inline int signalfd(int fd, const sigset_t *mask, int flags)
{
	int retval;

	retval = syscall (__NR_signalfd4, fd, mask, _NSIG / 8, flags);
	if (errno == ENOSYS && flags == 0)
		retval = syscall (__NR_signalfd, fd, mask, _NSIG / 8);
	return retval;
}
#endif

/* open a file with O_CLOEXEC */
FILE *fopen_cloexec(const char *path, const char *mode);


/**
 * BUILD_BUG_ON - break compile if a condition is true.
 * @condition: the condition which the compiler should know is false.
 *
 * If you have some code which relies on certain constants being equal, or
 * other compile-time-evaluated condition, you should use BUILD_BUG_ON to
 * detect if someone changes it.
 *
 * The implementation uses gcc's reluctance to create a negative array, but
 * gcc (as of 4.4) only emits that error for obvious cases (eg. not arguments
 * to inline functions).  So as a fallback we use the optimizer; if it can't
 * prove the condition is false, it will cause a link error on the undefined
 * "__build_bug_on_failed".  This error message can be harder to track down
 * though, hence the two different methods.
 */
#ifndef __OPTIMIZE__
#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)]))
#else
extern int __build_bug_on_failed;
#define BUILD_BUG_ON(condition)					\
	do {							\
		((void)sizeof(char[1 - 2*!!(condition)]));	\
		if (condition) __build_bug_on_failed = 1;	\
	} while(0)
#endif

/*
 * wait on a child we forked
 */
extern int wait_for_pid(pid_t pid);
extern int lxc_wait_for_pid_status(pid_t pid);

/* send and receive buffers completely */
extern ssize_t lxc_write_nointr(int fd, const void* buf, size_t count);
extern ssize_t lxc_read_nointr(int fd, void* buf, size_t count);
extern ssize_t lxc_read_nointr_expect(int fd, void* buf, size_t count, const void* expected_buf);
#if HAVE_LIBGNUTLS
#define SHA_DIGEST_LENGTH 20
extern int sha1sum_file(char *fnam, unsigned char *md_value);
#endif

/* read and write whole files */
extern int lxc_write_to_file(const char *filename, const void* buf, size_t count, bool add_newline);
extern int lxc_read_from_file(const char *filename, void* buf, size_t count);
extern char *lxc_read_line_from_file(const char *filename);

/* convert variadic argument lists to arrays (for execl type argument lists) */
extern char** lxc_va_arg_list_to_argv(va_list ap, size_t skip, int do_strdup);
extern const char** lxc_va_arg_list_to_argv_const(va_list ap, size_t skip);

/* Some simple string functions; if they return pointers, they are allocated buffers. */
extern char *lxc_string_replace(const char *needle, const char *replacement, const char *haystack);
extern bool lxc_string_in_array(const char *needle, const char **haystack);
extern char *lxc_string_join(const char *sep, const char **parts, bool use_as_prefix);
/* Normalize and split path: Leading and trailing / are removed, multiple
 * / are compactified, .. and . are resolved (.. on the top level is considered
 * identical to .).
 * Examples:
 *     /            ->   { NULL }
 *     foo/../bar   ->   { bar, NULL }
 *     ../../       ->   { NULL }
 *     ./bar/baz/.. ->   { bar, NULL }
 *     foo//bar     ->   { foo, bar, NULL }
 */
extern char **lxc_normalize_path(const char *path);
/* Note: the following two functions use strtok(), so they will never
 *       consider an empty element, even if two delimiters are next to
 *       each other.
 */
extern bool lxc_string_in_list(const char *needle, const char *haystack, char sep);
extern char **lxc_string_split(const char *string, char sep);
extern char **lxc_string_split_and_trim(const char *string, char sep);

/* some simple array manipulation utilities */
typedef void (*lxc_free_fn)(void *);
typedef void *(*lxc_dup_fn)(void *);
extern int lxc_grow_array(void ***array, size_t* capacity, size_t new_size, size_t capacity_increment);
extern void lxc_free_array(void **array, lxc_free_fn element_free_fn);
extern size_t lxc_array_len(void **array);
extern void **lxc_dup_array(void **array, lxc_dup_fn element_dup_fn, lxc_free_fn element_free_fn);

#endif

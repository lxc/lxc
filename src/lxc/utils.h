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
#ifndef __LXC_UTILS_H
#define __LXC_UTILS_H

#include "config.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "initutils.h"

/* returns 1 on success, 0 if there were any failures */
extern int lxc_rmdir_onedev(char *path, const char *exclude);
extern int get_u16(unsigned short *val, const char *arg, int base);
extern int mkdir_p(const char *dir, mode_t mode);
extern char *get_rundir(void);

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
#elif defined(__NR_set_ns)
	return syscall(__NR_set_ns, fd, nstype);
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

/* Struct to carry child pid from lxc_popen() to lxc_pclose().
 * Not an opaque struct to allow direct access to the underlying FILE *
 * (i.e., struct lxc_popen_FILE *file; fgets(buf, sizeof(buf), file->f))
 * without additional wrappers.
 */
struct lxc_popen_FILE {
	FILE *f;
	pid_t child_pid;
};

/* popen(command, "re") replacement that restores default signal mask
 * via sigprocmask(2) (unblocks all signals) after fork(2) but prior to calling exec(3).
 * In short, popen(command, "re") does pipe() + fork()                 + exec()
 * while lxc_popen(command)       does pipe() + fork() + sigprocmask() + exec().
 * Returns pointer to struct lxc_popen_FILE, that should be freed with lxc_pclose().
 * On error returns NULL.
 */
extern struct lxc_popen_FILE *lxc_popen(const char *command);

/* pclose() replacement to be used on struct lxc_popen_FILE *,
 * returned by lxc_popen().
 * Waits for associated process to terminate, returns its exit status and
 * frees resources, pointed to by struct lxc_popen_FILE *.
 */
extern int lxc_pclose(struct lxc_popen_FILE *fp);

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
extern char *lxc_append_paths(const char *first, const char *second);
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

extern void **lxc_append_null_to_array(void **array, size_t count);

/* mmap() wrapper. lxc_strmmap() will take care to \0-terminate files so that
 * normal string-handling functions can be used on the buffer. */
extern void *lxc_strmmap(void *addr, size_t length, int prot, int flags, int fd,
			 off_t offset);
/* munmap() wrapper. Use it to free memory mmap()ed with lxc_strmmap(). */
extern int lxc_strmunmap(void *addr, size_t length);

//initialize rand with urandom
extern int randseed(bool);

inline static bool am_unpriv(void) {
	return geteuid() != 0;
}

/*
 * parse /proc/self/uid_map to find what @orig maps to
 */
extern uid_t get_ns_uid(uid_t orig);

extern bool dir_exists(const char *path);

#define FNV1A_64_INIT ((uint64_t)0xcbf29ce484222325ULL)
uint64_t fnv_64a_buf(void *buf, size_t len, uint64_t hval);

int detect_shared_rootfs(void);
int detect_ramfs_rootfs(void);
char *on_path(char *cmd, const char *rootfs);
bool file_exists(const char *f);
bool cgns_supported(void);
char *choose_init(const char *rootfs);
int print_to_file(const char *file, const char *content);
bool switch_to_ns(pid_t pid, const char *ns);
int is_dir(const char *path);
char *get_template_path(const char *t);
int setproctitle(char *title);
int safe_mount(const char *src, const char *dest, const char *fstype,
		unsigned long flags, const void *data, const char *rootfs);
int mount_proc_if_needed(const char *rootfs);
int open_devnull(void);
int set_stdfds(int fd);
int null_stdfds(void);
int lxc_count_file_lines(const char *fn);

/* Check whether a signal is blocked by a process. */
bool task_blocking_signal(pid_t pid, int signal);
#endif /* __LXC_UTILS_H */

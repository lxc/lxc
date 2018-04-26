/* liblxcapi
 *
 * Copyright © 2018 Christian Brauner <christian.brauner@ubuntu.com>.
 * Copyright © 2018 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __LXC_UTILS_H
#define __LXC_UTILS_H

/* Properly support loop devices on 32bit systems. */
#define _FILE_OFFSET_BITS 64

#include "config.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>

#include <lxc/lxccontainer.h>

#include "tool_list.h"

#define TOOL_MAXPATHLEN 4096
#define TOOL_NUMSTRLEN64 21

#ifndef CLONE_PARENT_SETTID
#define CLONE_PARENT_SETTID 0x00100000
#endif

#ifndef CLONE_CHILD_CLEARTID
#define CLONE_CHILD_CLEARTID 0x00200000
#endif

#ifndef CLONE_CHILD_SETTID
#define CLONE_CHILD_SETTID 0x01000000
#endif

#ifndef CLONE_VFORK
#define CLONE_VFORK 0x00004000
#endif

#ifndef CLONE_THREAD
#define CLONE_THREAD 0x00010000
#endif

#ifndef CLONE_SETTLS
#define CLONE_SETTLS 0x00080000
#endif

#ifndef CLONE_VM
#define CLONE_VM 0x00000100
#endif

#ifndef CLONE_FILES
#define CLONE_FILES 0x00000400
#endif

#ifndef CLONE_FS
#  define CLONE_FS                0x00000200
#endif
#ifndef CLONE_NEWNS
#  define CLONE_NEWNS             0x00020000
#endif
#ifndef CLONE_NEWCGROUP
#  define CLONE_NEWCGROUP         0x02000000
#endif
#ifndef CLONE_NEWUTS
#  define CLONE_NEWUTS            0x04000000
#endif
#ifndef CLONE_NEWIPC
#  define CLONE_NEWIPC            0x08000000
#endif
#ifndef CLONE_NEWUSER
#  define CLONE_NEWUSER           0x10000000
#endif
#ifndef CLONE_NEWPID
#  define CLONE_NEWPID            0x20000000
#endif
#ifndef CLONE_NEWNET
#  define CLONE_NEWNET            0x40000000
#endif

enum {
	LXC_NS_USER,
	LXC_NS_MNT,
	LXC_NS_PID,
	LXC_NS_UTS,
	LXC_NS_IPC,
	LXC_NS_NET,
	LXC_NS_CGROUP,
	LXC_NS_MAX
};

extern int lxc_fill_elevated_privileges(char *flaglist, int *flags);
extern signed long lxc_config_parse_arch(const char *arch);
extern int lxc_namespace_2_cloneflag(const char *namespace);
extern int lxc_fill_namespace_flags(char *flaglist, int *flags);

#if !defined(__NR_setns) && !defined(__NR_set_ns)
	#if defined(__x86_64__)
		#define __NR_setns 308
	#elif defined(__i386__)
		#define __NR_setns 346
	#elif defined(__arm__)
		#define __NR_setns 375
	#elif defined(__aarch64__)
		#define __NR_setns 375
	#elif defined(__powerpc__)
		#define __NR_setns 350
	#elif defined(__s390__)
		#define __NR_setns 339
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

#if HAVE_LIBCAP
#include <sys/capability.h>

extern int lxc_caps_up(void);
extern int lxc_caps_init(void);
#else
static inline int lxc_caps_up(void) {
	return 0;
}

static inline int lxc_caps_init(void) {
	return 0;
}
#endif

extern int wait_for_pid(pid_t pid);
extern int lxc_wait_for_pid_status(pid_t pid);
extern int lxc_safe_uint(const char *numstr, unsigned int *converted);
extern int lxc_safe_int(const char *numstr, int *converted);
extern int lxc_safe_long(const char *numstr, long int *converted);

typedef void (*lxc_free_fn)(void *);
extern void lxc_free_array(void **array, lxc_free_fn element_free_fn);
extern size_t lxc_array_len(void **array);
extern int lxc_grow_array(void ***array, size_t *capacity, size_t new_size,
			  size_t capacity_increment);
extern char **lxc_string_split(const char *string, char _sep);
extern char **lxc_normalize_path(const char *path);
extern char *lxc_string_join(const char *sep, const char **parts,
			     bool use_as_prefix);
extern char **lxc_string_split_quoted(char *string);
extern char **lxc_string_split_and_trim(const char *string, char _sep);
extern char *lxc_append_paths(const char *first, const char *second);
extern char *lxc_string_replace(const char *needle, const char *replacement,
				const char *haystack);
extern char *must_copy_string(const char *entry);
extern void *must_realloc(void *orig, size_t sz);
extern char *must_make_path(const char *first, ...);

extern int mkdir_p(const char *dir, mode_t mode);
extern int rm_r(char *dirname);
extern bool file_exists(const char *f);
extern bool dir_exists(const char *path);
extern int is_dir(const char *path);
extern int lxc_read_from_file(const char *filename, void* buf, size_t count);

extern char *get_template_path(const char *t);

extern bool switch_to_ns(pid_t pid, const char *ns);

extern int lxc_config_define_add(struct lxc_list *defines, char *arg);
extern bool lxc_config_define_load(struct lxc_list *defines,
				   struct lxc_container *c);
extern void lxc_config_define_free(struct lxc_list *defines);
extern int lxc_char_left_gc(const char *buffer, size_t len);
extern int lxc_char_right_gc(const char *buffer, size_t len);

struct new_config_item {
        char *key;
        char *val;
};
extern struct new_config_item *parse_line(char *buffer);

extern ssize_t lxc_read_nointr(int fd, void* buf, size_t count);
extern ssize_t lxc_write_nointr(int fd, const void* buf, size_t count);

extern char *get_rundir();

extern void lxc_setup_fs(void);

static inline uint64_t lxc_getpagesize(void)
{
	int64_t pgsz;

	pgsz = sysconf(_SC_PAGESIZE);
	if (pgsz <= 0)
		pgsz = 1 << 12;

	return pgsz;
}

#if defined(__ia64__)
int __clone2(int (*__fn) (void *__arg), void *__child_stack_base,
             size_t __child_stack_size, int __flags, void *__arg, ...);
#else
int clone(int (*fn)(void *), void *child_stack,
	int flags, void *arg, ...
	/* pid_t *ptid, struct user_desc *tls, pid_t *ctid */ );
#endif

extern pid_t lxc_clone(int (*fn)(void *), void *arg, int flags);

#endif /* __LXC_UTILS_H */

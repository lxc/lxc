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

/* Properly support loop devices on 32bit systems. */
#define _FILE_OFFSET_BITS 64

#include <errno.h>
#include <linux/loop.h>
#include <linux/types.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <unistd.h>

#include "file_utils.h"
#include "initutils.h"
#include "macro.h"
#include "raw_syscalls.h"
#include "string_utils.h"

/* returns 1 on success, 0 if there were any failures */
extern int lxc_rmdir_onedev(const char *path, const char *exclude);
extern int get_u16(unsigned short *val, const char *arg, int base);
extern int mkdir_p(const char *dir, mode_t mode);
extern char *get_rundir(void);

/* Define getline() if missing from the C library */
#ifndef HAVE_GETLINE
#ifdef HAVE_FGETLN
#include <../include/getline.h>
#endif
#endif

static inline int lxc_set_cloexec(int fd)
{
	return fcntl(fd, F_SETFD, FD_CLOEXEC);
}

/* Struct to carry child pid from lxc_popen() to lxc_pclose().
 * Not an opaque struct to allow direct access to the underlying FILE *
 * (i.e., struct lxc_popen_FILE *file; fgets(buf, sizeof(buf), file->f))
 * without additional wrappers.
 */
struct lxc_popen_FILE {
	int pipe;
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

/*
 * wait on a child we forked
 */
extern int wait_for_pid(pid_t pid);
extern int lxc_wait_for_pid_status(pid_t pid);

#if HAVE_LIBGNUTLS
#define SHA_DIGEST_LENGTH 20
extern int sha1sum_file(char *fnam, unsigned char *md_value);
#endif

/* initialize rand with urandom */
extern int randseed(bool);

/* are we unprivileged with respect to our namespaces */
inline static bool am_guest_unpriv(void) {
	return geteuid() != 0;
}

/* are we unprivileged with respect to init_user_ns */
inline static bool am_host_unpriv(void)
{
	FILE *f;
	uid_t user, host, count;
	int ret;

	if (geteuid() != 0)
		return true;

	/* Now: are we in a user namespace? Because then we're also
	 * unprivileged.
	 */
	f = fopen("/proc/self/uid_map", "r");
	if (!f) {
		return false;
	}

	ret = fscanf(f, "%u %u %u", &user, &host, &count);
	fclose(f);
	if (ret != 3) {
		return false;
	}

	if (user != 0 || host != 0 || count != UINT32_MAX)
		return true;
	return false;
}

/*
 * parse /proc/self/uid_map to find what @orig maps to
 */
extern uid_t get_ns_uid(uid_t orig);
/*
 * parse /proc/self/gid_map to find what @orig maps to
 */
extern gid_t get_ns_gid(gid_t orig);

extern bool dir_exists(const char *path);

#define FNV1A_64_INIT ((uint64_t)0xcbf29ce484222325ULL)
extern uint64_t fnv_64a_buf(void *buf, size_t len, uint64_t hval);

extern int detect_shared_rootfs(void);
extern bool detect_ramfs_rootfs(void);
extern char *on_path(const char *cmd, const char *rootfs);
extern bool cgns_supported(void);
extern char *choose_init(const char *rootfs);
extern bool switch_to_ns(pid_t pid, const char *ns);
extern char *get_template_path(const char *t);
extern int safe_mount(const char *src, const char *dest, const char *fstype,
		      unsigned long flags, const void *data,
		      const char *rootfs);
extern int lxc_mount_proc_if_needed(const char *rootfs);
extern int open_devnull(void);
extern int set_stdfds(int fd);
extern int null_stdfds(void);
extern int lxc_preserve_ns(const int pid, const char *ns);

/* Check whether a signal is blocked by a process. */
extern bool task_blocks_signal(pid_t pid, int signal);

/* Switch to a new uid and gid.
 * If LXC_INVALID_{G,U}ID is passed then the set{g,u}id() will not be called.
 */
extern bool lxc_switch_uid_gid(uid_t uid, gid_t gid);
extern bool lxc_setgroups(int size, gid_t list[]);

/* Find an unused loop device and associate it with source. */
extern int lxc_prepare_loop_dev(const char *source, char *loop_dev, int flags);

/* Clear all mounts on a given node.
 * >= 0 successfully cleared. The number returned is the number of umounts
 *      performed.
 * < 0  error umounting. Return -errno.
 */
extern int lxc_unstack_mountpoint(const char *path, bool lazy);

/*
 * run_command runs a command and collect it's std{err,out} output in buf.
 *
 * @param[out] buf     The buffer where the commands std{err,out] output will be
 *                     read into. If no output was produced, buf will be memset
 *                     to 0.
 * @param[in] buf_size The size of buf. This function will reserve one byte for
 *                     \0-termination.
 * @param[in] child_fn The function to be run in the child process. This
 *                     function must exec.
 * @param[in] args     Arguments to be passed to child_fn.
 */
extern int run_command(char *buf, size_t buf_size, int (*child_fn)(void *),
		       void *args);

/* Concatenate all passed-in strings into one path. Do not fail. If any piece
 * is not prefixed with '/', add a '/'.
 */
__attribute__((sentinel)) extern char *must_concat(const char *first, ...);
__attribute__((sentinel)) extern char *must_make_path(const char *first, ...);
__attribute__((sentinel)) extern char *must_append_path(char *first, ...);

/* return copy of string @entry;  do not fail. */
extern char *must_copy_string(const char *entry);

/* Re-allocate a pointer, do not fail */
extern void *must_realloc(void *orig, size_t sz);

extern bool lxc_nic_exists(char *nic);

static inline uint64_t lxc_getpagesize(void)
{
	int64_t pgsz;

	pgsz = sysconf(_SC_PAGESIZE);
	if (pgsz <= 0)
		pgsz = 1 << 12;

	return pgsz;
}

/* If n is not a power of 2 this function will return the next power of 2
 * greater than that number. Note that this function always returns the *next*
 * power of 2 *greater* that number not the *nearest*. For example, passing 1025
 * as argument this function will return 2048 although the closest power of 2
 * would be 1024.
 * If the caller passes in 0 they will receive 0 in return since this is invalid
 * input and 0 is not a power of 2.
 */
extern uint64_t lxc_find_next_power2(uint64_t n);

/* Set a signal the child process will receive after the parent has died. */
extern int lxc_set_death_signal(int signal, pid_t parent);
extern int fd_cloexec(int fd, bool cloexec);
extern int recursive_destroy(char *dirname);
extern int lxc_setup_keyring(void);

#endif /* __LXC_UTILS_H */

/* SPDX-License-Identifier: LGPL-2.1+ */

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
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <unistd.h>

#include "compiler.h"
#include "file_utils.h"
#include "initutils.h"
#include "macro.h"
#include "memory_utils.h"
#include "process_utils.h"
#include "string_utils.h"

/* returns 1 on success, 0 if there were any failures */
__hidden extern int lxc_rmdir_onedev(const char *path, const char *exclude);
__hidden extern int get_u16(unsigned short *val, const char *arg, int base);
__hidden extern int mkdir_p(const char *dir, mode_t mode);
__hidden extern char *get_rundir(void);

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

/*
 * Struct to carry child pid from lxc_popen() to lxc_pclose(). Not an opaque
 * struct to allow direct access to the underlying FILE without additional
 * wrappers.
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
__hidden extern struct lxc_popen_FILE *lxc_popen(const char *command);

/* pclose() replacement to be used on struct lxc_popen_FILE *,
 * returned by lxc_popen().
 * Waits for associated process to terminate, returns its exit status and
 * frees resources, pointed to by struct lxc_popen_FILE *.
 */
__hidden extern int lxc_pclose(struct lxc_popen_FILE *fp);

static inline void __auto_lxc_pclose__(struct lxc_popen_FILE **f)
{
	if (*f)
		lxc_pclose(*f);
}
#define __do_lxc_pclose __attribute__((__cleanup__(__auto_lxc_pclose__)))

/*
 * wait on a child we forked
 */
__hidden extern int wait_for_pid(pid_t pid);
__hidden extern int lxc_wait_for_pid_status(pid_t pid);
__hidden extern int wait_for_pidfd(int pidfd);

#if HAVE_OPENSSL
__hidden extern int sha1sum_file(char *fnam, unsigned char *md_value, unsigned int *md_len);
#endif

/* initialize rand with urandom */
__hidden extern int randseed(bool);

/* are we unprivileged with respect to our namespaces */
inline static bool am_guest_unpriv(void) {
	return geteuid() != 0;
}

/* are we unprivileged with respect to init_user_ns */
inline static bool am_host_unpriv(void)
{
	__do_fclose FILE *f = NULL;
	uid_t user, host, count;
	int ret;

	if (geteuid() != 0)
		return true;

	/* Now: are we in a user namespace? Because then we're also
	 * unprivileged.
	 */
	f = fopen("/proc/self/uid_map", "re");
	if (!f)
		return false;

	ret = fscanf(f, "%u %u %u", &user, &host, &count);
	if (ret != 3)
		return false;

	return user != 0 || host != 0 || count != UINT32_MAX;
}

/*
 * parse /proc/self/uid_map to find what @orig maps to
 */
__hidden extern uid_t get_ns_uid(uid_t orig);
/*
 * parse /proc/self/gid_map to find what @orig maps to
 */
__hidden extern gid_t get_ns_gid(gid_t orig);

__hidden extern bool dir_exists(const char *path);

#define FNV1A_64_INIT ((uint64_t)0xcbf29ce484222325ULL)
__hidden extern uint64_t fnv_64a_buf(void *buf, size_t len, uint64_t hval);

__hidden extern bool is_shared_mountpoint(const char *path);
__hidden extern int detect_shared_rootfs(void);
__hidden extern bool detect_ramfs_rootfs(void);
__hidden extern char *on_path(const char *cmd, const char *rootfs);
__hidden extern char *choose_init(const char *rootfs);
__hidden extern bool switch_to_ns(pid_t pid, const char *ns);
__hidden extern char *get_template_path(const char *t);
__hidden extern int safe_mount(const char *src, const char *dest, const char *fstype,
			       unsigned long flags, const void *data, const char *rootfs);
__hidden extern int open_devnull(void);
__hidden extern int set_stdfds(int fd);
__hidden extern int null_stdfds(void);
__hidden extern int lxc_preserve_ns(const int pid, const char *ns);

/* Check whether a signal is blocked by a process. */
__hidden extern bool task_blocks_signal(pid_t pid, int signal);

/* Switch to a new uid and gid.
 * If LXC_INVALID_{G,U}ID is passed then the set{g,u}id() will not be called.
 */
__hidden extern bool lxc_switch_uid_gid(uid_t uid, gid_t gid);
__hidden extern bool lxc_setgroups(gid_t list[], size_t size);
__hidden extern bool lxc_drop_groups(void);

/* Find an unused loop device and associate it with source. */
__hidden extern int lxc_prepare_loop_dev(const char *source, char *loop_dev, int flags);

/* Clear all mounts on a given node.
 * >= 0 successfully cleared. The number returned is the number of umounts
 *      performed.
 * < 0  error umounting. Return -errno.
 */
__hidden extern int lxc_unstack_mountpoint(const char *path, bool lazy);

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
__hidden extern int run_command(char *buf, size_t buf_size, int (*child_fn)(void *), void *args);

/*
 * run_command runs a command and collect it's std{err,out} output in buf, returns exit status.
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
__hidden extern int run_command_status(char *buf, size_t buf_size, int (*child_fn)(void *),
				       void *args);

__hidden extern bool lxc_nic_exists(char *nic);

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
__hidden extern uint64_t lxc_find_next_power2(uint64_t n);

/* Set a signal the child process will receive after the parent has died. */
__hidden extern int lxc_set_death_signal(int signal, pid_t parent, int parent_status_fd);
__hidden extern int lxc_rm_rf(const char *dirname);
__hidden extern bool lxc_can_use_pidfd(int pidfd);

__hidden extern int fix_stdio_permissions(uid_t uid);

static inline bool uid_valid(uid_t uid)
{
	return uid != LXC_INVALID_UID;
}

static inline bool gid_valid(gid_t gid)
{
	return gid != LXC_INVALID_GID;
}

__hidden extern bool multiply_overflow(int64_t base, uint64_t mult, int64_t *res);

__hidden extern int safe_mount_beneath(const char *beneath, const char *src, const char *dst,
				       const char *fstype, unsigned int flags, const void *data);
__hidden extern int safe_mount_beneath_at(int beneat_fd, const char *src, const char *dst,
					  const char *fstype, unsigned int flags, const void *data);
__hidden __lxc_unused int print_r(int fd, const char *path);

static inline int copy_struct_from_client(__u32 server_size, void *dst,
					  __u32 client_size, const void *src)
{
	__u32 size = min(server_size, client_size);
	__u32 rest = min(server_size, client_size) - size;

	/* Deal with trailing bytes. */
	if (client_size < server_size) {
		memset(dst + size, 0, rest);
	} else if (client_size > server_size) {
		/* TODO: Actually come up with a nice way to test for 0. */
		return 0;
	}

	memcpy(dst, src, size);
	return 0;
}

static inline __u32 copy_struct_to_client(__u32 client_size, void *dst,
					  __u32 server_size, const void *src)
{
	__u32 size = min(server_size, client_size);
	memcpy(dst, src, size);
	return size;
}

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
static inline int is_in_comm(const char *s)
{
	__do_free char *buf = NULL;
	__do_free char *comm = NULL;
	size_t buf_size;

	buf = file_to_buf("/proc/self/comm", &buf_size);
	if (!buf)
		return -1;

	if (buf_size == 0)
		return -1;

	comm = malloc(buf_size + 1);
	if (!comm)
		return -1;
	memcpy(comm, buf, buf_size);
	comm[buf_size] = '\0';

	return strstr(comm, s) != NULL;
}
#endif /* FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */

#endif /* __LXC_UTILS_H */

/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_FILE_UTILS_H
#define __LXC_FILE_UTILS_H

#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/vfs.h>
#include <unistd.h>

#include "compiler.h"

/* read and write whole files */
__hidden extern int lxc_write_to_file(const char *filename, const void *buf, size_t count,
				      bool add_newline, mode_t mode) __access_r(2, 3);

__hidden extern int lxc_readat(int dirfd, const char *filename, void *buf, size_t count)
    __access_w(3, 4);

__hidden extern int lxc_writeat(int dirfd, const char *filename, const void *buf, size_t count)
    __access_r(3, 4);

__hidden extern int lxc_write_openat(const char *dir, const char *filename, const void *buf,
				     size_t count) __access_r(3, 4);

__hidden extern int lxc_read_from_file(const char *filename, void *buf, size_t count)
    __access_w(2, 3);

/* send and receive buffers completely */
__hidden extern ssize_t lxc_write_nointr(int fd, const void *buf, size_t count) __access_r(2, 3);

__hidden extern ssize_t lxc_pwrite_nointr(int fd, const void *buf, size_t count, off_t offset)
    __access_r(2, 3);

__hidden extern ssize_t lxc_send_nointr(int sockfd, void *buf, size_t len, int flags)
    __access_r(2, 3);

__hidden extern ssize_t lxc_read_nointr(int fd, void *buf, size_t count) __access_w(2, 3);

__hidden extern ssize_t lxc_read_nointr_expect(int fd, void *buf, size_t count,
					       const void *expected_buf) __access_w(2, 3);

__hidden extern ssize_t lxc_read_file_expect(const char *path, void *buf, size_t count,
					     const void *expected_buf) __access_w(2, 3);

__hidden extern ssize_t lxc_recv_nointr(int sockfd, void *buf, size_t len, int flags)
    __access_w(2, 3);

__hidden extern ssize_t lxc_recvmsg_nointr_iov(int sockfd, struct iovec *iov, size_t iovlen,
					       int flags);

__hidden extern bool file_exists(const char *f);
__hidden extern int print_to_file(const char *file, const char *content);
__hidden extern int is_dir(const char *path);
__hidden extern int lxc_count_file_lines(const char *fn);
__hidden extern int lxc_make_tmpfile(char *template, bool rm);

/* __typeof__ should be safe to use with all compilers. */
typedef __typeof__(((struct statfs *)NULL)->f_type) fs_type_magic;
__hidden extern bool has_fs_type(const char *path, fs_type_magic magic_val);
__hidden extern bool fhas_fs_type(int fd, fs_type_magic magic_val);
__hidden extern bool is_fs_type(const struct statfs *fs, fs_type_magic magic_val);
__hidden extern FILE *fopen_cloexec(const char *path, const char *mode);
__hidden extern ssize_t lxc_sendfile_nointr(int out_fd, int in_fd, off_t *offset, size_t count);
__hidden extern char *file_to_buf(const char *path, size_t *length);
__hidden extern int fd_to_buf(int fd, char **buf, size_t *length);
__hidden extern int fd_to_fd(int from, int to);
__hidden extern int lxc_open_dirfd(const char *dir);
__hidden extern FILE *fdopen_cached(int fd, const char *mode, void **caller_freed_buffer);
__hidden extern FILE *fopen_cached(const char *path, const char *mode, void **caller_freed_buffer);
__hidden extern int timens_offset_write(clockid_t clk_id, int64_t s_offset, int64_t ns_offset);
__hidden extern bool exists_dir_at(int dir_fd, const char *path);
__hidden extern bool exists_file_at(int dir_fd, const char *path);
__hidden extern int open_beneath(int dir_fd, const char *path, unsigned int flags);

#endif /* __LXC_FILE_UTILS_H */

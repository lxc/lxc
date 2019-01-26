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

#ifndef __LXC_FILE_UTILS_H
#define __LXC_FILE_UTILS_H

#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <unistd.h>

/* read and write whole files */
extern int lxc_write_to_file(const char *filename, const void *buf,
			     size_t count, bool add_newline, mode_t mode);
extern int lxc_read_from_file(const char *filename, void *buf, size_t count);

/* send and receive buffers completely */
extern ssize_t lxc_write_nointr(int fd, const void *buf, size_t count);
extern ssize_t lxc_send_nointr(int sockfd, void *buf, size_t len, int flags);
extern ssize_t lxc_read_nointr(int fd, void *buf, size_t count);
extern ssize_t lxc_read_nointr_expect(int fd, void *buf, size_t count,
				      const void *expected_buf);
extern ssize_t lxc_recv_nointr(int sockfd, void *buf, size_t len, int flags);

extern bool file_exists(const char *f);
extern int print_to_file(const char *file, const char *content);
extern int is_dir(const char *path);
extern int lxc_count_file_lines(const char *fn);
extern int lxc_make_tmpfile(char *template, bool rm);

/* __typeof__ should be safe to use with all compilers. */
typedef __typeof__(((struct statfs *)NULL)->f_type) fs_type_magic;
extern bool has_fs_type(const char *path, fs_type_magic magic_val);
extern bool fhas_fs_type(int fd, fs_type_magic magic_val);
extern bool is_fs_type(const struct statfs *fs, fs_type_magic magic_val);
extern FILE *fopen_cloexec(const char *path, const char *mode);
extern ssize_t lxc_sendfile_nointr(int out_fd, int in_fd, off_t *offset,
				   size_t count);
extern char *file_to_buf(char *path, size_t *length);

#endif /* __LXC_FILE_UTILS_H */

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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/sendfile.h>
#include <sys/types.h>

#include "config.h"
#include "file_utils.h"
#include "macro.h"
#include "string_utils.h"

int lxc_write_to_file(const char *filename, const void *buf, size_t count,
		      bool add_newline, mode_t mode)
{
	int fd, saved_errno;
	ssize_t ret;

	fd = open(filename, O_WRONLY | O_TRUNC | O_CREAT | O_CLOEXEC, mode);
	if (fd < 0)
		return -1;

	ret = lxc_write_nointr(fd, buf, count);
	if (ret < 0)
		goto out_error;

	if ((size_t)ret != count)
		goto out_error;

	if (add_newline) {
		ret = lxc_write_nointr(fd, "\n", 1);
		if (ret != 1)
			goto out_error;
	}

	close(fd);
	return 0;

out_error:
	saved_errno = errno;
	close(fd);
	errno = saved_errno;
	return -1;
}

int lxc_read_from_file(const char *filename, void *buf, size_t count)
{
	int fd = -1, saved_errno;
	ssize_t ret;

	fd = open(filename, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;

	if (!buf || !count) {
		char buf2[100];
		size_t count2 = 0;

		while ((ret = lxc_read_nointr(fd, buf2, 100)) > 0)
			count2 += ret;

		if (ret >= 0)
			ret = count2;
	} else {
		memset(buf, 0, count);
		ret = lxc_read_nointr(fd, buf, count);
	}

	saved_errno = errno;
	close(fd);
	errno = saved_errno;
	return ret;
}

ssize_t lxc_write_nointr(int fd, const void *buf, size_t count)
{
	ssize_t ret;
again:
	ret = write(fd, buf, count);
	if (ret < 0 && errno == EINTR)
		goto again;

	return ret;
}

ssize_t lxc_send_nointr(int sockfd, void *buf, size_t len, int flags)
{
	ssize_t ret;
again:
	ret = send(sockfd, buf, len, flags);
	if (ret < 0 && errno == EINTR)
		goto again;

	return ret;
}

ssize_t lxc_read_nointr(int fd, void *buf, size_t count)
{
	ssize_t ret;
again:
	ret = read(fd, buf, count);
	if (ret < 0 && errno == EINTR)
		goto again;

	return ret;
}

ssize_t lxc_recv_nointr(int sockfd, void *buf, size_t len, int flags)
{
	ssize_t ret;
again:
	ret = recv(sockfd, buf, len, flags);
	if (ret < 0 && errno == EINTR)
		goto again;

	return ret;
}

ssize_t lxc_read_nointr_expect(int fd, void *buf, size_t count, const void *expected_buf)
{
	ssize_t ret;

	ret = lxc_read_nointr(fd, buf, count);
	if (ret <= 0)
		return ret;

	if ((size_t)ret != count)
		return -1;

	if (expected_buf && memcmp(buf, expected_buf, count) != 0) {
		errno = EINVAL;
		return -1;
	}

	return ret;
}

bool file_exists(const char *f)
{
	struct stat statbuf;

	return stat(f, &statbuf) == 0;
}

int print_to_file(const char *file, const char *content)
{
	FILE *f;
	int ret = 0;

	f = fopen(file, "w");
	if (!f)
		return -1;

	if (fprintf(f, "%s", content) != strlen(content))
		ret = -1;

	fclose(f);
	return ret;
}

int is_dir(const char *path)
{
	struct stat statbuf;
	int ret;

	ret = stat(path, &statbuf);
	if (ret == 0 && S_ISDIR(statbuf.st_mode))
		return 1;

	return 0;
}

/*
 * Return the number of lines in file @fn, or -1 on error
 */
int lxc_count_file_lines(const char *fn)
{
	FILE *f;
	char *line = NULL;
	size_t sz = 0;
	int n = 0;

	f = fopen_cloexec(fn, "r");
	if (!f)
		return -1;

	while (getline(&line, &sz, f) != -1) {
		n++;
	}

	free(line);
	fclose(f);
	return n;
}

int lxc_make_tmpfile(char *template, bool rm)
{
	int fd, ret;
	mode_t msk;

	msk = umask(0022);
	fd = mkstemp(template);
	umask(msk);
	if (fd < 0)
		return -1;

	if (!rm)
		return fd;

	ret = unlink(template);
	if (ret < 0) {
		close(fd);
		return -1;
	}

	return fd;
}

bool is_fs_type(const struct statfs *fs, fs_type_magic magic_val)
{
	return (fs->f_type == (fs_type_magic)magic_val);
}

bool has_fs_type(const char *path, fs_type_magic magic_val)
{
	int ret;
	struct statfs sb;

	ret = statfs(path, &sb);
	if (ret < 0)
		return false;

	return is_fs_type(&sb, magic_val);
}

bool fhas_fs_type(int fd, fs_type_magic magic_val)
{
	int ret;
	struct statfs sb;

	ret = fstatfs(fd, &sb);
	if (ret < 0)
		return false;

	return is_fs_type(&sb, magic_val);
}

FILE *fopen_cloexec(const char *path, const char *mode)
{
	int open_mode = 0;
	int step = 0;
	int fd;
	int saved_errno = 0;
	FILE *ret;

	if (!strncmp(mode, "r+", 2)) {
		open_mode = O_RDWR;
		step = 2;
	} else if (!strncmp(mode, "r", 1)) {
		open_mode = O_RDONLY;
		step = 1;
	} else if (!strncmp(mode, "w+", 2)) {
		open_mode = O_RDWR | O_TRUNC | O_CREAT;
		step = 2;
	} else if (!strncmp(mode, "w", 1)) {
		open_mode = O_WRONLY | O_TRUNC | O_CREAT;
		step = 1;
	} else if (!strncmp(mode, "a+", 2)) {
		open_mode = O_RDWR | O_CREAT | O_APPEND;
		step = 2;
	} else if (!strncmp(mode, "a", 1)) {
		open_mode = O_WRONLY | O_CREAT | O_APPEND;
		step = 1;
	}
	for (; mode[step]; step++)
		if (mode[step] == 'x')
			open_mode |= O_EXCL;
	open_mode |= O_CLOEXEC;

	fd = open(path, open_mode, 0660);
	if (fd < 0)
		return NULL;

	ret = fdopen(fd, mode);
	saved_errno = errno;
	if (!ret)
		close(fd);
	errno = saved_errno;
	return ret;
}

ssize_t lxc_sendfile_nointr(int out_fd, int in_fd, off_t *offset, size_t count)
{
	ssize_t ret;

again:
	ret = sendfile(out_fd, in_fd, offset, count);
	if (ret < 0) {
		if (errno == EINTR)
			goto again;

		return -1;
	}

	return ret;
}

char *file_to_buf(char *path, size_t *length)
{
	int fd;
	char buf[PATH_MAX];
	char *copy = NULL;

	if (!length)
		return NULL;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return NULL;

	*length = 0;
	for (;;) {
		int n;
		char *old = copy;

		n = lxc_read_nointr(fd, buf, sizeof(buf));
		if (n < 0)
			goto on_error;
		if (!n)
			break;

		copy = must_realloc(old, (*length + n) * sizeof(*old));
		memcpy(copy + *length, buf, n);
		*length += n;
	}

	close(fd);
	return copy;

on_error:
	close(fd);
	free(copy);

	return NULL;
}

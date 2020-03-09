/* SPDX-License-Identifier: LGPL-2.1+ */

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
#include "log.h"
#include "macro.h"
#include "memory_utils.h"
#include "string_utils.h"
#include "utils.h"

int lxc_open_dirfd(const char *dir)
{
	return open(dir, O_DIRECTORY | O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
}

int lxc_readat(int dirfd, const char *filename, void *buf, size_t count)
{
	__do_close_prot_errno int fd = -EBADF;
	ssize_t ret;

	fd = openat(dirfd, filename, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;

	ret = lxc_read_nointr(fd, buf, count);
	if (ret < 0 || (size_t)ret != count)
		return -1;

	return 0;
}

int lxc_writeat(int dirfd, const char *filename, const void *buf, size_t count)
{
	__do_close_prot_errno int fd = -EBADF;
	ssize_t ret;

	fd = openat(dirfd, filename,
		    O_WRONLY | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW);
	if (fd < 0)
		return -1;

	ret = lxc_write_nointr(fd, buf, count);
	if (ret < 0 || (size_t)ret != count)
		return -1;

	return 0;
}

int lxc_write_openat(const char *dir, const char *filename, const void *buf,
		     size_t count)
{
	__do_close_prot_errno int dirfd = -EBADF;

	dirfd = open(dir, O_DIRECTORY | O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW);
	if (dirfd < 0)
		return -1;

	return lxc_writeat(dirfd, filename, buf, count);
}

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

ssize_t lxc_recvmsg_nointr_iov(int sockfd, struct iovec *iov, size_t iovlen,
			       int flags)
{
	ssize_t ret;
	struct msghdr msg;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = iov;
	msg.msg_iovlen = iovlen;

again:
	ret = recvmsg(sockfd, &msg, flags);
	if (ret < 0 && errno == EINTR)
		goto again;

	return ret;
}

ssize_t lxc_read_nointr_expect(int fd, void *buf, size_t count, const void *expected_buf)
{
	ssize_t ret;

	ret = lxc_read_nointr(fd, buf, count);
	if (ret < 0)
		return ret;

	if ((size_t)ret != count)
		return -1;

	if (expected_buf && memcmp(buf, expected_buf, count) != 0) {
		errno = EINVAL;
		return -1;
	}

	return 0;
}

ssize_t lxc_read_file_expect(const char *path, void *buf, size_t count, const void *expected_buf)
{
	__do_close_prot_errno int fd = -EBADF;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;

	return lxc_read_nointr_expect(fd, buf, count, expected_buf);
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

	f = fopen(file, "we");
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
	__do_close_prot_errno int fd = -EBADF;
	int ret;
	mode_t msk;

	msk = umask(0022);
	fd = mkstemp(template);
	umask(msk);
	if (fd < 0)
		return -1;

	if (lxc_set_cloexec(fd))
		return -1;

	if (!rm)
		return move_fd(fd);

	ret = unlink(template);
	if (ret < 0)
		return -1;

	return move_fd(fd);
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

int fd_to_fd(int from, int to)
{
	for (;;) {
		uint8_t buf[PATH_MAX];
		uint8_t *p = buf;
		ssize_t bytes_to_write;
		ssize_t bytes_read;

		bytes_read = lxc_read_nointr(from, buf, sizeof buf);
		if (bytes_read < 0)
			return -1;
		if (bytes_read == 0)
			break;

		bytes_to_write = (size_t)bytes_read;
		do {
			ssize_t bytes_written;

			bytes_written = lxc_write_nointr(to, p, bytes_to_write);
			if (bytes_written < 0)
				return -1;

			bytes_to_write -= bytes_written;
			p += bytes_written;
		} while (bytes_to_write > 0);
	}

	return 0;
}

static char *fd_to_buf(int fd, size_t *length)
{
	__do_free char *copy = NULL;

	if (!length)
		return NULL;

	*length = 0;
	for (;;) {
		ssize_t bytes_read;
		char buf[4096];
		char *old = copy;

		bytes_read = lxc_read_nointr(fd, buf, sizeof(buf));
		if (bytes_read < 0)
			return NULL;

		if (!bytes_read)
			break;

		copy = must_realloc(old, (*length + bytes_read) * sizeof(*old));
		memcpy(copy + *length, buf, bytes_read);
		*length += bytes_read;
	}

	return move_ptr(copy);
}

char *file_to_buf(const char *path, size_t *length)
{
	__do_close_prot_errno int fd = -EBADF;

	if (!length)
		return NULL;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return NULL;

	return fd_to_buf(fd, length);
}

FILE *fopen_cached(const char *path, const char *mode, void **caller_freed_buffer)
{
	__do_free char *buf = NULL;
	size_t len = 0;
	FILE *f;

	buf = file_to_buf(path, &len);
	if (!buf)
		return NULL;

	f = fmemopen(buf, len, mode);
	if (!f)
		return NULL;
	*caller_freed_buffer = move_ptr(buf);
	return f;
}

FILE *fdopen_cached(int fd, const char *mode, void **caller_freed_buffer)
{
	__do_free char *buf = NULL;
	size_t len = 0;
	FILE *f;

	buf = fd_to_buf(fd, &len);
	if (!buf)
		return NULL;

	f = fmemopen(buf, len, mode);
	if (!f)
		return NULL;

	*caller_freed_buffer = move_ptr(buf);
	return f;
}

/* SPDX-License-Identifier: LGPL-2.1+ */

#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#include "file_utils.h"
#include "macro.h"
#include "memory_utils.h"
#include "string_utils.h"
#include "syscall_wrappers.h"
#include "utils.h"

int lxc_open_dirfd(const char *dir)
{
	return open_at(-EBADF, dir, PROTECT_OPATH_DIRECTORY, PROTECT_LOOKUP_ABSOLUTE & ~RESOLVE_NO_XDEV, 0);
}

int lxc_readat(int dirfd, const char *filename, void *buf, size_t count)
{
	__do_close int fd = -EBADF;
	ssize_t ret;

	fd = open_at(dirfd, filename, PROTECT_OPEN, PROTECT_LOOKUP_BENEATH, 0);
	if (fd < 0)
		return -errno;

	ret = lxc_read_nointr(fd, buf, count);
	if (ret < 0)
		return -errno;

	return ret;
}

int lxc_writeat(int dirfd, const char *filename, const void *buf, size_t count)
{
	__do_close int fd = -EBADF;
	ssize_t ret;

	fd = open_at(dirfd, filename, PROTECT_OPEN_W_WITH_TRAILING_SYMLINKS, PROTECT_LOOKUP_BENEATH, 0);
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
	__do_close int dirfd = -EBADF;

	dirfd = open(dir, PROTECT_OPEN);
	if (dirfd < 0)
		return -errno;

	return lxc_writeat(dirfd, filename, buf, count);
}

int lxc_write_to_file(const char *filename, const void *buf, size_t count,
		      bool add_newline, mode_t mode)
{
	__do_close int fd = -EBADF;
	ssize_t ret;

	fd = open(filename, O_WRONLY | O_TRUNC | O_CREAT | O_CLOEXEC, mode);
	if (fd < 0)
		return -1;

	ret = lxc_write_nointr(fd, buf, count);
	if (ret < 0)
		return -1;

	if ((size_t)ret != count)
		return -1;

	if (add_newline) {
		ret = lxc_write_nointr(fd, "\n", 1);
		if (ret != 1)
			return -1;
	}

	return 0;
}

int lxc_read_from_file(const char *filename, void *buf, size_t count)
{
	__do_close int fd = -EBADF;
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

	return ret;
}

ssize_t lxc_read_try_buf_at(int dfd, const char *path, void *buf, size_t count)
{
	__do_close int fd = -EBADF;
	ssize_t ret;

	fd = open_at(dfd, path, PROTECT_OPEN, PROTECT_LOOKUP_BENEATH, 0);
	if (fd < 0)
		return -errno;

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

	return ret;
}

ssize_t lxc_write_nointr(int fd, const void *buf, size_t count)
{
	ssize_t ret;

	do {
		ret = write(fd, buf, count);
	} while (ret < 0 && errno == EINTR);

	return ret;
}

ssize_t lxc_pwrite_nointr(int fd, const void *buf, size_t count, off_t offset)
{
	ssize_t ret;

	do {
		ret = pwrite(fd, buf, count, offset);
	} while (ret < 0 && errno == EINTR);

	return ret;
}

ssize_t lxc_send_nointr(int sockfd, void *buf, size_t len, int flags)
{
	ssize_t ret;

	do {
		ret = send(sockfd, buf, len, flags);
	} while (ret < 0 && errno == EINTR);

	return ret;
}

ssize_t lxc_read_nointr(int fd, void *buf, size_t count)
{
	ssize_t ret;

	do {
		ret = read(fd, buf, count);
	} while (ret < 0 && errno == EINTR);

	return ret;
}

ssize_t lxc_recv_nointr(int sockfd, void *buf, size_t len, int flags)
{
	ssize_t ret;

	do {
		ret = recv(sockfd, buf, len, flags);
	} while (ret < 0 && errno == EINTR);

	return ret;
}

ssize_t lxc_recvmsg_nointr_iov(int sockfd, struct iovec *iov, size_t iovlen,
			       int flags)
{
	ssize_t ret;
	struct msghdr msg = {
		.msg_iov = iov,
		.msg_iovlen = iovlen,
	};

	do {
		ret = recvmsg(sockfd, &msg, flags);
	} while (ret < 0 && errno == EINTR);

	return ret;
}

ssize_t lxc_read_nointr_expect(int fd, void *buf, size_t count,
			       const void *expected_buf)
{
	ssize_t ret;

	ret = lxc_read_nointr(fd, buf, count);
	if (ret < 0)
		return ret;

	if ((size_t)ret != count)
		return -1;

	if (expected_buf && memcmp(buf, expected_buf, count) != 0)
		return ret_set_errno(-1, EINVAL);

	return 0;
}

ssize_t lxc_read_file_expect(const char *path, void *buf, size_t count,
			     const void *expected_buf)
{
	__do_close int fd = -EBADF;

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
	__do_fclose FILE *f = NULL;
	int ret;
	size_t len;

	f = fopen(file, "we");
	if (!f)
		return -1;

	len = strlen(content);
	ret = fprintf(f, "%s", content);
	if (ret < 0 || (size_t)ret != len)
		ret = -1;
	else
		ret = 0;

	return ret;
}

int is_dir(const char *path)
{
	int ret;
	struct stat statbuf;

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
	__do_free char *line = NULL;
	__do_fclose FILE *f = NULL;
	size_t sz = 0;
	int n = 0;

	f = fopen_cloexec(fn, "r");
	if (!f)
		return -1;

	while (getline(&line, &sz, f) != -1)
		n++;

	return n;
}

int lxc_make_tmpfile(char *template, bool rm)
{
	__do_close int fd = -EBADF;
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
	__do_close int fd = -EBADF;
	int open_mode = 0, step = 0;
	FILE *f;

	if (strnequal(mode, "r+", 2)) {
		open_mode = O_RDWR;
		step = 2;
	} else if (strnequal(mode, "r", 1)) {
		open_mode = O_RDONLY;
		step = 1;
	} else if (strnequal(mode, "w+", 2)) {
		open_mode = O_RDWR | O_TRUNC | O_CREAT;
		step = 2;
	} else if (strnequal(mode, "w", 1)) {
		open_mode = O_WRONLY | O_TRUNC | O_CREAT;
		step = 1;
	} else if (strnequal(mode, "a+", 2)) {
		open_mode = O_RDWR | O_CREAT | O_APPEND;
		step = 2;
	} else if (strnequal(mode, "a", 1)) {
		open_mode = O_WRONLY | O_CREAT | O_APPEND;
		step = 1;
	}
	for (; mode[step]; step++)
		if (mode[step] == 'x')
			open_mode |= O_EXCL;

	fd = open(path, open_mode | O_CLOEXEC, 0660);
	if (fd < 0)
		return NULL;

	f = fdopen(fd, mode);
	if (f)
		move_fd(fd);
	return f;
}

ssize_t lxc_sendfile_nointr(int out_fd, int in_fd, off_t *offset, size_t count)
{
	ssize_t ret;

	do {
		ret = sendfile(out_fd, in_fd, offset, count);
	} while (ret < 0 && errno == EINTR);

	return ret;
}

ssize_t __fd_to_fd(int from, int to)
{
	ssize_t total_bytes = 0;

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
		total_bytes += bytes_read;
		do {
			ssize_t bytes_written;

			bytes_written = lxc_write_nointr(to, p, bytes_to_write);
			if (bytes_written < 0)
				return -1;

			bytes_to_write -= bytes_written;
			p += bytes_written;
		} while (bytes_to_write > 0);
	}

	return total_bytes;
}

int fd_to_buf(int fd, char **buf, size_t *length)
{
	__do_free char *copy = NULL;

	if (!length)
		return 0;

	*length = 0;
	for (;;) {
		ssize_t bytes_read;
		char chunk[4096];
		char *old = copy;

		bytes_read = lxc_read_nointr(fd, chunk, sizeof(chunk));
		if (bytes_read < 0)
			return -errno;

		if (!bytes_read)
			break;

		copy = realloc(old, (*length + bytes_read) * sizeof(*old));
		if (!copy)
			return ret_errno(ENOMEM);

		memcpy(copy + *length, chunk, bytes_read);
		*length += bytes_read;
	}

	*buf = move_ptr(copy);
	return 0;
}

char *file_to_buf(const char *path, size_t *length)
{
	__do_close int fd = -EBADF;
	char *buf = NULL;

	if (!length)
		return NULL;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return NULL;

	if (fd_to_buf(fd, &buf, length) < 0)
		return NULL;

	return buf;
}

FILE *fopen_cached(const char *path, const char *mode, void **caller_freed_buffer)
{
#ifdef HAVE_FMEMOPEN
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
#else
	return fopen(path, mode);
#endif
}

FILE *fdopen_cached(int fd, const char *mode, void **caller_freed_buffer)
{
	FILE *f;
#ifdef HAVE_FMEMOPEN
	__do_free char *buf = NULL;
	size_t len = 0;

	if (fd_to_buf(fd, &buf, &len) < 0)
		return NULL;

	f = fmemopen(buf, len, mode);
	if (!f)
		return NULL;

	*caller_freed_buffer = move_ptr(buf);

#else

	__do_close int dupfd = -EBADF;

	dupfd = dup(fd);
	if (dupfd < 0)
		return NULL;

	f = fdopen(dupfd, "re");
	if (!f)
		return NULL;

	/* Transfer ownership of fd. */
	move_fd(dupfd);
#endif
	return f;
}

int fd_cloexec(int fd, bool cloexec)
{
	int oflags, nflags;

	oflags = fcntl(fd, F_GETFD, 0);
	if (oflags < 0)
		return -errno;

	if (cloexec)
		nflags = oflags | FD_CLOEXEC;
	else
		nflags = oflags & ~FD_CLOEXEC;

	if (nflags == oflags)
		return 0;

	if (fcntl(fd, F_SETFD, nflags) < 0)
		return -errno;

	return 0;
}

FILE *fdopen_at(int dfd, const char *path, const char *mode,
		unsigned int o_flags, unsigned int resolve_flags)
{
	__do_close int fd = -EBADF;
	__do_fclose FILE *f = NULL;

	if (is_empty_string(path))
		fd = dup_cloexec(dfd);
	else
		fd = open_at(dfd, path, o_flags, resolve_flags, 0);
	if (fd < 0)
		return NULL;

	f = fdopen(fd, "re");
	if (!f)
		return NULL;

	/* Transfer ownership of fd. */
	move_fd(fd);

	return move_ptr(f);
}

int timens_offset_write(clockid_t clk_id, int64_t s_offset, int64_t ns_offset)
{
	__do_close int fd = -EBADF;
	ssize_t len, ret;
	char buf[INTTYPE_TO_STRLEN(int) +
		 STRLITERALLEN(" ") + INTTYPE_TO_STRLEN(int64_t) +
		 STRLITERALLEN(" ") + INTTYPE_TO_STRLEN(int64_t) + 1];

	if (clk_id == CLOCK_MONOTONIC_COARSE || clk_id == CLOCK_MONOTONIC_RAW)
		clk_id = CLOCK_MONOTONIC;

	fd = open("/proc/self/timens_offsets", O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;

	len = strnprintf(buf, sizeof(buf), "%d %" PRId64 " %" PRId64, clk_id, s_offset, ns_offset);
	if (len < 0)
		return ret_errno(EFBIG);

	ret = lxc_write_nointr(fd, buf, len);
	if (ret < 0 || ret != len)
		return -EIO;

	return 0;
}

bool exists_dir_at(int dir_fd, const char *path)
{
	int ret;
	struct stat sb;

	ret = fstatat(dir_fd, path, &sb, 0);
	if (ret < 0)
		return false;

	ret = S_ISDIR(sb.st_mode);
	if (ret)
		errno = EEXIST;
	else
		errno = ENOTDIR;

	return ret;
}

bool exists_file_at(int dir_fd, const char *path)
{
	int ret;
	struct stat sb;

	ret = fstatat(dir_fd, path, &sb, 0);
	if (ret == 0)
		errno = EEXIST;
	return ret == 0;
}

int open_at(int dfd, const char *path, unsigned int o_flags,
	    unsigned int resolve_flags, mode_t mode)
{
	__do_close int fd = -EBADF;
	struct lxc_open_how how = {
		.flags		= o_flags,
		.mode		= mode,
		.resolve	= resolve_flags,
	};

	fd = openat2(dfd, path, &how, sizeof(how));
	if (fd >= 0)
		return move_fd(fd);

	if (errno != ENOSYS)
		return -errno;

	fd = openat(dfd, path, o_flags, mode);
	if (fd < 0)
		return -errno;

	return move_fd(fd);
}

int open_at_same(int fd_same, int dfd, const char *path, unsigned int o_flags,
		 unsigned int resolve_flags, mode_t mode)
{
	__do_close int fd = -EBADF;

	fd = open_at(dfd, path, o_flags, resolve_flags, mode);
	if (fd < 0)
		return -errno;

	if (!same_file_lax(fd_same, fd))
		return ret_errno(EINVAL);

	return move_fd(fd);
}

int fd_make_nonblocking(int fd)
{
	int flags;

	flags = fcntl(fd, F_GETFL);
	if (flags < 0)
		return -1;

	flags &= ~O_NONBLOCK;
	return fcntl(fd, F_SETFL, flags);
}

#define BATCH_SIZE 50
static void batch_realloc(char **mem, size_t oldlen, size_t newlen)
{
	int newbatches = (newlen / BATCH_SIZE) + 1;
	int oldbatches = (oldlen / BATCH_SIZE) + 1;

	if (!*mem || newbatches > oldbatches)
		*mem = must_realloc(*mem, newbatches * BATCH_SIZE);
}

static void append_line(char **dest, size_t oldlen, char *new, size_t newlen)
{
	size_t full = oldlen + newlen;

	batch_realloc(dest, oldlen, full + 1);

	memcpy(*dest + oldlen, new, newlen + 1);
}

/* Slurp in a whole file */
char *read_file_at(int dfd, const char *fnam,
		   unsigned int o_flags, unsigned resolve_flags)
{
	__do_close int fd = -EBADF;
	__do_free char *buf = NULL, *line = NULL;
	__do_fclose FILE *f = NULL;
	size_t len = 0, fulllen = 0;
	int linelen;

	fd = open_at(dfd, fnam, o_flags, resolve_flags, 0);
	if (fd < 0)
		return NULL;

	f = fdopen(fd, "re");
	if (!f)
		return NULL;
	/* Transfer ownership to fdopen(). */
	move_fd(fd);

	while ((linelen = getline(&line, &len, f)) != -1) {
		append_line(&buf, fulllen, line, linelen);
		fulllen += linelen;
	}

	return move_ptr(buf);
}

bool same_file_lax(int fda, int fdb)
{
	struct stat st_fda, st_fdb;


        if (fda == fdb)
                return true;

        if (fstat(fda, &st_fda) < 0)
                return false;

        if (fstat(fdb, &st_fdb) < 0)
                return false;

	errno = EINVAL;
	if ((st_fda.st_mode & S_IFMT) != (st_fdb.st_mode & S_IFMT))
		return false;

	errno = EINVAL;
	return (st_fda.st_dev == st_fdb.st_dev) &&
	       (st_fda.st_ino == st_fdb.st_ino);
}

bool same_device(int fda, const char *patha, int fdb, const char *pathb)
{
	int ret;
	mode_t modea, modeb;
	struct stat st_fda, st_fdb;

        if (fda == fdb)
                return true;

	if (is_empty_string(patha))
		ret = fstat(fda, &st_fda);
	else
		ret = fstatat(fda, patha, &st_fda, 0);
	if (ret)
		return false;

	if (is_empty_string(pathb))
		ret = fstat(fdb, &st_fdb);
	else
		ret = fstatat(fdb, pathb, &st_fdb, 0);
	if (ret)
		return false;

	errno = EINVAL;
	modea = (st_fda.st_mode & S_IFMT);
	modeb = (st_fdb.st_mode & S_IFMT);
	if (modea != modeb || !IN_SET(modea, S_IFCHR, S_IFBLK))
		return false;

	return (st_fda.st_rdev == st_fdb.st_rdev);
}

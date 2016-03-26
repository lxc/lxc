/*
 *
 * Copyright © 2016 Christian Brauner <christian.brauner@mailbox.org>.
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

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "lxc/utils.h"

#define TSTERR(fmt, ...) do { \
	fprintf(stderr, "%s:%d " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__); fflush(NULL); \
} while (0)

static bool is_expected_size(int fd, long expected_size)
{
	struct stat f;
	if (fstat(fd, &f) < 0) {
		TSTERR("Failed to fstat file descriptor %d of temporary file", fd);
		return false;
	}

	if (f.st_size != expected_size)
		return false;

	return true;
}

/*
 * Test whether mapping a file exactly the size of a single page is handeled
 * correctly. Expected behaviour:
 *	- lxc_mmap_str() will extend the underlying file by exactly one
 *	  terminating \0-byte.
 *	- lxc_munmap_str() will truncate the underlying file back to its
 *	  original size.
 */
static int test_pagesize_1(long pagesize)
{
	int ret = -1;
	char buf[1];
	char tmp[PATH_MAX] = "tmp_XXXXXX";

	// create unique temporary file
	int fd = mkstemp(tmp);
	if (fd < 0) {
		TSTERR("Failed to create temporary file.");
		exit(EXIT_FAILURE);
	}

	/* First test: Resize the file to exactly the size of a single page on
	 * the system. */
	if (ftruncate(fd, pagesize) < 0) {
		TSTERR("Failed to resize file.");
		goto out;
	}

	// Write a dummy letter as the last byte of the file.
	if (pwrite(fd, "A", 1, pagesize - 1) <= 0) {
		TSTERR("Failed to write dummy byte to file.");
		goto out;
	}

	if (!is_expected_size(fd, pagesize)) {
		TSTERR("Size of the file was not equal to one page.");
		goto out;
	}

	// Read the last byte of the file.
	if (pread(fd, &buf, 1, pagesize - 1) <= 0) {
		TSTERR("Failed to read next to last byte from file.");
		goto out;
	}

	// Check if it is really the dummy letter we read.
	if (*buf != 'A') {
		TSTERR("Next to last byte of file was not equal to 'A'.");
		goto out;
	}

	/* First test: We have just created a file exactly the size of a single
	 * page. That means mmap_file_to_str() should write a terminating
	 * \0-byte to the underlying file. */
	bool wrote_zero;
	char *map = lxc_mmap_str(NULL, pagesize, MAP_PRIVATE, fd, 0, &wrote_zero);
	if (!map) {
		TSTERR("Could not establish a mapping for the underlying file.");
		goto out;
	}

	// File should be exactly one byte bigger after calling lxc_mmap_str().
	if (!is_expected_size(fd, pagesize + 1)) {
		TSTERR("Size of the file was not equal to one page + one extra terminating \\0-byte.");
		goto out;
	}

	/* If the last byte is not \0 then mmap_file_to_str() is not behaving as
	 * advertised. */
	if (map[pagesize] != '\0') {
		TSTERR("Last byte was not '\\0'.");
		goto out;
	}

	if (map[pagesize - 1] != 'A') {
		TSTERR("Next to last byte was not 'A'.");
		goto out;
	}

	if (!wrote_zero) {
		TSTERR("We falsely reported that we did write not write a terminating '\\0'-byte to the underlying file.");
		goto out;
	}

	if (lxc_munmap_str(map, pagesize, pagesize, fd, wrote_zero) < 0) {
		TSTERR("Could not unmap the underlying file.");
		goto out;
	}

	/* File should be exactly the size of a single page after the call to
	 * lxc_munmap_str(). */
	if (!is_expected_size(fd, pagesize)) {
		TSTERR("Size of the file was not equal to one page.");
		goto out;
	}

	ret = 0;
out:
	unlink(tmp);
	close(fd);
	return ret;
}

/*
 * Test whether mapping a file exactly one byte less than the size of a single
 * page is handeled correctly. Expected behaviour:
 *	- lxc_mmap_str() will not extend the underlying file.
 *	- lxc_munmap_str() will not change the size of the underlying file.
 */
static int test_pagesize_2(long pagesize)
{
	int ret = -1;
	char buf[1];
	char tmp[PATH_MAX] = "tmp_XXXXXX";

	// create unique temporary file
	int fd = mkstemp(tmp);
	if (fd < 0) {
		TSTERR("Failed to create temporary file.");
		exit(EXIT_FAILURE);
	}

	/* Second test: Resize the file to exactly one byte less than the page
	 * size. */
	if (ftruncate(fd, pagesize - 1) < 0) {
		TSTERR("Failed to resize file.");
		goto out;
	}

	// Write a dummy letter as the last byte of the file.
	if (pwrite(fd, "A", 1, pagesize - 2) < 0) {
		TSTERR("Failed to write dummy byte as next to last byte to file.");
		goto out;
	}

	if (!is_expected_size(fd, pagesize - 1)) {
		TSTERR("Size of the file was not exactly one byte less than a single page.");
		goto out;
	}

	// Read the last byte of the file.
	if (pread(fd, &buf, 1, pagesize - 2) <= 0) {
		TSTERR("Failed to read next to last byte from file.");
		goto out;
	}

	// Check if it is really the dummy letter we read.
	if (*buf != 'A') {
		TSTERR("Next to last byte of file was not equal to 'A'.");
		goto out;
	}

	/* Second test: We have just created a file whose size is exactly one
	 * byte less than the size of a single page. That means
	 * mmap_file_to_str() should not write a terminating \0-byte to the
	 * underlying file. */
	bool wrote_zero;
	char *map = lxc_mmap_str(NULL, pagesize - 1, MAP_PRIVATE, fd, 0, &wrote_zero);
	if (!map) {
		TSTERR("Could not establish a mapping for the underlying file.");
		goto out;
	}

	if (!is_expected_size(fd, pagesize - 1)) {
		TSTERR("Size of the file was not equal to one page - one byte.");
		goto out;
	}

	/* If the last byte is not \0 then mmap_file_to_str() is not behaving as
	 * advertised. */
	if (map[pagesize - 1] != '\0') {
		TSTERR("Last byte was not '\\0'.");
		goto out;
	}

	if (map[pagesize - 2] != 'A') {
		TSTERR("Next to last byte was not 'A'.");
		goto out;
	}

	if (wrote_zero) {
		TSTERR("We falsely reported that we did write a terminating '\\0'-byte to the underlying file.");
		goto out;
	}

	if (lxc_munmap_str(map, pagesize - 1, pagesize - 1, fd, wrote_zero) < 0) {
		TSTERR("Could not unmap the underlying file.");
		goto out;
	}

	/* File should be exactly the size of a single page minus one byte after
	 * the call to lxc_munmap_str(). */
	if (!is_expected_size(fd, pagesize - 1)) {
		TSTERR("Size of the file was not equal to one page.");
		goto out;
	}

	ret = 0;
out:
	unlink(tmp);
	close(fd);
	return ret;
}

int main(int argc, char *argv[])
{
	long pagesize = sysconf(_SC_PAGESIZE);
	if (pagesize <= 0)
		exit(EXIT_FAILURE);

	if (test_pagesize_1(pagesize) < 0)
		exit(EXIT_FAILURE);

	if (test_pagesize_2(pagesize) < 0)
		exit(EXIT_FAILURE);

	exit(EXIT_SUCCESS);
}

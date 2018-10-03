/* liblxcapi
 *
 * Copyright © 2017 Christian Brauner <christian.brauner@ubuntu.com>.
 * Copyright © 2017 Canonical Ltd.
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
#define __STDC_FORMAT_MACROS
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "config.h"
#include "ringbuf.h"
#include "syscall_wrappers.h"
#include "utils.h"

int lxc_ringbuf_create(struct lxc_ringbuf *buf, size_t size)
{
	char *tmp;
	int ret;
	int memfd = -1;

	buf->size = size;
	buf->r_off = 0;
	buf->w_off = 0;

	/* verify that we are at least given the multiple of a page size */
	if (buf->size % lxc_getpagesize())
		return -EINVAL;

	buf->addr = mmap(NULL, buf->size * 2, PROT_NONE,
			 MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (buf->addr == MAP_FAILED)
		return -EINVAL;

	memfd = memfd_create(".lxc_ringbuf", MFD_CLOEXEC);
	if (memfd < 0) {
		char template[] = P_tmpdir "/.lxc_ringbuf_XXXXXX";

		if (errno != ENOSYS)
			goto on_error;

		memfd = lxc_make_tmpfile(template, true);
	}
	if (memfd < 0)
		goto on_error;

	ret = ftruncate(memfd, buf->size);
	if (ret < 0)
		goto on_error;

	tmp = mmap(buf->addr, buf->size, PROT_READ | PROT_WRITE,
		   MAP_FIXED | MAP_SHARED, memfd, 0);
	if (tmp == MAP_FAILED || tmp != buf->addr)
		goto on_error;

	tmp = mmap(buf->addr + buf->size, buf->size, PROT_READ | PROT_WRITE,
		   MAP_FIXED | MAP_SHARED, memfd, 0);
	if (tmp == MAP_FAILED || tmp != (buf->addr + buf->size))
		goto on_error;

	close(memfd);

	return 0;

on_error:
	lxc_ringbuf_release(buf);
	if (memfd >= 0)
		close(memfd);
	return -1;
}

void lxc_ringbuf_move_read_addr(struct lxc_ringbuf *buf, size_t len)
{
	buf->r_off += len;

	if (buf->r_off < buf->size)
		return;

	/* wrap around */
	buf->r_off -= buf->size;
	buf->w_off -= buf->size;
}

/**
 * lxc_ringbuf_write - write a message to the ringbuffer
 * - The size of the message should never be greater than the size of the whole
 *   ringbuffer.
 * - The write method will always succeed i.e. it will always advance the r_off
 *   if it detects that there's not enough space available to write the
 *   message.
 */
int lxc_ringbuf_write(struct lxc_ringbuf *buf, const char *msg, size_t len)
{
	char *w_addr;
	uint64_t free;

	/* sanity check: a write should never exceed the ringbuffer's total size */
	if (len > buf->size)
		return -EFBIG;

	free = lxc_ringbuf_free(buf);

	/* not enough space left so advance read address */
	if (len > free)
		lxc_ringbuf_move_read_addr(buf, len);
	w_addr = lxc_ringbuf_get_write_addr(buf);
	memcpy(w_addr, msg, len);
	lxc_ringbuf_move_write_addr(buf, len);
	return 0;
}

int lxc_ringbuf_read(struct lxc_ringbuf *buf, char *out, size_t *len)
{
	uint64_t used;

	/* there's nothing to read */
	if (buf->r_off == buf->w_off)
		return -ENODATA;

	/* read maximum amount available */
	used = lxc_ringbuf_used(buf);
	if (used < *len)
		*len = used;

	/* copy data to reader but don't advance addr */
	memcpy(out, lxc_ringbuf_get_read_addr(buf), *len);
	out[*len - 1] = '\0';
	return 0;
}

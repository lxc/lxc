/* liblxcapi
 *
 * Copyright © 2017 Christian Brauner <christian.brauner@ubuntu.com>.
 * Copyright © 2017 Canonical Ltd.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.

 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef __LXC_RINGBUF_H
#define __LXC_RINGBUF_H

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/mman.h>

/**
 * lxc_ringbuf - Implements a simple and efficient memory mapped ringbuffer.
 * - The "addr" field of struct lxc_ringbuf is considered immutable. Instead the
 *   read and write offsets r_off and w_off are used to calculate the current
 *   read and write addresses. There should never be a need to use any of those
 *   fields directly. Instead use the appropriate helpers below.
 * - Callers are expected to synchronize read and write accesses to the
 *   ringbuffer.
 */
struct lxc_ringbuf {
	char *addr; /* start address of the ringbuffer */
	uint64_t size; /* total size of the ringbuffer in bytes */
	uint64_t r_off; /* read offset */
	uint64_t w_off; /* write offset */
};

/**
 * lxc_ringbuf_create - Initialize a new ringbuffer.
 *
 * @param[in] size	Size of the new ringbuffer as a power of 2.
 */
extern int lxc_ringbuf_create(struct lxc_ringbuf *buf, size_t size);
extern void lxc_ringbuf_move_read_addr(struct lxc_ringbuf *buf, size_t len);
extern int lxc_ringbuf_write(struct lxc_ringbuf *buf, const char *msg, size_t len);
extern int lxc_ringbuf_read(struct lxc_ringbuf *buf, char *out, size_t *len);

static inline void lxc_ringbuf_release(struct lxc_ringbuf *buf)
{
	munmap(buf->addr, buf->size * 2);
}

static inline void lxc_ringbuf_clear(struct lxc_ringbuf *buf)
{
	buf->r_off = 0;
	buf->w_off = 0;
}

static inline uint64_t lxc_ringbuf_used(struct lxc_ringbuf *buf)
{
	return buf->w_off - buf->r_off;
}

static inline uint64_t lxc_ringbuf_free(struct lxc_ringbuf *buf)
{
	return buf->size - lxc_ringbuf_used(buf);
}

static inline char *lxc_ringbuf_get_read_addr(struct lxc_ringbuf *buf)
{
	return buf->addr + buf->r_off;
}

static inline char *lxc_ringbuf_get_write_addr(struct lxc_ringbuf *buf)
{
	return buf->addr + buf->w_off;
}

static inline void lxc_ringbuf_move_write_addr(struct lxc_ringbuf *buf, size_t len)
{
	buf->w_off += len;
}

#endif /* __LXC_RINGBUF_H */

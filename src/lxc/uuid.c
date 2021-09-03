/* SPDX-License-Identifier: LGPL-2.1+ */

#define _GNU_SOURCE
#define __STDC_FORMAT_MACROS /* Required for PRIu64 to work. */
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/types.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"
#include "file_utils.h"
#include "memory_utils.h"
#include "uuid.h"

static lxc_id128_t make_v4_uuid(lxc_id128_t id)
{
	/* Stolen from generate_random_uuid() of drivers/char/random.c
	 * in the kernel sources */

	/* Set UUID version to 4 --- truly random generation */
	id.bytes[6] = (id.bytes[6] & 0x0F) | 0x40;

	/* Set the UUID variant to DCE */
	id.bytes[8] = (id.bytes[8] & 0x3F) | 0x80;

	return id;
}

static int get_random_bytes(void *p, size_t n)
{
	__do_close int fd = -EBADF;
	ssize_t bytes = 0;

	fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC | O_NOCTTY);
	if (fd < 0)
		return -1;

	bytes = read(fd, p, n);
	if ((size_t)bytes != n)
		return -1;

	return 0;
}

int lxc_id128_randomize(lxc_id128_t *ret)
{
	lxc_id128_t t;
	int r;

	/* We allow usage if x86-64 RDRAND here. It might not be trusted enough
	 * for keeping secrets, but it should be fine for UUIDS. */
	r = get_random_bytes(&t, sizeof(t));
	if (r < 0)
		return r;

	/* Turn this into a valid v4 UUID, to be nice. Note that we
	 * only guarantee this for newly generated UUIDs, not for
	 * pre-existing ones. */

	*ret = make_v4_uuid(t);
	return 0;
}

static char hexchar(int x)
{
	static const char table[16] = "0123456789abcdef";

	return table[x & 15];
}

char *id128_to_uuid_string(lxc_id128_t id, char s[37])
{
	unsigned n, k = 0;

	for (n = 0; n < 16; n++) {

		if (n == 4 || n == 6 || n == 8 || n == 10)
			s[k++] = '-';

		s[k++] = hexchar(id.bytes[n] >> 4);
		s[k++] = hexchar(id.bytes[n] & 0xF);
	}

	s[k] = 0;

	return s;
}

int lxc_id128_write_fd(int fd, lxc_id128_t id)
{
	char buffer[36 + 2];
	size_t sz;
	int ret;

	id128_to_uuid_string(id, buffer);
	buffer[36] = '\n';
	sz = 37;

	ret = lxc_write_nointr(fd, buffer, sz);
	if (ret < 0)
		return -1;

	return 0;
}

int lxc_id128_write(const char *p, lxc_id128_t id)
{
	__do_close int fd = -EBADF;

        fd = open(p, O_WRONLY|O_CREAT|O_CLOEXEC|O_NOCTTY|O_TRUNC, 0444);
        if (fd < 0)
                return -1;

        return lxc_id128_write_fd(fd, id);
}

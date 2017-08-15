/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2008
 *
 * Authors:
 * Daniel Lezcano <daniel.lezcano at free.fr>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef __LXC_RSYNC_H
#define __LXC_RSYNC_H

#define _GNU_SOURCE
#include <stdio.h>

struct rsync_data {
	struct bdev *orig;
	struct bdev *new;
};

struct rsync_data_char {
	char *src;
	char *dest;
};

int do_rsync(const char *src, const char *dest);
int rsync_delta_wrapper(void *data);
int rsync_delta(struct rsync_data_char *data);
int rsync_rootfs(struct rsync_data *data);
int rsync_rootfs_wrapper(void *data);

#endif // __LXC_RSYNC_H

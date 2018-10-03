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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <grp.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"
#include "log.h"
#include "rsync.h"
#include "storage.h"
#include "syscall_wrappers.h"
#include "utils.h"

lxc_log_define(rsync, lxc);

int lxc_storage_rsync_exec_wrapper(void *data)
{
	struct rsync_data *arg = data;
	return lxc_rsync(arg);
}

int lxc_rsync_exec_wrapper(void *data)
{
	struct rsync_data_char *args = data;

	if (!lxc_switch_uid_gid(0, 0))
		return -1;

	if (!lxc_setgroups(0, NULL))
		return -1;

	return lxc_rsync_exec(args->src, args->dest);
}

int lxc_rsync_exec(const char *src, const char *dest)
{
	int ret;
	size_t l;
	char *s;

	l = strlen(src) + 2;
	s = malloc(l);
	if (!s)
		return -1;

	ret = snprintf(s, l, "%s", src);
	if (ret < 0 || (size_t)ret >= l) {
		free(s);
		return -1;
	}

	s[l - 2] = '/';
	s[l - 1] = '\0';

	execlp("rsync", "rsync", "-aHXS", "--delete", s, dest, (char *)NULL);
	free(s);
	return -1;
}

int lxc_rsync(struct rsync_data *data)
{
	int ret;
	const char *dest, *src;
	struct lxc_storage *orig = data->orig, *new = data->new;

	ret = unshare(CLONE_NEWNS);
	if (ret < 0) {
		SYSERROR("Failed to unshare CLONE_NEWNS");
		return -1;
	}

	ret = detect_shared_rootfs();
	if (ret) {
		ret = mount(NULL, "/", NULL, MS_SLAVE|MS_REC, NULL);
		if (ret < 0)
			SYSERROR("Failed to make \"/\" a slave mount");
	}

	ret = orig->ops->mount(orig);
	if (ret < 0) {
		ERROR("Failed mounting \"%s\" on \"%s\"", orig->src, orig->dest);
		return -1;
	}

	ret = new->ops->mount(new);
	if (ret < 0) {
		ERROR("Failed mounting \"%s\" onto \"%s\"", new->src, new->dest);
		return -1;
	}

	if (!lxc_switch_uid_gid(0, 0))
		return -1;

	if (!lxc_setgroups(0, NULL))
		return -1;

	src = lxc_storage_get_path(orig->dest, orig->type);
	dest = lxc_storage_get_path(new->dest, new->type);

	ret = lxc_rsync_exec(src, dest);
	if (ret < 0) {
		ERROR("Failed to rsync from \"%s\" into \"%s\"", src, dest);
		return -1;
	}

	return 0;
}

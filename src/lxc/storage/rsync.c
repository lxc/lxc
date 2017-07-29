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

#define _GNU_SOURCE
#include <grp.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mount.h>

#include "log.h"
#include "rsync.h"
#include "storage.h"
#include "utils.h"

lxc_log_define(lxcrsync, lxc);

/* the bulk of this needs to become a common helper */
int do_rsync(const char *src, const char *dest)
{
	// call out to rsync
	pid_t pid;
	char *s;
	size_t l;

	pid = fork();
	if (pid < 0)
		return -1;
	if (pid > 0)
		return wait_for_pid(pid);

	l = strlen(src) + 2;
	s = malloc(l);
	if (!s)
		exit(1);
	strcpy(s, src);
	s[l-2] = '/';
	s[l-1] = '\0';

	execlp("rsync", "rsync", "-aHXS", "--delete", s, dest, (char *)NULL);
	exit(1);
}

int rsync_delta(struct rsync_data_char *data)
{
	if (setgid(0) < 0) {
		ERROR("Failed to setgid to 0");
		return -1;
	}
	if (setgroups(0, NULL) < 0)
		WARN("Failed to clear groups");
	if (setuid(0) < 0) {
		ERROR("Failed to setuid to 0");
		return -1;
	}
	if (do_rsync(data->src, data->dest) < 0) {
		ERROR("rsyncing %s to %s", data->src, data->dest);
		return -1;
	}

	return 0;
}

int rsync_delta_wrapper(void *data)
{
	struct rsync_data_char *arg = data;
	return rsync_delta(arg);
}

int rsync_rootfs(struct rsync_data *data)
{
	struct bdev *orig = data->orig,
		    *new = data->new;

	if (unshare(CLONE_NEWNS) < 0) {
		SYSERROR("unshare CLONE_NEWNS");
		return -1;
	}
	if (detect_shared_rootfs()) {
		if (mount(NULL, "/", NULL, MS_SLAVE|MS_REC, NULL)) {
			SYSERROR("Failed to make / rslave");
			ERROR("Continuing...");
		}
	}

	// If not a snapshot, copy the fs.
	if (orig->ops->mount(orig) < 0) {
		ERROR("failed mounting %s onto %s", orig->src, orig->dest);
		return -1;
	}
	if (new->ops->mount(new) < 0) {
		ERROR("failed mounting %s onto %s", new->src, new->dest);
		return -1;
	}
	if (setgid(0) < 0) {
		ERROR("Failed to setgid to 0");
		return -1;
	}
	if (setgroups(0, NULL) < 0)
		WARN("Failed to clear groups");
	if (setuid(0) < 0) {
		ERROR("Failed to setuid to 0");
		return -1;
	}
	if (do_rsync(orig->dest, new->dest) < 0) {
		ERROR("rsyncing %s to %s", orig->src, new->src);
		return -1;
	}

	return 0;
}

int rsync_rootfs_wrapper(void *data)
{
	struct rsync_data *arg = data;
	return rsync_rootfs(arg);
}

/* new helpers */
int lxc_rsync_exec_wrapper(void *data)
{
	struct rsync_data *arg = data;
	return lxc_rsync(arg);
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
	if (ret < 0 || (size_t)ret >= l)
		return -1;

	s[l - 2] = '/';
	s[l - 1] = '\0';

	execlp("rsync", "rsync", "-aHXS", "--delete", s, dest, (char *)NULL);
	return -1;
}

int lxc_rsync(struct rsync_data *data)
{
	int ret;
	struct bdev *orig = data->orig, *new = data->new;
	char *dest, *src;

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

	ret = lxc_switch_uid_gid(0, 0);
	if (ret < 0)
		return -1;
	ret = lxc_setgroups(0, NULL);
	if (ret < 0)
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

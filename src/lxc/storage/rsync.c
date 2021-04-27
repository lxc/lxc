/* SPDX-License-Identifier: LGPL-2.1+ */

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

	if (!lxc_drop_groups())
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

	if (detect_shared_rootfs() && mount(NULL, "/", NULL, MS_SLAVE | MS_REC, NULL))
		SYSERROR("Failed to recursively turn root mount tree into dependent mount");

	ret = orig->ops->mount(orig);
	if (ret < 0) {
		ERROR("Failed mounting \"%s\" on \"%s\"", orig->src, orig->dest);
		return -1;
	}
	TRACE("Mounted \"%s\" on \"%s\"", orig->src, orig->dest);

	ret = new->ops->mount(new);
	if (ret < 0) {
		ERROR("Failed mounting \"%s\" onto \"%s\"", new->src, new->dest);
		return -1;
	}
	TRACE("Mounted \"%s\" on \"%s\"", new->src, new->dest);

	if (!lxc_switch_uid_gid(0, 0))
		return -1;

	if (!lxc_drop_groups())
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

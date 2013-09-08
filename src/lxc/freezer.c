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
#include <stdio.h>
#undef _GNU_SOURCE
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/param.h>

#include "error.h"
#include "state.h"
#include "monitor.h"

#include <lxc/log.h>
#include <lxc/cgroup.h>

lxc_log_define(lxc_freezer, lxc);

static int do_unfreeze(const char *nsgroup, int freeze, const char *name, const char *lxcpath)
{
	char freezer[MAXPATHLEN], *f;
	char tmpf[32];
	int fd, ret;

	ret = snprintf(freezer, MAXPATHLEN, "%s/freezer.state", nsgroup);
	if (ret >= MAXPATHLEN) {
		ERROR("freezer.state name too long");
		return -1;
	}

	fd = open(freezer, O_RDWR);
	if (fd < 0) {
		SYSERROR("failed to open freezer at '%s'", nsgroup);
		return -1;
	}

	if (freeze) {
		f = "FROZEN";
		ret = write(fd, f, strlen(f) + 1);
	} else {
		f = "THAWED";
		ret = write(fd, f, strlen(f) + 1);

		/* compatibility code with old freezer interface */
		if (ret < 0) {
			f = "RUNNING";
			ret = write(fd, f, strlen(f) + 1) < 0;
		}
	}

	if (ret < 0) {
		SYSERROR("failed to write '%s' to '%s'", f, freezer);
		goto out;
	}

	while (1) {
		ret = lseek(fd, 0L, SEEK_SET);
		if (ret < 0) {
			SYSERROR("failed to lseek on file '%s'", freezer);
			goto out;
		}

		ret = read(fd, tmpf, sizeof(tmpf));
		if (ret < 0) {
			SYSERROR("failed to read to '%s'", freezer);
			goto out;
		}

		ret = strncmp(f, tmpf, strlen(f));
		if (!ret)
		{
			if (name)
				lxc_monitor_send_state(name, freeze ? FROZEN : THAWED, lxcpath);
			break;		/* Success */
		}

		sleep(1);

		ret = lseek(fd, 0L, SEEK_SET);
		if (ret < 0) {
			SYSERROR("failed to lseek on file '%s'", freezer);
			goto out;
		}

		ret = write(fd, f, strlen(f) + 1);
		if (ret < 0) {
			SYSERROR("failed to write '%s' to '%s'", f, freezer);
			goto out;
		}
	}

out:
	close(fd);
	return ret;
}

static int freeze_unfreeze(const char *name, int freeze, const char *lxcpath)
{
	char *cgabspath;
	int ret;

	cgabspath = lxc_cgroup_get_hierarchy_abs_path("freezer", name, lxcpath);
	if (!cgabspath)
		return -1;

	ret = do_unfreeze(cgabspath, freeze, name, lxcpath);
	free(cgabspath);
	return ret;
}

int lxc_freeze(const char *name, const char *lxcpath)
{
	lxc_monitor_send_state(name, FREEZING, lxcpath);
	return freeze_unfreeze(name, 1, lxcpath);
}

int lxc_unfreeze(const char *name, const char *lxcpath)
{
	return freeze_unfreeze(name, 0, lxcpath);
}

int lxc_unfreeze_bypath(const char *cgrelpath)
{
	char *cgabspath;
	int ret;

	cgabspath = lxc_cgroup_find_abs_path("freezer", cgrelpath, true, NULL);
	if (!cgabspath)
		return -1;

	ret = do_unfreeze(cgabspath, 0, NULL, NULL);
	free(cgabspath);
	return ret;
}

/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2008
 *
 * Authors:
 * Daniel Lezcano <dlezcano at fr.ibm.com>
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */
#define _GNU_SOURCE
#include <stdio.h>
#undef _GNU_SOURCE
#include <stdlib.h>
#include <errno.h>
#include <mntent.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/inotify.h>
#include <netinet/in.h>
#include <net/if.h>

#include "error.h"

#include <lxc/lxc.h>
#include <lxc/log.h>

lxc_log_define(lxc_cgroup, lxc);

#define MTAB "/etc/mtab"

static int get_cgroup_mount(const char *mtab, char *mnt)
{
        struct mntent *mntent;
        FILE *file = NULL;
        int err = -1;

        file = setmntent(mtab, "r");
        if (!file) {
                SYSERROR("failed to open %s", mtab);
                goto out;
        }

        while ((mntent = getmntent(file))) {
                if (strcmp(mntent->mnt_type, "cgroup"))
                        continue;
                strcpy(mnt, mntent->mnt_dir);
                err = 0;
                break;
        };

        fclose(file);
out:
        return err;
}

int lxc_link_nsgroup(const char *name, pid_t pid)
{
	char lxc[MAXPATHLEN];
	char nsgroup[MAXPATHLEN];
	char cgroup[MAXPATHLEN];
	int ret;

	if (get_cgroup_mount(MTAB, cgroup)) {
		INFO("cgroup is not mounted");
		return -1;
	}

	snprintf(lxc, MAXPATHLEN, LXCPATH "/%s/nsgroup", name);
	snprintf(nsgroup, MAXPATHLEN, "%s/%d", cgroup, pid);

	unlink(lxc);
	ret = symlink(nsgroup, lxc);
	if (ret)
		SYSERROR("failed to create symlink %s->%s",
				 nsgroup, lxc);
      return ret;
}

int lxc_unlink_nsgroup(const char *name)
{
	char nsgroup[MAXPATHLEN];
	char path[MAXPATHLEN];

	snprintf(nsgroup, MAXPATHLEN, LXCPATH "/%s/nsgroup", name);
	
	if (readlink(nsgroup, path, MAXPATHLEN) >  0)
		rmdir(path);

	return unlink(nsgroup);
}

int lxc_cgroup_set(const char *name, const char *subsystem, const char *value)
{
	int fd, ret = -LXC_ERROR_INTERNAL;;
	char path[MAXPATHLEN];

        snprintf(path, MAXPATHLEN, LXCPATH "/%s/nsgroup/%s", name, subsystem);

	fd = open(path, O_WRONLY);
	if (fd < 0)
		return -1;

	if (write(fd, value, strlen(value)) < 0)
		goto out;
	
	ret = 0;
out:
	close(fd);
	return ret;
}

int lxc_cgroup_get(const char *name, const char *subsystem,  
		   char *value, size_t len)
{
	int fd, ret = -LXC_ERROR_INTERNAL;
	char path[MAXPATHLEN];

        snprintf(path, MAXPATHLEN, LXCPATH "/%s/nsgroup/%s", name, subsystem);

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;

	if (read(fd, value, len) < 0)
		goto out;
	
	ret = 0;
out:
	close(fd);
	return ret;
}

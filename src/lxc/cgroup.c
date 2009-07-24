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

		/* there is a cgroup mounted named "lxc" */
		if (!strcmp(mntent->mnt_fsname, "lxc") &&
		    !strcmp(mntent->mnt_type, "cgroup")) {
			strcpy(mnt, mntent->mnt_dir);
			err = 0;
			break;
		}

		/* fallback to the first non-lxc cgroup found */
                if (!strcmp(mntent->mnt_type, "cgroup") && err) {
			strcpy(mnt, mntent->mnt_dir);
			err = 0;
		}
        };

	DEBUG("using cgroup mounted at '%s'", mnt);

        fclose(file);
out:
        return err;
}

int lxc_rename_nsgroup(const char *name, pid_t pid)
{
	char oldname[MAXPATHLEN];
	char newname[MAXPATHLEN];
	char cgroup[MAXPATHLEN];
	int ret;

	if (get_cgroup_mount(MTAB, cgroup)) {
		ERROR("cgroup is not mounted");
		return -1;
	}

	snprintf(oldname, MAXPATHLEN, "%s/%d", cgroup, pid);
	snprintf(newname, MAXPATHLEN, "%s/%s", cgroup, name);

	/* there is a previous cgroup, assume it is empty, otherwise
	 * that fails */
	if (!access(newname, F_OK)) {
		ret = rmdir(newname);
		if (ret) {
			SYSERROR("failed to remove previous cgroup '%s'",
				 newname);
			return ret;
		}
	}

	ret = rename(oldname, newname);
	if (ret)
		SYSERROR("failed to rename cgroup %s->%s", oldname, newname);
	else
		DEBUG("'%s' renamed to '%s'", oldname, newname);

	return ret;
}

int lxc_link_nsgroup(const char *name)
{
	char lxc[MAXPATHLEN];
	char nsgroup[MAXPATHLEN];
	char cgroup[MAXPATHLEN];
	int ret;

	if (get_cgroup_mount(MTAB, cgroup)) {
		ERROR("cgroup is not mounted");
		return -1;
	}

	snprintf(lxc, MAXPATHLEN, LXCPATH "/%s/nsgroup", name);
	snprintf(nsgroup, MAXPATHLEN, "%s/%s", cgroup, name);

	unlink(lxc);
	ret = symlink(nsgroup, lxc);
	if (ret)
		SYSERROR("failed to create symlink %s->%s", nsgroup, lxc);
	else
		DEBUG("'%s' linked to '%s'", nsgroup, lxc);

	return ret;
}

int lxc_unlink_nsgroup(const char *name)
{
	char nsgroup[MAXPATHLEN];
	char path[MAXPATHLEN];
	ssize_t len;

	snprintf(nsgroup, MAXPATHLEN, LXCPATH "/%s/nsgroup", name);
	
	len = readlink(nsgroup, path, MAXPATHLEN-1);
	if (len >  0) {
		path[len] = '\0';
		rmdir(path);
	}

	DEBUG("unlinking '%s'", nsgroup);

	return unlink(nsgroup);
}

int lxc_cgroup_set(const char *name, const char *subsystem, const char *value)
{
	int fd, ret = -1;
	char path[MAXPATHLEN];

        snprintf(path, MAXPATHLEN, LXCPATH "/%s/nsgroup/%s", name, subsystem);

	fd = open(path, O_WRONLY);
	if (fd < 0) {
		ERROR("open %s : %s", path, strerror(errno));
		return -1;
	}

	if (write(fd, value, strlen(value)) < 0) {
		ERROR("write %s : %s", path, strerror(errno));
		goto out;
	}
	
	ret = 0;
out:
	close(fd);
	return ret;
}

int lxc_cgroup_get(const char *name, const char *subsystem,  
		   char *value, size_t len)
{
	int fd, ret = -1;
	char path[MAXPATHLEN];

        snprintf(path, MAXPATHLEN, LXCPATH "/%s/nsgroup/%s", name, subsystem);

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		ERROR("open %s : %s", path, strerror(errno));
		return -1;
	}

	if (read(fd, value, len) < 0) {
		ERROR("read %s : %s", path, strerror(errno));
		goto out;
	}
	
	ret = 0;
out:
	close(fd);
	return ret;
}

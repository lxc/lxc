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
#include "config.h"

#include <lxc/log.h>
#include <lxc/cgroup.h>
#include <lxc/start.h>

lxc_log_define(lxc_cgroup, lxc);

#define MTAB "/etc/mtab"

static char nsgroup_path[MAXPATHLEN];

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

int lxc_rename_nsgroup(const char *name, struct lxc_handler *handler)
{
	char oldname[MAXPATHLEN];
	char *newname = handler->nsgroup;
	char cgroup[MAXPATHLEN];
	int ret;

	if (get_cgroup_mount(MTAB, cgroup)) {
		ERROR("cgroup is not mounted");
		return -1;
	}

	snprintf(oldname, MAXPATHLEN, "%s/%d", cgroup, handler->pid);
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

int lxc_unlink_nsgroup(const char *name)
{
	char nsgroup[MAXPATHLEN];
	char cgroup[MAXPATHLEN];
	int ret;

	if (get_cgroup_mount(MTAB, cgroup)) {
		ERROR("cgroup is not mounted");
		return -1;
	}

	snprintf(nsgroup, MAXPATHLEN, "%s/%s", cgroup, name);
	ret = rmdir(nsgroup);
	if (ret)
		SYSERROR("failed to remove cgroup '%s'", nsgroup);
	else
		DEBUG("'%s' unlinked", nsgroup);

	return ret;
}

int lxc_cgroup_path_get(char **path, const char *name)
{
	char cgroup[MAXPATHLEN];

	*path = &nsgroup_path[0];

	/*
	 * report nsgroup_path string if already set
	 */
	if (**path != 0)
		return 0;

	if (get_cgroup_mount(MTAB, cgroup)) {
		ERROR("cgroup is not mounted");
		return -1;
	}

	snprintf(nsgroup_path, MAXPATHLEN, "%s/%s", cgroup, name);
	return 0;
}

int lxc_cgroup_set(const char *name, const char *subsystem, const char *value)
{
	int fd, ret;
	char *nsgroup;
	char path[MAXPATHLEN];

	ret = lxc_cgroup_path_get(&nsgroup, name);
	if (ret)
		return -1;

        snprintf(path, MAXPATHLEN, "%s/%s", nsgroup, subsystem);

	fd = open(path, O_WRONLY);
	if (fd < 0) {
		ERROR("open %s : %s", path, strerror(errno));
		return -1;
	}

	ret = write(fd, value, strlen(value));
	if (ret < 0) {
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
	char *nsgroup;
	char path[MAXPATHLEN];

	ret = lxc_cgroup_path_get(&nsgroup, name);
	if (ret)
		return -1;

        snprintf(path, MAXPATHLEN, "%s/%s", nsgroup, subsystem);

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		ERROR("open %s : %s", path, strerror(errno));
		return -1;
	}

	ret = read(fd, value, len);
	if (ret < 0)
		ERROR("read %s : %s", path, strerror(errno));

	close(fd);
	return ret;
}

int lxc_cgroup_nrtasks(const char *name)
{
	char *nsgroup;
	char path[MAXPATHLEN];
	int pid, ret, count = 0;
	FILE *file;

	ret = lxc_cgroup_path_get(&nsgroup, name);
	if (ret)
		return -1;

        snprintf(path, MAXPATHLEN, "%s/tasks", nsgroup);

	file = fopen(path, "r");
	if (!file) {
		SYSERROR("fopen '%s' failed", path);
		return -1;
	}

	while (fscanf(file, "%d", &pid) != EOF)
		count++;

	fclose(file);

	return count;
}

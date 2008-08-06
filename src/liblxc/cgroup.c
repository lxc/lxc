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

#include <lxc.h>
#include <log.h>

#define MAXPRIOLEN 24
#define MTAB "/etc/mtab"

static int get_cgroup_mount(const char *mtab, char *mnt)
{
        struct mntent *mntent;
        FILE *file = NULL;
        int err = -1;

        file = setmntent(mtab, "r");
        if (!file) {
                lxc_log_syserror("failed to open %s", mtab);
                goto out;
        }

        while ((mntent = getmntent(file))) {
                if (strcmp(mntent->mnt_fsname, "cgroup"))
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
	char *lxc, *nsgroup, cgroup[MAXPATHLEN];
	int ret;

	if (get_cgroup_mount(MTAB, cgroup)) {
		lxc_log_info("cgroup is not mounted");
		return -1;
	}

	asprintf(&lxc, LXCPATH "/%s/nsgroup", name);
	asprintf(&nsgroup, "%s/%d", cgroup, pid);

	ret = symlink(nsgroup, lxc);
	if (ret)
		lxc_log_syserror("failed to create symlink %s->%s",
				 nsgroup, lxc);
	free(lxc);
	free(nsgroup);
	return ret;
}

int lxc_unlink_nsgroup(const char *name)
{
	char *nsgroup;
	int ret;

	asprintf(&nsgroup, LXCPATH "/%s/nsgroup", name);
	ret = unlink(nsgroup);
	free(nsgroup);

	return ret;
}

int lxc_set_priority(const char *name, int priority)
{
	int fd;
	char *path = NULL, *prio = NULL;

        asprintf(&path, LXCPATH "/%s/nsgroup/cpu.shares", name);

	fd = open(path, O_WRONLY);
	if (fd < 0) {
		lxc_log_syserror("failed to open '%s'", path);
		goto out;
	}

	asprintf(&prio, "%d", priority);

	if (write(fd, prio, strlen(prio) + 1) < 0) {
		lxc_log_syserror("failed to write to '%s'", path);
		close(fd);
		goto out;
	}

	close(fd);
out:
	free(path);
	free(prio);
	return 0;
}

int lxc_get_priority(const char *name, int *priority)
{
	int fd, ret = -1;
	char *path, prio[MAXPRIOLEN];

        asprintf(&path, LXCPATH "/%s/nsgroup/cpu.shares", name);

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		lxc_log_syserror("failed to open '%s'", path);
		goto out;
	}

	if (read(fd, prio, MAXPRIOLEN) < 0) {
		lxc_log_syserror("failed to read from '%s'", path);
		close(fd);
		goto out;
	}

	close(fd);
	*priority = atoi(prio);

	ret = 0;
out:
	free(path);
	return 0;
}

int lxc_set_memory(const char *name, size_t memmax)
{
	return 0;
}

int lxc_get_memory(const char *name, size_t *memmax)
{
	return 0;
}

int lxc_get_memstat(const char *name, struct lxc_mem_stat *memstat)
{
	return 0;
}

int lxc_set_cpuset(const char *name, long *cpumask, int len, int shared)
{
	return 0;
}

int lxc_get_cpuset(const char *name, long *cpumask, int len, int *shared)
{
	return 0;
}

int lxc_get_cpu_usage(const char *name, long long *usage)
{
	return 0;
}

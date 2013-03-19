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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */
#define _GNU_SOURCE
#include <stdio.h>
#undef _GNU_SOURCE
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/inotify.h>
#include <netinet/in.h>
#include <net/if.h>

#include "error.h"
#include "config.h"
#include "commands.h"

#include <lxc/log.h>
#include <lxc/cgroup.h>
#include <lxc/start.h>

#if IS_BIONIC
#include <../include/lxcmntent.h>
#else
#include <mntent.h>
#endif

lxc_log_define(lxc_cgroup, lxc);

#define MTAB "/proc/mounts"

/* Check if a mount is a cgroup hierarchy for any subsystem.
 * Return the first subsystem found (or NULL if none).
 */
static char *mount_has_subsystem(const struct mntent *mntent)
{
	FILE *f;
	char *c, *ret = NULL;
	char line[MAXPATHLEN];

	/* read the list of subsystems from the kernel */
	f = fopen("/proc/cgroups", "r");
	if (!f)
		return 0;

	/* skip the first line, which contains column headings */
	if (!fgets(line, MAXPATHLEN, f))
		return 0;

	while (fgets(line, MAXPATHLEN, f)) {
		c = strchr(line, '\t');
		if (!c)
			continue;
		*c = '\0';

		ret = hasmntopt(mntent, line);
		if (ret)
			break;
	}

	fclose(f);
	return ret;
}

/*
 * Determine mountpoint for a cgroup subsystem.
 * @subsystem: cgroup subsystem (i.e. freezer).  If this is NULL, the first
 * cgroup mountpoint with any subsystems is used.
 * @mnt: a passed-in buffer of at least size MAXPATHLEN into which the path
 * is copied.
 *
 * Returns 0 on success, -1 on error.
 */
static int get_cgroup_mount(const char *subsystem, char *mnt)
{
	struct mntent *mntent;
	FILE *file = NULL;
	int ret, err = -1;

	file = setmntent(MTAB, "r");
	if (!file) {
		SYSERROR("failed to open %s", MTAB);
		return -1;
	}

	while ((mntent = getmntent(file))) {
		if (strcmp(mntent->mnt_type, "cgroup"))
			continue;

		if (subsystem) {
			if (!hasmntopt(mntent, subsystem))
				continue;
		} else {
			if (!mount_has_subsystem(mntent))
				continue;
		}

		ret = snprintf(mnt, MAXPATHLEN, "%s", mntent->mnt_dir);
		if (ret < 0 || ret >= MAXPATHLEN)
			goto fail;

		DEBUG("using cgroup mounted at '%s'", mnt);
		err = 0;
		goto out;
	};

fail:
	DEBUG("Failed to find cgroup for %s\n",
	      subsystem ? subsystem : "(NULL)");
out:
	endmntent(file);
	return err;
}

/*
 * cgroup_path_get: Calculate the full path for a particular subsystem, plus
 * a passed-in (to be appended) relative cgpath for a container.
 * @path: a char** into which a pointer to the answer is copied
 * @subsystem: subsystem of interest (i.e. freezer).
 * @cgpath: a container's (relative) cgroup path, i.e. "/lxc/c1".
 *
 * Returns 0 on success, -1 on error.
 *
 * The answer is written in a static char[MAXPATHLEN] in this function and
 * should not be freed.
 */
extern int cgroup_path_get(char **path, const char *subsystem, const char *cgpath)
{
	static char        buf[MAXPATHLEN];
	static char        retbuf[MAXPATHLEN];
	int rc;

	/* lxc_cgroup_set passes a state object for the subsystem,
	 * so trim it to just the subsystem part */
	if (subsystem) {
		rc = snprintf(retbuf, MAXPATHLEN, "%s", subsystem);
		if (rc < 0 || rc >= MAXPATHLEN) {
			ERROR("subsystem name too long");
			return -1;
		}
		char *s = index(retbuf, '.');
		if (s)
			*s = '\0';
		DEBUG("%s: called for subsys %s name %s\n", __func__, retbuf, cgpath);
	}
	if (get_cgroup_mount(subsystem ? retbuf : NULL, buf)) {
		ERROR("cgroup is not mounted");
		return -1;
	}

	rc = snprintf(retbuf, MAXPATHLEN, "%s/%s", buf, cgpath);
	if (rc < 0 || rc >= MAXPATHLEN) {
		ERROR("name too long");
		return -1;
	}

	DEBUG("%s: returning %s for subsystem %s", __func__, retbuf, subsystem);

	*path = retbuf;
	return 0;
}

/*
 * Calculate a container's cgroup path for a particular subsystem.  This
 * is the cgroup path relative to the root of the cgroup filesystem.
 * @path: A char ** into which we copy the char* containing the answer
 * @subsystem: the cgroup subsystem of interest (i.e. freezer)
 * @name: container name
 * @lxcpath: the lxcpath in which the container is running.
 *
 * Returns 0 on success, -1 on error.
 *
 * Note that the char* copied into *path is a static char[MAXPATHLEN] in
 * commands.c:receive_answer().  It should not be freed.
 */
extern int lxc_get_cgpath(const char **path, const char *subsystem, const char *name, const char *lxcpath)
{
	struct lxc_command command = {
		.request = { .type = LXC_COMMAND_CGROUP },
	};

	int ret, stopped = 0;

	ret = lxc_command(name, &command, &stopped, lxcpath);
	if (ret < 0) {
		if (!stopped)
			ERROR("failed to send command");
		return -1;
	}

	if (!ret) {
		WARN("'%s' has stopped before sending its state", name);
		return -1;
	}

	if (command.answer.ret < 0 || command.answer.pathlen < 0) {
		ERROR("failed to get state for '%s': %s",
			name, strerror(-command.answer.ret));
		return -1;
	}

	*path = command.answer.path;

	return 0;
}

/*
 * lxc_cgroup_path_get: determine full pathname for a cgroup
 * file for a specific container.
 * @path: char ** used to return the answer.  The char * will point
 * into the static char* retuf from cgroup_path_get() (so no need
 * to free it).
 * @subsystem: cgroup subsystem (i.e. "freezer") for which to
 * return an answer.  If NULL, then the first cgroup entry in
 * mtab will be used.
 *
 * This is the exported function, which determines cgpath from the
 * monitor running in lxcpath.
 *
 * Returns 0 on success, < 0 on error.
 */
int lxc_cgroup_path_get(char **path, const char *subsystem, const char *name, const char *lxcpath)
{
	const char *cgpath;

	if (lxc_get_cgpath(&cgpath, subsystem, name, lxcpath) < 0)
		return -1;

	return cgroup_path_get(path, subsystem, cgpath);
}

/*
 * small helper which simply write a value into a (cgroup) file
 */
static int do_cgroup_set(const char *path, const char *value)
{
	int fd, ret;

	if ((fd = open(path, O_WRONLY)) < 0) {
		SYSERROR("open %s : %s", path, strerror(errno));
		return -1;
	}

	if ((ret = write(fd, value, strlen(value))) < 0) {
		close(fd);
		SYSERROR("write %s : %s", path, strerror(errno));
		return ret;
	}

	if ((ret = close(fd)) < 0) {
		SYSERROR("close %s : %s", path, strerror(errno));
		return ret;
	}
	return 0;
}

/*
 * small helper to write a value into a file in a particular directory.
 * @cgpath: the directory in which to find the file
 * @filename: the file (under cgpath) to which to write
 * @value: what to write
 *
 * Returns 0 on success, < 0 on error.
 */
int lxc_cgroup_set_bypath(const char *cgpath, const char *filename, const char *value)
{
	int ret;
	char *dirpath;
	char path[MAXPATHLEN];

	ret = cgroup_path_get(&dirpath, filename, cgpath);
	if (ret)
		return -1;

	ret = snprintf(path, MAXPATHLEN, "%s/%s", dirpath, filename);
	if (ret < 0 || ret >= MAXPATHLEN) {
		ERROR("pathname too long");
		return -1;
	}

	return do_cgroup_set(path, value);
}

/*
 * set a cgroup value for a container
 *
 * @name: name of the container
 * @filename: the cgroup file (i.e. freezer.state) whose value to change
 * @value: the value to write to the file
 * @lxcpath: the lxcpath under which the container is running.
 *
 * Returns 0 on success, < 0 on error.
 */

int lxc_cgroup_set(const char *name, const char *filename, const char *value,
		   const char *lxcpath)
{
	int ret;
	char *dirpath;
	char path[MAXPATHLEN];

	ret = lxc_cgroup_path_get(&dirpath, filename, name, lxcpath);
	if (ret)
		return -1;

	ret = snprintf(path, MAXPATHLEN, "%s/%s", dirpath, filename);
	if (ret < 0 || ret >= MAXPATHLEN) {
		ERROR("pathname too long");
		return -1;
	}

	return do_cgroup_set(path, value);
}

/*
 * Get value of a cgroup setting for a container.
 *
 * @name: name of the container
 * @filename: the cgroup file to read (i.e. 'freezer.state')
 * @value: a preallocated char* into which to copy the answer
 * @len: the length of pre-allocated @value
 * @lxcpath: the lxcpath in which the container is running (i.e.
 * /var/lib/lxc)
 *
 * Returns < 0 on error, or the number of bytes read.
 *
 * If you pass in NULL value or 0 len, then you are asking for the size of the
 * file.
 *
 * Note that we can't get the file size quickly through stat or lseek.
 * Therefore if you pass in len > 0 but less than the file size, your only
 * indication will be that the return value will be equal to the passed-in ret.
 * We will not return the actual full file size.
 */
int lxc_cgroup_get(const char *name, const char *filename, char *value,
		   size_t len, const char *lxcpath)
{
	int fd, ret = -1;
	char *dirpath;
	char path[MAXPATHLEN];
	int rc;

	ret = lxc_cgroup_path_get(&dirpath, filename, name, lxcpath);
	if (ret)
		return -1;

	rc = snprintf(path, MAXPATHLEN, "%s/%s", dirpath, filename);
	if (rc < 0 || rc >= MAXPATHLEN) {
		ERROR("pathname too long");
		return -1;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		ERROR("open %s : %s", path, strerror(errno));
		return -1;
	}

	if (!len || !value) {
		char buf[100];
		int count = 0;
		while ((ret = read(fd, buf, 100)) > 0)
			count += ret;
		if (ret >= 0)
			ret = count;
	} else {
		memset(value, 0, len);
		ret = read(fd, value, len);
	}

	if (ret < 0)
		ERROR("read %s : %s", path, strerror(errno));

	close(fd);
	return ret;
}

int lxc_cgroup_nrtasks(const char *cgpath)
{
	char *dpath;
	char path[MAXPATHLEN];
	int pid, ret, count = 0;
	FILE *file;
	int rc;

	ret = cgroup_path_get(&dpath, NULL, cgpath);
	if (ret)
		return -1;

	rc = snprintf(path, MAXPATHLEN, "%s/tasks", dpath);
	if (rc < 0 || rc >= MAXPATHLEN) {
		ERROR("pathname too long");
		return -1;
	}

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

/*
 * If first creating the /sys/fs/cgroup/$subsys/lxc container, then
 * try to set clone_children to 1.  Some kernels don't support
 * clone_children, and cgroup maintainer wants to deprecate it.  So
 * XXX TODO we should instead after each cgroup mkdir (here and in
 * hooks/mountcgroup) check if cpuset is in the subsystems, and if so
 * manually copy over mems and cpus.
 */
static void set_clone_children(const char *mntdir)
{
	char path[MAXPATHLEN];
	FILE *fout;
	int ret;

	ret = snprintf(path, MAXPATHLEN, "%s/cgroup.clone_children", mntdir);
	INFO("writing to %s\n", path);
	if (ret < 0 || ret > MAXPATHLEN)
		return;
	fout = fopen(path, "w");
	if (!fout)
		return;
	fprintf(fout, "1\n");
	fclose(fout);
}

/*
 * Make sure the 'cgroup group' exists, so that we don't have to worry about
 * that later.
 *
 * @lxcgroup: the cgroup group, i.e. 'lxc' by default.
 *
 * See detailed comments at lxc_cgroup_path_create for more information.
 *
 * Returns 0 on success, -1 on error.
 */
static int create_lxcgroups(const char *lxcgroup)
{
	FILE *file = NULL;
	struct mntent *mntent;
	int ret, retv = -1;
	char path[MAXPATHLEN];

	file = setmntent(MTAB, "r");
	if (!file) {
		SYSERROR("failed to open %s", MTAB);
		return -1;
	}

	while ((mntent = getmntent(file))) {

		if (strcmp(mntent->mnt_type, "cgroup"))
			continue;
		if (!mount_has_subsystem(mntent))
			continue;

		/* 
		 * TODO - handle case where lxcgroup has subdirs?  (i.e. build/l1)
		 * We probably only want to support that for /users/joe
		 */
		ret = snprintf(path, MAXPATHLEN, "%s/%s",
			       mntent->mnt_dir, lxcgroup ? lxcgroup : "lxc");
		if (ret < 0 || ret >= MAXPATHLEN)
			goto fail;
		if (access(path, F_OK)) {
			set_clone_children(mntent->mnt_dir);
			ret = mkdir(path, 0755);
			if (ret == -1 && errno != EEXIST) {
				SYSERROR("failed to create '%s' directory", path);
				goto fail;
			}
		}

	}

	retv = 0;
fail:
	endmntent(file);
	return retv;
}

/*
 * For a new container, find a cgroup path which is unique in all cgroup mounts.
 * I.e. if r1 is already running, then /lxc/r1-1 may be used.
 *
 * @lxcgroup: the cgroup 'group' the contaienr should run in.  By default, this
 * is just 'lxc'.  Admins may wish to group some containers into other groups,
 * i.e. 'build', to take advantage of cgroup hierarchy to simplify group
 * administration.  Also, unprivileged users who are placed into a cgroup by
 * libcgroup_pam will be using that cgroup rather than the system-wide 'lxc'
 * group.
 * @name: the name of the container
 *
 * The chosen cgpath is returned as a strdup'd string.  The caller will have to
 * free that eventually, however the lxc monitor will keep that string so as to
 * return it in response to a LXC_COMMAND_CGROUP query.
 *
 * Note the path is relative to cgroup mounts.  I.e. if the freezer subsystem
 * is at /sys/fs/cgroup/freezer, and this fn returns '/lxc/r1', then the
 * freezer cgroup's full path will be /sys/fs/cgroup/freezer/lxc/r1/.
 *
 * XXX This should probably be locked globally
 * 
 * Races won't be determintal, you'll just end up with leftover unused cgroups
 */
char *lxc_cgroup_path_create(const char *lxcgroup, const char *name)
{
	int i = 0, ret;
	char *retpath, path[MAXPATHLEN];
	char tail[12];
	FILE *file = NULL;
	struct mntent *mntent;

	if (create_lxcgroups(lxcgroup) < 0)
		return NULL;

again:
	file = setmntent(MTAB, "r");
	if (!file) {
		SYSERROR("failed to open %s", MTAB);
		return NULL;
	}

	if (i)
		snprintf(tail, 12, "-%d", i);
	else
		*tail = '\0';

	while ((mntent = getmntent(file))) {

		if (strcmp(mntent->mnt_type, "cgroup"))
			continue;
		if (!mount_has_subsystem(mntent))
			continue;

		/* find unused mnt_dir + lxcgroup + name + -$i */
		ret = snprintf(path, MAXPATHLEN, "%s/%s/%s%s", mntent->mnt_dir,
			       lxcgroup ? lxcgroup : "lxc", name, tail);
		if (ret < 0 || ret >= MAXPATHLEN)
			goto fail;

		if (access(path, F_OK) == 0) goto next;

		if (mkdir(path, 0755)) {
			ERROR("Error creating cgroups");
			goto fail;
		}

	}

	endmntent(file);

	// print out the cgpath part
	ret = snprintf(path, MAXPATHLEN, "%s/%s%s",
		       lxcgroup ? lxcgroup : "lxc", name, tail);
	if (ret < 0 || ret >= MAXPATHLEN) // can't happen
		goto fail;

	retpath = strdup(path);

	return retpath;

next:
	endmntent(file);
	i++;
	goto again;

fail:
	endmntent(file);
	return NULL;
}

int lxc_cgroup_enter(const char *cgpath, pid_t pid)
{
	char path[MAXPATHLEN];
	FILE *file = NULL, *fout;
	struct mntent *mntent;
	int ret, retv = -1;

	file = setmntent(MTAB, "r");
	if (!file) {
		SYSERROR("failed to open %s", MTAB);
		return -1;
	}

	while ((mntent = getmntent(file))) {
		if (strcmp(mntent->mnt_type, "cgroup"))
			continue;
		if (!mount_has_subsystem(mntent))
			continue;
		ret = snprintf(path, MAXPATHLEN, "%s/%s/tasks",
			       mntent->mnt_dir, cgpath);
		if (ret < 0 || ret >= MAXPATHLEN) {
			ERROR("entering cgroup");
			goto out;
		}
		fout = fopen(path, "w");
		if (!fout) {
			ERROR("entering cgroup");
			goto out;
		}
		fprintf(fout, "%d\n", (int)pid);
		fclose(fout);
	}
	retv = 0;

out:
	endmntent(file);
	return retv;
}

int recursive_rmdir(char *dirname)
{
	struct dirent dirent, *direntp;
	DIR *dir;
	int ret;
	char pathname[MAXPATHLEN];

	dir = opendir(dirname);
	if (!dir) {
		WARN("failed to open directory: %m");
		return -1;
	}

	while (!readdir_r(dir, &dirent, &direntp)) {
		struct stat mystat;
		int rc;

		if (!direntp)
			break;

		if (!strcmp(direntp->d_name, ".") ||
		    !strcmp(direntp->d_name, ".."))
			continue;

		rc = snprintf(pathname, MAXPATHLEN, "%s/%s", dirname, direntp->d_name);
		if (rc < 0 || rc >= MAXPATHLEN) {
			ERROR("pathname too long");
			continue;
		}
		ret = stat(pathname, &mystat);
		if (ret)
			continue;
		if (S_ISDIR(mystat.st_mode))
			recursive_rmdir(pathname);
	}

	ret = rmdir(dirname);

	if (closedir(dir))
		ERROR("failed to close directory");
	return ret;


}

static int lxc_one_cgroup_destroy(struct mntent *mntent, const char *cgpath)
{
	char cgname[MAXPATHLEN];
	char *cgmnt = mntent->mnt_dir;
	int rc;

	rc = snprintf(cgname, MAXPATHLEN, "%s/%s", cgmnt, cgpath);
	if (rc < 0 || rc >= MAXPATHLEN) {
		ERROR("name too long");
		return -1;
	}
	DEBUG("destroying %s\n", cgname);
	if (recursive_rmdir(cgname)) {
		SYSERROR("failed to remove cgroup '%s'", cgname);
		return -1;
	}

	DEBUG("'%s' unlinked", cgname);

	return 0;
}

/*
 * for each mounted cgroup, destroy the cgroup for the container
 */
int lxc_cgroup_destroy(const char *cgpath)
{
	struct mntent *mntent;
	FILE *file = NULL;
	int err, retv  = 0;

	file = setmntent(MTAB, "r");
	if (!file) {
		SYSERROR("failed to open %s", MTAB);
		return -1;
	}

	while ((mntent = getmntent(file))) {
		if (strcmp(mntent->mnt_type, "cgroup"))
			continue;
		if (!mount_has_subsystem(mntent))
			continue;

		err = lxc_one_cgroup_destroy(mntent, cgpath);
		if (err)  // keep trying to clean up the others
			retv = -1;
	}

	endmntent(file);
	return retv;
}

int lxc_cgroup_attach(pid_t pid, const char *name, const char *lxcpath)
{
	const char *dirpath;

	if (lxc_get_cgpath(&dirpath, NULL, name, lxcpath) < 0) {
		ERROR("Error getting cgroup for container %s: %s", lxcpath, name);
		return -1;
	}
	INFO("joining pid %d to cgroup %s", pid, dirpath);

	return lxc_cgroup_enter(dirpath, pid);
}

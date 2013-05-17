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

/* In the case of a bind mount, there could be two long pathnames in the
 * mntent plus options so use large enough buffer size
 */
#define LARGE_MAXPATHLEN 4 * MAXPATHLEN

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
	if (!fgets(line, MAXPATHLEN, f)) {
		fclose(f);
		return 0;
	}

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
	struct mntent mntent_r;
	FILE *file = NULL;
	int ret, err = -1;

	char buf[LARGE_MAXPATHLEN] = {0};

	file = setmntent(MTAB, "r");
	if (!file) {
		SYSERROR("failed to open %s", MTAB);
		return -1;
	}

	while ((getmntent_r(file, &mntent_r, buf, sizeof(buf)))) {
		if (strcmp(mntent_r.mnt_type, "cgroup") != 0)
			continue;

		if (subsystem) {
			if (!hasmntopt(&mntent_r, subsystem))
				continue;
		} else {
			if (!mount_has_subsystem(&mntent_r))
				continue;
		}

		ret = snprintf(mnt, MAXPATHLEN, "%s", mntent_r.mnt_dir);
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
 * cgroup_path_get: Get the absolute path to a particular subsystem,
 * plus a passed-in (to be appended) relative cgpath for a container.
 *
 * @subsystem : subsystem of interest (e.g. "freezer")
 * @cgrelpath : a container's relative cgroup path (e.g. "lxc/c1")
 *
 * Returns absolute path on success, NULL on error. The caller must free()
 * the returned path.
 *
 * Note that @subsystem may be the name of an item (e.g. "freezer.state")
 * in which case the subsystem will be determined by taking the string up
 * to the first '.'
 */
char *cgroup_path_get(const char *subsystem, const char *cgrelpath)
{
	int rc;

	char *buf = NULL;
	char *cgabspath = NULL;

	buf = malloc(MAXPATHLEN * sizeof(char));
	if (!buf) {
		ERROR("malloc failed");
		goto out1;
	}

	cgabspath = malloc(MAXPATHLEN * sizeof(char));
	if (!cgabspath) {
		ERROR("malloc failed");
		goto out2;
	}

	/* lxc_cgroup_set passes a state object for the subsystem,
	 * so trim it to just the subsystem part */
	if (subsystem) {
		rc = snprintf(cgabspath, MAXPATHLEN, "%s", subsystem);
		if (rc < 0 || rc >= MAXPATHLEN) {
			ERROR("subsystem name too long");
			goto err3;
		}
		char *s = index(cgabspath, '.');
		if (s)
			*s = '\0';
		DEBUG("%s: called for subsys %s name %s\n", __func__,
		      subsystem, cgrelpath);
	}
	if (get_cgroup_mount(subsystem ? cgabspath : NULL, buf)) {
		ERROR("cgroup is not mounted");
		goto err3;
	}

	rc = snprintf(cgabspath, MAXPATHLEN, "%s/%s", buf, cgrelpath);
	if (rc < 0 || rc >= MAXPATHLEN) {
		ERROR("name too long");
		goto err3;
	}

	DEBUG("%s: returning %s for subsystem %s relpath %s", __func__,
		cgabspath, subsystem, cgrelpath);
	goto out2;

err3:
	free(cgabspath);
	cgabspath = NULL;
out2:
	free(buf);
out1:
	return cgabspath;
}

/*
 * lxc_cgroup_path_get: Get the absolute pathname for a cgroup
 * file for a running container.
 *
 * @subsystem : subsystem of interest (e.g. "freezer"). If NULL, then
 *              the first cgroup entry in mtab will be used.
 * @name      : name of container to connect to
 * @lxcpath   : the lxcpath in which the container is running
 *
 * This is the exported function, which determines cgpath from the
 * lxc-start of the @name container running in @lxcpath.
 *
 * Returns path on success, NULL on error. The caller must free()
 * the returned path.
 */
char *lxc_cgroup_path_get(const char *subsystem, const char *name,
			  const char *lxcpath)
{
	char *cgabspath;
	char *cgrelpath;

	cgrelpath = lxc_cmd_get_cgroup_path(name, lxcpath);
	if (!cgrelpath)
		return NULL;

	cgabspath = cgroup_path_get(subsystem, cgrelpath);
	free(cgrelpath);
	return cgabspath;
}

/*
 * do_cgroup_set: Write a value into a cgroup file
 *
 * @path      : absolute path to cgroup file
 * @value     : value to write into file
 *
 * Returns 0 on success, < 0 on error.
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
 * lxc_cgroup_set_bypath: Write a value into a cgroup file
 *
 * @cgrelpath : a container's relative cgroup path (e.g. "lxc/c1")
 * @filename  : the cgroup file to write (e.g. "freezer.state")
 * @value     : value to write into file
 *
 * Returns 0 on success, < 0 on error.
 */
int lxc_cgroup_set_bypath(const char *cgrelpath, const char *filename, const char *value)
{
	int ret;
	char *cgabspath;
	char path[MAXPATHLEN];

	cgabspath = cgroup_path_get(filename, cgrelpath);
	if (!cgabspath)
		return -1;

	ret = snprintf(path, MAXPATHLEN, "%s/%s", cgabspath, filename);
	if (ret < 0 || ret >= MAXPATHLEN) {
		ERROR("pathname too long");
		ret = -1;
		goto out;
	}

	ret = do_cgroup_set(path, value);

out:
	free(cgabspath);
	return ret;
}

/*
 * lxc_cgroup_set: Write a value into a cgroup file
 *
 * @name      : name of container to connect to
 * @filename  : the cgroup file to write (e.g. "freezer.state")
 * @value     : value to write into file
 * @lxcpath   : the lxcpath in which the container is running
 *
 * Returns 0 on success, < 0 on error.
 */
int lxc_cgroup_set(const char *name, const char *filename, const char *value,
		   const char *lxcpath)
{
	int ret;
	char *cgabspath;
	char path[MAXPATHLEN];

	cgabspath = lxc_cgroup_path_get(filename, name, lxcpath);
	if (!cgabspath)
		return -1;

	ret = snprintf(path, MAXPATHLEN, "%s/%s", cgabspath, filename);
	if (ret < 0 || ret >= MAXPATHLEN) {
		ERROR("pathname too long");
		ret = -1;
		goto out;
	}

	ret = do_cgroup_set(path, value);

out:
	free(cgabspath);
	return ret;
}

/*
 * lxc_cgroup_get: Read value from a cgroup file
 *
 * @name      : name of container to connect to
 * @filename  : the cgroup file to read (e.g. "freezer.state")
 * @value     : a pre-allocated buffer to copy the answer into
 * @len       : the length of pre-allocated @value
 * @lxcpath   : the lxcpath in which the container is running
 *
 * Returns the number of bytes read on success, < 0 on error
 *
 * If you pass in NULL value or 0 len, the return value will be the size of
 * the file, and @value will not contain the contents.
 *
 * Note that we can't get the file size quickly through stat or lseek.
 * Therefore if you pass in len > 0 but less than the file size, your only
 * indication will be that the return value will be equal to the passed-in ret.
 * We will not return the actual full file size.
 */
int lxc_cgroup_get(const char *name, const char *filename, char *value,
		   size_t len, const char *lxcpath)
{
	int fd, ret;
	char *cgabspath;
	char path[MAXPATHLEN];

	cgabspath = lxc_cgroup_path_get(filename, name, lxcpath);
	if (!cgabspath)
		return -1;

	ret = snprintf(path, MAXPATHLEN, "%s/%s", cgabspath, filename);
	if (ret < 0 || ret >= MAXPATHLEN) {
		ERROR("pathname too long");
		ret = -1;
		goto out;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		ERROR("open %s : %s", path, strerror(errno));
		ret = -1;
		goto out;
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
out:
	free(cgabspath);
	return ret;
}

int lxc_cgroup_nrtasks(const char *cgrelpath)
{
	char *cgabspath = NULL;
	char path[MAXPATHLEN];
	int pid, ret;
	FILE *file;

	cgabspath = cgroup_path_get(NULL, cgrelpath);
	if (!cgabspath)
		return -1;

	ret = snprintf(path, MAXPATHLEN, "%s/tasks", cgabspath);
	if (ret < 0 || ret >= MAXPATHLEN) {
		ERROR("pathname too long");
		ret = -1;
		goto out;
	}

	file = fopen(path, "r");
	if (!file) {
		SYSERROR("fopen '%s' failed", path);
		ret = -1;
		goto out;
	}

	ret = 0;
	while (fscanf(file, "%d", &pid) != EOF)
		ret++;

	fclose(file);

out:
	free(cgabspath);
	return ret;
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

static char *get_all_cgroups(void)
{
	FILE *f;
	char *line = NULL, *ret = NULL;
	size_t len;
	int first = 1;

	/* read the list of subsystems from the kernel */
	f = fopen("/proc/cgroups", "r");
	if (!f)
		return NULL;

	while (getline(&line, &len, f) != -1) {
		char *c;
		int oldlen, newlen, inc;

		/* skip the first line */
		if (first) {
			first=0;
			continue;
		}

		c = strchr(line, '\t');
		if (!c)
			continue;
		*c = '\0';

		oldlen = ret ? strlen(ret) : 0;
		newlen = oldlen + strlen(line) + 2;
		ret = realloc(ret, newlen);
		if (!ret)
			goto out;
		inc = snprintf(ret + oldlen, newlen, ",%s", line);
		if (inc < 0 || inc >= newlen) {
			free(ret);
			ret = NULL;
			goto out;
		}
	}

out:
	if (line)
		free(line);
	fclose(f);
	return ret;
}

static int in_cgroup_list(char *s, char *list)
{
	char *token, *str, *saveptr = NULL;

	if (!list || !s)
		return 0;

	for (str = strdupa(list); (token = strtok_r(str, ",", &saveptr)); str = NULL) {
		if (strcmp(s, token) == 0)
			return 1;
	}

	return 0;
}

static int have_visited(char *opts, char *visited, char *allcgroups)
{
	char *str, *s = NULL, *token;

	for (str = strdupa(opts); (token = strtok_r(str, ",", &s)); str = NULL) {
		if (!in_cgroup_list(token, allcgroups))
			continue;
		if (visited && in_cgroup_list(token, visited))
			return 1;
	}

	return 0;
}

static int record_visited(char *opts, char **visitedp, char *allcgroups)
{
	char *s = NULL, *token, *str;
	int oldlen, newlen, ret;

	for (str = strdupa(opts); (token = strtok_r(str, ",", &s)); str = NULL) {
		if (!in_cgroup_list(token, allcgroups))
			continue;
		if (*visitedp && in_cgroup_list(token, *visitedp))
			continue;
		oldlen = (*visitedp) ? strlen(*visitedp) : 0;
		newlen = oldlen + strlen(token) + 2;
		(*visitedp) = realloc(*visitedp, newlen);
		if (!(*visitedp))
			return -1;
		ret = snprintf((*visitedp)+oldlen, newlen, ",%s", token);
		if (ret < 0 || ret >= newlen)
			return -1;
	}

	return 0;
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
	struct mntent mntent_r;
	int ret, retv = -1;
	char path[MAXPATHLEN];

	char buf[LARGE_MAXPATHLEN] = {0};

	file = setmntent(MTAB, "r");
	if (!file) {
		SYSERROR("failed to open %s", MTAB);
		return -1;
	}

	while ((getmntent_r(file, &mntent_r, buf, sizeof(buf)))) {

		if (strcmp(mntent_r.mnt_type, "cgroup"))
			continue;
		if (!mount_has_subsystem(&mntent_r))
			continue;

		/*
		 * TODO - handle case where lxcgroup has subdirs?  (i.e. build/l1)
		 * We probably only want to support that for /users/joe
		 */
		ret = snprintf(path, MAXPATHLEN, "%s/%s",
			       mntent_r.mnt_dir, lxcgroup ? lxcgroup : "lxc");
		if (ret < 0 || ret >= MAXPATHLEN)
			goto fail;
		if (access(path, F_OK)) {
			set_clone_children(mntent_r.mnt_dir);
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
	struct mntent mntent_r;
	char *allcgroups = get_all_cgroups();
	char *visited = NULL;

	char buf[LARGE_MAXPATHLEN] = {0};

	if (!allcgroups)
		return NULL;

	if (create_lxcgroups(lxcgroup) < 0)
		goto err1;

again:
	if (visited) {
		/* we're checking for a new name, so start over with all cgroup
		 * mounts */
		free(visited);
		visited = NULL;
	}
	file = setmntent(MTAB, "r");
	if (!file) {
		SYSERROR("failed to open %s", MTAB);
		goto err1;
	}

	if (i)
		snprintf(tail, 12, "-%d", i);
	else
		*tail = '\0';

	while ((getmntent_r(file, &mntent_r, buf, sizeof(buf)))) {

		if (strcmp(mntent_r.mnt_type, "cgroup"))
			continue;
		if (!mount_has_subsystem(&mntent_r))
			continue;

		/* make sure we haven't checked this subsystem already */
		if (have_visited(mntent_r.mnt_opts, visited, allcgroups))
			continue;
		if (record_visited(mntent_r.mnt_opts, &visited, allcgroups) < 0)
			goto fail;

		/* find unused mnt_dir + lxcgroup + name + -$i */
		ret = snprintf(path, MAXPATHLEN, "%s/%s/%s%s", mntent_r.mnt_dir,
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
	free(allcgroups);
	if (visited)
		free(visited);

	return retpath;

next:
	endmntent(file);
	i++;
	goto again;

fail:
	endmntent(file);
err1:
	free(allcgroups);
	if (visited)
		free(visited);
	return NULL;
}

int lxc_cgroup_enter(const char *cgpath, pid_t pid)
{
	char path[MAXPATHLEN];
	FILE *file = NULL, *fout;
	struct mntent mntent_r;
	int ret, retv = -1;
	char buf[LARGE_MAXPATHLEN] = {0};

	file = setmntent(MTAB, "r");
	if (!file) {
		SYSERROR("failed to open %s", MTAB);
		return -1;
	}

	while ((getmntent_r(file, &mntent_r, buf, sizeof(buf)))) {
		if (strcmp(mntent_r.mnt_type, "cgroup"))
			continue;
		if (!mount_has_subsystem(&mntent_r))
			continue;
		ret = snprintf(path, MAXPATHLEN, "%s/%s/tasks",
			       mntent_r.mnt_dir, cgpath);
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

static int cgroup_rmdir(char *dirname)
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
			cgroup_rmdir(pathname);
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
	if (cgroup_rmdir(cgname)) {
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
	struct mntent mntent_r;
	FILE *file = NULL;
	int err, retv  = 0;

	char buf[LARGE_MAXPATHLEN] = {0};

	file = setmntent(MTAB, "r");
	if (!file) {
		SYSERROR("failed to open %s", MTAB);
		return -1;
	}

	while ((getmntent_r(file, &mntent_r, buf, sizeof(buf)))) {
		if (strcmp(mntent_r.mnt_type, "cgroup"))
			continue;
		if (!mount_has_subsystem(&mntent_r))
			continue;

		err = lxc_one_cgroup_destroy(&mntent_r, cgpath);
		if (err)  // keep trying to clean up the others
			retv = -1;
	}

	endmntent(file);
	return retv;
}

int lxc_cgroup_attach(pid_t pid, const char *name, const char *lxcpath)
{
	int ret;
	char *dirpath;

	dirpath = lxc_cmd_get_cgroup_path(name, lxcpath);
	if (!dirpath) {
		ERROR("Error getting cgroup for container %s: %s", lxcpath, name);
		return -1;
	}
	INFO("joining pid %d to cgroup %s", pid, dirpath);

	ret = lxc_cgroup_enter(dirpath, pid);
	free(dirpath);
	return ret;
}

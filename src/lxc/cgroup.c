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
#include <dirent.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/inotify.h>
#include <netinet/in.h>
#include <net/if.h>

#include "error.h"
#include "config.h"
#include "commands.h"
#include "list.h"
#include "conf.h"

#include <lxc/log.h>
#include <lxc/cgroup.h>
#include <lxc/start.h>

#if IS_BIONIC
#include <../include/lxcmntent.h>
#else
#include <mntent.h>
#endif

#ifndef HAVE_GETLINE
#ifdef HAVE_FGETLN
#include <../include/getline.h>
#endif
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
 * @dest: a passed-in buffer of at least size MAXPATHLEN into which the path
 * is copied.
 * @subsystem: cgroup subsystem (i.e. freezer)
 *
 * Returns true on success, false on error.
 */
bool get_subsys_mount(char *dest, const char *subsystem)
{
	struct mntent mntent_r;
	FILE *file = NULL;
	int ret;
	bool retv = false;
	char buf[LARGE_MAXPATHLEN] = {0};

	file = setmntent(MTAB, "r");
	if (!file) {
		SYSERROR("failed to open %s", MTAB);
		return -1;
	}

	while ((getmntent_r(file, &mntent_r, buf, sizeof(buf)))) {
		if (strcmp(mntent_r.mnt_type, "cgroup"))
			continue;

		if (subsystem) {
			if (!hasmntopt(&mntent_r, subsystem))
				continue;
		} else {
			if (!mount_has_subsystem(&mntent_r))
				continue;
		}

		ret = snprintf(dest, MAXPATHLEN, "%s", mntent_r.mnt_dir);
		if (ret < 0 || ret >= MAXPATHLEN)
			goto fail;

		retv = true;
		goto out;
	};

fail:
	DEBUG("Failed to find cgroup for %s\n",
	      subsystem ? subsystem : "(NULL)");
out:
	endmntent(file);
	return retv;
}

/*
 * is_in_cgroup: check whether pid is found in the passed-in cgroup tasks
 * file.
 * @path:  in full path to a cgroup tasks file
 * Note that in most cases the file will simply not exist, which is ok - it
 * just means that's not our cgroup.
 */
static bool is_in_cgroup(pid_t pid, char *path)
{
	int cmppid;
	FILE *f = fopen(path, "r");
	char *line = NULL;
	size_t sz = 0;

	if (!f)
		return false;
	while (getline(&line, &sz, f) != -1) {
		if (sscanf(line, "%d", &cmppid) == 1 && cmppid == pid) {
			fclose(f);
			free(line);
			return true;
		}
	}
	fclose(f);
	if (line)
		free(line);
	return false;
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
	char *cgpath, *cgp, path[MAXPATHLEN], *pathp, *p;
	pid_t initpid = lxc_cmd_get_init_pid(name, lxcpath);
	int ret;

	if (initpid < 0)
		return NULL;

	cgpath = lxc_cmd_get_cgroup_path(name, lxcpath, subsystem);
	if (!cgpath)
		return NULL;

	if (!get_subsys_mount(path, subsystem))
		return NULL;

	pathp = path + strlen(path);
	/*
	 * find a mntpt where i have the subsystem mounted, then find
	 * a subset cgpath under that which has pid in it.
	 *
	 * If d->mntpt is '/a/b/c/d', and the mountpoint is /x/y/z,
	 * then look for ourselves in:
	 *    /x/y/z/a/b/c/d/tasks
	 *    /x/y/z/b/c/d/tasks
	 *    /x/y/z/c/d/tasks
	 *    /x/y/z/d/tasks
	 *    /x/y/z/tasks
	 */
	cgp = cgpath;
	while (cgp[0]) {
		ret = snprintf(pathp, MAXPATHLEN - (pathp - path), "%s/tasks", cgp);
		if (ret < 0 || ret >= MAXPATHLEN)
			return NULL;
		if (!is_in_cgroup(initpid, path)) {
			// does not exist, try the next one
			cgp = index(cgp+1, '/');
			if (!cgp)
				break;
			continue;
		}
		break;
	}
	if (!cgp || !*cgp) {
		// try just the path
		ret = snprintf(pathp, MAXPATHLEN - (pathp - path), "/tasks");
		if (ret < 0 || ret >= MAXPATHLEN)
			return NULL;
		if (!is_in_cgroup(initpid, path)) {
			return NULL;
		}
		return strdup("/");
	}
	// path still has 'tasks' on the end, drop it
	if ((p = strrchr(path, '/')) != NULL)
		*p = '\0';
	return strdup(path);
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

static int in_subsys_list(const char *s, const char *list)
{
	char *token, *str, *saveptr = NULL;

	if (!list || !s)
		return 0;

	str = alloca(strlen(list)+1);
	strcpy(str, list);
	for (; (token = strtok_r(str, ",", &saveptr)); str = NULL) {
		if (strcmp(s, token) == 0)
			return 1;
	}

	return 0;
}

static char *cgroup_get_subsys_abspath(struct lxc_handler *handler, const char *subsys)
{
	struct cgroup_desc *d;

	for (d = handler->cgroup; d; d = d->next) {
		if (in_subsys_list(subsys, d->subsystems))
			return d->curcgroup;
	}

	return NULL;
}

static bool cgroup_devices_has_deny(struct lxc_handler *h, char *v)
{
	char *cgabspath, path[MAXPATHLEN];
	FILE *f;
	char *line = NULL;
	size_t len = 0;
	bool ret = true;
	int r;

	// XXX FIXME if users could use something other than 'lxc.devices.deny = a'.
	// not sure they ever do, but they *could*
	// right now, I'm assuming they do NOT
	if (strcmp(v, "a") && strcmp(v, "a *:* rwm"))
		return false;
	cgabspath = cgroup_get_subsys_abspath(h, "devices");
	if (!cgabspath)
		return false;

	r = snprintf(path, MAXPATHLEN, "%s/devices.list", cgabspath);
	if (r < 0 || r >= MAXPATHLEN) {
		ERROR("pathname too long for devices.list");
		return false;
	}

	if (!(f = fopen(path, "r")))
		return false;

	while (getline(&line, &len, f) != -1) {
		size_t len = strlen(line);
		if (len > 0 && line[len-1] == '\n')
			line[len-1] = '\0';
		if (strcmp(line, "a *:* rwm") == 0) {
			ret = false;
			goto out;
		}
	}

out:
	fclose(f);
	if (line)
		free(line);
	return ret;
}

static bool cgroup_devices_has_allow(struct lxc_handler *h, char *v)
{
	char *cgabspath, path[MAXPATHLEN];
	int r;
	bool ret = false;
	FILE *f;
	char *line = NULL;
	size_t len = 0;

	cgabspath = cgroup_get_subsys_abspath(h, "devices");
	if (!cgabspath)
		return false;

	r = snprintf(path, MAXPATHLEN, "%s/devices.list", cgabspath);
	if (r < 0 || r >= MAXPATHLEN) {
		ERROR("pathname too long to for devices.list");
		return false;
	}

	if (!(f = fopen(path, "r")))
		return false;

	while (getline(&line, &len, f) != -1) {
		if (len < 1)
			goto out;
		if (line[len-1] == '\n')
			line[len-1] = '\0';
		if (strcmp(line, "a *:* rwm") == 0 || strcmp(line, v) == 0) {
			ret = true;
			goto out;
		}
	}

out:
	if (line)
		free(line);
	fclose(f);
	return ret;
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
int lxc_cgroup_set_value(struct lxc_handler *handler, const char *filename,
			const char *value)
{
	char *cgabspath, path[MAXPATHLEN], *p;
	int ret;

	ret = snprintf(path, MAXPATHLEN, "%s", filename);
	if (ret < 0 || ret >= MAXPATHLEN)
		return -1;
	if ((p = index(path, '.')) != NULL)
		*p = '\0';
	cgabspath = cgroup_get_subsys_abspath(handler, path);
	if (!cgabspath)
		return -1;

	ret = snprintf(path, MAXPATHLEN, "%s/%s", cgabspath, filename);
	if (ret < 0 || ret >= MAXPATHLEN) {
		ERROR("pathname too long to set cgroup value %s to %s",
			filename, value);
		return -1;
	}

	return do_cgroup_set(path, value);
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
	char *subsystem = alloca(strlen(filename)+1), *p;
	strcpy(subsystem, filename);

	if ((p = index(subsystem, '.')) != NULL)
		*p = '\0';

	cgabspath = lxc_cgroup_path_get(subsystem, name, lxcpath);
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
	char *subsystem = alloca(strlen(filename)+1), *p;

	strcpy(subsystem, filename);

	if ((p = index(subsystem, '.')) != NULL)
		*p = '\0';

	cgabspath = lxc_cgroup_path_get(subsystem, name, lxcpath);
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

int lxc_cgroup_nrtasks(struct lxc_handler *handler)
{
	char path[MAXPATHLEN];
	int pid, ret;
	FILE *file;

	if (!handler->cgroup)
		return -1;

	/* XXX Should we use a specific subsystem rather than the first one we
	 * found (handler->cgroup->curcgroup)? */
	ret = snprintf(path, MAXPATHLEN, "%s/tasks", handler->cgroup->curcgroup);
	if (ret < 0 || ret >= MAXPATHLEN) {
		ERROR("pathname too long");
		return -1;
	}

	file = fopen(path, "r");
	if (!file) {
		SYSERROR("fopen '%s' failed", path);
		return -1;
	}

	ret = 0;
	while (fscanf(file, "%d", &pid) != EOF)
		ret++;

	fclose(file);
	return ret;
}

static int subsys_lists_match(const char *list1, const char *list2)
{
	char *token, *str, *saveptr = NULL;

	if (!list1 || !list2)
		return 0;

        if (strlen(list1) != strlen(list2))
                return 0;

	str = alloca(strlen(list1)+1);
	strcpy(str, list1);
	for (; (token = strtok_r(str, ",", &saveptr)); str = NULL) {
		if (in_subsys_list(token, list2) == 0)
			return 0;
	}

	return 1;
}

static void set_clone_children(struct mntent *m)
{
	char path[MAXPATHLEN];
	FILE *fout;
	int ret;

	if (!in_subsys_list("cpuset", m->mnt_opts))
		return;
	ret = snprintf(path, MAXPATHLEN, "%s/cgroup.clone_children", m->mnt_dir);
	if (ret < 0 || ret > MAXPATHLEN)
		return;
	fout = fopen(path, "w");
	if (!fout)
		return;
	fprintf(fout, "1\n");
	fclose(fout);
}

static bool have_visited(char *opts, char *visited, char *all_subsystems)
{
	char *str, *s = NULL, *token;

	str = alloca(strlen(opts)+1);
	strcpy(str, opts);
	for (; (token = strtok_r(str, ",", &s)); str = NULL) {
		if (!in_subsys_list(token, all_subsystems))
			continue;
		if (visited && in_subsys_list(token, visited))
			return true;
	}

	return false;
}

static bool is_in_desclist(struct cgroup_desc *d, char *opts, char *all_subsystems)
{
	while (d) {
		if (have_visited(opts, d->subsystems, all_subsystems))
			return true;
		d = d->next;
	}
	return false;
}

static char *record_visited(char *opts, char *all_subsystems)
{
	char *s = NULL, *token, *str;
	int oldlen = 0, newlen, toklen;
	char *visited = NULL;

	str = alloca(strlen(opts)+1);
	strcpy(str, opts);
	for (; (token = strtok_r(str, ",", &s)); str = NULL) {
		if (!in_subsys_list(token, all_subsystems))
			continue;
		toklen = strlen(token);
		newlen = oldlen + toklen +  1; // ',' + token or token + '\0'
		visited = realloc(visited, newlen);
		if (!visited)
			return (char *)-ENOMEM;
		if (oldlen)
			strcat(visited, ",");
		else
			*visited = '\0';
		strcat(visited, token);
		oldlen = newlen;
	}

	return visited;
}

static char *get_all_subsystems(void)
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

/*
 * /etc/lxc/lxc.conf can contain lxc.cgroup.use = entries.
 * If any of those are present, then lxc will ONLY consider
 * cgroup filesystems mounted at one of the listed entries.
 */
static char *get_cgroup_uselist()
{
	FILE *f;
	char *line = NULL, *ret = NULL;
	size_t sz = 0, retsz = 0, newsz;

	if ((f = fopen(LXC_GLOBAL_CONF, "r")) == NULL)
		return NULL;
	while (getline(&line, &sz, f) != -1) {
		char *p = line;
		while (*p && isblank(*p))
			p++;
		if (strncmp(p, "lxc.cgroup.use", 14) != 0)
			continue;
		p = index(p, '=');
		if (!p)
			continue;
		p++;
		while (*p && isblank(*p))
			p++;
		if (strlen(p) < 1)
			continue;
		newsz = retsz + strlen(p);
		if (retsz == 0)
			newsz += 1;  // for trailing \0
		// the last line in the file could lack \n
		if (p[strlen(p)-1] != '\n')
			newsz += 1;
		ret = realloc(ret, newsz);
		if (!ret) {
			ERROR("Out of memory reading cgroup uselist");
			fclose(f);
			free(line);
			return (char *)-ENOMEM;
		}
		if (retsz == 0)
			strcpy(ret, p);
		else
			strcat(ret, p);
		if (p[strlen(p)-1] != '\n')
			ret[newsz-2] = '\0';
		ret[newsz-1] = '\0';
		retsz = newsz;
	}

	if (line)
		free(line);
	return ret;
}

static bool is_in_uselist(char *uselist, struct mntent *m)
{
	char *p;
	if (!uselist)
		return true;
	if (!*uselist)
		return false;
	while (*uselist) {
		p = index(uselist, '\n');
		if (strncmp(m->mnt_dir, uselist, p - uselist) == 0)
			return true;
		uselist = p+1;
	}
	return false;
}

static bool find_real_cgroup(struct cgroup_desc *d, char *path)
{
	FILE *f;
	char *line = NULL, *p, *p2;
	int ret = 0;
	size_t len;

	if ((f = fopen("/proc/self/cgroup", "r")) == NULL) {
		SYSERROR("Error opening /proc/self/cgroups");
		return false;
	}

	// If there is no subsystem, ignore the mount.  Note we may want
	// to change this, so that unprivileged users can use a unbound
	// cgroup mount to arrange their container tasks.
	if (!d->subsystems) {
		fclose(f);
		return false;
	}
	while (getline(&line, &len, f) != -1) {
		if (!(p = index(line, ':')))
			continue;
		if (!(p2 = index(++p, ':')))
			continue;
		*p2 = '\0';
		// remove trailing newlines
		if (*(p2 + 1) && p2[strlen(p2 + 1)] == '\n')
		        p2[strlen(p2 + 1)] = '\0';
		// in case of multiple mounts it may be more correct to
		// insist all subsystems be the same
		if (subsys_lists_match(p, d->subsystems))
			goto found;
       }

	if (line)
		free(line);
	fclose(f);
	return false;;

found:
	fclose(f);
	ret = snprintf(path, MAXPATHLEN, "%s", p2+1);
	if (ret < 0 || ret >= MAXPATHLEN) {
		free(line);
		return false;
	}
	free(line);
	return true;
}


/*
 * for a given cgroup mount entry, and a to-be-created container,
 * 1. Figure out full path of the cgroup we are currently in,
 * 2. Find a new free cgroup which is $path / $lxc_name with an
 *    optional '-$n' where n is an ever-increasing integer.
 */
static char *find_free_cgroup(struct cgroup_desc *d, const char *lxc_name)
{
	char tail[20], cgpath[MAXPATHLEN], *cgp, path[MAXPATHLEN];
	int i = 0, ret;
	size_t l;

	if (!find_real_cgroup(d, cgpath)) {
		ERROR("Failed to find current cgroup");
		return NULL;
	}

	/*
	 * If d->mntpt is '/a/b/c/d', and the mountpoint is /x/y/z,
	 * then look for ourselves in:
	 *    /x/y/z/a/b/c/d/tasks
	 *    /x/y/z/b/c/d/tasks
	 *    /x/y/z/c/d/tasks
	 *    /x/y/z/d/tasks
	 *    /x/y/z/tasks
	 */
	cgp = cgpath;
	while (cgp[0]) {
		ret = snprintf(path, MAXPATHLEN, "%s%s/tasks", d->mntpt, cgp);
		if (ret < 0 || ret >= MAXPATHLEN)
			return NULL;
		if (!is_in_cgroup(getpid(), path)) {
			// does not exist, try the next one
			cgp = index(cgp+1, '/');
			if (!cgp)
				break;
			continue;
		}
		break;
	}
	if (!cgp || !*cgp) {
		// try just the path
		ret = snprintf(path, MAXPATHLEN, "%s/tasks", d->mntpt);
		if (ret < 0 || ret >= MAXPATHLEN)
			return NULL;
		if (!is_in_cgroup(getpid(), path))
			return NULL;
	}
	// found it
	// path has '/tasks' at end, drop that
	if (!(cgp = strrchr(path, '/'))) {
		ERROR("Got nonsensical path name %s\n", path);
		return NULL;
	}
	*cgp = '\0';

	if (strlen(path) + strlen(lxc_name) + 20 > MAXPATHLEN) {
		ERROR("Error: cgroup path too long");
		return NULL;
	}
	tail[0] = '\0';
	while (1) {
		struct stat sb;
		int freebytes = MAXPATHLEN - (cgp - path);

		if (i) {
			ret = snprintf(tail, 20, "-%d", i);
			if (ret < 0 || ret >= 20)
				return NULL;
		}
		ret = snprintf(cgp, freebytes, "/%s%s", lxc_name, tail);
		if (ret < 0 || ret >= freebytes)
			return NULL;
		if (stat(path, &sb) == -1)
			break;
		i++;
	}

	l = strlen(cgpath);
	ret = snprintf(cgpath + l, MAXPATHLEN - l, "/%s%s", lxc_name, tail);
	if (ret < 0 || ret >= (MAXPATHLEN - l)) {
		ERROR("Out of memory");
		return NULL;
	}
	if ((d->realcgroup = strdup(cgpath)) == NULL) {
		ERROR("Out of memory");
		return NULL;
	}
	l = strlen(d->realcgroup);
	if (l > 0 && d->realcgroup[l-1] == '\n')
		d->realcgroup[l-1] = '\0';
	return strdup(path);
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
 * Races won't be determintal, you'll just end up with leftover unused cgroups
 */
struct cgroup_desc *lxc_cgroup_path_create(const char *name)
{
	struct cgroup_desc *retdesc = NULL, *newdesc = NULL;
	FILE *file = NULL;
	struct mntent mntent_r;
	char buf[LARGE_MAXPATHLEN] = {0};
	char *all_subsystems = get_all_subsystems();
	char *cgroup_uselist = get_cgroup_uselist();

	if (cgroup_uselist == (char *)-ENOMEM) {
		if (all_subsystems)
			free(all_subsystems);
		return NULL;
	}
	if (!all_subsystems) {
		ERROR("failed to get a list of all cgroup subsystems");
		if (cgroup_uselist)
			free(cgroup_uselist);
		return NULL;
	}
	file = setmntent(MTAB, "r");
	if (!file) {
		SYSERROR("failed to open %s", MTAB);
		free(all_subsystems);
		if (cgroup_uselist)
			free(cgroup_uselist);
		return NULL;
	}

	while ((getmntent_r(file, &mntent_r, buf, sizeof(buf)))) {

		if (strcmp(mntent_r.mnt_type, "cgroup"))
			continue;

		if (cgroup_uselist && !is_in_uselist(cgroup_uselist, &mntent_r))
			continue;

		/* make sure we haven't checked this subsystem already */
		if (is_in_desclist(retdesc, mntent_r.mnt_opts, all_subsystems))
			continue;

		if (!(newdesc = malloc(sizeof(struct cgroup_desc)))) {
			ERROR("Out of memory reading cgroups");
			goto fail;
		}
		newdesc->subsystems = record_visited(mntent_r.mnt_opts, all_subsystems);
		if (newdesc->subsystems == (char *)-ENOMEM) {
			ERROR("Out of memory recording cgroup subsystems");
			free(newdesc);
			newdesc = NULL;
			goto fail;
		}
		if (!newdesc->subsystems) {
			free(newdesc);
			newdesc = NULL;
			continue;
		}
		newdesc->mntpt = strdup(mntent_r.mnt_dir);
		newdesc->realcgroup = NULL;
		newdesc->curcgroup = find_free_cgroup(newdesc, name);
		if (!newdesc->mntpt || !newdesc->curcgroup) {
			ERROR("Out of memory reading cgroups");
			goto fail;
		}

		set_clone_children(&mntent_r);

		if (mkdir(newdesc->curcgroup, 0755)) {
			ERROR("Error creating cgroup %s", newdesc->curcgroup);
			goto fail;
		}
		newdesc->next = retdesc;
		retdesc = newdesc;
	}

	endmntent(file);
	free(all_subsystems);
	if (cgroup_uselist)
		free(cgroup_uselist);
	return retdesc;

fail:
	endmntent(file);
	free(all_subsystems);
	if (cgroup_uselist)
		free(cgroup_uselist);
	if (newdesc) {
		if (newdesc->mntpt)
			free(newdesc->mntpt);
		if (newdesc->subsystems)
			free(newdesc->subsystems);
		if (newdesc->curcgroup)
			free(newdesc->curcgroup);
		if (newdesc->realcgroup)
			free(newdesc->realcgroup);
		free(newdesc);
	}
	while (retdesc) {
		struct cgroup_desc *t = retdesc;
		retdesc = retdesc->next;
		if (t->mntpt)
			free(t->mntpt);
		if (t->subsystems)
			free(t->subsystems);
		if (t->curcgroup)
			free(t->curcgroup);
		if (t->realcgroup)
			free(t->realcgroup);
		free(t);

	}
	return NULL;
}

static bool lxc_cgroup_enter_one(const char *dir, int pid)
{
	char path[MAXPATHLEN];
	int ret;
	FILE *fout;

	ret = snprintf(path, MAXPATHLEN, "%s/tasks", dir);
	if (ret < 0 || ret >= MAXPATHLEN) {
		ERROR("Error entering cgroup");
		return false;
	}
	fout = fopen(path, "w");
	if (!fout) {
		SYSERROR("Error entering cgroup");
		return false;
	}
	if (fprintf(fout, "%d\n", (int)pid) < 0) {
		ERROR("Error writing pid to %s to enter cgroup", path);
		fclose(fout);
		return false;
	}
	if (fclose(fout) < 0) {
		SYSERROR("Error writing pid to %s to enter cgroup", path);
		return false;
	}

	return true;
}

int lxc_cgroup_enter(struct cgroup_desc *cgroups, pid_t pid)
{
	while (cgroups) {
		if (!cgroups->subsystems)
			goto next;

		if (!lxc_cgroup_enter_one(cgroups->curcgroup, pid))
			return -1;
next:
		cgroups = cgroups->next;
	}
	return 0;
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

/*
 * for each mounted cgroup, destroy the cgroup for the container
 */
void lxc_cgroup_destroy_desc(struct cgroup_desc *cgroups)
{
	while (cgroups) {
		struct cgroup_desc *next = cgroups->next;
		if (cgroup_rmdir(cgroups->curcgroup) < 0)
			SYSERROR("Error removing cgroup directory %s", cgroups->curcgroup);
		free(cgroups->mntpt);
		free(cgroups->subsystems);
		free(cgroups->curcgroup);
		free(cgroups->realcgroup);
		free(cgroups);
		cgroups = next;
	}
}

int lxc_cgroup_attach(pid_t pid, const char *name, const char *lxcpath)
{
	FILE *f;
	char *line = NULL, ret = 0;
	size_t len = 0;
	int first = 1;
	char *dirpath;

	/* read the list of subsystems from the kernel */
	f = fopen("/proc/cgroups", "r");
	if (!f)
		return -1;

	while (getline(&line, &len, f) != -1) {
		char *c;

		/* skip the first line */
		if (first) {
			first=0;
			continue;
		}

		c = strchr(line, '\t');
		if (!c)
			continue;
		*c = '\0';
		dirpath = lxc_cgroup_path_get(line, name, lxcpath);
		if (!dirpath)
			continue;

		INFO("joining pid %d to cgroup %s", pid, dirpath);
		if (!lxc_cgroup_enter_one(dirpath, pid)) {
			ERROR("Failed joining %d to %s\n", pid, dirpath);
			ret = -1;
			continue;
		}
	}

	if (line)
		free(line);
	fclose(f);
	return ret;
}

bool is_in_subcgroup(int pid, const char *subsystem, struct cgroup_desc *d)
{
	char filepath[MAXPATHLEN], *line = NULL, v1[MAXPATHLEN], v2[MAXPATHLEN];
	FILE *f;
	int ret, junk;
	size_t sz = 0, l1, l2;
	char *end = index(subsystem, '.');
	int len = end ? (end - subsystem) : strlen(subsystem);
	const char *cgpath = NULL;

	while (d) {
		if (in_subsys_list("devices", d->subsystems)) {
			cgpath = d->realcgroup;
			l1 = strlen(cgpath);
			break;
		}
		d = d->next;
	}
	if (!d)
		return false;

	ret = snprintf(filepath, MAXPATHLEN, "/proc/%d/cgroup", pid);
	if (ret < 0 || ret >= MAXPATHLEN)
		return false;
	if ((f = fopen(filepath, "r")) == NULL)
		return false;
	while (getline(&line, &sz, f) != -1) {
		// nr:subsystem:path
		v2[0] = v2[1] = '\0';
		ret = sscanf(line, "%d:%[^:]:%s", &junk, v1, v2);
		if (ret != 3) {
			fclose(f);
			free(line);
			return false;
		}
		len = end ? end - subsystem : strlen(subsystem);
		if (strncmp(v1, subsystem, len) != 0)
			continue;
		// v2 will start with '/', skip it by using v2+1
		// we must be in SUBcgroup, so make sure l2 > l1
		l2 = strlen(v2+1);
		if (l2 > l1 && strncmp(v2+1, cgpath, l1) == 0) {
			fclose(f);
			free(line);
			return true;
		}
	}
	fclose(f);
	if (line)
		free(line);
	return false;
}

char *cgroup_get_subsys_path(struct lxc_handler *handler, const char *subsys)
{
	struct cgroup_desc *d;

	for (d = handler->cgroup; d; d = d->next) {
		if (in_subsys_list(subsys, d->subsystems))
			return d->realcgroup;
	}

	return NULL;
}

static int _setup_cgroup(struct lxc_handler *h, struct lxc_list *cgroups,
			  int devices)
{
	struct lxc_list *iterator;
	struct lxc_cgroup *cg;
	int ret = -1;

	if (lxc_list_empty(cgroups))
		return 0;

	lxc_list_for_each(iterator, cgroups) {
		cg = iterator->elem;

		if (devices == !strncmp("devices", cg->subsystem, 7)) {
			if (strcmp(cg->subsystem, "devices.deny") == 0 &&
					cgroup_devices_has_deny(h, cg->value))
				continue;
			if (strcmp(cg->subsystem, "devices.allow") == 0 &&
					cgroup_devices_has_allow(h, cg->value))
				continue;
			if (lxc_cgroup_set_value(h, cg->subsystem, cg->value)) {
				ERROR("Error setting %s to %s for %s\n",
				      cg->subsystem, cg->value, h->name);
				goto out;
			}
		}

		DEBUG("cgroup '%s' set to '%s'", cg->subsystem, cg->value);
	}

	ret = 0;
	INFO("cgroup has been setup");
out:
	return ret;
}

int setup_cgroup_devices(struct lxc_handler *h, struct lxc_list *cgroups)
{
	return _setup_cgroup(h, cgroups, 1);
}

int setup_cgroup(struct lxc_handler *h, struct lxc_list *cgroups)
{
	return _setup_cgroup(h, cgroups, 0);
}

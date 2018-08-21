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

#include "config.h"

#define __STDC_FORMAT_MACROS /* Required for PRIu64 to work. */
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <libgen.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "log.h"
#include "lxclock.h"
#include "namespace.h"
#include "parse.h"
#include "utils.h"

#ifndef HAVE_STRLCPY
#include "include/strlcpy.h"
#endif

#ifndef HAVE_STRLCAT
#include "include/strlcat.h"
#endif

#ifndef O_PATH
#define O_PATH      010000000
#endif

#ifndef O_NOFOLLOW
#define O_NOFOLLOW  00400000
#endif

lxc_log_define(utils, lxc);

/*
 * if path is btrfs, tries to remove it and any subvolumes beneath it
 */
extern bool btrfs_try_remove_subvol(const char *path);

static int _recursive_rmdir(const char *dirname, dev_t pdev,
			    const char *exclude, int level, bool onedev)
{
	struct dirent *direntp;
	DIR *dir;
	int ret, failed=0;
	char pathname[MAXPATHLEN];
	bool hadexclude = false;

	dir = opendir(dirname);
	if (!dir) {
		ERROR("failed to open %s", dirname);
		return -1;
	}

	while ((direntp = readdir(dir))) {
		struct stat mystat;
		int rc;

		if (!strcmp(direntp->d_name, ".") ||
		    !strcmp(direntp->d_name, ".."))
			continue;

		rc = snprintf(pathname, MAXPATHLEN, "%s/%s", dirname, direntp->d_name);
		if (rc < 0 || rc >= MAXPATHLEN) {
			ERROR("pathname too long");
			failed=1;
			continue;
		}

		if (!level && exclude && !strcmp(direntp->d_name, exclude)) {
			ret = rmdir(pathname);
			if (ret < 0) {
				switch(errno) {
				case ENOTEMPTY:
					INFO("Not deleting snapshot %s", pathname);
					hadexclude = true;
					break;
				case ENOTDIR:
					ret = unlink(pathname);
					if (ret)
						INFO("Failed to remove %s", pathname);
					break;
				default:
					SYSERROR("Failed to rmdir %s", pathname);
					failed = 1;
					break;
				}
			}
			continue;
		}

		ret = lstat(pathname, &mystat);
		if (ret) {
			ERROR("Failed to stat %s", pathname);
			failed = 1;
			continue;
		}

		if (onedev && mystat.st_dev != pdev) {
			/* TODO should we be checking /proc/self/mountinfo for
			 * pathname and not doing this if found? */
			if (btrfs_try_remove_subvol(pathname))
				INFO("Removed btrfs subvolume at %s\n", pathname);
			continue;
		}

		if (S_ISDIR(mystat.st_mode)) {
			if (_recursive_rmdir(pathname, pdev, exclude, level+1, onedev) < 0)
				failed=1;
		} else {
			if (unlink(pathname) < 0) {
				SYSERROR("Failed to delete %s", pathname);
				failed=1;
			}
		}
	}

	if (rmdir(dirname) < 0 && !btrfs_try_remove_subvol(dirname) && !hadexclude) {
		ERROR("Failed to delete %s", dirname);
		failed=1;
	}

	ret = closedir(dir);
	if (ret) {
		ERROR("Failed to close directory %s", dirname);
		failed=1;
	}

	return failed ? -1 : 0;
}

/* In overlayfs, st_dev is unreliable. So on overlayfs we don't do the
 * lxc_rmdir_onedev()
 */
static bool is_native_overlayfs(const char *path)
{
	if (has_fs_type(path, OVERLAY_SUPER_MAGIC) ||
	    has_fs_type(path, OVERLAYFS_SUPER_MAGIC))
		return true;

	return false;
}

/* returns 0 on success, -1 if there were any failures */
extern int lxc_rmdir_onedev(const char *path, const char *exclude)
{
	struct stat mystat;
	bool onedev = true;

	if (is_native_overlayfs(path))
		onedev = false;

	if (lstat(path, &mystat) < 0) {
		if (errno == ENOENT)
			return 0;

		ERROR("Failed to stat %s", path);
		return -1;
	}

	return _recursive_rmdir(path, mystat.st_dev, exclude, 0, onedev);
}

/* borrowed from iproute2 */
extern int get_u16(unsigned short *val, const char *arg, int base)
{
	unsigned long res;
	char *ptr;

	if (!arg || !*arg)
		return -1;

	errno = 0;
	res = strtoul(arg, &ptr, base);
	if (!ptr || ptr == arg || *ptr || res > 0xFFFF || errno != 0)
		return -1;

	*val = res;

	return 0;
}

extern int mkdir_p(const char *dir, mode_t mode)
{
	const char *tmp = dir;
	const char *orig = dir;
	char *makeme;

	do {
		dir = tmp + strspn(tmp, "/");
		tmp = dir + strcspn(dir, "/");

		makeme = strndup(orig, dir - orig);
		if (*makeme) {
			if (mkdir(makeme, mode) && errno != EEXIST) {
				SYSERROR("failed to create directory '%s'", makeme);
				free(makeme);
				return -1;
			}
		}
		free(makeme);
	} while(tmp != dir);

	return 0;
}

char *get_rundir()
{
	char *rundir;
	const char *homedir;
	struct stat sb;

	if (stat(RUNTIME_PATH, &sb) < 0)
		return NULL;

	if (geteuid() == sb.st_uid || getegid() == sb.st_gid) {
		rundir = strdup(RUNTIME_PATH);
		return rundir;
	}

	rundir = getenv("XDG_RUNTIME_DIR");
	if (rundir) {
		rundir = strdup(rundir);
		return rundir;
	}

	INFO("XDG_RUNTIME_DIR isn't set in the environment.");
	homedir = getenv("HOME");
	if (!homedir) {
		ERROR("HOME isn't set in the environment.");
		return NULL;
	}

	rundir = malloc(sizeof(char) * (17 + strlen(homedir)));
	if (!rundir)
		return NULL;

	sprintf(rundir, "%s/.cache/lxc/run/", homedir);

	return rundir;
}

int wait_for_pid(pid_t pid)
{
	int status, ret;

again:
	ret = waitpid(pid, &status, 0);
	if (ret == -1) {
		if (errno == EINTR)
			goto again;

		return -1;
	}

	if (ret != pid)
		goto again;

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return -1;

	return 0;
}

int lxc_wait_for_pid_status(pid_t pid)
{
	int status, ret;

again:
	ret = waitpid(pid, &status, 0);
	if (ret == -1) {
		if (errno == EINTR)
			goto again;

		return -1;
	}

	if (ret != pid)
		goto again;

	return status;
}

#if HAVE_LIBGNUTLS
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

__attribute__((constructor))
static void gnutls_lxc_init(void)
{
	gnutls_global_init();
}

int sha1sum_file(char *fnam, unsigned char *digest)
{
	char *buf;
	int ret;
	FILE *f;
	long flen;

	if (!fnam)
		return -1;

	f = fopen_cloexec(fnam, "r");
	if (!f) {
		SYSERROR("Error opening template");
		return -1;
	}

	if (fseek(f, 0, SEEK_END) < 0) {
		SYSERROR("Error seeking to end of template");
		fclose(f);
		return -1;
	}

	if ((flen = ftell(f)) < 0) {
		SYSERROR("Error telling size of template");
		fclose(f);
		return -1;
	}

	if (fseek(f, 0, SEEK_SET) < 0) {
		SYSERROR("Error seeking to start of template");
		fclose(f);
		return -1;
	}

	if ((buf = malloc(flen+1)) == NULL) {
		SYSERROR("Out of memory");
		fclose(f);
		return -1;
	}

	if (fread(buf, 1, flen, f) != flen) {
		SYSERROR("Failure reading template");
		free(buf);
		fclose(f);
		return -1;
	}

	if (fclose(f) < 0) {
		SYSERROR("Failre closing template");
		free(buf);
		return -1;
	}

	buf[flen] = '\0';
	ret = gnutls_hash_fast(GNUTLS_DIG_SHA1, buf, flen, (void *)digest);
	free(buf);
	return ret;
}
#endif

struct lxc_popen_FILE *lxc_popen(const char *command)
{
	int ret;
	int pipe_fds[2];
	pid_t child_pid;
	struct lxc_popen_FILE *fp = NULL;

	ret = pipe2(pipe_fds, O_CLOEXEC);
	if (ret < 0)
		return NULL;

	child_pid = fork();
	if (child_pid < 0)
		goto on_error;

	if (!child_pid) {
		sigset_t mask;

		close(pipe_fds[0]);

		/* duplicate stdout */
		if (pipe_fds[1] != STDOUT_FILENO)
			ret = dup2(pipe_fds[1], STDOUT_FILENO);
		else
			ret = fcntl(pipe_fds[1], F_SETFD, 0);
		if (ret < 0) {
			close(pipe_fds[1]);
			_exit(EXIT_FAILURE);
		}

		/* duplicate stderr */
		if (pipe_fds[1] != STDERR_FILENO)
			ret = dup2(pipe_fds[1], STDERR_FILENO);
		else
			ret = fcntl(pipe_fds[1], F_SETFD, 0);
		close(pipe_fds[1]);
		if (ret < 0)
			_exit(EXIT_FAILURE);

		/* unblock all signals */
		ret = sigfillset(&mask);
		if (ret < 0)
			_exit(EXIT_FAILURE);

		ret = pthread_sigmask(SIG_UNBLOCK, &mask, NULL);
		if (ret < 0)
			_exit(EXIT_FAILURE);

		execl("/bin/sh", "sh", "-c", command, (char *)NULL);
		_exit(127);
	}

	close(pipe_fds[1]);
	pipe_fds[1] = -1;

	fp = malloc(sizeof(*fp));
	if (!fp)
		goto on_error;

	memset(fp, 0, sizeof(*fp));

	fp->child_pid = child_pid;
	fp->pipe = pipe_fds[0];

	/* From now on, closing fp->f will also close fp->pipe. So only ever
	 * call fclose(fp->f).
	 */
	fp->f = fdopen(pipe_fds[0], "r");
	if (!fp->f)
		goto on_error;

	return fp;

on_error:
	/* We can only close pipe_fds[0] if fdopen() didn't succeed or wasn't
	 * called yet. Otherwise the fd belongs to the file opened by fdopen()
	 * since it isn't dup()ed.
	 */
	if (fp && !fp->f && pipe_fds[0] >= 0)
		close(pipe_fds[0]);

	if (pipe_fds[1] >= 0)
		close(pipe_fds[1]);

	if (fp && fp->f)
		fclose(fp->f);

	if (fp)
		free(fp);

	return NULL;
}

int lxc_pclose(struct lxc_popen_FILE *fp)
{
	pid_t wait_pid;
	int wstatus = 0;

	if (!fp)
		return -1;

	do {
		wait_pid = waitpid(fp->child_pid, &wstatus, 0);
	} while (wait_pid < 0 && errno == EINTR);

	fclose(fp->f);
	free(fp);

	if (wait_pid < 0)
		return -1;

	return wstatus;
}

int randseed(bool srand_it)
{
	/*
	   srand pre-seed function based on /dev/urandom
	   */
	unsigned int seed = time(NULL) + getpid();

	FILE *f;
	f = fopen("/dev/urandom", "r");
	if (f) {
		int ret = fread(&seed, sizeof(seed), 1, f);
		if (ret != 1)
			SYSDEBUG("unable to fread /dev/urandom, fallback to time+pid rand seed");

		fclose(f);
	}

	if (srand_it)
		srand(seed);

	return seed;
}

uid_t get_ns_uid(uid_t orig)
{
	char *line = NULL;
	size_t sz = 0;
	uid_t nsid, hostid, range;
	FILE *f = fopen("/proc/self/uid_map", "r");
	if (!f)
		return 0;

	while (getline(&line, &sz, f) != -1) {
		if (sscanf(line, "%u %u %u", &nsid, &hostid, &range) != 3)
			continue;

		if (hostid <= orig && hostid + range > orig) {
			nsid += orig - hostid;
			goto found;
		}
	}

	nsid = 0;

found:
	fclose(f);
	free(line);
	return nsid;
}

bool dir_exists(const char *path)
{
	struct stat sb;
	int ret;

	ret = stat(path, &sb);
	if (ret < 0)
		/* Could be something other than eexist, just say "no". */
		return false;

	return S_ISDIR(sb.st_mode);
}

/* Note we don't use SHA-1 here as we don't want to depend on HAVE_GNUTLS.
 * FNV has good anti collision properties and we're not worried
 * about pre-image resistance or one-way-ness, we're just trying to make
 * the name unique in the 108 bytes of space we have.
 */
uint64_t fnv_64a_buf(void *buf, size_t len, uint64_t hval)
{
	unsigned char *bp;

	for(bp = buf; bp < (unsigned char *)buf + len; bp++)
	{
		/* xor the bottom with the current octet */
		hval ^= (uint64_t)*bp;

		/* gcc optimised:
		 * multiply by the 64 bit FNV magic prime mod 2^64
		 */
		hval += (hval << 1) + (hval << 4) + (hval << 5) +
			(hval << 7) + (hval << 8) + (hval << 40);
	}

	return hval;
}

/*
 * Detect whether / is mounted MS_SHARED.  The only way I know of to
 * check that is through /proc/self/mountinfo.
 * I'm only checking for /.  If the container rootfs or mount location
 * is MS_SHARED, but not '/', then you're out of luck - figuring that
 * out would be too much work to be worth it.
 */
int detect_shared_rootfs(void)
{
	char buf[LXC_LINELEN], *p;
	FILE *f;
	int i;
	char *p2;

	f = fopen("/proc/self/mountinfo", "r");
	if (!f)
		return 0;

	while (fgets(buf, LXC_LINELEN, f)) {
		for (p = buf, i = 0; p && i < 4; i++)
			p = strchr(p + 1, ' ');
		if (!p)
			continue;

		p2 = strchr(p + 1, ' ');
		if (!p2)
			continue;

		*p2 = '\0';
		if (strcmp(p + 1, "/") == 0) {
			/* This is '/'. Is it shared? */
			p = strchr(p2 + 1, ' ');
			if (p && strstr(p, "shared:")) {
				fclose(f);
				return 1;
			}
		}
	}

	fclose(f);
	return 0;
}

bool switch_to_ns(pid_t pid, const char *ns)
{
	int fd, ret;
	char nspath[MAXPATHLEN];

	/* Switch to new ns */
	ret = snprintf(nspath, MAXPATHLEN, "/proc/%d/ns/%s", pid, ns);
	if (ret < 0 || ret >= MAXPATHLEN)
		return false;

	fd = open(nspath, O_RDONLY);
	if (fd < 0) {
		SYSERROR("Failed to open %s", nspath);
		return false;
	}

	ret = setns(fd, 0);
	if (ret) {
		SYSERROR("Failed to set process %d to %s of %d.", pid, ns, fd);
		close(fd);
		return false;
	}

	close(fd);
	return true;
}

/*
 * looking at fs/proc_namespace.c, it appears we can
 * actually expect the rootfs entry to very specifically contain
 * " - rootfs rootfs "
 * IIUC, so long as we've chrooted so that rootfs is not our root,
 * the rootfs entry should always be skipped in mountinfo contents.
 */
bool detect_ramfs_rootfs(void)
{
	FILE *f;
	char *p, *p2;
	char *line = NULL;
	size_t len = 0;
	int i;

	f = fopen("/proc/self/mountinfo", "r");
	if (!f)
		return false;

	while (getline(&line, &len, f) != -1) {
		for (p = line, i = 0; p && i < 4; i++)
			p = strchr(p + 1, ' ');
		if (!p)
			continue;

		p2 = strchr(p + 1, ' ');
		if (!p2)
			continue;

		*p2 = '\0';
		if (strcmp(p + 1, "/") == 0) {
			/* This is '/'. Is it the ramfs? */
			p = strchr(p2 + 1, '-');
			if (p && strncmp(p, "- rootfs rootfs ", 16) == 0) {
				free(line);
				fclose(f);
				INFO("Rootfs is located on ramfs");
				return true;
			}
		}
	}

	free(line);
	fclose(f);
	return false;
}

char *on_path(const char *cmd, const char *rootfs)
{
	char *entry = NULL, *path = NULL;
	char cmdpath[MAXPATHLEN];
	int ret;

	path = getenv("PATH");
	if (!path)
		return NULL;

	path = strdup(path);
	if (!path)
		return NULL;

	lxc_iterate_parts (entry, path, ":") {
		if (rootfs)
			ret = snprintf(cmdpath, MAXPATHLEN, "%s/%s/%s", rootfs,
				       entry, cmd);
		else
			ret = snprintf(cmdpath, MAXPATHLEN, "%s/%s", entry, cmd);
		if (ret < 0 || ret >= MAXPATHLEN)
			continue;

		if (access(cmdpath, X_OK) == 0) {
			free(path);
			return strdup(cmdpath);
		}
	}

	free(path);
	return NULL;
}

bool cgns_supported(void)
{
	return file_exists("/proc/self/ns/cgroup");
}

/* historically lxc-init has been under /usr/lib/lxc and under
 * /usr/lib/$ARCH/lxc.  It now lives as $prefix/sbin/init.lxc.
 */
char *choose_init(const char *rootfs)
{
	char *retv = NULL;
	const char *empty = "",
		   *tmp;
	int ret, env_set = 0;

	if (!getenv("PATH")) {
		if (setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 0))
			SYSERROR("Failed to setenv");

		env_set = 1;
	}

	retv = on_path("init.lxc", rootfs);

	if (env_set) {
		if (unsetenv("PATH"))
			SYSERROR("Failed to unsetenv");
	}

	if (retv)
		return retv;

	retv = malloc(PATH_MAX);
	if (!retv)
		return NULL;

	if (rootfs)
		tmp = rootfs;
	else
		tmp = empty;

	ret = snprintf(retv, PATH_MAX, "%s/%s/%s", tmp, SBINDIR, "/init.lxc");
	if (ret < 0 || ret >= PATH_MAX) {
		ERROR("pathname too long");
		goto out1;
	}

	if (access(retv, X_OK) == 0)
		return retv;

	ret = snprintf(retv, PATH_MAX, "%s/%s/%s", tmp, LXCINITDIR, "/lxc/lxc-init");
	if (ret < 0 || ret >= PATH_MAX) {
		ERROR("pathname too long");
		goto out1;
	}

	if (access(retv, X_OK) == 0)
		return retv;

	ret = snprintf(retv, PATH_MAX, "%s/usr/lib/lxc/lxc-init", tmp);
	if (ret < 0 || ret >= PATH_MAX) {
		ERROR("pathname too long");
		goto out1;
	}

	if (access(retv, X_OK) == 0)
		return retv;

	ret = snprintf(retv, PATH_MAX, "%s/sbin/lxc-init", tmp);
	if (ret < 0 || ret >= PATH_MAX) {
		ERROR("pathname too long");
		goto out1;
	}

	if (access(retv, X_OK) == 0)
		return retv;

	/*
	 * Last resort, look for the statically compiled init.lxc which we
	 * hopefully bind-mounted in.
	 * If we are called during container setup, and we get to this point,
	 * then the init.lxc.static from the host will need to be bind-mounted
	 * in.  So we return NULL here to indicate that.
	 */
	if (rootfs)
		goto out1;

	ret = snprintf(retv, PATH_MAX, "/init.lxc.static");
	if (ret < 0 || ret >= PATH_MAX) {
		WARN("Nonsense - name /lxc.init.static too long");
		goto out1;
	}

	if (access(retv, X_OK) == 0)
		return retv;

out1:
	free(retv);
	return NULL;
}

/*
 * Given the '-t' template option to lxc-create, figure out what to
 * do.  If the template is a full executable path, use that.  If it
 * is something like 'sshd', then return $templatepath/lxc-sshd.
 * On success return the template, on error return NULL.
 */
char *get_template_path(const char *t)
{
	int ret, len;
	char *tpath;

	if (t[0] == '/' && access(t, X_OK) == 0) {
		tpath = strdup(t);
		return tpath;
	}

	len = strlen(LXCTEMPLATEDIR) + strlen(t) + strlen("/lxc-") + 1;

	tpath = malloc(len);
	if (!tpath)
		return NULL;

	ret = snprintf(tpath, len, "%s/lxc-%s", LXCTEMPLATEDIR, t);
	if (ret < 0 || ret >= len) {
		free(tpath);
		return NULL;
	}

	if (access(tpath, X_OK) < 0) {
		SYSERROR("bad template: %s", t);
		free(tpath);
		return NULL;
	}

	return tpath;
}

/*
 * @path:    a pathname where / replaced with '\0'.
 * @offsetp: pointer to int showing which path segment was last seen.
 *           Updated on return to reflect the next segment.
 * @fulllen: full original path length.
 * Returns a pointer to the next path segment, or NULL if done.
 */
static char *get_nextpath(char *path, int *offsetp, int fulllen)
{
	int offset = *offsetp;

	if (offset >= fulllen)
		return NULL;

	while (path[offset] != '\0' && offset < fulllen)
		offset++;

	while (path[offset] == '\0' && offset < fulllen)
		offset++;

	*offsetp = offset;
	return (offset < fulllen) ? &path[offset] : NULL;
}

/*
 * Check that @subdir is a subdir of @dir.  @len is the length of
 * @dir (to avoid having to recalculate it).
 */
static bool is_subdir(const char *subdir, const char *dir, size_t len)
{
	size_t subdirlen = strlen(subdir);

	if (subdirlen < len)
		return false;

	if (strncmp(subdir, dir, len) != 0)
		return false;

	if (dir[len-1] == '/')
		return true;

	if (subdir[len] == '/' || subdirlen == len)
		return true;

	return false;
}

/*
 * Check if the open fd is a symlink.  Return -ELOOP if it is.  Return
 * -ENOENT if we couldn't fstat.  Return 0 if the fd is ok.
 */
static int check_symlink(int fd)
{
	struct stat sb;
	int ret;

	ret = fstat(fd, &sb);
	if (ret < 0)
		return -ENOENT;

	if (S_ISLNK(sb.st_mode))
		return -ELOOP;

	return 0;
}

/*
 * Open a file or directory, provided that it contains no symlinks.
 *
 * CAVEAT: This function must not be used for other purposes than container
 * setup before executing the container's init
 */
static int open_if_safe(int dirfd, const char *nextpath)
{
	int newfd = openat(dirfd, nextpath, O_RDONLY | O_NOFOLLOW);
	if (newfd >= 0) /* Was not a symlink, all good. */
		return newfd;

	if (errno == ELOOP)
		return newfd;

	if (errno == EPERM || errno == EACCES) {
		/* We're not root (cause we got EPERM) so try opening with
		 * O_PATH.
		 */
		newfd = openat(dirfd, nextpath, O_PATH | O_NOFOLLOW);
		if (newfd >= 0) {
			/* O_PATH will return an fd for symlinks. We know
			 * nextpath wasn't a symlink at last openat, so if fd is
			 * now a link, then something * fishy is going on.
			 */
			int ret = check_symlink(newfd);
			if (ret < 0) {
				close(newfd);
				newfd = ret;
			}
		}
	}

	return newfd;
}

/*
 * Open a path intending for mounting, ensuring that the final path
 * is inside the container's rootfs.
 *
 * CAVEAT: This function must not be used for other purposes than container
 * setup before executing the container's init
 *
 * @target: path to be opened
 * @prefix_skip: a part of @target in which to ignore symbolic links.  This
 * would be the container's rootfs.
 *
 * Return an open fd for the path, or <0 on error.
 */
static int open_without_symlink(const char *target, const char *prefix_skip)
{
	int curlen = 0, dirfd, fulllen, i;
	char *dup = NULL;

	fulllen = strlen(target);

	/* make sure prefix-skip makes sense */
	if (prefix_skip && strlen(prefix_skip) > 0) {
		curlen = strlen(prefix_skip);
		if (!is_subdir(target, prefix_skip, curlen)) {
			ERROR("WHOA there - target '%s' didn't start with prefix '%s'",
				target, prefix_skip);
			return -EINVAL;
		}

		/*
		 * get_nextpath() expects the curlen argument to be
		 * on a  (turned into \0) / or before it, so decrement
		 * curlen to make sure that happens
		 */
		if (curlen)
			curlen--;
	} else {
		prefix_skip = "/";
		curlen = 0;
	}

	/* Make a copy of target which we can hack up, and tokenize it */
	if ((dup = strdup(target)) == NULL) {
		SYSERROR("Out of memory checking for symbolic link");
		return -ENOMEM;
	}

	for (i = 0; i < fulllen; i++) {
		if (dup[i] == '/')
			dup[i] = '\0';
	}

	dirfd = open(prefix_skip, O_RDONLY);
	if (dirfd < 0)
		goto out;

	while (1) {
		int newfd, saved_errno;
		char *nextpath;

		if ((nextpath = get_nextpath(dup, &curlen, fulllen)) == NULL)
			goto out;

		newfd = open_if_safe(dirfd, nextpath);
		saved_errno = errno;
		close(dirfd);

		dirfd = newfd;
		if (newfd < 0) {
			errno = saved_errno;
			if (errno == ELOOP)
				SYSERROR("%s in %s was a symbolic link!", nextpath, target);

			goto out;
		}
	}

out:
	free(dup);
	return dirfd;
}

/*
 * Safely mount a path into a container, ensuring that the mount target
 * is under the container's @rootfs.  (If @rootfs is NULL, then the container
 * uses the host's /)
 *
 * CAVEAT: This function must not be used for other purposes than container
 * setup before executing the container's init
 */
int safe_mount(const char *src, const char *dest, const char *fstype,
		unsigned long flags, const void *data, const char *rootfs)
{
	int destfd, ret, saved_errno;
	/* Only needs enough for /proc/self/fd/<fd>. */
	char srcbuf[50], destbuf[50];
	int srcfd = -1;
	const char *mntsrc = src;

	if (!rootfs)
		rootfs = "";

	/* todo - allow symlinks for relative paths if 'allowsymlinks' option is passed */
	if (flags & MS_BIND && src && src[0] != '/') {
		INFO("this is a relative bind mount");

		srcfd = open_without_symlink(src, NULL);
		if (srcfd < 0)
			return srcfd;

		ret = snprintf(srcbuf, 50, "/proc/self/fd/%d", srcfd);
		if (ret < 0 || ret > 50) {
			close(srcfd);
			ERROR("Out of memory");
			return -EINVAL;
		}
		mntsrc = srcbuf;
	}

	destfd = open_without_symlink(dest, rootfs);
	if (destfd < 0) {
		if (srcfd != -1) {
			saved_errno = errno;
			close(srcfd);
			errno = saved_errno;
		}

		return destfd;
	}

	ret = snprintf(destbuf, 50, "/proc/self/fd/%d", destfd);
	if (ret < 0 || ret > 50) {
		if (srcfd != -1)
			close(srcfd);

		close(destfd);
		ERROR("Out of memory");
		return -EINVAL;
	}

	ret = mount(mntsrc, destbuf, fstype, flags, data);
	saved_errno = errno;
	if (srcfd != -1)
		close(srcfd);

	close(destfd);
	if (ret < 0) {
		errno = saved_errno;
		SYSERROR("Failed to mount %s onto %s", src ? src : "(null)", dest);
		return ret;
	}

	return 0;
}

/*
 * Mount a proc under @rootfs if proc self points to a pid other than
 * my own.  This is needed to have a known-good proc mount for setting
 * up LSMs both at container startup and attach.
 *
 * @rootfs : the rootfs where proc should be mounted
 *
 * Returns < 0 on failure, 0 if the correct proc was already mounted
 * and 1 if a new proc was mounted.
 *
 * NOTE: not to be called from inside the container namespace!
 */
int lxc_mount_proc_if_needed(const char *rootfs)
{
	char path[MAXPATHLEN];
	int link_to_pid, linklen, mypid, ret;
	char link[LXC_NUMSTRLEN64] = {0};

	ret = snprintf(path, MAXPATHLEN, "%s/proc/self", rootfs);
	if (ret < 0 || ret >= MAXPATHLEN) {
		SYSERROR("proc path name too long");
		return -1;
	}

	linklen = readlink(path, link, LXC_NUMSTRLEN64);

	ret = snprintf(path, MAXPATHLEN, "%s/proc", rootfs);
	if (ret < 0 || ret >= MAXPATHLEN) {
		SYSERROR("proc path name too long");
		return -1;
	}

	/* /proc not mounted */
	if (linklen < 0) {
		if (mkdir(path, 0755) && errno != EEXIST)
			return -1;

		goto domount;
	} else if (linklen >= LXC_NUMSTRLEN64) {
		link[linklen - 1] = '\0';
		ERROR("readlink returned truncated content: \"%s\"", link);
		return -1;
	}

	mypid = lxc_raw_getpid();
	INFO("I am %d, /proc/self points to \"%s\"", mypid, link);

	if (lxc_safe_int(link, &link_to_pid) < 0)
		return -1;

	/* correct procfs is already mounted */
	if (link_to_pid == mypid)
		return 0;

	ret = umount2(path, MNT_DETACH);
	if (ret < 0)
		WARN("failed to umount \"%s\" with MNT_DETACH", path);

domount:
	/* rootfs is NULL */
	if (!strcmp(rootfs, ""))
		ret = mount("proc", path, "proc", 0, NULL);
	else
		ret = safe_mount("proc", path, "proc", 0, NULL, rootfs);
	if (ret < 0)
		return -1;

	INFO("mounted /proc in container for security transition");
	return 1;
}

int open_devnull(void)
{
	int fd = open("/dev/null", O_RDWR);

	if (fd < 0)
		SYSERROR("Can't open /dev/null");

	return fd;
}

int set_stdfds(int fd)
{
	int ret;

	if (fd < 0)
		return -1;

	ret = dup2(fd, STDIN_FILENO);
	if (ret < 0)
		return -1;

	ret = dup2(fd, STDOUT_FILENO);
	if (ret < 0)
		return -1;

	ret = dup2(fd, STDERR_FILENO);
	if (ret < 0)
		return -1;

	return 0;
}

int null_stdfds(void)
{
	int ret = -1;
	int fd;

	fd = open_devnull();
	if (fd >= 0) {
		ret = set_stdfds(fd);
		close(fd);
	}

	return ret;
}

/* Check whether a signal is blocked by a process. */
/* /proc/pid-to-str/status\0 = (5 + 21 + 7 + 1) */
#define __PROC_STATUS_LEN (6 + (LXC_NUMSTRLEN64) + 7 + 1)
bool task_blocks_signal(pid_t pid, int signal)
{
	int ret;
	char status[__PROC_STATUS_LEN];
	FILE *f;
	uint64_t sigblk = 0, one = 1;
	size_t n = 0;
	bool bret = false;
	char *line = NULL;

	ret = snprintf(status, __PROC_STATUS_LEN, "/proc/%d/status", pid);
	if (ret < 0 || ret >= __PROC_STATUS_LEN)
		return bret;

	f = fopen(status, "r");
	if (!f)
		return bret;

	while (getline(&line, &n, f) != -1) {
		char *numstr;

		if (strncmp(line, "SigBlk:", 7))
			continue;

		numstr = lxc_trim_whitespace_in_place(line + 7);
		ret = lxc_safe_uint64(numstr, &sigblk, 16);
		if (ret < 0)
			goto out;

		break;
	}

	if (sigblk & (one << (signal - 1)))
		bret = true;

out:
	free(line);
	fclose(f);
	return bret;
}

int lxc_preserve_ns(const int pid, const char *ns)
{
	int ret;
/* 5 /proc + 21 /int_as_str + 3 /ns + 20 /NS_NAME + 1 \0 */
#define __NS_PATH_LEN 50
	char path[__NS_PATH_LEN];

	/* This way we can use this function to also check whether namespaces
	 * are supported by the kernel by passing in the NULL or the empty
	 * string.
	 */
	ret = snprintf(path, __NS_PATH_LEN, "/proc/%d/ns%s%s", pid,
		       !ns || strcmp(ns, "") == 0 ? "" : "/",
		       !ns || strcmp(ns, "") == 0 ? "" : ns);
	if (ret < 0 || (size_t)ret >= __NS_PATH_LEN) {
		errno = EFBIG;
		return -1;
	}

	return open(path, O_RDONLY | O_CLOEXEC);
}

int lxc_switch_uid_gid(uid_t uid, gid_t gid)
{
	if (setgid(gid) < 0) {
		SYSERROR("Failed to switch to gid %d.", gid);
		return -errno;
	}
	NOTICE("Switched to gid %d.", gid);

	if (setuid(uid) < 0) {
		SYSERROR("Failed to switch to uid %d.", uid);
		return -errno;
	}
	NOTICE("Switched to uid %d.", uid);

	return 0;
}

/* Simple covenience function which enables uniform logging. */
int lxc_setgroups(int size, gid_t list[])
{
	if (setgroups(size, list) < 0) {
		SYSERROR("Failed to setgroups().");
		return -errno;
	}
	NOTICE("Dropped additional groups.");

	return 0;
}

static int lxc_get_unused_loop_dev_legacy(char *loop_name)
{
	struct dirent *dp;
	struct loop_info64 lo64;
	DIR *dir;
	int dfd = -1, fd = -1, ret = -1;

	dir = opendir("/dev");
	if (!dir)
		return -1;

	while ((dp = readdir(dir))) {
		if (strncmp(dp->d_name, "loop", 4) != 0)
			continue;

		dfd = dirfd(dir);
		if (dfd < 0)
			continue;

		fd = openat(dfd, dp->d_name, O_RDWR);
		if (fd < 0)
			continue;

		ret = ioctl(fd, LOOP_GET_STATUS64, &lo64);
		if (ret < 0) {
			if (ioctl(fd, LOOP_GET_STATUS64, &lo64) == 0 ||
			    errno != ENXIO) {
				close(fd);
				fd = -1;
				continue;
			}
		}

		ret = snprintf(loop_name, LO_NAME_SIZE, "/dev/%s", dp->d_name);
		if (ret < 0 || ret >= LO_NAME_SIZE) {
			close(fd);
			fd = -1;
			continue;
		}

		break;
	}

	closedir(dir);

	if (fd < 0)
		return -1;

	return fd;
}

static int lxc_get_unused_loop_dev(char *name_loop)
{
	int loop_nr, ret;
	int fd_ctl = -1, fd_tmp = -1;

	fd_ctl = open("/dev/loop-control", O_RDWR | O_CLOEXEC);
	if (fd_ctl < 0)
		return -ENODEV;

	loop_nr = ioctl(fd_ctl, LOOP_CTL_GET_FREE);
	if (loop_nr < 0)
		goto on_error;

	ret = snprintf(name_loop, LO_NAME_SIZE, "/dev/loop%d", loop_nr);
	if (ret < 0 || ret >= LO_NAME_SIZE)
		goto on_error;

	fd_tmp = open(name_loop, O_RDWR | O_CLOEXEC);
	if (fd_tmp < 0)
		goto on_error;

on_error:
	close(fd_ctl);
	return fd_tmp;
}

int lxc_prepare_loop_dev(const char *source, char *loop_dev, int flags)
{
	int ret;
	struct loop_info64 lo64;
	int fd_img = -1, fret = -1, fd_loop = -1;

	fd_loop = lxc_get_unused_loop_dev(loop_dev);
	if (fd_loop < 0) {
		if (fd_loop == -ENODEV)
			fd_loop = lxc_get_unused_loop_dev_legacy(loop_dev);
		else
			goto on_error;
	}

	fd_img = open(source, O_RDWR | O_CLOEXEC);
	if (fd_img < 0)
		goto on_error;

	ret = ioctl(fd_loop, LOOP_SET_FD, fd_img);
	if (ret < 0)
		goto on_error;

	memset(&lo64, 0, sizeof(lo64));
	lo64.lo_flags = flags;

	ret = ioctl(fd_loop, LOOP_SET_STATUS64, &lo64);
	if (ret < 0)
		goto on_error;

	fret = 0;

on_error:
	if (fd_img >= 0)
		close(fd_img);

	if (fret < 0 && fd_loop >= 0) {
		close(fd_loop);
		fd_loop = -1;
	}

	return fd_loop;
}

int lxc_unstack_mountpoint(const char *path, bool lazy)
{
	int ret;
	int umounts = 0;

pop_stack:
	ret = umount2(path, lazy ? MNT_DETACH : 0);
	if (ret < 0) {
		/* We consider anything else than EINVAL deadly to prevent going
		 * into an infinite loop. (The other alternative is constantly
		 * parsing /proc/self/mountinfo which is yucky and probably
		 * racy.)
		 */
		if (errno != EINVAL)
			return -errno;
	} else {
		/* Just stop counting when this happens. That'd just be so
		 * stupid that we won't even bother trying to report back the
		 * correct value anymore.
		 */
		if (umounts != INT_MAX)
			umounts++;

		/* We succeeded in umounting. Make sure that there's no other
		 * mountpoint stacked underneath.
		 */
		goto pop_stack;
	}

	return umounts;
}

int run_command(char *buf, size_t buf_size, int (*child_fn)(void *), void *args)
{
	pid_t child;
	int ret, fret, pipefd[2];
	ssize_t bytes;

	/* Make sure our callers do not receive uninitialized memory. */
	if (buf_size > 0 && buf)
		buf[0] = '\0';

	if (pipe(pipefd) < 0) {
		SYSERROR("failed to create pipe");
		return -1;
	}

	child = lxc_raw_clone(0);
	if (child < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		SYSERROR("failed to create new process");
		return -1;
	}

	if (child == 0) {
		/* Close the read-end of the pipe. */
		close(pipefd[0]);

		/* Redirect std{err,out} to write-end of the
		 * pipe.
		 */
		ret = dup2(pipefd[1], STDOUT_FILENO);
		if (ret >= 0)
			ret = dup2(pipefd[1], STDERR_FILENO);

		/* Close the write-end of the pipe. */
		close(pipefd[1]);

		if (ret < 0) {
			SYSERROR("failed to duplicate std{err,out} file descriptor");
			_exit(EXIT_FAILURE);
		}

		/* Does not return. */
		child_fn(args);
		ERROR("failed to exec command");
		_exit(EXIT_FAILURE);
	}

	/* close the write-end of the pipe */
	close(pipefd[1]);

	if (buf && buf_size > 0) {
		bytes = lxc_read_nointr(pipefd[0], buf, buf_size - 1);
		if (bytes > 0)
			buf[bytes - 1] = '\0';
	}

	fret = wait_for_pid(child);
	/* close the read-end of the pipe */
	close(pipefd[0]);

	return fret;
}

bool lxc_nic_exists(char *nic)
{
#define __LXC_SYS_CLASS_NET_LEN 15 + IFNAMSIZ + 1
	char path[__LXC_SYS_CLASS_NET_LEN];
	int ret;
	struct stat sb;

	if (!strcmp(nic, "none"))
		return true;

	ret = snprintf(path, __LXC_SYS_CLASS_NET_LEN, "/sys/class/net/%s", nic);
	if (ret < 0 || (size_t)ret >= __LXC_SYS_CLASS_NET_LEN)
		return false;

	ret = stat(path, &sb);
	if (ret < 0)
		return false;

	return true;
}

uint64_t lxc_find_next_power2(uint64_t n)
{
	/* 0 is not valid input. We return 0 to the caller since 0 is not a
	 * valid power of two.
	 */
	if (n == 0)
		return 0;

	if (!(n & (n - 1)))
		return n;

	while (n & (n - 1))
		n = n & (n - 1);

	n = n << 1;
	return n;
}

int lxc_set_death_signal(int signal)
{
	int ret;
	pid_t ppid;

	ret = prctl(PR_SET_PDEATHSIG, prctl_arg(signal), prctl_arg(0),
		    prctl_arg(0), prctl_arg(0));

	/* Check whether we have been orphaned. */
	ppid = (pid_t)syscall(SYS_getppid);
	if (ppid == 1) {
		pid_t self;

		self = lxc_raw_getpid();
		ret = kill(self, SIGKILL);
		if (ret < 0)
			return -1;
	}

	if (ret < 0) {
		SYSERROR("Failed to set PR_SET_PDEATHSIG to %d", signal);
		return -1;
	}

	return 0;
}

int fd_cloexec(int fd, bool cloexec)
{
	int oflags, nflags;

	oflags = fcntl(fd, F_GETFD, 0);
	if (oflags < 0)
		return -errno;

	if (cloexec)
		nflags = oflags | FD_CLOEXEC;
	else
		nflags = oflags & ~FD_CLOEXEC;

	if (nflags == oflags)
		return 0;

	if (fcntl(fd, F_SETFD, nflags) < 0)
		return -errno;

	return 0;
}

int recursive_destroy(char *dirname)
{
	int ret;
	struct dirent *direntp;
	DIR *dir;
	int r = 0;

	dir = opendir(dirname);
	if (!dir)
		return -1;

	while ((direntp = readdir(dir))) {
		char *pathname;
		struct stat mystat;

		if (!strcmp(direntp->d_name, ".") ||
		    !strcmp(direntp->d_name, ".."))
			continue;

		pathname = must_make_path(dirname, direntp->d_name, NULL);

		ret = lstat(pathname, &mystat);
		if (ret < 0) {
			if (!r)
				WARN("Failed to stat \"%s\"", pathname);

			r = -1;
			goto next;
		}

		if (!S_ISDIR(mystat.st_mode))
			goto next;

		ret = recursive_destroy(pathname);
		if (ret < 0)
			r = -1;

	next:
		free(pathname);
	}

	ret = rmdir(dirname);
	if (ret < 0) {
		if (!r)
			SYSWARN("Failed to delete \"%s\"", dirname);

		r = -1;
	}

	ret = closedir(dir);
	if (ret < 0) {
		if (!r)
			SYSWARN("Failed to delete \"%s\"", dirname);

		r = -1;
	}

	return r;
}

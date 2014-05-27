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

#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <dirent.h>
#include <fcntl.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <assert.h>

#include "utils.h"
#include "log.h"
#include "lxclock.h"

lxc_log_define(lxc_utils, lxc);

static int _recursive_rmdir_onedev(char *dirname, dev_t pdev,
				   const char *exclude, int level)
{
	struct dirent dirent, *direntp;
	DIR *dir;
	int ret, failed=0;
	char pathname[MAXPATHLEN];
	bool hadexclude = false;

	dir = opendir(dirname);
	if (!dir) {
		ERROR("%s: failed to open %s", __func__, dirname);
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
			failed=1;
			continue;
		}

		if (!level && exclude && !strcmp(direntp->d_name, exclude)) {
			ret = rmdir(pathname);
			if (ret < 0) {
				switch(errno) {
				case ENOTEMPTY:
					INFO("Not deleting snapshots");
					hadexclude = true;
					break;
				case ENOTDIR:
					ret = unlink(pathname);
					if (ret)
						INFO("%s: failed to remove %s", __func__, pathname);
					break;
				default:
					SYSERROR("%s: failed to rmdir %s", __func__, pathname);
					failed = 1;
					break;
				}
			}
			continue;
		}

		ret = lstat(pathname, &mystat);
		if (ret) {
			ERROR("%s: failed to stat %s", __func__, pathname);
			failed=1;
			continue;
		}
		if (mystat.st_dev != pdev)
			continue;
		if (S_ISDIR(mystat.st_mode)) {
			if (_recursive_rmdir_onedev(pathname, pdev, exclude, level+1) < 0)
				failed=1;
		} else {
			if (unlink(pathname) < 0) {
				ERROR("%s: failed to delete %s", __func__, pathname);
				failed=1;
			}
		}
	}

	if (rmdir(dirname) < 0) {
		if (!hadexclude) {
			ERROR("%s: failed to delete %s", __func__, dirname);
			failed=1;
		}
	}

	ret = closedir(dir);
	if (ret) {
		ERROR("%s: failed to close directory %s", __func__, dirname);
		failed=1;
	}

	return failed ? -1 : 0;
}

/* returns 0 on success, -1 if there were any failures */
extern int lxc_rmdir_onedev(char *path, const char *exclude)
{
	struct stat mystat;

	if (lstat(path, &mystat) < 0) {
		ERROR("%s: failed to stat %s", __func__, path);
		return -1;
	}

	return _recursive_rmdir_onedev(path, mystat.st_dev, exclude, 0);
}

static int mount_fs(const char *source, const char *target, const char *type)
{
	/* the umount may fail */
	if (umount(target))
		WARN("failed to unmount %s : %s", target, strerror(errno));

	if (mount(source, target, type, 0, NULL)) {
		ERROR("failed to mount %s : %s", target, strerror(errno));
		return -1;
	}

	DEBUG("'%s' mounted on '%s'", source, target);

	return 0;
}

extern void lxc_setup_fs(void)
{
	if (mount_fs("proc", "/proc", "proc"))
		INFO("failed to remount proc");

	/* if we can't mount /dev/shm, continue anyway */
	if (mount_fs("shmfs", "/dev/shm", "tmpfs"))
		INFO("failed to mount /dev/shm");

	/* If we were able to mount /dev/shm, then /dev exists */
	/* Sure, but it's read-only per config :) */
	if (access("/dev/mqueue", F_OK) && mkdir("/dev/mqueue", 0666)) {
		DEBUG("failed to create '/dev/mqueue'");
		return;
	}

	/* continue even without posix message queue support */
	if (mount_fs("mqueue", "/dev/mqueue", "mqueue"))
		INFO("failed to mount /dev/mqueue");
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

extern void remove_trailing_slashes(char *p)
{
	int l = strlen(p);
	while (--l >= 0 && (p[l] == '/' || p[l] == '\n'))
		p[l] = '\0';
}

static char *copy_global_config_value(char *p)
{
	int len = strlen(p);
	char *retbuf;

	if (len < 1)
		return NULL;
	if (p[len-1] == '\n') {
		p[len-1] = '\0';
		len--;
	}
	retbuf = malloc(len+1);
	if (!retbuf)
		return NULL;
	strcpy(retbuf, p);
	return retbuf;
}

#define DEFAULT_VG "lxc"
#define DEFAULT_THIN_POOL "lxc"
#define DEFAULT_ZFSROOT "lxc"

const char *lxc_global_config_value(const char *option_name)
{
	static const char * const options[][2] = {
		{ "lxc.bdev.lvm.vg",        DEFAULT_VG      },
		{ "lxc.bdev.lvm.thin_pool", DEFAULT_THIN_POOL },
		{ "lxc.bdev.zfs.root",      DEFAULT_ZFSROOT },
		{ "lxc.lxcpath",            NULL            },
		{ "lxc.default_config",     NULL            },
		{ "lxc.cgroup.pattern",     DEFAULT_CGROUP_PATTERN },
		{ "lxc.cgroup.use",         NULL            },
		{ NULL, NULL },
	};

	/* placed in the thread local storage pool for non-bionic targets */
#ifdef HAVE_TLS
	static __thread const char *values[sizeof(options) / sizeof(options[0])] = { 0 };
#else
	static const char *values[sizeof(options) / sizeof(options[0])] = { 0 };
#endif
	char *user_config_path = NULL;
	char *user_default_config_path = NULL;
	char *user_lxc_path = NULL;

	if (geteuid() > 0) {
		const char *user_home = getenv("HOME");
		if (!user_home)
			user_home = "/";

		user_config_path = malloc(sizeof(char) * (22 + strlen(user_home)));
		user_default_config_path = malloc(sizeof(char) * (26 + strlen(user_home)));
		user_lxc_path = malloc(sizeof(char) * (19 + strlen(user_home)));

		sprintf(user_config_path, "%s/.config/lxc/lxc.conf", user_home);
		sprintf(user_default_config_path, "%s/.config/lxc/default.conf", user_home);
		sprintf(user_lxc_path, "%s/.local/share/lxc/", user_home);
	}
	else {
		user_config_path = strdup(LXC_GLOBAL_CONF);
		user_default_config_path = strdup(LXC_DEFAULT_CONFIG);
		user_lxc_path = strdup(LXCPATH);
	}

	const char * const (*ptr)[2];
	size_t i;
	char buf[1024], *p, *p2;
	FILE *fin = NULL;

	for (i = 0, ptr = options; (*ptr)[0]; ptr++, i++) {
		if (!strcmp(option_name, (*ptr)[0]))
			break;
	}
	if (!(*ptr)[0]) {
		free(user_config_path);
		free(user_default_config_path);
		free(user_lxc_path);
		errno = EINVAL;
		return NULL;
	}

	if (values[i]) {
		free(user_config_path);
		free(user_default_config_path);
		free(user_lxc_path);
		return values[i];
	}

	fin = fopen_cloexec(user_config_path, "r");
	free(user_config_path);
	if (fin) {
		while (fgets(buf, 1024, fin)) {
			if (buf[0] == '#')
				continue;
			p = strstr(buf, option_name);
			if (!p)
				continue;
			/* see if there was just white space in front
			 * of the option name
			 */
			for (p2 = buf; p2 < p; p2++) {
				if (*p2 != ' ' && *p2 != '\t')
					break;
			}
			if (p2 < p)
				continue;
			p = strchr(p, '=');
			if (!p)
				continue;
			/* see if there was just white space after
			 * the option name
			 */
			for (p2 += strlen(option_name); p2 < p; p2++) {
				if (*p2 != ' ' && *p2 != '\t')
					break;
			}
			if (p2 < p)
				continue;
			p++;
			while (*p && (*p == ' ' || *p == '\t')) p++;
			if (!*p)
				continue;

			free(user_default_config_path);

			if (strcmp(option_name, "lxc.lxcpath") == 0) {
				free(user_lxc_path);
				user_lxc_path = copy_global_config_value(p);
				remove_trailing_slashes(user_lxc_path);
				values[i] = user_lxc_path;
				goto out;
			}

			values[i] = copy_global_config_value(p);
			free(user_lxc_path);
			goto out;
		}
	}
	/* could not find value, use default */
	if (strcmp(option_name, "lxc.lxcpath") == 0) {
		remove_trailing_slashes(user_lxc_path);
		values[i] = user_lxc_path;
		free(user_default_config_path);
	}
	else if (strcmp(option_name, "lxc.default_config") == 0) {
		values[i] = user_default_config_path;
		free(user_lxc_path);
	}
	else {
		free(user_default_config_path);
		free(user_lxc_path);
		values[i] = (*ptr)[1];
	}
	/* special case: if default value is NULL,
	 * and there is no config, don't view that
	 * as an error... */
	if (!values[i])
		errno = 0;

out:
	if (fin)
		fclose(fin);

	return values[i];
}

char *get_rundir()
{
	char *rundir;
	const char *homedir;

	if (geteuid() == 0) {
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

ssize_t lxc_write_nointr(int fd, const void* buf, size_t count)
{
	ssize_t ret;
again:
	ret = write(fd, buf, count);
	if (ret < 0 && errno == EINTR)
		goto again;
	return ret;
}

ssize_t lxc_read_nointr(int fd, void* buf, size_t count)
{
	ssize_t ret;
again:
	ret = read(fd, buf, count);
	if (ret < 0 && errno == EINTR)
		goto again;
	return ret;
}

ssize_t lxc_read_nointr_expect(int fd, void* buf, size_t count, const void* expected_buf)
{
	ssize_t ret;
	ret = lxc_read_nointr(fd, buf, count);
	if (ret <= 0)
		return ret;
	if ((size_t)ret != count)
		return -1;
	if (expected_buf && memcmp(buf, expected_buf, count) != 0) {
		errno = EINVAL;
		return -1;
	}
	return ret;
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

char** lxc_va_arg_list_to_argv(va_list ap, size_t skip, int do_strdup)
{
	va_list ap2;
	size_t count = 1 + skip;
	char **result;

	/* first determine size of argument list, we don't want to reallocate
	 * constantly...
	 */
	va_copy(ap2, ap);
	while (1) {
		char* arg = va_arg(ap2, char*);
		if (!arg)
			break;
		count++;
	}
	va_end(ap2);

	result = calloc(count, sizeof(char*));
	if (!result)
		return NULL;
	count = skip;
	while (1) {
		char* arg = va_arg(ap, char*);
		if (!arg)
			break;
		arg = do_strdup ? strdup(arg) : arg;
		if (!arg)
			goto oom;
		result[count++] = arg;
	}

	/* calloc has already set last element to NULL*/
	return result;

oom:
	free(result);
	return NULL;
}

const char** lxc_va_arg_list_to_argv_const(va_list ap, size_t skip)
{
	return (const char**)lxc_va_arg_list_to_argv(ap, skip, 0);
}

FILE *fopen_cloexec(const char *path, const char *mode)
{
	int open_mode = 0;
	int step = 0;
	int fd;
	int saved_errno = 0;
	FILE *ret;

	if (!strncmp(mode, "r+", 2)) {
		open_mode = O_RDWR;
		step = 2;
	} else if (!strncmp(mode, "r", 1)) {
		open_mode = O_RDONLY;
		step = 1;
	} else if (!strncmp(mode, "w+", 2)) {
		open_mode = O_RDWR | O_TRUNC | O_CREAT;
		step = 2;
	} else if (!strncmp(mode, "w", 1)) {
		open_mode = O_WRONLY | O_TRUNC | O_CREAT;
		step = 1;
	} else if (!strncmp(mode, "a+", 2)) {
		open_mode = O_RDWR | O_CREAT | O_APPEND;
		step = 2;
	} else if (!strncmp(mode, "a", 1)) {
		open_mode = O_WRONLY | O_CREAT | O_APPEND;
		step = 1;
	}
	for (; mode[step]; step++)
		if (mode[step] == 'x')
			open_mode |= O_EXCL;
	open_mode |= O_CLOEXEC;

	fd = open(path, open_mode, 0666);
	if (fd < 0)
		return NULL;

	ret = fdopen(fd, mode);
	saved_errno = errno;
	if (!ret)
		close(fd);
	errno = saved_errno;
	return ret;
}

extern struct lxc_popen_FILE *lxc_popen(const char *command)
{
	struct lxc_popen_FILE *fp = NULL;
	int parent_end = -1, child_end = -1;
	int pipe_fds[2];
	pid_t child_pid;

	int r = pipe2(pipe_fds, O_CLOEXEC);

	if (r < 0) {
		ERROR("pipe2 failure");
		return NULL;
	}

	parent_end = pipe_fds[0];
	child_end = pipe_fds[1];

	child_pid = fork();

	if (child_pid == 0) {
		/* child */
		int child_std_end = STDOUT_FILENO;

		if (child_end != child_std_end) {
			/* dup2() doesn't dup close-on-exec flag */
			dup2(child_end, child_std_end);

			/* it's safe not to close child_end here
			 * as it's marked close-on-exec anyway
			 */
		} else {
			/*
			 * The descriptor is already the one we will use.
			 * But it must not be marked close-on-exec.
			 * Undo the effects.
			 */
			if (fcntl(child_end, F_SETFD, 0) != 0) {
				SYSERROR("Failed to remove FD_CLOEXEC from fd.");
				exit(127);
			}
		}

		/*
		 * Unblock signals.
		 * This is the main/only reason
		 * why we do our lousy popen() emulation.
		 */
		{
			sigset_t mask;
			sigfillset(&mask);
			sigprocmask(SIG_UNBLOCK, &mask, NULL);
		}

		execl("/bin/sh", "sh", "-c", command, (char *) NULL);
		exit(127);
	}

	/* parent */

	close(child_end);
	child_end = -1;

	if (child_pid < 0) {
		ERROR("fork failure");
		goto error;
	}

	fp = calloc(1, sizeof(*fp));
	if (!fp) {
		ERROR("failed to allocate memory");
		goto error;
	}

	fp->f = fdopen(parent_end, "r");
	if (!fp->f) {
		ERROR("fdopen failure");
		goto error;
	}

	fp->child_pid = child_pid;

	return fp;

error:

	if (fp) {
		if (fp->f) {
			fclose(fp->f);
			parent_end = -1; /* so we do not close it second time */
		}

		free(fp);
	}

	if (parent_end != -1)
		close(parent_end);

	return NULL;
}

extern int lxc_pclose(struct lxc_popen_FILE *fp)
{
	FILE *f = NULL;
	pid_t child_pid = 0;
	int wstatus = 0;
	pid_t wait_pid;

	if (fp) {
		f = fp->f;
		child_pid = fp->child_pid;
		/* free memory (we still need to close file stream) */
		free(fp);
		fp = NULL;
	}

	if (!f || fclose(f)) {
		ERROR("fclose failure");
		return -1;
	}

	do {
		wait_pid = waitpid(child_pid, &wstatus, 0);
	} while (wait_pid == -1 && errno == EINTR);

	if (wait_pid == -1) {
		ERROR("waitpid failure");
		return -1;
	}

	return wstatus;
}

char *lxc_string_replace(const char *needle, const char *replacement, const char *haystack)
{
	ssize_t len = -1, saved_len = -1;
	char *result = NULL;
	size_t replacement_len = strlen(replacement);
	size_t needle_len = strlen(needle);

	/* should be executed exactly twice */
	while (len == -1 || result == NULL) {
		char *p;
		char *last_p;
		ssize_t part_len;

		if (len != -1) {
			result = calloc(1, len + 1);
			if (!result)
				return NULL;
			saved_len = len;
		}

		len = 0;

		for (last_p = (char *)haystack, p = strstr(last_p, needle); p; last_p = p, p = strstr(last_p, needle)) {
			part_len = (ssize_t)(p - last_p);
			if (result && part_len > 0)
				memcpy(&result[len], last_p, part_len);
			len += part_len;
			if (result && replacement_len > 0)
				memcpy(&result[len], replacement, replacement_len);
			len += replacement_len;
			p += needle_len;
		}
		part_len = strlen(last_p);
		if (result && part_len > 0)
			memcpy(&result[len], last_p, part_len);
		len += part_len;
	}

	/* make sure we did the same thing twice,
	 * once for calculating length, the other
	 * time for copying data */
	assert(saved_len == len);
	/* make sure we didn't overwrite any buffer,
	 * due to calloc the string should be 0-terminated */
	assert(result[len] == '\0');

	return result;
}

bool lxc_string_in_array(const char *needle, const char **haystack)
{
	for (; haystack && *haystack; haystack++)
		if (!strcmp(needle, *haystack))
			return true;
	return false;
}

char *lxc_string_join(const char *sep, const char **parts, bool use_as_prefix)
{
	char *result;
	char **p;
	size_t sep_len = strlen(sep);
	size_t result_len = use_as_prefix * sep_len;

	/* calculate new string length */
	for (p = (char **)parts; *p; p++)
		result_len += (p > (char **)parts) * sep_len + strlen(*p);

	result = calloc(result_len + 1, 1);
	if (!result)
		return NULL;

	if (use_as_prefix)
		strcpy(result, sep);
	for (p = (char **)parts; *p; p++) {
		if (p > (char **)parts)
			strcat(result, sep);
		strcat(result, *p);
	}

	return result;
}

char **lxc_normalize_path(const char *path)
{
	char **components;
	char **p;
	size_t components_len = 0;
	size_t pos = 0;

	components = lxc_string_split(path, '/');
	if (!components)
		return NULL;
	for (p = components; *p; p++)
		components_len++;

	/* resolve '.' and '..' */
	for (pos = 0; pos < components_len; ) {
		if (!strcmp(components[pos], ".") || (!strcmp(components[pos], "..") && pos == 0)) {
			/* eat this element */
			free(components[pos]);
			memmove(&components[pos], &components[pos+1], sizeof(char *) * (components_len - pos));
			components_len--;
		} else if (!strcmp(components[pos], "..")) {
			/* eat this and the previous element */
			free(components[pos - 1]);
			free(components[pos]);
			memmove(&components[pos-1], &components[pos+1], sizeof(char *) * (components_len - pos));
			components_len -= 2;
			pos--;
		} else {
			pos++;
		}
	}

	return components;
}

char *lxc_append_paths(const char *first, const char *second)
{
	size_t len = strlen(first) + strlen(second) + 1;
	const char *pattern = "%s%s";
	char *result = NULL;

	if (second[0] != '/') {
		len += 1;
		pattern = "%s/%s";
	}

	result = calloc(1, len);
	if (!result)
		return NULL;

	snprintf(result, len, pattern, first, second);
	return result;
}

bool lxc_string_in_list(const char *needle, const char *haystack, char _sep)
{
	char *token, *str, *saveptr = NULL;
	char sep[2] = { _sep, '\0' };

	if (!haystack || !needle)
		return 0;

	str = alloca(strlen(haystack)+1);
	strcpy(str, haystack);
	for (; (token = strtok_r(str, sep, &saveptr)); str = NULL) {
		if (strcmp(needle, token) == 0)
			return 1;
	}

	return 0;
}

char **lxc_string_split(const char *string, char _sep)
{
	char *token, *str, *saveptr = NULL;
	char sep[2] = { _sep, '\0' };
	char **result = NULL;
	size_t result_capacity = 0;
	size_t result_count = 0;
	int r, saved_errno;

	if (!string)
		return calloc(1, sizeof(char *));

	str = alloca(strlen(string)+1);
	strcpy(str, string);
	for (; (token = strtok_r(str, sep, &saveptr)); str = NULL) {
		r = lxc_grow_array((void ***)&result, &result_capacity, result_count + 1, 16);
		if (r < 0)
			goto error_out;
		result[result_count] = strdup(token);
		if (!result[result_count])
			goto error_out;
		result_count++;
	}

	/* if we allocated too much, reduce it */
	return realloc(result, (result_count + 1) * sizeof(char *));
error_out:
	saved_errno = errno;
	lxc_free_array((void **)result, free);
	errno = saved_errno;
	return NULL;
}

char **lxc_string_split_and_trim(const char *string, char _sep)
{
	char *token, *str, *saveptr = NULL;
	char sep[2] = { _sep, '\0' };
	char **result = NULL;
	size_t result_capacity = 0;
	size_t result_count = 0;
	int r, saved_errno;
	size_t i = 0;

	if (!string)
		return calloc(1, sizeof(char *));

	str = alloca(strlen(string)+1);
	strcpy(str, string);
	for (; (token = strtok_r(str, sep, &saveptr)); str = NULL) {
		while (token[0] == ' ' || token[0] == '\t')
			token++;
		i = strlen(token);
		while (i > 0 && (token[i - 1] == ' ' || token[i - 1] == '\t')) {
			token[i - 1] = '\0';
			i--;
		}
		r = lxc_grow_array((void ***)&result, &result_capacity, result_count + 1, 16);
		if (r < 0)
			goto error_out;
		result[result_count] = strdup(token);
		if (!result[result_count])
			goto error_out;
		result_count++;
	}

	/* if we allocated too much, reduce it */
	return realloc(result, (result_count + 1) * sizeof(char *));
error_out:
	saved_errno = errno;
	lxc_free_array((void **)result, free);
	errno = saved_errno;
	return NULL;
}

void lxc_free_array(void **array, lxc_free_fn element_free_fn)
{
	void **p;
	for (p = array; p && *p; p++)
		element_free_fn(*p);
	free((void*)array);
}

int lxc_grow_array(void ***array, size_t* capacity, size_t new_size, size_t capacity_increment)
{
	size_t new_capacity;
	void **new_array;

	/* first time around, catch some trivial mistakes of the user
	 * only initializing one of these */
	if (!*array || !*capacity) {
		*array = NULL;
		*capacity = 0;
	}

	new_capacity = *capacity;
	while (new_size + 1 > new_capacity)
		new_capacity += capacity_increment;
	if (new_capacity != *capacity) {
		/* we have to reallocate */
		new_array = realloc(*array, new_capacity * sizeof(void *));
		if (!new_array)
			return -1;
		memset(&new_array[*capacity], 0, (new_capacity - (*capacity)) * sizeof(void *));
		*array = new_array;
		*capacity = new_capacity;
	}

	/* array has sufficient elements */
	return 0;
}

size_t lxc_array_len(void **array)
{
	void **p;
	size_t result = 0;

	for (p = array; p && *p; p++)
		result++;

	return result;
}

int lxc_write_to_file(const char *filename, const void* buf, size_t count, bool add_newline)
{
	int fd, saved_errno;
	ssize_t ret;

	fd = open(filename, O_WRONLY | O_TRUNC | O_CREAT | O_CLOEXEC, 0666);
	if (fd < 0)
		return -1;
	ret = lxc_write_nointr(fd, buf, count);
	if (ret < 0)
		goto out_error;
	if ((size_t)ret != count)
		goto out_error;
	if (add_newline) {
		ret = lxc_write_nointr(fd, "\n", 1);
		if (ret != 1)
			goto out_error;
	}
	close(fd);
	return 0;

out_error:
	saved_errno = errno;
	close(fd);
	errno = saved_errno;
	return -1;
}

int lxc_read_from_file(const char *filename, void* buf, size_t count)
{
	int fd = -1, saved_errno;
	ssize_t ret;

	fd = open(filename, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;

	if (!buf || !count) {
		char buf2[100];
		size_t count2 = 0;
		while ((ret = read(fd, buf2, 100)) > 0)
			count2 += ret;
		if (ret >= 0)
			ret = count2;
	} else {
		memset(buf, 0, count);
		ret = read(fd, buf, count);
	}

	if (ret < 0)
		ERROR("read %s: %s", filename, strerror(errno));

	saved_errno = errno;
	close(fd);
	errno = saved_errno;
	return ret;
}

void **lxc_append_null_to_array(void **array, size_t count)
{
	void **temp;

	/* Append NULL to the array */
	if (count) {
		temp = realloc(array, (count + 1) * sizeof(*array));
		if (!temp) {
			int i;
			for (i = 0; i < count; i++)
				free(array[i]);
			free(array);
			return NULL;
		}
		array = temp;
		array[count] = NULL;
	}
	return array;
}

int randseed(bool srand_it)
{
	/*
	   srand pre-seed function based on /dev/urandom
	   */
	unsigned int seed=time(NULL)+getpid();

	FILE *f;
	f = fopen("/dev/urandom", "r");
	if (f) {
		int ret = fread(&seed, sizeof(seed), 1, f);
		if (ret != 1)
			DEBUG("unable to fread /dev/urandom, %s, fallback to time+pid rand seed", strerror(errno));
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
		// could be something other than eexist, just say no
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
#define LINELEN 4096
int detect_shared_rootfs(void)
{
	char buf[LINELEN], *p;
	FILE *f;
	int i;
	char *p2;

	f = fopen("/proc/self/mountinfo", "r");
	if (!f)
		return 0;
	while (fgets(buf, LINELEN, f)) {
		for (p = buf, i=0; p && i < 4; i++)
			p = strchr(p+1, ' ');
		if (!p)
			continue;
		p2 = strchr(p+1, ' ');
		if (!p2)
			continue;
		*p2 = '\0';
		if (strcmp(p+1, "/") == 0) {
			// this is '/'.  is it shared?
			p = strchr(p2+1, ' ');
			if (p && strstr(p, "shared:")) {
				fclose(f);
				return 1;
			}
		}
	}
	fclose(f);
	return 0;
}

/*
 * looking at fs/proc_namespace.c, it appears we can
 * actually expect the rootfs entry to very specifically contain
 * " - rootfs rootfs "
 * IIUC, so long as we've chrooted so that rootfs is not our root,
 * the rootfs entry should always be skipped in mountinfo contents.
 */
int detect_ramfs_rootfs(void)
{
	char buf[LINELEN], *p;
	FILE *f;
	int i;
	char *p2;

	f = fopen("/proc/self/mountinfo", "r");
	if (!f)
		return 0;
	while (fgets(buf, LINELEN, f)) {
		for (p = buf, i=0; p && i < 4; i++)
			p = strchr(p+1, ' ');
		if (!p)
			continue;
		p2 = strchr(p+1, ' ');
		if (!p2)
			continue;
		*p2 = '\0';
		if (strcmp(p+1, "/") == 0) {
			// this is '/'.  is it the ramfs?
			p = strchr(p2+1, '-');
			if (p && strncmp(p, "- rootfs rootfs ", 16) == 0) {
				fclose(f);
				return 1;
			}
		}
	}
	fclose(f);
	return 0;
}

char *on_path(char *cmd, const char *rootfs) {
	char *path = NULL;
	char *entry = NULL;
	char *saveptr = NULL;
	char cmdpath[MAXPATHLEN];
	int ret;

	path = getenv("PATH");
	if (!path)
		return NULL;

	path = strdup(path);
	if (!path)
		return NULL;

	entry = strtok_r(path, ":", &saveptr);
	while (entry) {
		if (rootfs)
			ret = snprintf(cmdpath, MAXPATHLEN, "%s/%s/%s", rootfs, entry, cmd);
		else
			ret = snprintf(cmdpath, MAXPATHLEN, "%s/%s", entry, cmd);

		if (ret < 0 || ret >= MAXPATHLEN)
			goto next_loop;

		if (access(cmdpath, X_OK) == 0) {
			free(path);
			return strdup(cmdpath);
		}

next_loop:
		entry = strtok_r(NULL, ":", &saveptr);
	}

	free(path);
	return NULL;
}

bool file_exists(const char *f)
{
	struct stat statbuf;

	return stat(f, &statbuf) == 0;
}

/* historically lxc-init has been under /usr/lib/lxc and under
 * /usr/lib/$ARCH/lxc.  It now lives as $prefix/sbin/init.lxc.
 */
char *choose_init(const char *rootfs)
{
	char *retv = NULL;
	int ret, env_set = 0;
	struct stat mystat;

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
		ret = snprintf(retv, PATH_MAX, "%s/%s/init.lxc", rootfs, SBINDIR);
	else
		ret = snprintf(retv, PATH_MAX, SBINDIR "/init.lxc");
	if (ret < 0 || ret >= PATH_MAX) {
		ERROR("pathname too long");
		goto out1;
	}

	ret = stat(retv, &mystat);
	if (ret == 0)
		return retv;

	if (rootfs)
		ret = snprintf(retv, PATH_MAX, "%s/%s/lxc/lxc-init", rootfs, LXCINITDIR);
	else
		ret = snprintf(retv, PATH_MAX, LXCINITDIR "/lxc/lxc-init");
	if (ret < 0 || ret >= PATH_MAX) {
		ERROR("pathname too long");
		goto out1;
	}

	ret = stat(retv, &mystat);
	if (ret == 0)
		return retv;

	if (rootfs)
		ret = snprintf(retv, PATH_MAX, "%s/usr/lib/lxc/lxc-init", rootfs);
	else
		ret = snprintf(retv, PATH_MAX, "/usr/lib/lxc/lxc-init");
	if (ret < 0 || ret >= PATH_MAX) {
		ERROR("pathname too long");
		goto out1;
	}
	ret = stat(retv, &mystat);
	if (ret == 0)
		return retv;

	if (rootfs)
		ret = snprintf(retv, PATH_MAX, "%s/sbin/lxc-init", rootfs);
	else
		ret = snprintf(retv, PATH_MAX, "/sbin/lxc-init");
	if (ret < 0 || ret >= PATH_MAX) {
		ERROR("pathname too long");
		goto out1;
	}
	ret = stat(retv, &mystat);
	if (ret == 0)
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
	ret = stat(retv, &mystat);
	if (ret == 0)
		return retv;

out1:
	free(retv);
	return NULL;
}

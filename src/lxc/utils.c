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

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
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
#include <sys/vfs.h>
#include <sys/wait.h>

#include "log.h"
#include "lxclock.h"
#include "namespace.h"
#include "utils.h"

#ifndef PR_SET_MM
#define PR_SET_MM 35
#endif

#ifndef PR_SET_MM_MAP
#define PR_SET_MM_MAP 14

struct prctl_mm_map {
        uint64_t   start_code;
        uint64_t   end_code;
        uint64_t   start_data;
        uint64_t   end_data;
        uint64_t   start_brk;
        uint64_t   brk;
        uint64_t   start_stack;
        uint64_t   arg_start;
        uint64_t   arg_end;
        uint64_t   env_start;
        uint64_t   env_end;
        uint64_t   *auxv;
        uint32_t   auxv_size;
        uint32_t   exe_fd;
};
#endif

#ifndef O_PATH
#define O_PATH      010000000
#endif

#ifndef O_NOFOLLOW
#define O_NOFOLLOW  00400000
#endif

lxc_log_define(lxc_utils, lxc);

/*
 * if path is btrfs, tries to remove it and any subvolumes beneath it
 */
extern bool btrfs_try_remove_subvol(const char *path);

static int _recursive_rmdir(char *dirname, dev_t pdev,
			    const char *exclude, int level, bool onedev)
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
					INFO("Not deleting snapshot %s", pathname);
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
				SYSERROR("%s: failed to delete %s", __func__, pathname);
				failed=1;
			}
		}
	}

	if (rmdir(dirname) < 0 && !btrfs_try_remove_subvol(dirname) && !hadexclude) {
		ERROR("%s: failed to delete %s", __func__, dirname);
		failed=1;
	}

	ret = closedir(dir);
	if (ret) {
		ERROR("%s: failed to close directory %s", __func__, dirname);
		failed=1;
	}

	return failed ? -1 : 0;
}

/* we have two different magic values for overlayfs, yay */
#define OVERLAYFS_SUPER_MAGIC 0x794c764f
#define OVERLAY_SUPER_MAGIC 0x794c7630
/*
 * In overlayfs, st_dev is unreliable.  so on overlayfs we don't do
 * the lxc_rmdir_onedev()
 */
static bool is_native_overlayfs(const char *path)
{
	struct statfs sb;

	if (statfs(path, &sb) < 0)
		return false;
	if (sb.f_type == OVERLAYFS_SUPER_MAGIC ||
			sb.f_type == OVERLAY_SUPER_MAGIC)
		return true;
	return false;
}

/* returns 0 on success, -1 if there were any failures */
extern int lxc_rmdir_onedev(char *path, const char *exclude)
{
	struct stat mystat;
	bool onedev = true;

	if (is_native_overlayfs(path)) {
		onedev = false;
	}

	if (lstat(path, &mystat) < 0) {
		if (errno == ENOENT)
			return 0;
		ERROR("%s: failed to stat %s", __func__, path);
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
			size_t i;
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

bool switch_to_ns(pid_t pid, const char *ns) {
	int fd, ret;
	char nspath[MAXPATHLEN];

	/* Switch to new ns */
	ret = snprintf(nspath, MAXPATHLEN, "/proc/%d/ns/%s", pid, ns);
	if (ret < 0 || ret >= MAXPATHLEN)
		return false;

	fd = open(nspath, O_RDONLY);
	if (fd < 0) {
		SYSERROR("failed to open %s", nspath);
		return false;
	}

	ret = setns(fd, 0);
	if (ret) {
		SYSERROR("failed to set process %d to %s of %d.", pid, ns, fd);
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
		tmp = rootfs;
	else
		tmp = empty;

	ret = snprintf(retv, PATH_MAX, "%s/%s/%s", tmp, SBINDIR, "/init.lxc");
	if (ret < 0 || ret >= PATH_MAX) {
		ERROR("pathname too long");
		goto out1;
	}

	ret = stat(retv, &mystat);
	if (ret == 0)
		return retv;

	ret = snprintf(retv, PATH_MAX, "%s/%s/%s", tmp, LXCINITDIR, "/lxc/lxc-init");
	if (ret < 0 || ret >= PATH_MAX) {
		ERROR("pathname too long");
		goto out1;
	}

	ret = stat(retv, &mystat);
	if (ret == 0)
		return retv;

	ret = snprintf(retv, PATH_MAX, "%s/usr/lib/lxc/lxc-init", tmp);
	if (ret < 0 || ret >= PATH_MAX) {
		ERROR("pathname too long");
		goto out1;
	}
	ret = stat(retv, &mystat);
	if (ret == 0)
		return retv;

	ret = snprintf(retv, PATH_MAX, "%s/sbin/lxc-init", tmp);
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

int print_to_file(const char *file, const char *content)
{
	FILE *f;
	int ret = 0;

	f = fopen(file, "w");
	if (!f)
		return -1;
	if (fprintf(f, "%s", content) != strlen(content))
		ret = -1;
	fclose(f);
	return ret;
}

int is_dir(const char *path)
{
	struct stat statbuf;
	int ret = stat(path, &statbuf);
	if (ret == 0 && S_ISDIR(statbuf.st_mode))
		return 1;
	return 0;
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
 * Sets the process title to the specified title. Note:
 *   1. this function requires root to succeed
 *   2. it clears /proc/self/environ
 *   3. it may not succed (e.g. if title is longer than /proc/self/environ +
 *      the original title)
 */
int setproctitle(char *title)
{
	static char *proctitle = NULL;
	char buf[2048], *tmp;
	FILE *f;
	int i, len, ret = 0;

	/* We don't really need to know all of this stuff, but unfortunately
	 * PR_SET_MM_MAP requires us to set it all at once, so we have to
	 * figure it out anyway.
	 */
	unsigned long start_data, end_data, start_brk, start_code, end_code,
			start_stack, arg_start, arg_end, env_start, env_end,
			brk_val;
	struct prctl_mm_map prctl_map;

	f = fopen_cloexec("/proc/self/stat", "r");
	if (!f) {
		return -1;
	}

	tmp = fgets(buf, sizeof(buf), f);
	fclose(f);
	if (!tmp) {
		return -1;
	}

	/* Skip the first 25 fields, column 26-28 are start_code, end_code,
	 * and start_stack */
	tmp = strchr(buf, ' ');
	for (i = 0; i < 24; i++) {
		if (!tmp)
			return -1;
		tmp = strchr(tmp+1, ' ');
	}
	if (!tmp)
		return -1;

	i = sscanf(tmp, "%lu %lu %lu", &start_code, &end_code, &start_stack);
	if (i != 3)
		return -1;

	/* Skip the next 19 fields, column 45-51 are start_data to arg_end */
	for (i = 0; i < 19; i++) {
		if (!tmp)
			return -1;
		tmp = strchr(tmp+1, ' ');
	}

	if (!tmp)
		return -1;

	i = sscanf(tmp, "%lu %lu %lu %lu %lu %lu %lu",
		&start_data,
		&end_data,
		&start_brk,
		&arg_start,
		&arg_end,
		&env_start,
		&env_end);
	if (i != 7)
		return -1;

	/* Include the null byte here, because in the calculations below we
	 * want to have room for it. */
	len = strlen(title) + 1;

	/* If we don't have enough room by just overwriting the old proctitle,
	 * let's allocate a new one.
	 */
	if (len > arg_end - arg_start) {
		void *m;
		m = realloc(proctitle, len);
		if (!m)
			return -1;
		proctitle = m;

		arg_start = (unsigned long) proctitle;
	}

	arg_end = arg_start + len;

	brk_val = syscall(__NR_brk, 0);

	prctl_map = (struct prctl_mm_map) {
		.start_code = start_code,
		.end_code = end_code,
		.start_stack = start_stack,
		.start_data = start_data,
		.end_data = end_data,
		.start_brk = start_brk,
		.brk = brk_val,
		.arg_start = arg_start,
		.arg_end = arg_end,
		.env_start = env_start,
		.env_end = env_end,
		.auxv = NULL,
		.auxv_size = 0,
		.exe_fd = -1,
	};

	ret = prctl(PR_SET_MM, PR_SET_MM_MAP, (long) &prctl_map, sizeof(prctl_map), 0);
	if (ret == 0)
		strcpy((char*)arg_start, title);
	else
		INFO("setting cmdline failed - %s", strerror(errno));

	return ret;
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
	int ret = fstat(fd, &sb);
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
	if (newfd >= 0) // was not a symlink, all good
		return newfd;

	if (errno == ELOOP)
		return newfd;

	if (errno == EPERM || errno == EACCES) {
		/* we're not root (cause we got EPERM) so
		   try opening with O_PATH */
		newfd = openat(dirfd, nextpath, O_PATH | O_NOFOLLOW);
		if (newfd >= 0) {
			/* O_PATH will return an fd for symlinks.  We know
			 * nextpath wasn't a symlink at last openat, so if fd
			 * is now a link, then something * fishy is going on
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
	int srcfd = -1, destfd, ret, saved_errno;
	char srcbuf[50], destbuf[50]; // only needs enough for /proc/self/fd/<fd>
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
		SYSERROR("Failed to mount %s onto %s", src, dest);
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
int mount_proc_if_needed(const char *rootfs)
{
	char path[MAXPATHLEN];
	char link[20];
	int linklen, ret;
	int mypid;

	ret = snprintf(path, MAXPATHLEN, "%s/proc/self", rootfs);
	if (ret < 0 || ret >= MAXPATHLEN) {
		SYSERROR("proc path name too long");
		return -1;
	}
	memset(link, 0, 20);
	linklen = readlink(path, link, 20);
	mypid = (int)getpid();
	INFO("I am %d, /proc/self points to '%s'", mypid, link);
	ret = snprintf(path, MAXPATHLEN, "%s/proc", rootfs);
	if (ret < 0 || ret >= MAXPATHLEN) {
		SYSERROR("proc path name too long");
		return -1;
	}
	if (linklen < 0) /* /proc not mounted */
		goto domount;
	if (atoi(link) != mypid) {
		/* wrong /procs mounted */
		umount2(path, MNT_DETACH); /* ignore failure */
		goto domount;
	}
	/* the right proc is already mounted */
	return 0;

domount:
	if (!strcmp(rootfs,"")) /* rootfs is NULL */
		ret = mount("proc", path, "proc", 0, NULL);
	else
		ret = safe_mount("proc", path, "proc", 0, NULL, rootfs);

	if (ret < 0)
		return -1;

	INFO("Mounted /proc in container for security transition");
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
	if (fd < 0)
		return -1;

	if (dup2(fd, 0) < 0)
		return -1;
	if (dup2(fd, 1) < 0)
		return -1;
	if (dup2(fd, 2) < 0)
		return -1;

	return 0;
}

int null_stdfds(void)
{
	int ret = -1;
	int fd = open_devnull();

	if (fd >= 0) {
		ret = set_stdfds(fd);
		close(fd);
	}

	return ret;
}

/*
 * Return the number of lines in file @fn, or -1 on error
 */
int lxc_count_file_lines(const char *fn)
{
	FILE *f;
	char *line = NULL;
	size_t sz = 0;
	int n = 0;

	f = fopen_cloexec(fn, "r");
	if (!f)
		return -1;

	while (getline(&line, &sz, f) != -1) {
		n++;
	}
	free(line);
	fclose(f);
	return n;
}

void *lxc_strmmap(void *addr, size_t length, int prot, int flags, int fd,
		  off_t offset)
{
	void *tmp = NULL, *overlap = NULL;

	/* We establish an anonymous mapping that is one byte larger than the
	 * underlying file. The pages handed to us are zero filled. */
	tmp = mmap(addr, length + 1, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (tmp == MAP_FAILED)
		return tmp;

	/* Now we establish a fixed-address mapping starting at the address we
	 * received from our anonymous mapping and replace all bytes excluding
	 * the additional \0-byte with the file. This allows us to use normal
	 * string-handling functions. */
	overlap = mmap(tmp, length, prot, MAP_FIXED | flags, fd, offset);
	if (overlap == MAP_FAILED)
		munmap(tmp, length + 1);

	return overlap;
}

int lxc_strmunmap(void *addr, size_t length)
{
	return munmap(addr, length + 1);
}

/* Check whether a signal is blocked by a process. */
bool task_blocking_signal(pid_t pid, int signal)
{
	bool bret = false;
	char *line = NULL;
	long unsigned int sigblk = 0;
	size_t n = 0;
	int ret;
	FILE *f;

	/* The largest integer that can fit into long int is 2^64. This is a
	 * 20-digit number. */
	size_t len = /* /proc */ 5 + /* /pid-to-str */ 21 + /* /status */ 7 + /* \0 */ 1;
	char status[len];

	ret = snprintf(status, len, "/proc/%d/status", pid);
	if (ret < 0 || ret >= len)
		return bret;

	f = fopen(status, "r");
	if (!f)
		return bret;

	while (getline(&line, &n, f) != -1) {
		if (!strncmp(line, "SigBlk:\t", 8))
			if (sscanf(line + 8, "%lx", &sigblk) != 1)
				goto out;
	}

	if (sigblk & signal)
		bret = true;

out:
	free(line);
	fclose(f);
	return bret;
}

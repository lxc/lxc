/* liblxcapi
 *
 * Copyright © 2018 Christian Brauner <christian.brauner@ubuntu.com>.
 * Copyright © 2018 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _GNU_SOURCE
#define __STDC_FORMAT_MACROS /* Required for PRIu64 to work. */
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <linux/sched.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#if HAVE_SYS_PERSONALITY_H
#include <sys/personality.h>
#endif

#include <lxc/lxccontainer.h>

#include "tool_utils.h"

int lxc_fill_elevated_privileges(char *flaglist, int *flags)
{
	char *token, *saveptr = NULL;
	int i, aflag;
	struct {
		const char *token;
		int flag;
	} all_privs[] = {
		{ "CGROUP", LXC_ATTACH_MOVE_TO_CGROUP    },
		{ "CAP",    LXC_ATTACH_DROP_CAPABILITIES },
		{ "LSM",    LXC_ATTACH_LSM_EXEC          },
		{ NULL,     0                            }
	};

	if (!flaglist) {
		/* For the sake of backward compatibility, drop all privileges
		*  if none is specified.
		 */
		for (i = 0; all_privs[i].token; i++)
			*flags |= all_privs[i].flag;

		return 0;
	}

	token = strtok_r(flaglist, "|", &saveptr);
	while (token) {
		aflag = -1;
		for (i = 0; all_privs[i].token; i++)
			if (!strcmp(all_privs[i].token, token))
				aflag = all_privs[i].flag;
		if (aflag < 0)
			return -1;

		*flags |= aflag;

		token = strtok_r(NULL, "|", &saveptr);
	}

	return 0;
}

signed long lxc_config_parse_arch(const char *arch)
{
#if HAVE_SYS_PERSONALITY_H
	size_t i;
	struct per_name {
		char *name;
		unsigned long per;
	} pername[] = {
	    { "x86",       PER_LINUX32 },
	    { "linux32",   PER_LINUX32 },
	    { "i386",      PER_LINUX32 },
	    { "i486",      PER_LINUX32 },
	    { "i586",      PER_LINUX32 },
	    { "i686",      PER_LINUX32 },
	    { "athlon",    PER_LINUX32 },
	    { "mips",      PER_LINUX32 },
	    { "mipsel",    PER_LINUX32 },
	    { "ppc",       PER_LINUX32 },
	    { "arm",       PER_LINUX32 },
	    { "armv7l",    PER_LINUX32 },
	    { "armhf",     PER_LINUX32 },
	    { "armel",     PER_LINUX32 },
	    { "powerpc",   PER_LINUX32 },
	    { "linux64",   PER_LINUX   },
	    { "x86_64",    PER_LINUX   },
	    { "amd64",     PER_LINUX   },
	    { "mips64",    PER_LINUX   },
	    { "mips64el",  PER_LINUX   },
	    { "ppc64",     PER_LINUX   },
	    { "ppc64le",   PER_LINUX   },
	    { "ppc64el",   PER_LINUX   },
	    { "powerpc64", PER_LINUX   },
	    { "s390x",     PER_LINUX   },
	    { "aarch64",   PER_LINUX   },
	    { "arm64",     PER_LINUX   },
	};
	size_t len = sizeof(pername) / sizeof(pername[0]);

	for (i = 0; i < len; i++) {
		if (!strcmp(pername[i].name, arch))
			return pername[i].per;
	}
#endif

	return -1;
}

enum {
	LXC_NS_USER,
	LXC_NS_MNT,
	LXC_NS_PID,
	LXC_NS_UTS,
	LXC_NS_IPC,
	LXC_NS_NET,
	LXC_NS_CGROUP,
	LXC_NS_MAX
};

const static struct ns_info {
	const char *proc_name;
	int clone_flag;
} ns_info[LXC_NS_MAX]   = {
	[LXC_NS_USER]   = { "user",   CLONE_NEWUSER   },
	[LXC_NS_MNT]    = { "mnt",    CLONE_NEWNS     },
	[LXC_NS_PID]    = { "pid",    CLONE_NEWPID    },
	[LXC_NS_UTS]    = { "uts",    CLONE_NEWUTS    },
	[LXC_NS_IPC]    = { "ipc",    CLONE_NEWIPC    },
	[LXC_NS_NET]    = { "net",    CLONE_NEWNET    },
	[LXC_NS_CGROUP] = { "cgroup", CLONE_NEWCGROUP }
};

int lxc_namespace_2_cloneflag(const char *namespace)
{
	int i;
	for (i = 0; i < LXC_NS_MAX; i++)
		if (!strcasecmp(ns_info[i].proc_name, namespace))
			return ns_info[i].clone_flag;

	fprintf(stderr, "Invalid namespace name \"%s\"", namespace);
	return -EINVAL;
}

int lxc_fill_namespace_flags(char *flaglist, int *flags)
{
	char *token, *saveptr = NULL;
	int aflag;

	if (!flaglist) {
		fprintf(stderr, "At least one namespace is needed\n");
		return -1;
	}

	token = strtok_r(flaglist, "|", &saveptr);
	while (token) {

		aflag = lxc_namespace_2_cloneflag(token);
		if (aflag < 0)
			return -1;

		*flags |= aflag;

		token = strtok_r(NULL, "|", &saveptr);
	}

	return 0;
}

#if HAVE_LIBCAP

#ifndef PR_CAPBSET_READ
#define PR_CAPBSET_READ 23
#endif

int lxc_caps_init(void)
{
	uid_t uid = getuid();
	gid_t gid = getgid();
	uid_t euid = geteuid();

	if (!uid)
		return 0;

	if (uid && !euid) {
		if (prctl(PR_SET_KEEPCAPS, 1)) {
			fprintf(stderr, "%s - Failed to set PR_SET_KEEPCAPS\n", strerror(errno));
			return -1;
		}

		if (setresgid(gid, gid, gid)) {
			fprintf(stderr, "%s - Failed to change gid to %d\n", strerror(errno), gid);
			return -1;
		}

		if (setresuid(uid, uid, uid)) {
			fprintf(stderr, "%s - Failed to change uid to %d\n", strerror(errno), uid);
			return -1;
		}

		if (lxc_caps_up()) {
			fprintf(stderr, "%s - Failed to restore capabilities\n", strerror(errno));
			return -1;
		}
	}

	return 0;
}

int lxc_caps_up(void)
{
	cap_t caps;
	cap_value_t cap;
	int ret;

	/* when we are run as root, we don't want to play
	 * with the capabilities */
	if (!getuid())
		return 0;

	caps = cap_get_proc();
	if (!caps) {
		fprintf(stderr, "%s - Failed to cap_get_proc\n", strerror(errno));
		return -1;
	}

	for (cap = 0; cap <= CAP_LAST_CAP; cap++) {
		cap_flag_value_t flag;

		ret = cap_get_flag(caps, cap, CAP_PERMITTED, &flag);
		if (ret) {
			if (errno == EINVAL) {
				break;
			} else {
				fprintf(stderr, "%s- Failed to call cap_get_flag\n", strerror(errno));
				goto out;
			}
		}

		ret = cap_set_flag(caps, CAP_EFFECTIVE, 1, &cap, flag);
		if (ret) {
			fprintf(stderr, "%s - Failed to call cap_set_flag", strerror(errno));
			goto out;
		}
	}

	ret = cap_set_proc(caps);
	if (ret) {
		fprintf(stderr, "%s - Failed to cap_set_proc", strerror(errno));
		goto out;
	}

out:
	cap_free(caps);
	return 0;
}

#endif

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

int lxc_safe_uint(const char *numstr, unsigned int *converted)
{
	char *err = NULL;
	unsigned long int uli;

	while (isspace(*numstr))
		numstr++;

	if (*numstr == '-')
		return -EINVAL;

	errno = 0;
	uli = strtoul(numstr, &err, 0);
	if (errno == ERANGE && uli == ULONG_MAX)
		return -ERANGE;

	if (err == numstr || *err != '\0')
		return -EINVAL;

	if (uli > UINT_MAX)
		return -ERANGE;

	*converted = (unsigned int)uli;
	return 0;
}

int lxc_safe_int(const char *numstr, int *converted)
{
	char *err = NULL;
	signed long int sli;

	errno = 0;
	sli = strtol(numstr, &err, 0);
	if (errno == ERANGE && (sli == LONG_MAX || sli == LONG_MIN))
		return -ERANGE;

	if (errno != 0 && sli == 0)
		return -EINVAL;

	if (err == numstr || *err != '\0')
		return -EINVAL;

	if (sli > INT_MAX || sli < INT_MIN)
		return -ERANGE;

	*converted = (int)sli;
	return 0;
}

int lxc_safe_long(const char *numstr, long int *converted)
{
	char *err = NULL;
	signed long int sli;

	errno = 0;
	sli = strtol(numstr, &err, 0);
	if (errno == ERANGE && (sli == LONG_MAX || sli == LONG_MIN))
		return -ERANGE;

	if (errno != 0 && sli == 0)
		return -EINVAL;

	if (err == numstr || *err != '\0')
		return -EINVAL;

	*converted = sli;
	return 0;
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

char **lxc_string_split(const char *string, char _sep)
{
	char *token, *str, *saveptr = NULL;
	char sep[2] = {_sep, '\0'};
	char **tmp = NULL, **result = NULL;
	size_t result_capacity = 0;
	size_t result_count = 0;
	int r, saved_errno;

	if (!string)
		return calloc(1, sizeof(char *));

	str = alloca(strlen(string) + 1);
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
	tmp = realloc(result, (result_count + 1) * sizeof(char *));
	if (!tmp)
		goto error_out;
	result = tmp;
	/* Make sure we don't return uninitialized memory. */
	if (result_count == 0)
		*result = NULL;
	return result;
error_out:
	saved_errno = errno;
	lxc_free_array((void **)result, free);
	errno = saved_errno;
	return NULL;
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

int is_dir(const char *path)
{
	struct stat statbuf;
	int ret = stat(path, &statbuf);
	if (ret == 0 && S_ISDIR(statbuf.st_mode))
		return 1;
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
		fprintf(stderr, "Bad template: %s\n", t);
		free(tpath);
		return NULL;
	}

	return tpath;
}

int mkdir_p(const char *dir, mode_t mode)
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
				fprintf(stderr, "Failed to create directory \"%s\"\n", makeme);
				free(makeme);
				return -1;
			}
		}
		free(makeme);
	} while(tmp != dir);

	return 0;
}

bool file_exists(const char *f)
{
	struct stat statbuf;

	return stat(f, &statbuf) == 0;
}

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
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <linux/sched.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "config.h"

#if HAVE_SYS_PERSONALITY_H
#include <sys/personality.h>
#endif

#include <lxc/lxccontainer.h>

#include "arguments.h"
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

bool switch_to_ns(pid_t pid, const char *ns) {
	int fd, ret;
	char nspath[TOOL_MAXPATHLEN];

	/* Switch to new ns */
	ret = snprintf(nspath, TOOL_MAXPATHLEN, "/proc/%d/ns/%s", pid, ns);
	if (ret < 0 || ret >= TOOL_MAXPATHLEN)
		return false;

	fd = open(nspath, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Failed to open %s\n", nspath);
		return false;
	}

	ret = setns(fd, 0);
	if (ret) {
		fprintf(stderr, "Failed to set process %d to %s of %d\n", pid, ns, fd);
		close(fd);
		return false;
	}
	close(fd);
	return true;
}

static bool complete_word(char ***result, char *start, char *end, size_t *cap, size_t *cnt)
{
	int r;

	r = lxc_grow_array((void ***)result, cap, 2 + *cnt, 16);
	if (r < 0)
		return false;
	(*result)[*cnt] = strndup(start, end - start);
	if (!(*result)[*cnt])
		return false;
	(*cnt)++;

	return true;
}

/*
 * Given a a string 'one two "three four"', split into three words,
 * one, two, and "three four"
 */
char **lxc_string_split_quoted(char *string)
{
	char *nextword = string, *p, state;
	char **result = NULL;
	size_t result_capacity = 0;
	size_t result_count = 0;

	if (!string || !*string)
		return calloc(1, sizeof(char *));

	// TODO I'm *not* handling escaped quote
	state = ' ';
	for (p = string; *p; p++) {
		switch(state) {
		case ' ':
			if (isspace(*p))
				continue;
			else if (*p == '"' || *p == '\'') {
				nextword = p;
				state = *p;
				continue;
			}
			nextword = p;
			state = 'a';
			continue;
		case 'a':
			if (isspace(*p)) {
				complete_word(&result, nextword, p, &result_capacity, &result_count);
				state = ' ';
				continue;
			}
			continue;
		case '"':
		case '\'':
			if (*p == state) {
				complete_word(&result, nextword+1, p, &result_capacity, &result_count);
				state = ' ';
				continue;
			}
			continue;
		}
	}

	if (state == 'a')
		complete_word(&result, nextword, p, &result_capacity, &result_count);

	return realloc(result, (result_count + 1) * sizeof(char *));
}

int lxc_char_left_gc(const char *buffer, size_t len)
{
	size_t i;
	for (i = 0; i < len; i++) {
		if (buffer[i] == ' ' ||
		    buffer[i] == '\t')
			continue;
		return i;
	}
	return 0;
}

int lxc_char_right_gc(const char *buffer, size_t len)
{
	int i;
	for (i = len - 1; i >= 0; i--) {
		if (buffer[i] == ' '  ||
		    buffer[i] == '\t' ||
		    buffer[i] == '\n' ||
		    buffer[i] == '\0')
			continue;
		return i + 1;
	}
	return 0;
}

struct new_config_item *parse_line(char *buffer)
{
	char *dot, *key, *line, *linep, *value;
	int ret = 0;
	char *dup = buffer;
    struct new_config_item *new = NULL;

	linep = line = strdup(dup);
	if (!line)
		return NULL;

	line += lxc_char_left_gc(line, strlen(line));

	/* martian option - don't add it to the config itself */
	if (strncmp(line, "lxc.", 4))
		goto on_error;

	ret = -1;
	dot = strchr(line, '=');
	if (!dot) {
		fprintf(stderr, "Invalid configuration item: %s\n", line);
		goto on_error;
	}

	*dot = '\0';
	value = dot + 1;

	key = line;
	key[lxc_char_right_gc(key, strlen(key))] = '\0';

	value += lxc_char_left_gc(value, strlen(value));
	value[lxc_char_right_gc(value, strlen(value))] = '\0';

	if (*value == '\'' || *value == '\"') {
		size_t len;

		len = strlen(value);
		if (len > 1 && value[len - 1] == *value) {
			value[len - 1] = '\0';
			value++;
		}
	}

    ret = -1;
    new = malloc(sizeof(struct new_config_item));
    if (!new)
            goto on_error;

    new->key = strdup(key);
    new->val = strdup(value);
    if (!new->val || !new->key)
            goto on_error;
    ret = 0;

on_error:
	free(linep);
    if (ret < 0 && new) {
            free(new->key);
            free(new->val);
            free(new);
            new = NULL;
    }

	return new;
}

int lxc_config_define_add(struct lxc_list *defines, char *arg)
{
	struct lxc_list *dent;

	dent = malloc(sizeof(struct lxc_list));
	if (!dent)
		return -1;

	dent->elem = parse_line(arg);
	if (!dent->elem) {
		free(dent);
		return -1;
	}

	lxc_list_add_tail(defines, dent);
	return 0;
}

bool lxc_config_define_load(struct lxc_list *defines, struct lxc_container *c)
{
	struct lxc_list *it;
	bool bret = true;

	lxc_list_for_each(it, defines) {
		struct new_config_item *new_item = it->elem;
		bret = c->set_config_item(c, new_item->key, new_item->val);
		if (!bret)
			break;
	}

	lxc_config_define_free(defines);
	return bret;
}

void lxc_config_define_free(struct lxc_list *defines)
{
	struct lxc_list *it, *next;

	lxc_list_for_each_safe(it, defines, next) {
		struct new_config_item *new_item = it->elem;
		free(new_item->key);
		free(new_item->val);
		lxc_list_del(it);
		free(it);
	}
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

	saved_errno = errno;
	close(fd);
	errno = saved_errno;
	return ret;
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

char *lxc_append_paths(const char *first, const char *second)
{
	int ret;
	size_t len;
	char *result = NULL;
	const char *pattern = "%s%s";

	len = strlen(first) + strlen(second) + 1;
	if (second[0] != '/') {
		len += 1;
		pattern = "%s/%s";
	}

	result = calloc(1, len);
	if (!result)
		return NULL;

	ret = snprintf(result, len, pattern, first, second);
	if (ret < 0 || (size_t)ret >= len) {
		free(result);
		return NULL;
	}

	return result;
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

char *lxc_string_replace(const char *needle, const char *replacement,
			 const char *haystack)
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
	if (saved_len != len) {
		free(result);
		return NULL;
	}
	/* make sure we didn't overwrite any buffer,
	 * due to calloc the string should be 0-terminated */
	if (result[len] != '\0') {
		free(result);
		return NULL;
	}

	return result;
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

	homedir = getenv("HOME");
	if (!homedir)
		return NULL;

	rundir = malloc(sizeof(char) * (17 + strlen(homedir)));
	sprintf(rundir, "%s/.cache/lxc/run/", homedir);

	return rundir;
}

char *must_copy_string(const char *entry)
{
	char *ret;

	if (!entry)
		return NULL;
	do {
		ret = strdup(entry);
	} while (!ret);

	return ret;
}


void *must_realloc(void *orig, size_t sz)
{
	void *ret;

	do {
		ret = realloc(orig, sz);
	} while (!ret);

	return ret;
}

char *must_make_path(const char *first, ...)
{
	va_list args;
	char *cur, *dest;
	size_t full_len = strlen(first);

	dest = must_copy_string(first);

	va_start(args, first);
	while ((cur = va_arg(args, char *)) != NULL) {
		full_len += strlen(cur);
		if (cur[0] != '/')
			full_len++;
		dest = must_realloc(dest, full_len + 1);
		if (cur[0] != '/')
			strcat(dest, "/");
		strcat(dest, cur);
	}
	va_end(args);

	return dest;
}

int rm_r(char *dirname)
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
			r = -1;
			goto next;
		}

		if (!S_ISDIR(mystat.st_mode))
			goto next;

		ret = rm_r(pathname);
		if (ret < 0)
			r = -1;
	next:
		free(pathname);
	}

	ret = rmdir(dirname);
	if (ret < 0)
		r = -1;

	ret = closedir(dir);
	if (ret < 0)
		r = -1;

	return r;
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

static int mount_fs(const char *source, const char *target, const char *type)
{
	/* the umount may fail */
	if (umount(target) < 0)

	if (mount(source, target, type, 0, NULL) < 0)
		return -1;

	return 0;
}

void lxc_setup_fs(void)
{
	(void)mount_fs("proc", "/proc", "proc");

	/* if /dev has been populated by us, /dev/shm does not exist */
	if (access("/dev/shm", F_OK))
		(void)mkdir("/dev/shm", 0777);

	/* if we can't mount /dev/shm, continue anyway */
	(void)mount_fs("shmfs", "/dev/shm", "tmpfs");

	/* If we were able to mount /dev/shm, then /dev exists */
	/* Sure, but it's read-only per config :) */
	if (access("/dev/mqueue", F_OK))
		(void)mkdir("/dev/mqueue", 0666);

	/* continue even without posix message queue support */
	(void)mount_fs("mqueue", "/dev/mqueue", "mqueue");
}

struct clone_arg {
	int (*fn)(void *);
	void *arg;
};

static int do_clone(void *arg)
{
	struct clone_arg *clone_arg = arg;
	return clone_arg->fn(clone_arg->arg);
}

pid_t lxc_clone(int (*fn)(void *), void *arg, int flags)
{
	struct clone_arg clone_arg = {
		.fn = fn,
		.arg = arg,
	};

	size_t stack_size = lxc_getpagesize();
	void *stack = alloca(stack_size);
	pid_t ret;

#ifdef __ia64__
	ret = __clone2(do_clone, stack, stack_size, flags | SIGCHLD, &clone_arg);
#else
	ret = clone(do_clone, stack  + stack_size, flags | SIGCHLD, &clone_arg);
#endif
	return ret;
}

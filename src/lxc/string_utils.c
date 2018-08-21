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
#include "string_utils.h"
#include "utils.h"

#ifndef HAVE_STRLCPY
#include "include/strlcpy.h"
#endif

#ifndef HAVE_STRLCAT
#include "include/strlcat.h"
#endif

#ifndef NO_LOG
lxc_log_define(string_utils, lxc);
#endif

char **lxc_va_arg_list_to_argv(va_list ap, size_t skip, int do_strdup)
{
	va_list ap2;
	size_t count = 1 + skip;
	char **result;

	/* first determine size of argument list, we don't want to reallocate
	 * constantly...
	 */
	va_copy(ap2, ap);
	while (1) {
		char *arg = va_arg(ap2, char *);
		if (!arg)
			break;
		count++;
	}
	va_end(ap2);

	result = calloc(count, sizeof(char *));
	if (!result)
		return NULL;

	count = skip;
	while (1) {
		char *arg = va_arg(ap, char *);
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

const char **lxc_va_arg_list_to_argv_const(va_list ap, size_t skip)
{
	return (const char **)lxc_va_arg_list_to_argv(ap, skip, 0);
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

		for (last_p = (char *)haystack, p = strstr(last_p, needle); p;
		     last_p = p, p = strstr(last_p, needle)) {
			part_len = (ssize_t)(p - last_p);
			if (result && part_len > 0)
				memcpy(&result[len], last_p, part_len);

			len += part_len;

			if (result && replacement_len > 0)
				memcpy(&result[len], replacement,
				       replacement_len);

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
	size_t buf_len;

	/* calculate new string length */
	for (p = (char **)parts; *p; p++)
		result_len += (p > (char **)parts) * sep_len + strlen(*p);

	buf_len = result_len + 1;
	result = calloc(buf_len, 1);
	if (!result)
		return NULL;

	if (use_as_prefix)
		(void)strlcpy(result, sep, buf_len);

	for (p = (char **)parts; *p; p++) {
		if (p > (char **)parts)
			(void)strlcat(result, sep, buf_len);

		(void)strlcat(result, *p, buf_len);
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
	for (pos = 0; pos < components_len;) {
		if (!strcmp(components[pos], ".") ||
		    (!strcmp(components[pos], "..") && pos == 0)) {
			/* eat this element */
			free(components[pos]);
			memmove(&components[pos], &components[pos + 1],
				sizeof(char *) * (components_len - pos));
			components_len--;
		} else if (!strcmp(components[pos], "..")) {
			/* eat this and the previous element */
			free(components[pos - 1]);
			free(components[pos]);
			memmove(&components[pos - 1], &components[pos + 1],
				sizeof(char *) * (components_len - pos));
			components_len -= 2;
			pos--;
		} else {
			pos++;
		}
	}

	return components;
}

char *lxc_deslashify(const char *path)
{
	char *dup, *p;
	char **parts = NULL;
	size_t n, len;

	dup = strdup(path);
	if (!dup)
		return NULL;

	parts = lxc_normalize_path(dup);
	if (!parts) {
		free(dup);
		return NULL;
	}

	/* We'll end up here if path == "///" or path == "". */
	if (!*parts) {
		len = strlen(dup);
		if (!len) {
			lxc_free_array((void **)parts, free);
			return dup;
		}

		n = strcspn(dup, "/");
		if (n == len) {
			free(dup);
			lxc_free_array((void **)parts, free);

			p = strdup("/");
			if (!p)
				return NULL;

			return p;
		}
	}

	p = lxc_string_join("/", (const char **)parts, *dup == '/');
	free(dup);
	lxc_free_array((void **)parts, free);
	return p;
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

bool lxc_string_in_list(const char *needle, const char *haystack, char _sep)
{
	char *token, *str;
	char sep[2] = { _sep, '\0' };
	size_t len;

	if (!haystack || !needle)
		return 0;

	len = strlen(haystack);
	str = alloca(len + 1);
	(void)strlcpy(str, haystack, len + 1);

	lxc_iterate_parts(token, str, sep)
		if (strcmp(needle, token) == 0)
			return 1;

	return 0;
}

char **lxc_string_split(const char *string, char _sep)
{
	char *token, *str;
	char sep[2] = {_sep, '\0'};
	char **tmp = NULL, **result = NULL;
	size_t result_capacity = 0;
	size_t result_count = 0;
	int r, saved_errno;
	size_t len;

	if (!string)
		return calloc(1, sizeof(char *));

	len = strlen(string);
	str = alloca(len + 1);
	(void)strlcpy(str, string, len + 1);

	lxc_iterate_parts(token, str, sep) {
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

static bool complete_word(char ***result, char *start, char *end, size_t *cap,
			  size_t *cnt)
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

char **lxc_string_split_and_trim(const char *string, char _sep)
{
	char *token, *str;
	char sep[2] = { _sep, '\0' };
	char **result = NULL;
	size_t result_capacity = 0;
	size_t result_count = 0;
	int r, saved_errno;
	size_t i = 0;
	size_t len;

	if (!string)
		return calloc(1, sizeof(char *));

	len = strlen(string);
	str = alloca(len + 1);
	(void)strlcpy(str, string, len + 1);

	lxc_iterate_parts(token, str, sep) {
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

int lxc_grow_array(void ***array, size_t *capacity, size_t new_size, size_t capacity_increment)
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

static int lxc_append_null_to_list(void ***list)
{
	int newentry = 0;
	void **tmp;

	if (*list)
		for (; (*list)[newentry]; newentry++) {
			;
		}

	tmp = realloc(*list, (newentry + 2) * sizeof(void **));
	if (!tmp)
		return -1;

	*list = tmp;
	(*list)[newentry + 1] = NULL;

	return newentry;
}

int lxc_append_string(char ***list, char *entry)
{
	char *copy;
	int newentry;

	newentry = lxc_append_null_to_list((void ***)list);
	if (newentry < 0)
		return -1;

	copy = strdup(entry);
	if (!copy)
		return -1;

	(*list)[newentry] = copy;

	return 0;
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

int lxc_safe_ulong(const char *numstr, unsigned long *converted)
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

	*converted = uli;
	return 0;
}

int lxc_safe_uint64(const char *numstr, uint64_t *converted, int base)
{
	char *err = NULL;
	uint64_t u;

	while (isspace(*numstr))
		numstr++;

	if (*numstr == '-')
		return -EINVAL;

	errno = 0;
	u = strtoull(numstr, &err, base);
	if (errno == ERANGE && u == ULLONG_MAX)
		return -ERANGE;

	if (err == numstr || *err != '\0')
		return -EINVAL;

	*converted = u;
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

int lxc_safe_long_long(const char *numstr, long long int *converted)
{
	char *err = NULL;
	signed long long int sli;

	errno = 0;
	sli = strtoll(numstr, &err, 0);
	if (errno == ERANGE && (sli == LLONG_MAX || sli == LLONG_MIN))
		return -ERANGE;

	if (errno != 0 && sli == 0)
		return -EINVAL;

	if (err == numstr || *err != '\0')
		return -EINVAL;

	*converted = sli;
	return 0;
}

char *must_concat(const char *first, ...)
{
	va_list args;
	char *cur, *dest;
	size_t cur_len, it_len;

	dest = must_copy_string(first);
	cur_len = it_len = strlen(first);

	va_start(args, first);
	while ((cur = va_arg(args, char *)) != NULL) {
		it_len = strlen(cur);

		dest = must_realloc(dest, cur_len + it_len + 1);

		(void)memcpy(dest + cur_len, cur, it_len);
		cur_len += it_len;
	}
	va_end(args);

	dest[cur_len] = 0;
	return dest;
}

char *must_make_path(const char *first, ...)
{
	va_list args;
	char *cur, *dest;
	size_t full_len = strlen(first);
	size_t buf_len;

	dest = must_copy_string(first);

	va_start(args, first);
	while ((cur = va_arg(args, char *)) != NULL) {
		full_len += strlen(cur);
		if (cur[0] != '/')
			full_len++;

		buf_len = full_len + 1;
		dest = must_realloc(dest, buf_len);

		if (cur[0] != '/')
			(void)strlcat(dest, "/", buf_len);
		(void)strlcat(dest, cur, buf_len);
	}
	va_end(args);

	return dest;
}

char *must_append_path(char *first, ...)
{
	char *cur;
	size_t full_len;
	va_list args;
	char *dest = first;
	size_t buf_len;

	full_len = strlen(first);
	va_start(args, first);
	while ((cur = va_arg(args, char *)) != NULL) {
		full_len += strlen(cur);
		if (cur[0] != '/')
			full_len++;

		buf_len = full_len + 1;
		dest = must_realloc(dest, buf_len);

		if (cur[0] != '/')
			(void)strlcat(dest, "/", buf_len);
		(void)strlcat(dest, cur, buf_len);
	}
	va_end(args);

	return dest;
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

int parse_byte_size_string(const char *s, int64_t *converted)
{
	int ret, suffix_len;
	long long int conv;
	int64_t mltpl, overflow;
	char *end;
	char dup[LXC_NUMSTRLEN64 + 2];
	char suffix[3] = {0};

	if (!s || !strcmp(s, ""))
		return -EINVAL;

	end = stpncpy(dup, s, sizeof(dup) - 1);
	if (*end != '\0')
		return -EINVAL;

	if (isdigit(*(end - 1)))
		suffix_len = 0;
	else if (isalpha(*(end - 1)))
		suffix_len = 1;
	else
		return -EINVAL;

	if (suffix_len > 0 && (end - 2) == dup && !isdigit(*(end - 2)))
		return -EINVAL;

	if (suffix_len > 0 && isalpha(*(end - 2)))
		suffix_len++;

	if (suffix_len > 0) {
		memcpy(suffix, end - suffix_len, suffix_len);
		*(suffix + suffix_len) = '\0';
		*(end - suffix_len) = '\0';
	}
	dup[lxc_char_right_gc(dup, strlen(dup))] = '\0';

	ret = lxc_safe_long_long(dup, &conv);
	if (ret < 0)
		return -ret;

	if (suffix_len != 2) {
		*converted = conv;
		return 0;
	}

	if (strcasecmp(suffix, "KB") == 0)
		mltpl = 1024;
	else if (strcasecmp(suffix, "MB") == 0)
		mltpl = 1024 * 1024;
	else if (strcasecmp(suffix, "GB") == 0)
		mltpl = 1024 * 1024 * 1024;
	else
		return -EINVAL;

	overflow = conv * mltpl;
	if (conv != 0 && (overflow / conv) != mltpl)
		return -ERANGE;

	*converted = overflow;
	return 0;
}

void remove_trailing_newlines(char *l)
{
	char *p = l;

	while (*p)
		p++;

	while (--p >= l && *p == '\n')
		*p = '\0';
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

char *lxc_trim_whitespace_in_place(char *buffer)
{
	buffer += lxc_char_left_gc(buffer, strlen(buffer));
	buffer[lxc_char_right_gc(buffer, strlen(buffer))] = '\0';
	return buffer;
}

int lxc_is_line_empty(const char *line)
{
	int i;
	size_t len = strlen(line);

	for (i = 0; i < len; i++)
		if (line[i] != ' ' && line[i] != '\t' &&
		    line[i] != '\n' && line[i] != '\r' &&
		    line[i] != '\f' && line[i] != '\0')
			return 0;
	return 1;
}

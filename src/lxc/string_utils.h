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

#ifndef __LXC_STRING_UTILS_H
#define __LXC_STRING_UTILS_H

#include "config.h"

#include "initutils.h"
#include "macro.h"

/* convert variadic argument lists to arrays (for execl type argument lists) */
extern char **lxc_va_arg_list_to_argv(va_list ap, size_t skip, int do_strdup);
extern const char **lxc_va_arg_list_to_argv_const(va_list ap, size_t skip);

/*
 * Some simple string functions; if they return pointers, they are allocated
 * buffers.
 */
extern char *lxc_string_replace(const char *needle, const char *replacement,
				const char *haystack);
extern bool lxc_string_in_array(const char *needle, const char **haystack);
extern char *lxc_string_join(const char *sep, const char **parts,
			     bool use_as_prefix);
/*
 * Normalize and split path: Leading and trailing / are removed, multiple
 * / are compactified, .. and . are resolved (.. on the top level is considered
 * identical to .).
 * Examples:
 *     /            ->   { NULL }
 *     foo/../bar   ->   { bar, NULL }
 *     ../../       ->   { NULL }
 *     ./bar/baz/.. ->   { bar, NULL }
 *     foo//bar     ->   { foo, bar, NULL }
 */
extern char **lxc_normalize_path(const char *path);

/* remove multiple slashes from the path, e.g. ///foo//bar -> /foo/bar */
extern char *lxc_deslashify(const char *path);
extern char *lxc_append_paths(const char *first, const char *second);

/*
 * Note: the following two functions use strtok(), so they will never
 *       consider an empty element, even if two delimiters are next to
 *       each other.
 */
extern bool lxc_string_in_list(const char *needle, const char *haystack,
			       char sep);
extern char **lxc_string_split(const char *string, char sep);
extern char **lxc_string_split_and_trim(const char *string, char sep);
extern char **lxc_string_split_quoted(char *string);

/* Append string to NULL-terminated string array. */
extern int lxc_append_string(char ***list, char *entry);

/* Some simple array manipulation utilities */
typedef void (*lxc_free_fn)(void *);
typedef void *(*lxc_dup_fn)(void *);
extern int lxc_grow_array(void ***array, size_t *capacity, size_t new_size,
			  size_t capacity_increment);
extern void lxc_free_array(void **array, lxc_free_fn element_free_fn);
extern size_t lxc_array_len(void **array);

extern void **lxc_append_null_to_array(void **array, size_t count);
extern void remove_trailing_newlines(char *l);

/* Helper functions to parse numbers. */
extern int lxc_safe_uint(const char *numstr, unsigned int *converted);
extern int lxc_safe_int(const char *numstr, int *converted);
extern int lxc_safe_long(const char *numstr, long int *converted);
extern int lxc_safe_long_long(const char *numstr, long long int *converted);
extern int lxc_safe_ulong(const char *numstr, unsigned long *converted);
extern int lxc_safe_uint64(const char *numstr, uint64_t *converted, int base);
/* Handles B, kb, MB, GB. Detects overflows and reports -ERANGE. */
extern int parse_byte_size_string(const char *s, int64_t *converted);

/*
 * Concatenate all passed-in strings into one path. Do not fail. If any piece
 * is not prefixed with '/', add a '/'.
 */
__attribute__((sentinel)) extern char *must_concat(const char *first, ...);
__attribute__((sentinel)) extern char *must_make_path(const char *first, ...);
__attribute__((sentinel)) extern char *must_append_path(char *first, ...);

/* Return copy of string @entry. Do not fail. */
extern char *must_copy_string(const char *entry);

/* Re-allocate a pointer, do not fail */
extern void *must_realloc(void *orig, size_t sz);

extern int lxc_char_left_gc(const char *buffer, size_t len);

extern int lxc_char_right_gc(const char *buffer, size_t len);

extern char *lxc_trim_whitespace_in_place(char *buffer);

extern int lxc_is_line_empty(const char *line);
extern void remove_trailing_slashes(char *p);

#endif /* __LXC_STRING_UTILS_H */

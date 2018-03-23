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
#ifndef __PAM_UTILS_H
#define __PAM_UTILS_H

#include <sys/vfs.h>

#ifndef CGROUP_SUPER_MAGIC
#define CGROUP_SUPER_MAGIC 0x27e0eb
#endif

#ifndef CGROUP2_SUPER_MAGIC
#define CGROUP2_SUPER_MAGIC 0x63677270
#endif

typedef __typeof__(((struct statfs *)NULL)->f_type) fs_type_magic;
extern bool file_exists(const char *f);
extern void *must_realloc(void *orig, size_t sz);
extern char *must_copy_string(const char *entry);
__attribute__((sentinel)) extern char *must_make_path(const char *first, ...);
extern bool has_fs_type(const char *path, fs_type_magic magic_val);

#endif /* __PAM_UTILS_H */

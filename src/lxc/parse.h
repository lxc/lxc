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
#ifndef __LXC_PARSE_H
#define __LXC_PARSE_H

#include <stdio.h>
#include <sys/types.h>

#include "compiler.h"

typedef int (*lxc_dir_cb)(const char *name, const char *directory,
			  const char *file, void *data);

typedef int (*lxc_file_cb)(char *buffer, void *data);

__hot extern int lxc_file_for_each_line(const char *file, lxc_file_cb callback,
					void *data);

__hot extern int lxc_file_for_each_line_mmap(const char *file,
					     lxc_file_cb callback, void *data);

/* mmap() wrapper. lxc_strmmap() will take care to \0-terminate files so that
 * normal string-handling functions can be used on the buffer. */
extern void *lxc_strmmap(void *addr, size_t length, int prot, int flags, int fd,
			 off_t offset);
/* munmap() wrapper. Use it to free memory mmap()ed with lxc_strmmap(). */
extern int lxc_strmunmap(void *addr, size_t length);

#endif

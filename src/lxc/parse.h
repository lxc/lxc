/* SPDX-License-Identifier: LGPL-2.1+ */

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

/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_MEMORY_UTILS_H
#define __LXC_MEMORY_UTILS_H

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "macro.h"

#define define_cleanup_attribute(type, func)     \
	static inline void func##_ptr(type *ptr) \
	{                                        \
		if (*ptr)                        \
			func(*ptr);              \
	}

#define free_disarm(ptr)       \
	({                     \
		free(ptr);     \
		move_ptr(ptr); \
	})

static inline void __auto_free__(void *p)
{
	free(*(void **)p);
}

static inline void free_string_list(char **list)
{
	if (list) {
		for (int i = 0; list[i]; i++)
			free(list[i]);
		free_disarm(list);
	}
}
define_cleanup_attribute(char **, free_string_list);
#define __do_free_string_list __attribute__((__cleanup__(free_string_list_ptr)))

static inline void __auto_fclose__(FILE **f)
{
	if (*f)
		fclose(*f);
}

static inline void __auto_closedir__(DIR **d)
{
	if (*d)
		closedir(*d);
}

#define close_prot_errno_disarm(fd) \
	if (fd >= 0) {              \
		int _e_ = errno;    \
		close(fd);          \
		errno = _e_;        \
		fd = -EBADF;        \
	}

static inline void __auto_close__(int *fd)
{
	close_prot_errno_disarm(*fd);
}

#define __do_close_prot_errno __attribute__((__cleanup__(__auto_close__)))
#define __do_free __attribute__((__cleanup__(__auto_free__)))
#define __do_fclose __attribute__((__cleanup__(__auto_fclose__)))
#define __do_closedir __attribute__((__cleanup__(__auto_closedir__)))

static inline void *memdup(const void *data, size_t len)
{
	void *copy = NULL;

	copy = len ? malloc(len) : NULL;
	return copy ? memcpy(copy, data, len) : NULL;
}

#define zalloc(__size__) (calloc(1, __size__))

#endif /* __LXC_MEMORY_UTILS_H */

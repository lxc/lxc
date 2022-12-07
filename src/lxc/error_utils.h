/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_ERROR_UTILS_H
#define __LXC_ERROR_UTILS_H

#include "config.h"

#include <stdbool.h>

#include "macro.h"

#define MAX_ERRNO 4095

#define IS_ERR_VALUE(x) unlikely((x) >= (unsigned long)-MAX_ERRNO)

static inline void *ERR_PTR(long error)
{
	return (void *)error;
}

static inline long PTR_ERR(const void *ptr)
{
	return (long)ptr;
}

static inline long IS_ERR(const void *ptr)
{
	return IS_ERR_VALUE((unsigned long)ptr);
}

static inline long IS_ERR_OR_NULL(const void *ptr)
{
	return !ptr || IS_ERR_VALUE((unsigned long)ptr);
}

static inline void *ERR_CAST(const void *ptr)
{
	return (void *)ptr;
}

static inline int PTR_RET(const void *ptr)
{
	if (IS_ERR(ptr))
		return PTR_ERR(ptr);
	else
		return 0;
}

static inline bool ERRNO_IS_NOT_SUPPORTED(int r) {
	int x = abs(r);
	return x == EOPNOTSUPP || x == ENOSYS;
}

#endif /* __LXC_ERROR_UTILS_H */

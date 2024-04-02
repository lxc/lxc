/* liblxcapi
 *
 * SPDX-License-Identifier: LGPL-2.1+ *
 *
 * This function has been copied from musl.
 */

#include <limits.h>
#include <stdint.h>
#include <string.h>

#if !HAVE_STRLCPY
#include "strlcpy.h"
#endif

size_t strlcat(char *src, const char *append, size_t len)
{
	size_t src_len;

	src_len = strnlen(src, len);
	if (src_len == len)
		return src_len + strlen(append);

	return src_len + strlcpy(src + src_len, append, len - src_len);
}

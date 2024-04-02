/* liblxcapi
 *
 * SPDX-License-Identifier: LGPL-2.1+ *
 *
 * This function has been copied from musl.
 */

#include <string.h>

size_t strlcpy(char *dest, const char *src, size_t size)
{
	size_t ret = strlen(src);

	if (size) {
		size_t len = (ret >= size) ? size - 1 : ret;
		memcpy(dest, src, len);
		dest[len] = '\0';
	}

	return ret;
}

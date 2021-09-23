/* liblxcapi
 *
 * Copyright © 2018 Christian Brauner <christian@brauner.io>.
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

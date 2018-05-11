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

#define ALIGN (sizeof(size_t) - 1)
#define ONES ((size_t)-1 / UCHAR_MAX)
#define HIGHS (ONES * (UCHAR_MAX / 2 + 1))
#define HASZERO(x) (((x)-ONES) & ~(x)&HIGHS)

size_t strlcpy(char *d, const char *s, size_t n)
{
	char *d0 = d;
	size_t *wd;
	const size_t *ws;

	if (!n--)
		goto finish;

	if (((uintptr_t)s & ALIGN) == ((uintptr_t)d & ALIGN)) {
		for (; ((uintptr_t)s & ALIGN) && n && (*d = *s); n--, s++, d++)
			;
		if (n && *s) {
			wd = (void *)d;
			ws = (const void *)s;
			for (; n >= sizeof(size_t) && !HASZERO(*ws);
			     n -= sizeof(size_t), ws++, wd++)
				*wd = *ws;
			d = (void *)wd;
			s = (const void *)ws;
		}
	}

	for (; n && (*d = *s); n--, s++, d++)
		;

	*d = 0;

finish:
	return d - d0 + strlen(s);
}

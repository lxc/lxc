/* Utilities for reading/writing fstab, mtab, etc.
   Copyright (C) 1995-2000, 2001, 2002, 2003, 2006
   Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <stdio.h>
#include <string.h>
#include <mntent.h>

/* Search MNT->mnt_opts for an option matching OPT.
 Returns the address of the substring, or null if none found. */
char *hasmntopt (const struct mntent *mnt, const char *opt)
{
    const size_t optlen = strlen (opt);
    char *rest = mnt->mnt_opts, *p;

    while ((p = strstr (rest, opt)) != NULL)
    {
        if ((p == rest || p[-1] == ',')
            && (p[optlen] == '\0' || p[optlen] == '=' || p[optlen] == ','))
            return p;

        rest = strchr (p, ',');
        if (rest == NULL)
            break;
        ++rest;
    }

    return NULL;
}

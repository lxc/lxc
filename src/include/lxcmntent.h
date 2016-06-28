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

#ifndef _lxcmntent_h
#define _lxcmntent_h

#if IS_BIONIC
struct mntent
{
    char* mnt_fsname;
    char* mnt_dir;
    char* mnt_type;
    char* mnt_opts;
    int mnt_freq;
    int mnt_passno;
};

extern struct mntent *getmntent (FILE *stream);
extern struct mntent *getmntent_r (FILE *stream, struct mntent *mp, char *buffer, int bufsiz);
#endif

#if !defined(HAVE_SETMNTENT) || IS_BIONIC
FILE *setmntent (const char *file, const char *mode);
#endif

#if !defined(HAVE_ENDMNTENT) || IS_BIONIC
int endmntent (FILE *stream);
#endif

#if !defined(HAVE_HASMNTOPT) || IS_BIONIC
extern char *hasmntopt (const struct mntent *mnt, const char *opt);
#endif

#endif

/* Utilities for reading/writing fstab, mtab, etc.
 *
 * SPDX-License-Identifier: LGPL-2.1+
 *
 */

#ifndef _LXCMNTENT_H
#define _LXCMNTENT_H

#include "../lxc/compiler.h"

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

__hidden extern struct mntent *getmntent(FILE *stream);
__hidden extern struct mntent *getmntent_r(FILE *stream, struct mntent *mp,
					   char *buffer, int bufsiz);
#endif

#if !HAVE_SETMNTENT || IS_BIONIC
__hidden FILE *setmntent(const char *file, const char *mode);
#endif

#if !HAVE_ENDMNTENT || IS_BIONIC
__hidden int endmntent(FILE *stream);
#endif

#if !HAVE_HASMNTOPT || IS_BIONIC
__hidden extern char *hasmntopt(const struct mntent *mnt, const char *opt);
#endif

#endif

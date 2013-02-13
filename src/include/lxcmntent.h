#ifndef _lxcmntent_h
#define _lxcmntent_h

#include <../config.h>

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
#endif

#ifndef HAVE_SETMNTENT
FILE *setmntent (const char *file, const char *mode);
#endif

#ifndef HAVE_ENDMNTENT
int endmntent (FILE *stream);
#endif

#ifndef HAVE_HASMNTOPT
extern char *hasmntopt (const struct mntent *mnt, const char *opt);
#endif

#endif

/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_OPEN_UTILS_H
#define __LXC_OPEN_UTILS_H

#include "config.h"

#include "syscall_numbers.h"

/*
 * Arguments for how openat2(2) should open the target path. If only @flags and
 * @mode are non-zero, then openat2(2) operates very similarly to openat(2).
 *
 * However, unlike openat(2), unknown or invalid bits in @flags result in
 * -EINVAL rather than being silently ignored. @mode must be zero unless one of
 * {O_CREAT, O_TMPFILE} are set.
 *
 * @flags: O_* flags.
 * @mode: O_CREAT/O_TMPFILE file mode.
 * @resolve: RESOLVE_* flags.
 */
#if !HAVE_STRUCT_OPEN_HOW
struct open_how {
	__u64 flags;
	__u64 mode;
	__u64 resolve;
};
#endif

/* how->resolve flags for openat2(2). */
#ifndef RESOLVE_NO_XDEV
#define RESOLVE_NO_XDEV		0x01 /* Block mount-point crossings
					(includes bind-mounts). */
#endif

#ifndef RESOLVE_NO_MAGICLINKS
#define RESOLVE_NO_MAGICLINKS	0x02 /* Block traversal through procfs-style
					"magic-links". */
#endif

#ifndef RESOLVE_NO_SYMLINKS
#define RESOLVE_NO_SYMLINKS	0x04 /* Block traversal through all symlinks
					(implies OEXT_NO_MAGICLINKS) */
#endif

#ifndef RESOLVE_BENEATH
#define RESOLVE_BENEATH		0x08 /* Block "lexical" trickery like
					"..", symlinks, and absolute
					paths which escape the dirfd. */
#endif

#ifndef RESOLVE_IN_ROOT
#define RESOLVE_IN_ROOT		0x10 /* Make all jumps to "/" and ".."
					be scoped inside the dirfd
					(similar to chroot(2)). */
#endif

#define PROTECT_LOOKUP_BENEATH  (RESOLVE_BENEATH | RESOLVE_NO_XDEV | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS)
#define PROTECT_LOOKUP_BENEATH_WITH_SYMLINKS (PROTECT_LOOKUP_BENEATH & ~RESOLVE_NO_SYMLINKS)
#define PROTECT_LOOKUP_BENEATH_WITH_MAGICLINKS (PROTECT_LOOKUP_BENEATH & ~(RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS))
#define PROTECT_LOOKUP_BENEATH_XDEV (PROTECT_LOOKUP_BENEATH & ~RESOLVE_NO_XDEV)

#define PROTECT_LOOKUP_ABSOLUTE (PROTECT_LOOKUP_BENEATH & ~RESOLVE_BENEATH)
#define PROTECT_LOOKUP_ABSOLUTE_WITH_SYMLINKS (PROTECT_LOOKUP_ABSOLUTE & ~RESOLVE_NO_SYMLINKS)
#define PROTECT_LOOKUP_ABSOLUTE_WITH_MAGICLINKS (PROTECT_LOOKUP_ABSOLUTE & ~(RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS))
#define PROTECT_LOOKUP_ABSOLUTE_XDEV (PROTECT_LOOKUP_ABSOLUTE & ~RESOLVE_NO_XDEV)
#define PROTECT_LOOKUP_ABSOLUTE_XDEV_SYMLINKS (PROTECT_LOOKUP_ABSOLUTE_WITH_SYMLINKS & ~RESOLVE_NO_XDEV)

#define PROTECT_OPATH_FILE (O_NOFOLLOW | O_PATH | O_CLOEXEC)
#define PROTECT_OPATH_DIRECTORY (PROTECT_OPATH_FILE | O_DIRECTORY)

#define PROTECT_OPEN_WITH_TRAILING_SYMLINKS (O_CLOEXEC | O_NOCTTY | O_RDONLY)
#define PROTECT_OPEN (PROTECT_OPEN_WITH_TRAILING_SYMLINKS | O_NOFOLLOW)

#define PROTECT_OPEN_W_WITH_TRAILING_SYMLINKS (O_CLOEXEC | O_NOCTTY | O_WRONLY)
#define PROTECT_OPEN_W (PROTECT_OPEN_W_WITH_TRAILING_SYMLINKS | O_NOFOLLOW)
#define PROTECT_OPEN_RW (O_CLOEXEC | O_NOCTTY | O_RDWR | O_NOFOLLOW)

#if !HAVE_OPENAT2
static inline int openat2(int dfd, const char *filename, struct open_how *how, size_t size)
{
	return syscall(__NR_openat2, dfd, filename, how, size);
}
#endif /* HAVE_OPENAT2 */

#endif /* __LXC_OPEN_UTILS_H */


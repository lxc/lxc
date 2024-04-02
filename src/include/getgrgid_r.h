/* liblxcapi
 *
 * SPDX-License-Identifier: LGPL-2.1+
 *
 * This function has been copied from musl.
 */

#ifndef _GETGRGID_R_H
#define _GETGRGID_R_H

#include <stdio.h>
#include <sys/types.h>
#include <grp.h>

#include "../lxc/compiler.h"

__hidden extern int getgrgid_r(gid_t gid, struct group *gr, char *buf, size_t size,
		      struct group **res);

#endif /* _GETGRGID_R_H */

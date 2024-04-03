/* liblxcapi
 *
 * SPDX-License-Identifier: LGPL-2.1+
 *
 */

#ifndef _LXC_FEXECVE_H
#define _LXC_FEXECVE_H

#include "../lxc/compiler.h"
#include <stdio.h>

__hidden extern int fexecve(int fd, char *const argv[], char *const envp[]);

#endif /* _LXC_FEXECVE_H */

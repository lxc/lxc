/* liblxcapi
 *
 * SPDX-License-Identifier: LGPL-2.1+ *
 *
 * This function has been copied from musl.
 */

#ifndef _STRLCAT_H
#define _STRLCAT_H

#include "../lxc/compiler.h"
#include <stdio.h>

__hidden extern size_t strlcat(char *src, const char *append, size_t len);

#endif

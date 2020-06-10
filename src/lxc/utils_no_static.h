/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_UTILS_NO_STATIC_H
#define __LXC_UTILS_NO_STATIC_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <stdlib.h>

#include "config.h"

extern char *getgname(void);
extern char *getuname(void);

#endif /* __LXC_UTILS_NO_STATIC_H */

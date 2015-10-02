/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2008
 *
 * Authors:
 * Daniel Lezcano <daniel.lezcano at free.fr>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef __LXC_INITUTILS_H
#define __LXC_INITUTILS_H

#include <errno.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>


#include "config.h"

#define DEFAULT_VG "lxc"
#define DEFAULT_THIN_POOL "lxc"
#define DEFAULT_ZFSROOT "lxc"
#define DEFAULT_RBDPOOL "lxc"

extern void lxc_setup_fs(void);
extern const char *lxc_global_config_value(const char *option_name);

/* open a file with O_CLOEXEC */
extern void remove_trailing_slashes(char *p);
FILE *fopen_cloexec(const char *path, const char *mode);

#endif /* __LXC_INITUTILS_H */

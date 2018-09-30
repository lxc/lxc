/* liblxcapi
 *
 * Copyright © 2018 Christian Brauner <christian.brauner@ubuntu.com>.
 * Copyright © 2018 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __LXC_RAW_SYSCALL_H
#define __LXC_RAW_SYSCALL_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <stdio.h>
#include <stdlib.h>

extern int lxc_raw_execveat(int dirfd, const char *pathname, char *const argv[],
			    char *const envp[], int flags);

#endif /* __LXC_RAW_SYSCALL_H */

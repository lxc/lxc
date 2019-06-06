/* liblxcapi
 *
 * Copyright © 2019 Christian Brauner <christian.brauner@ubuntu.com>.
 * Copyright © 2019 Canonical Ltd.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.

 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Stolen and reworked from systemd.
 */

#ifndef __LXC_UUID_H
#define __LXC_UUID_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#define __STDC_FORMAT_MACROS
#include <inttypes.h>

typedef union lxc_id128 lxc_id128_t;

union lxc_id128 {
        uint8_t bytes[16];
        uint64_t qwords[2];
}
;
extern int lxc_id128_randomize(lxc_id128_t *ret);
extern int lxc_id128_write(const char *p, lxc_id128_t id);
extern int lxc_id128_write_fd(int fd, lxc_id128_t id);
extern char *id128_to_uuid_string(lxc_id128_t id, char s[37]);

#endif /* __LXC_UUID_H */

/* SPDX-License-Identifier: LGPL-2.1+ */

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

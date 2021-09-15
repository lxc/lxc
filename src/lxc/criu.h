/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_CRIU_H
#define __LXC_CRIU_H

#include "config.h"

#include <stdbool.h>

#include "lxc.h"

__hidden extern bool __criu_pre_dump(struct lxc_container *c, struct migrate_opts *opts);
__hidden extern bool __criu_dump(struct lxc_container *c, struct migrate_opts *opts);
__hidden extern bool __criu_restore(struct lxc_container *c, struct migrate_opts *opts);
__hidden extern bool __criu_check_feature(uint64_t *features_to_check);

#endif

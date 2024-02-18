/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_IDMAP_UTILS_H
#define __LXC_IDMAP_UTILS_H

#include "config.h"

#include <fcntl.h>
#include <semaphore.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "compiler.h"
#include "conf.h"

__hidden extern int lxc_map_ids(struct list_head *idmap, pid_t pid);
__hidden extern int find_unmapped_nsid(const struct lxc_conf *conf, enum idtype idtype);
__hidden extern int mapped_hostid(unsigned id, const struct lxc_conf *conf, enum idtype idtype);
__hidden extern struct id_map *mapped_hostid_add(const struct lxc_conf *conf, uid_t id,
						 enum idtype type);
__hidden extern struct id_map *mapped_nsid_add(const struct lxc_conf *conf, unsigned id,
					       enum idtype idtype);

__hidden extern int write_id_mapping(enum idtype idtype, pid_t pid, const char *buf, size_t buf_size)
    __access_r(3, 4);

#endif

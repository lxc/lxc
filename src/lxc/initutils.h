/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_INITUTILS_H
#define __LXC_INITUTILS_H

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"
#include "cgroups/cgroup.h"
#include "compiler.h"
#include "string_utils.h"

#define DEFAULT_VG "lxc"
#define DEFAULT_THIN_POOL "lxc"
#define DEFAULT_ZFSROOT "lxc"
#define DEFAULT_RBDPOOL "lxc"

#ifndef PR_SET_MM
#define PR_SET_MM 35
#endif

#ifndef PR_SET_MM_MAP
#define PR_SET_MM_MAP 14

struct prctl_mm_map {
	uint64_t start_code;
	uint64_t end_code;
	uint64_t start_data;
	uint64_t end_data;
	uint64_t start_brk;
	uint64_t brk;
	uint64_t start_stack;
	uint64_t arg_start;
	uint64_t arg_end;
	uint64_t env_start;
	uint64_t env_end;
	uint64_t *auxv;
	uint32_t auxv_size;
	uint32_t exe_fd;
};
#endif

__hidden extern const char *lxc_global_config_value(const char *option_name);

__hidden extern int setproctitle(char *title);

__hidden __noreturn int lxc_container_init(int argc, char *const *argv, bool quiet);

#endif /* __LXC_INITUTILS_H */

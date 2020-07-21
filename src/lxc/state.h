/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_STATE_H
#define __LXC_STATE_H

#include "compiler.h"

#define MAX_STATE_LENGTH (8 + 1)

typedef enum {
	STOPPED,
	STARTING,
	RUNNING,
	STOPPING,
	ABORTING,
	FREEZING,
	FROZEN,
	THAWED,
	MAX_STATE,
} lxc_state_t;

enum {
	REBOOT_NONE,
	REBOOT_REQ,
	REBOOT_INIT
};

__hidden extern lxc_state_t lxc_getstate(const char *name, const char *lxcpath);

__hidden extern lxc_state_t lxc_str2state(const char *state);
__hidden extern const char *lxc_state2str(lxc_state_t state);
__hidden extern int lxc_wait(const char *lxcname, const char *states, int timeout,
			     const char *lxcpath);

#endif /* __LXC_STATE_H */

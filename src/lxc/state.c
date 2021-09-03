/* SPDX-License-Identifier: LGPL-2.1+ */

#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "cgroup.h"
#include "commands.h"
#include "commands_utils.h"
#include "log.h"
#include "lxc.h"
#include "monitor.h"
#include "start.h"
#include "utils.h"

lxc_log_define(state, lxc);

static const char *const strstate[] = {
    "STOPPED",  "STARTING", "RUNNING", "STOPPING",
    "ABORTING", "FREEZING", "FROZEN",  "THAWED",
};

const char *lxc_state2str(lxc_state_t state)
{
	if (state < STOPPED || state > MAX_STATE - 1)
		return "INVALID STATE";
	return strstate[state];
}

lxc_state_t lxc_str2state(const char *state)
{
	size_t len;

	len = sizeof(strstate) / sizeof(strstate[0]);
	for (lxc_state_t i = 0; i < len; i++) {
		if (strequal(strstate[i], state))
			return i;
	}

	ERROR("invalid state '%s'", state);
	return -1;
}

lxc_state_t lxc_getstate(const char *name, const char *lxcpath)
{
	return lxc_cmd_get_state(name, lxcpath);
}

static int fillwaitedstates(const char *strstates, lxc_state_t *states)
{
	char *token;
	char *strstates_dup;
	int state;

	strstates_dup = strdup(strstates);
	if (!strstates_dup)
		return -1;

	lxc_iterate_parts(token, strstates_dup, "|") {
		state = lxc_str2state(token);
		if (state < 0) {
			free(strstates_dup);
			return -1;
		}

		states[state] = 1;
	}
	free(strstates_dup);
	return 0;
}

int lxc_wait(const char *lxcname, const char *states, int timeout,
	     const char *lxcpath)
{
	int state = -1;
	lxc_state_t s[MAX_STATE] = {0};

	if (fillwaitedstates(states, s))
		return -1;

	for (;;) {
		struct timespec onesec = {
		    .tv_sec = 1,
		    .tv_nsec = 0,
		};

		state = lxc_cmd_sock_get_state(lxcname, lxcpath, s, timeout);
		if (state >= 0)
			break;

		if (errno != ECONNREFUSED)
			return log_error_errno(-1, errno, "Failed to receive state from monitor");

		if (timeout > 0)
			timeout--;

		if (timeout == 0)
			return -1;

		(void)nanosleep(&onesec, NULL);
	}

	TRACE("Retrieved state of container %s", lxc_state2str(state));
	if (!s[state])
		return -1;

	return 0;
}

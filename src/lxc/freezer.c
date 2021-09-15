/* SPDX-License-Identifier: LGPL-2.1+ */

#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/types.h>
#include <unistd.h>

#include "attach_options.h"
#include "cgroups/cgroup.h"
#include "cgroups/cgroup_utils.h"
#include "commands.h"
#include "commands_utils.h"
#include "error.h"
#include "log.h"
#include "lxc.h"
#include "monitor.h"
#include "state.h"
#include "string_utils.h"

lxc_log_define(freezer, lxc);

static int do_freeze_thaw(bool freeze, struct lxc_conf *conf, const char *name,
			  const char *lxcpath)
{
	call_cleaner(cgroup_exit) struct cgroup_ops *cgroup_ops = NULL;
	lxc_state_t new_state = freeze ? FROZEN : THAWED;
	int ret;
	const char *state;
	size_t state_len;

	state = lxc_state2str(new_state);
	state_len = strlen(state);

	cgroup_ops = cgroup_init(conf);
	if (!cgroup_ops)
		return -1;

	ret = cgroup_ops->set(cgroup_ops, "freezer.state", state, name, lxcpath);
	if (ret < 0)
		return log_error(-1, "Failed to %s %s",
				 freeze ? "freeze" : "unfreeze", name);

	for (;;) {
		char cur_state[MAX_STATE_LENGTH] = "";

		ret = cgroup_ops->get(cgroup_ops, "freezer.state", cur_state,
				      sizeof(cur_state), name, lxcpath);
		if (ret < 0)
			return log_error(-1, "Failed to get freezer state of %s", name);

		cur_state[lxc_char_right_gc(cur_state, strlen(cur_state))] = '\0';
		if (strnequal(cur_state, state, state_len)) {
			lxc_cmd_notify_state_listeners(name, lxcpath, new_state);
			return 0;
		}

		sleep(1);
	}

	return 0;
}

int lxc_freeze(struct lxc_conf *conf, const char *name, const char *lxcpath)
{
	int ret;

	lxc_cmd_notify_state_listeners(name, lxcpath, FREEZING);
	ret = do_freeze_thaw(true, conf, name, lxcpath);
	lxc_cmd_notify_state_listeners(name, lxcpath, !ret ? FROZEN : RUNNING);
	return ret;
}

int lxc_unfreeze(struct lxc_conf *conf, const char *name, const char *lxcpath)
{
	int ret;

	lxc_cmd_notify_state_listeners(name, lxcpath, THAWED);
	ret = do_freeze_thaw(false, conf, name, lxcpath);
	lxc_cmd_notify_state_listeners(name, lxcpath, !ret ? RUNNING : FROZEN);
	return ret;
}

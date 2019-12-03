/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/types.h>
#include <unistd.h>

#include "cgroup.h"
#include "commands.h"
#include "config.h"
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
	int ret;
	char v[100];
	struct cgroup_ops *cgroup_ops;
	const char *state;
	size_t state_len;
	lxc_state_t new_state = freeze ? FROZEN : THAWED;

	state = lxc_state2str(new_state);
	state_len = strlen(state);

	cgroup_ops = cgroup_init(conf);
	if (!cgroup_ops)
		return -1;

	if (cgroup_ops->cgroup_layout != CGROUP_LAYOUT_UNIFIED) {
		ret = cgroup_ops->set(cgroup_ops, "freezer.state", state, name,
				      lxcpath);
		if (ret < 0) {
			cgroup_exit(cgroup_ops);
			ERROR("Failed to %s %s",
			      (new_state == FROZEN ? "freeze" : "unfreeze"),
			      name);
			return -1;
		}

		for (;;) {
			ret = cgroup_ops->get(cgroup_ops, "freezer.state", v,
					      sizeof(v), name, lxcpath);
			if (ret < 0) {
				cgroup_exit(cgroup_ops);
				ERROR("Failed to get freezer state of %s", name);
				return -1;
			}

			v[sizeof(v) - 1] = '\0';
			v[lxc_char_right_gc(v, strlen(v))] = '\0';

			ret = strncmp(v, state, state_len);
			if (ret == 0) {
				cgroup_exit(cgroup_ops);
				lxc_cmd_serve_state_clients(name, lxcpath,
							    new_state);
				lxc_monitor_send_state(name, new_state, lxcpath);
				return 0;
			}

			sleep(1);
		}
	}

	if (freeze)
		ret = lxc_cmd_freeze(name, lxcpath, -1);
	else
		ret = lxc_cmd_unfreeze(name, lxcpath, -1);
	cgroup_exit(cgroup_ops);
	if (ret < 0)
		return error_log_errno(-1, "Failed to %s container",
				       freeze ? "freeze" : "unfreeze");
	return 0;
}

static void notify_state_listeners(const char *name, const char *lxcpath,
				   lxc_state_t state)
{
	lxc_cmd_serve_state_clients(name, lxcpath, state);
	lxc_monitor_send_state(name, state, lxcpath);
}

int lxc_freeze(struct lxc_conf *conf, const char *name, const char *lxcpath)
{
	int ret;

	notify_state_listeners(name, lxcpath, FREEZING);
	ret = do_freeze_thaw(true, conf, name, lxcpath);
	notify_state_listeners(name, lxcpath, !ret ? FROZEN : RUNNING);
	return ret;
}

int lxc_unfreeze(struct lxc_conf *conf, const char *name, const char *lxcpath)
{
	int ret;

	notify_state_listeners(name, lxcpath, THAWED);
	ret = do_freeze_thaw(false, conf, name, lxcpath);
	notify_state_listeners(name, lxcpath, !ret ? RUNNING : FROZEN);
	return ret;
}

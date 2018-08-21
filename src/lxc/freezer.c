/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2008
 *
 * Authors:
 * Daniel Lezcano <daniel.lezcano at free.fr>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/param.h>

#include "cgroup.h"
#include "commands.h"
#include "error.h"
#include "log.h"
#include "lxc.h"
#include "monitor.h"
#include "state.h"
#include "string_utils.h"

lxc_log_define(freezer, lxc);

static int do_freeze_thaw(bool freeze, const char *name, const char *lxcpath)
{
	int ret;
	char v[100];
	struct cgroup_ops *cgroup_ops;
	const char *state = freeze ? "FROZEN" : "THAWED";
	size_t state_len = 6;
	lxc_state_t new_state = freeze ? FROZEN : THAWED;

	cgroup_ops = cgroup_init(NULL);
	if (!cgroup_ops)
		return -1;

	ret = cgroup_ops->set(cgroup_ops, "freezer.state", state, name, lxcpath);
	if (ret < 0) {
		cgroup_exit(cgroup_ops);
		ERROR("Failed to freeze %s", name);
		return -1;
	}

	for (;;) {
		ret = cgroup_ops->get(cgroup_ops, "freezer.state", v, sizeof(v), name, lxcpath);
		if (ret < 0) {
			cgroup_exit(cgroup_ops);
			ERROR("Failed to get freezer state of %s", name);
			return -1;
		}

		v[99] = '\0';
		v[lxc_char_right_gc(v, strlen(v))] = '\0';

		ret = strncmp(v, state, state_len);
		if (ret == 0) {
			cgroup_exit(cgroup_ops);
			lxc_cmd_serve_state_clients(name, lxcpath, new_state);
			lxc_monitor_send_state(name, new_state, lxcpath);
			return 0;
		}

		sleep(1);
	}
}

int lxc_freeze(const char *name, const char *lxcpath)
{
	lxc_cmd_serve_state_clients(name, lxcpath, FREEZING);
	lxc_monitor_send_state(name, FREEZING, lxcpath);
	return do_freeze_thaw(true, name, lxcpath);
}

int lxc_unfreeze(const char *name, const char *lxcpath)
{
	return do_freeze_thaw(false, name, lxcpath);
}

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

#include "error.h"
#include "state.h"
#include "monitor.h"
#include "log.h"
#include "lxc.h"

lxc_log_define(lxc_freezer, lxc);

lxc_state_t freezer_state(const char *name, const char *lxcpath)
{
	char v[100];
	if (lxc_cgroup_get("freezer.state", v, 100, name, lxcpath) < 0)
		return -1;

	if (v[strlen(v)-1] == '\n')
		v[strlen(v)-1] = '\0';
	return lxc_str2state(v);
}

static int do_freeze_thaw(int freeze, const char *name, const char *lxcpath)
{
	char v[100];
	const char *state = freeze ? "FROZEN" : "THAWED";

	if (lxc_cgroup_set("freezer.state", state, name, lxcpath) < 0) {
		ERROR("Failed to freeze %s:%s", lxcpath, name);
		return -1;
	}
	while (1) {
		if (lxc_cgroup_get("freezer.state", v, 100, name, lxcpath) < 0) {
			ERROR("Failed to get new freezer state for %s:%s", lxcpath, name);
			return -1;
		}
		if (v[strlen(v)-1] == '\n')
			v[strlen(v)-1] = '\0';
		if (strncmp(v, state, strlen(state)) == 0) {
			if (name)
				lxc_monitor_send_state(name, freeze ? FROZEN : THAWED, lxcpath);
			return 0;
		}
		sleep(1);
	}
}

int lxc_freeze(const char *name, const char *lxcpath)
{
	lxc_monitor_send_state(name, FREEZING, lxcpath);
	return do_freeze_thaw(1, name, lxcpath);
}

int lxc_unfreeze(const char *name, const char *lxcpath)
{
	return do_freeze_thaw(0, name, lxcpath);
}

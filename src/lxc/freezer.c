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
#define _GNU_SOURCE
#include <stdio.h>
#undef _GNU_SOURCE
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
#include "cgroup.h"

lxc_log_define(lxc_freezer, lxc);


int lxc_freeze(const char *name, const char *lxcpath)
{
	lxc_monitor_send_state(name, FREEZING, lxcpath);
	return freeze_unfreeze(name, 1, lxcpath);
}

int lxc_unfreeze(const char *name, const char *lxcpath)
{
	return freeze_unfreeze(name, 0, lxcpath);
}

int lxc_unfreeze_bypath(const char *cgrelpath)
{
	char *cgabspath;
	int ret;

	cgabspath = lxc_cgroup_find_abs_path("freezer", cgrelpath, true, NULL);
	if (!cgabspath)
		return -1;

	ret = do_unfreeze(cgabspath, 0, NULL, NULL);
	free(cgabspath);
	return ret;
}

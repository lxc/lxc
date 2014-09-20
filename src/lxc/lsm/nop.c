/*
 * lxc: linux Container library
 *
 * Copyright © 2013 Oracle.
 *
 * Authors:
 * Dwight Engen <dwight.engen@oracle.com>
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

#include <stdlib.h>
#include "lsm/lsm.h"

static char *nop_process_label_get(pid_t pid)
{
	return NULL;
}

static int nop_process_label_set(const char *label, struct lxc_conf *conf,
		int use_default, int on_exec)
{
	return 0;
}

static int nop_enabled(void)
{
	return 0;
}

static struct lsm_drv nop_drv = {
	.name = "nop",
	.enabled           = nop_enabled,
	.process_label_get = nop_process_label_get,
	.process_label_set = nop_process_label_set,
};

struct lsm_drv *lsm_nop_drv_init(void)
{
	return &nop_drv;
}

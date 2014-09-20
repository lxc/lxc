/*
 * lxc: linux Container library
 *
 * Authors:
 * Copyright © 2012 Serge Hallyn <serge.hallyn@ubuntu.com>
 * Copyright © 2012 Canonical Ltd.
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

#if HAVE_APPARMOR || HAVE_SELINUX

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/param.h>

#include "conf.h"
#include "log.h"
#include "lsm/lsm.h"

lxc_log_define(lxc_lsm, lxc);

static struct lsm_drv *drv = NULL;

extern struct lsm_drv *lsm_apparmor_drv_init(void);
extern struct lsm_drv *lsm_selinux_drv_init(void);
extern struct lsm_drv *lsm_nop_drv_init(void);

__attribute__((constructor))
void lsm_init(void)
{
	if (drv) {
		INFO("LSM security driver %s", drv->name);
		return;
	}

	#if HAVE_APPARMOR
	drv = lsm_apparmor_drv_init();
	#endif
	#if HAVE_SELINUX
	if (!drv)
		drv = lsm_selinux_drv_init();
	#endif

	if (!drv)
		drv = lsm_nop_drv_init();
	INFO("Initialized LSM security driver %s", drv->name);
}

int lsm_enabled(void)
{
	if (drv)
		return drv->enabled();
	return 0;
}

const char *lsm_name(void)
{
	if (drv)
		return drv->name;
	return "none";
}

char *lsm_process_label_get(pid_t pid)
{
	if (!drv) {
		ERROR("LSM driver not inited");
		return NULL;
	}
	return drv->process_label_get(pid);
}

int lsm_process_label_set(const char *label, struct lxc_conf *conf,
		int use_default, int on_exec)
{
	if (!drv) {
		ERROR("LSM driver not inited");
		return -1;
	}
	return drv->process_label_set(label, conf, use_default, on_exec);
}

#endif

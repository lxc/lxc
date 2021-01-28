/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <errno.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <unistd.h>

#include "compiler.h"
#include "conf.h"
#include "config.h"
#include "log.h"
#include "lsm.h"

lxc_log_define(lsm, lxc);

__hidden extern struct lsm_ops *lsm_apparmor_ops_init(void);
__hidden extern struct lsm_ops *lsm_selinux_ops_init(void);
__hidden extern struct lsm_ops *lsm_nop_ops_init(void);

struct lsm_ops *lsm_init_static(void)
{
	struct lsm_ops *ops = NULL;

	#if HAVE_APPARMOR
	ops = lsm_apparmor_ops_init();
	#endif

	#if HAVE_SELINUX
	if (!ops)
		ops = lsm_selinux_ops_init();
	#endif

	if (!ops)
		ops = lsm_nop_ops_init();

	INFO("Initialized LSM security driver %s", ops->name);
	return ops;
}

/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <stdlib.h>

#include "config.h"
#include "lsm/lsm.h"

static char *nop_process_label_get(pid_t pid)
{
	return NULL;
}

static int nop_process_label_set(const char *label, struct lxc_conf *conf,
				 bool on_exec)
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

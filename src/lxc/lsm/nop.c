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

static int nop_keyring_label_set(const char *label)
{
	return 0;
}

static int nop_prepare(struct lxc_conf *conf, const char *lxcpath)
{
	return 0;
}

static void nop_cleanup(struct lxc_conf *conf, const char *lxcpath)
{
}

static int nop_process_label_fd_get(pid_t pid, bool on_exec)
{
	return 0;
}

static int nop_process_label_set_at(int label_fd, const char *label, bool on_exec)
{
	return 0;
}

static struct lsm_ops nop_ops = {
	.name			= "nop",
	.cleanup		= nop_cleanup,
	.enabled		= nop_enabled,
	.keyring_label_set	= nop_keyring_label_set,
	.prepare		= nop_prepare,
	.process_label_fd_get	= nop_process_label_fd_get,
	.process_label_get	= nop_process_label_get,
	.process_label_set	= nop_process_label_set,
	.process_label_set_at	= nop_process_label_set_at,
};

const struct lsm_ops *lsm_nop_ops_init(void)
{
	return &nop_ops;
}

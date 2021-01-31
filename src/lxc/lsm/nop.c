/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <stdlib.h>

#include "config.h"
#include "lsm/lsm.h"

static char *nop_process_label_get(struct lsm_ops *ops, pid_t pid)
{
	return NULL;
}

static char *nop_process_label_get_at(struct lsm_ops *ops, int fd_pid)
{
	return NULL;
}

static int nop_process_label_set(struct lsm_ops *ops, const char *label, struct lxc_conf *conf,
				 bool on_exec)
{
	return 0;
}

static int nop_enabled(struct lsm_ops *ops)
{
	return 0;
}

static int nop_keyring_label_set(struct lsm_ops *ops, const char *label)
{
	return 0;
}

static int nop_prepare(struct lsm_ops *ops, struct lxc_conf *conf, const char *lxcpath)
{
	return 0;
}

static void nop_cleanup(struct lsm_ops *ops, struct lxc_conf *conf, const char *lxcpath)
{
}

static int nop_process_label_fd_get(struct lsm_ops *ops, pid_t pid, bool on_exec)
{
	return 0;
}

static int nop_process_label_set_at(struct lsm_ops *ops, int label_fd, const char *label, bool on_exec)
{
	return 0;
}

static struct lsm_ops nop_ops = {
	.name				= "nop",
	.aa_admin			= -1,
	.aa_can_stack			= -1,
	.aa_enabled			= -1,
	.aa_is_stacked			= -1,
	.aa_mount_features_enabled	= -1,
	.aa_parser_available		= -1,
	.aa_supports_unix		= -1,
	.cleanup			= nop_cleanup,
    	.enabled			= nop_enabled,
    	.keyring_label_set		= nop_keyring_label_set,
    	.prepare			= nop_prepare,
    	.process_label_fd_get		= nop_process_label_fd_get,
    	.process_label_get		= nop_process_label_get,
	.process_label_set		= nop_process_label_set,
	.process_label_get_at		= nop_process_label_get_at,
	.process_label_set_at		= nop_process_label_set_at,
};

struct lsm_ops *lsm_nop_ops_init(void)
{
	return &nop_ops;
}

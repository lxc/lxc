/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <errno.h>
#include <selinux/selinux.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "conf.h"
#include "config.h"
#include "log.h"
#include "lsm.h"

#define DEFAULT_LABEL "unconfined_t"

lxc_log_define(selinux, lsm);

/*
 * selinux_process_label_get: Get SELinux context of a process
 *
 * @pid     : the pid to get, or 0 for self
 *
 * Returns the context of the given pid. The caller must free()
 * the returned string.
 *
 * Note that this relies on /proc being available.
 */
static char *selinux_process_label_get(pid_t pid)
{
	security_context_t ctx;
	char *label;

	if (getpidcon_raw(pid, &ctx) < 0) {
		SYSERROR("failed to get SELinux context for pid %d", pid);
		return NULL;
	}
	label = strdup((char *)ctx);
	freecon(ctx);
	return label;
}

/*
 * selinux_process_label_set: Set SELinux context of a process
 *
 * @label   : label string
 * @conf    : the container configuration to use if @label is NULL
 * @default : use the default context if @label is NULL
 * @on_exec : the new context will take effect on exec(2) not immediately
 *
 * Returns 0 on success, < 0 on failure
 *
 * Notes: This relies on /proc being available.
 */
static int selinux_process_label_set(const char *inlabel, struct lxc_conf *conf,
				     bool on_exec)
{
	int ret;
	const char *label;

	label = inlabel ? inlabel : conf->lsm_se_context;
	if (!label) {

		label = DEFAULT_LABEL;
	}

	if (strcmp(label, "unconfined_t") == 0)
		return 0;

	if (on_exec)
		ret = setexeccon_raw((char *)label);
	else
		ret = setcon_raw((char *)label);
	if (ret < 0) {
		SYSERROR("Failed to set SELinux%s context to \"%s\"",
			 on_exec ? " exec" : "", label);
		return -1;
	}

	INFO("Changed SELinux%s context to \"%s\"", on_exec ? " exec" : "", label);
	return 0;
}

/*
 * selinux_keyring_label_set: Set SELinux context that will be assigned to the keyring
 *
 * @label   : label string
 *
 * Returns 0 on success, < 0 on failure
 */
static int selinux_keyring_label_set(char *label)
{
	return setkeycreatecon_raw(label);
};

static struct lsm_drv selinux_drv = {
	.name = "SELinux",
	.enabled           = is_selinux_enabled,
	.process_label_get = selinux_process_label_get,
	.process_label_set = selinux_process_label_set,
	.keyring_label_set = selinux_keyring_label_set,
};

struct lsm_drv *lsm_selinux_drv_init(void)
{
	if (!is_selinux_enabled())
		return NULL;
	return &selinux_drv;
}

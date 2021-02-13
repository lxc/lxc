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
#include "file_utils.h"
#include "log.h"
#include "lsm.h"
#include "memory_utils.h"

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
static char *selinux_process_label_get(struct lsm_ops *ops, pid_t pid)
{
	char *label;

	if (getpidcon_raw(pid, &label) < 0)
		return log_error_errno(NULL, errno, "failed to get SELinux context for pid %d", pid);

	return label;
}

/*
 * selinux_process_label_get_at: Get SELinux context of a process
 *
 * @fd_pid     : file descriptor to /proc/<pid> of the process
 *
 * Returns the context of the given pid. The caller must free()
 * the returned string.
 *
 * Note that this relies on /proc being available.
 */
static char *selinux_process_label_get_at(struct lsm_ops *ops, int fd_pid)
{
	__do_free char *label = NULL;
	size_t len;

	label = read_file_at(fd_pid, "attr/current", PROTECT_OPEN, PROTECT_LOOKUP_BENEATH);
	if (!label)
		return log_error_errno(NULL, errno, "Failed to get SELinux context");

	len = strcspn(label, "\n \t");
	if (len)
		label[len] = '\0';

	return move_ptr(label);
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
static int selinux_process_label_set(struct lsm_ops *ops, const char *inlabel,
				     struct lxc_conf *conf, bool on_exec)
{
	int ret;
	const char *label;

	label = inlabel ? inlabel : conf->lsm_se_context;
	if (!label)
		label = DEFAULT_LABEL;

	if (strequal(label, "unconfined_t"))
		return 0;

	if (on_exec)
		ret = setexeccon_raw((char *)label);
	else
		ret = setcon_raw((char *)label);
	if (ret < 0)
		return log_error_errno(-1, errno, "Failed to set SELinux%s context to \"%s\"",
				       on_exec ? " exec" : "", label);

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
static int selinux_keyring_label_set(struct lsm_ops *ops, const char *label)
{
	return setkeycreatecon_raw(label);
}

static int selinux_prepare(struct lsm_ops *ops, struct lxc_conf *conf, const char *lxcpath)
{
	return 0;
}

static void selinux_cleanup(struct lsm_ops *ops, struct lxc_conf *conf, const char *lxcpath)
{
}

static int selinux_process_label_fd_get(struct lsm_ops *ops, pid_t pid, bool on_exec)
{
	int ret = -1;
	int labelfd;
	char path[LXC_LSMATTRLEN];

	if (on_exec)
		ret = snprintf(path, LXC_LSMATTRLEN, "/proc/%d/attr/exec", pid);
	else
		ret = snprintf(path, LXC_LSMATTRLEN, "/proc/%d/attr/current", pid);
	if (ret < 0 || ret >= LXC_LSMATTRLEN)
		return -1;

	labelfd = open(path, O_RDWR);
	if (labelfd < 0)
		return log_error_errno(-errno, errno, "Unable to open SELinux LSM label file descriptor");

	return labelfd;
}

static int selinux_process_label_set_at(struct lsm_ops *ops, int label_fd, const char *label, bool on_exec)
{
	int ret;

	if (!label)
		return 0;

	ret = lxc_write_nointr(label_fd, label, strlen(label));
	if (ret < 0)
		return log_error_errno(-errno, errno, "Failed to set AppArmor SELinux label to \"%s\"", label);

	INFO("Set SELinux label to \"%s\"", label);
	return 0;
}

static int selinux_enabled(struct lsm_ops *ops)
{
	return is_selinux_enabled();
}

static struct lsm_ops selinux_ops = {
	.name				= "SELinux",
	.aa_admin			= -1,
	.aa_can_stack			= -1,
	.aa_enabled			= -1,
	.aa_is_stacked			= -1,
	.aa_mount_features_enabled	= -1,
	.aa_parser_available		= -1,
	.aa_supports_unix		= -1,
	.cleanup			= selinux_cleanup,
	.enabled			= selinux_enabled,
	.keyring_label_set		= selinux_keyring_label_set,
	.prepare			= selinux_prepare,
	.process_label_fd_get		= selinux_process_label_fd_get,
	.process_label_get		= selinux_process_label_get,
	.process_label_set		= selinux_process_label_set,
	.process_label_get_at		= selinux_process_label_get_at,
	.process_label_set_at		= selinux_process_label_set_at,
};

struct lsm_ops *lsm_selinux_ops_init(void)
{
	if (!is_selinux_enabled())
		return NULL;

	return &selinux_ops;
}

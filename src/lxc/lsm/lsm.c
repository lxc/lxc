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

#define _GNU_SOURCE
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/param.h>

#include "conf.h"
#include "log.h"
#include "lsm.h"

lxc_log_define(lsm, lxc);

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

int lsm_process_label_fd_get(pid_t pid, bool on_exec)
{
	int ret = -1;
	int labelfd = -1;
	const char *name;
	char path[LXC_LSMATTRLEN];

	name = lsm_name();

	if (strcmp(name, "nop") == 0)
		return 0;

	if (strcmp(name, "none") == 0)
		return 0;

	/* We don't support on-exec with AppArmor */
	if (strcmp(name, "AppArmor") == 0)
		on_exec = 0;

	if (on_exec)
		ret = snprintf(path, LXC_LSMATTRLEN, "/proc/%d/attr/exec", pid);
	else
		ret = snprintf(path, LXC_LSMATTRLEN, "/proc/%d/attr/current", pid);
	if (ret < 0 || ret >= LXC_LSMATTRLEN)
		return -1;

	labelfd = open(path, O_RDWR);
	if (labelfd < 0) {
		SYSERROR("Unable to %s LSM label file descriptor", name);
		return -1;
	}

	return labelfd;
}

int lsm_process_label_set_at(int label_fd, const char *label, bool on_exec)
{
	int ret = -1;
	const char *name;

	name = lsm_name();

	if (strcmp(name, "nop") == 0)
		return 0;

	if (strcmp(name, "none") == 0)
		return 0;

	/* We don't support on-exec with AppArmor */
	if (strcmp(name, "AppArmor") == 0)
		on_exec = false;

	if (strcmp(name, "AppArmor") == 0) {
		size_t len;
		char *command;

		if (on_exec) {
			ERROR("Changing AppArmor profile on exec not supported");
			return -1;
		}

		len = strlen(label) + strlen("changeprofile ") + 1;
		command = malloc(len);
		if (!command)
			goto on_error;

		ret = snprintf(command, len, "changeprofile %s", label);
		if (ret < 0 || (size_t)ret >= len) {
			int saved_errno = errno;
			free(command);
			errno = saved_errno;
			goto on_error;
		}

		ret = lxc_write_nointr(label_fd, command, len - 1);
		free(command);
	} else if (strcmp(name, "SELinux") == 0) {
		ret = lxc_write_nointr(label_fd, label, strlen(label));
	} else {
		errno = EINVAL;
		ret = -1;
	}
	if (ret < 0) {
on_error:
		SYSERROR("Failed to set %s label \"%s\"", name, label);
		return -1;
	}

	INFO("Set %s label to \"%s\"", name, label);
	return 0;
}

int lsm_process_label_set(const char *label, struct lxc_conf *conf,
			  bool use_default, bool on_exec)
{
	if (!drv) {
		ERROR("LSM driver not inited");
		return -1;
	}
	return drv->process_label_set(label, conf, use_default, on_exec);
}

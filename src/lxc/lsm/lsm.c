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

int lsm_process_label_set(const char *label, int use_default, int on_exec)
{
	if (!drv) {
		ERROR("LSM driver not inited");
		return -1;
	}
	return drv->process_label_set(label, use_default, on_exec);
}

/*
 * _lsm_mount_proc: Mount /proc inside container to enable
 * security domain transition
 *
 * @rootfs : the rootfs where proc should be mounted
 *
 * Returns < 0 on failure, 0 if the correct proc was already mounted
 * and 1 if a new proc was mounted.
 */
static int _lsm_proc_mount(const char *rootfs)
{
	char path[MAXPATHLEN];
	char link[20];
	int linklen, ret;

	ret = snprintf(path, MAXPATHLEN, "%s/proc/self", rootfs);
	if (ret < 0 || ret >= MAXPATHLEN) {
		SYSERROR("proc path name too long");
		return -1;
	}
	memset(link, 0, 20);
	linklen = readlink(path, link, 20);
	INFO("I am %d, /proc/self points to '%s'", getpid(), link);
	ret = snprintf(path, MAXPATHLEN, "%s/proc", rootfs);
	if (linklen < 0) /* /proc not mounted */
		goto domount;
	/* can't be longer than rootfs/proc/1 */
	if (strncmp(link, "1", linklen) != 0) {
		/* wrong /procs mounted */
		umount2(path, MNT_DETACH); /* ignore failure */
		goto domount;
	}
	/* the right proc is already mounted */
	return 0;

domount:
	if (mount("proc", path, "proc", 0, NULL))
		return -1;
	INFO("Mounted /proc in container for security transition");
	return 1;
}

int lsm_proc_mount(struct lxc_conf *lxc_conf)
{
	int mounted;

	if (!drv || strcmp(drv->name, "nop") == 0)
		return 0;

	if (lxc_conf->rootfs.path == NULL || strlen(lxc_conf->rootfs.path) == 0) {
		if (mount("proc", "/proc", "proc", 0, NULL)) {
			SYSERROR("Failed mounting /proc, proceeding");
			mounted = 0;
		} else
			mounted = 1;
	} else
		mounted = _lsm_proc_mount(lxc_conf->rootfs.mount);
	if (mounted == -1) {
		SYSERROR("failed to mount /proc in the container.");
		return -1;
	} else if (mounted == 1) {
		lxc_conf->lsm_umount_proc = 1;
	}
	return 0;
}

void lsm_proc_unmount(struct lxc_conf *lxc_conf)
{
	if (lxc_conf->lsm_umount_proc == 1) {
		umount("/proc");
		lxc_conf->lsm_umount_proc = 0;
	}
}
#endif

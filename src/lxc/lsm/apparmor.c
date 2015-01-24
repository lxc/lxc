/* apparmor
 *
 * Copyright © 2012 Serge Hallyn <serge.hallyn@ubuntu.com>.
 * Copyright © 2012 Canonical Ltd.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.

 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.

 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/apparmor.h>

#include "log.h"
#include "lsm/lsm.h"

lxc_log_define(lxc_apparmor, lxc);

/* set by lsm_apparmor_drv_init if true */
static int aa_enabled = 0;

#define AA_DEF_PROFILE "lxc-container-default"
#define AA_MOUNT_RESTR "/sys/kernel/security/apparmor/features/mount/mask"
#define AA_ENABLED_FILE "/sys/module/apparmor/parameters/enabled"

/* aa_getcon is not working right now.  Use our hand-rolled version below */
static int apparmor_enabled(void)
{
	struct stat statbuf;
	FILE *fin;
	char e;
	int ret;

	ret = stat(AA_MOUNT_RESTR, &statbuf);
	if (ret != 0)
		return 0;
	fin = fopen(AA_ENABLED_FILE, "r");
	if (!fin)
		return 0;
	ret = fscanf(fin, "%c", &e);
	fclose(fin);
	if (ret == 1 && e == 'Y')
		return 1;
	return 0;
}

static char *apparmor_process_label_get(pid_t pid)
{
	char path[100], *space;
	int ret;
	char *buf = NULL, *newbuf;
	int sz = 0;
	FILE *f;

	ret = snprintf(path, 100, "/proc/%d/attr/current", pid);
	if (ret < 0 || ret >= 100) {
		ERROR("path name too long");
		return NULL;
	}
again:
	f = fopen(path, "r");
	if (!f) {
		SYSERROR("opening %s", path);
		free(buf);
		return NULL;
	}
	sz += 1024;
	newbuf = realloc(buf, sz);
	if (!newbuf) {
		free(buf);
		ERROR("out of memory");
		fclose(f);
		return NULL;
	}
	buf = newbuf;
	memset(buf, 0, sz);
	ret = fread(buf, 1, sz - 1, f);
	fclose(f);
	if (ret < 0) {
		ERROR("reading %s", path);
		free(buf);
		return NULL;
	}
	if (ret >= sz)
		goto again;
	space = strchr(buf, '\n');
	if (space)
		*space = '\0';
	space = strchr(buf, ' ');
	if (space)
		*space = '\0';
	return buf;
}

static int apparmor_am_unconfined(void)
{
	char *p = apparmor_process_label_get(getpid());
	int ret = 0;
	if (!p || strcmp(p, "unconfined") == 0)
		ret = 1;
	free(p);
	return ret;
}

/*
 * apparmor_process_label_set: Set AppArmor process profile
 *
 * @label   : the profile to set
 * @default : use the default profile if label is NULL
 * @on_exec : this is ignored.  Apparmor profile will be changed immediately
 *
 * Returns 0 on success, < 0 on failure
 *
 * Notes: This relies on /proc being available.
 */
static int apparmor_process_label_set(const char *label, int use_default,
				      int on_exec)
{
	if (!aa_enabled)
		return 0;

	if (!label) {
		if (use_default)
			label = AA_DEF_PROFILE;
		else
			return 0;
	}

	if (strcmp(label, "unconfined") == 0 && apparmor_am_unconfined()) {
		INFO("apparmor profile unchanged");
		return 0;
	}

	if (aa_change_profile(label) < 0) {
		SYSERROR("failed to change apparmor profile to %s", label);
		return -1;
	}

	INFO("changed apparmor profile to %s", label);
	return 0;
}

static struct lsm_drv apparmor_drv = {
	.name = "AppArmor",
	.enabled           = apparmor_enabled,
	.process_label_get = apparmor_process_label_get,
	.process_label_set = apparmor_process_label_set,
};

struct lsm_drv *lsm_apparmor_drv_init(void)
{
	if (!apparmor_enabled())
		return NULL;
	aa_enabled = 1;
	return &apparmor_drv;
}

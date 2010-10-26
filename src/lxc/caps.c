/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2008
 *
 * Authors:
 * Daniel Lezcano <dlezcano at fr.ibm.com>
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/capability.h>

#include "log.h"

lxc_log_define(lxc_caps, lxc);

int lxc_caps_reset(void)
{
	cap_t cap = cap_init();
	int ret = 0;

	if (!cap) {
		ERROR("cap_init() failed : %m");
		return -1;
	}

	if (cap_set_proc(cap)) {
		ERROR("cap_set_proc() failed : %m");
		ret = -1;
	}

	cap_free(cap);
	return ret;
}

int lxc_caps_down(void)
{
	cap_t caps;
	int ret;

	/* when we are run as root, we don't want to play
	 * with the capabilities */
	if (!getuid())
		return 0;

	caps = cap_get_proc();
	if (!caps) {
		ERROR("failed to cap_get_proc: %m");
		return -1;
	}

	ret = cap_clear_flag(caps, CAP_EFFECTIVE);
	if (ret) {
		ERROR("failed to cap_clear_flag: %m");
		goto out;
	}

	ret = cap_set_proc(caps);
	if (ret) {
		ERROR("failed to cap_set_proc: %m");
		goto out;
	}

out:
	cap_free(caps);
        return 0;
}

int lxc_caps_up(void)
{
	cap_t caps;
	cap_value_t cap;
	int ret;

	/* when we are run as root, we don't want to play
	 * with the capabilities */
	if (!getuid())
		return 0;

	caps = cap_get_proc();
	if (!caps) {
		ERROR("failed to cap_get_proc: %m");
		return -1;
	}

	for (cap = 0; cap <= CAP_LAST_CAP; cap++) {

		cap_flag_value_t flag;

		ret = cap_get_flag(caps, cap, CAP_PERMITTED, &flag);
		if (ret) {
			ERROR("failed to cap_get_flag: %m");
			goto out;
		}

		ret = cap_set_flag(caps, CAP_EFFECTIVE, 1, &cap, flag);
		if (ret) {
			ERROR("failed to cap_set_flag: %m");
			goto out;
		}
	}

	ret = cap_set_proc(caps);
	if (ret) {
		ERROR("failed to cap_set_proc: %m");
		goto out;
	}

out:
	cap_free(caps);
        return 0;
}

int lxc_caps_init(void)
{
	uid_t uid = getuid();
	gid_t gid = getgid();
	uid_t euid = geteuid();

	if (!uid) {
		INFO("command is run as 'root'");
		return 0;
	}

	if (uid && !euid) {
		INFO("command is run as setuid root (uid : %d)", uid);

		if (prctl(PR_SET_KEEPCAPS, 1)) {
			ERROR("failed to 'PR_SET_KEEPCAPS': %m");
			return -1;
		}

		if (setresgid(gid, gid, gid)) {
			ERROR("failed to change gid to '%d': %m", gid);
			return -1;
		}

		if (setresuid(uid, uid, uid)) {
			ERROR("failed to change uid to '%d': %m", uid);
			return -1;
		}

		if (lxc_caps_up()) {
			ERROR("failed to restore capabilities: %m");
			return -1;
		}
	}

	if (uid == euid)
		INFO("command is run as user '%d'", uid);

	return 0;
}

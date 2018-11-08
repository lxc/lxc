/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2008
 *
 * Authors:
 * Daniel Lezcano <daniel.lezcano at free.fr>
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/prctl.h>

#include "caps.h"
#include "config.h"
#include "file_utils.h"
#include "log.h"
#include "macro.h"

lxc_log_define(caps, lxc);

#if HAVE_LIBCAP

int lxc_caps_down(void)
{
	cap_t caps;
	int ret = -1;

	/* When we are root, we don't want to play with capabilities. */
	if (!getuid())
		return 0;

	caps = cap_get_proc();
	if (!caps) {
		SYSERROR("Failed to retrieve capabilities");
		return ret;
	}

	ret = cap_clear_flag(caps, CAP_EFFECTIVE);
	if (ret) {
		SYSERROR("Failed to clear effective capabilities");
		goto on_error;
	}

	ret = cap_set_proc(caps);
	if (ret) {
		SYSERROR("Failed to change effective capabilities");
		goto on_error;
	}

	ret = 0;

on_error:
	cap_free(caps);

	return ret;
}

int lxc_caps_up(void)
{
	cap_t caps;
	cap_value_t cap;
	int ret = -1;

	/* When we are root, we don't want to play with capabilities. */
	if (!getuid())
		return 0;

	caps = cap_get_proc();
	if (!caps) {
		SYSERROR("Failed to retrieve capabilities");
		return ret;
	}

	for (cap = 0; cap <= CAP_LAST_CAP; cap++) {
		cap_flag_value_t flag;

		ret = cap_get_flag(caps, cap, CAP_PERMITTED, &flag);
		if (ret) {
			if (errno == EINVAL) {
				INFO("Last supported cap was %d", cap - 1);
				break;
			} else {
				SYSERROR("Failed to retrieve setting for "
					 "permitted capability %d", cap - 1);
				goto on_error;
			}
		}

		ret = cap_set_flag(caps, CAP_EFFECTIVE, 1, &cap, flag);
		if (ret) {
			SYSERROR("Failed to set effective capability %d", cap - 1);
			goto on_error;
		}
	}

	ret = cap_set_proc(caps);
	if (ret) {
		SYSERROR("Failed to change effective capabilities");
		goto on_error;
	}

	ret = 0;

on_error:
	cap_free(caps);

	return ret;
}

int lxc_ambient_caps_up(void)
{
	int ret;
	cap_t caps;
	cap_value_t cap;
	int last_cap = CAP_LAST_CAP;
	char *cap_names = NULL;

	/* When we are root, we don't want to play with capabilities. */
	if (!getuid())
		return 0;

	caps = cap_get_proc();
	if (!caps) {
		SYSERROR("Failed to retrieve capabilities");
		return -1;
	}

	for (cap = 0; cap <= CAP_LAST_CAP; cap++) {
		cap_flag_value_t flag;

		ret = cap_get_flag(caps, cap, CAP_PERMITTED, &flag);
		if (ret < 0) {
			if (errno == EINVAL) {
				last_cap = (cap - 1);
				INFO("Last supported cap was %d", last_cap);
				break;
			}

			SYSERROR("Failed to retrieve capability flag");
			goto out;
		}

		ret = cap_set_flag(caps, CAP_INHERITABLE, 1, &cap, flag);
		if (ret < 0) {
			SYSERROR("Failed to set capability flag");
			goto out;
		}
	}

	ret = cap_set_proc(caps);
	if (ret < 0) {
		SYSERROR("Failed to set capabilities");
		goto out;
	}

	for (cap = 0; cap <= last_cap; cap++) {
		ret = prctl(PR_CAP_AMBIENT, prctl_arg(PR_CAP_AMBIENT_RAISE),
			    prctl_arg(cap), prctl_arg(0), prctl_arg(0));
		if (ret < 0) {
			SYSWARN("Failed to raise ambient capability %d", cap);
			goto out;
		}
	}

	cap_names = cap_to_text(caps, NULL);
	if (!cap_names) {
		SYSWARN("Failed to convert capabilities %d", cap);
		goto out;
	}

	TRACE("Raised %s in inheritable and ambient capability set", cap_names);

out:

	cap_free(cap_names);
	cap_free(caps);
	return 0;
}

int lxc_ambient_caps_down(void)
{
	int ret;
	cap_t caps;
	cap_value_t cap;

	/* When we are root, we don't want to play with capabilities. */
	if (!getuid())
		return 0;

	ret = prctl(PR_CAP_AMBIENT, prctl_arg(PR_CAP_AMBIENT_CLEAR_ALL),
		    prctl_arg(0), prctl_arg(0), prctl_arg(0));
	if (ret < 0) {
		SYSERROR("Failed to clear ambient capability set");
		return -1;
	}

	caps = cap_get_proc();
	if (!caps) {
		SYSERROR("Failed to retrieve capabilities");
		return -1;
	}

	for (cap = 0; cap <= CAP_LAST_CAP; cap++) {
		ret = cap_set_flag(caps, CAP_INHERITABLE, 1, &cap, CAP_CLEAR);
		if (ret < 0) {
			SYSERROR("Failed to remove capability from inheritable set");
			goto out;
		}
	}

	ret = cap_set_proc(caps);
	if (ret < 0) {
		SYSERROR("Failed to set capabilities");
		goto out;
	}

out:
	cap_free(caps);
	return 0;
}

int lxc_caps_init(void)
{
	uid_t euid, uid;

	uid = getuid();
	if (!uid)
		return 0;

	euid = geteuid();
	if (uid && !euid) {
		int ret;
		gid_t gid;

		INFO("Command is run as setuid root (uid: %d)", uid);

		ret = prctl(PR_SET_KEEPCAPS, prctl_arg(1));
		if (ret < 0) {
			SYSERROR("Failed to set PR_SET_KEEPCAPS");
			return -1;
		}

		gid = getgid();
		ret = setresgid(gid, gid, gid);
		if (ret < 0) {
			SYSERROR("Failed to change rgid, egid, and sgid to %d", gid);
			return -1;
		}

		ret = setresuid(uid, uid, uid);
		if (ret < 0) {
			SYSERROR("Failed to change ruid, euid, and suid to %d", uid);
			return -1;
		}

		ret = lxc_caps_up();
		if (ret < 0) {
			SYSERROR("Failed to restore capabilities");
			return -1;
		}
	}

	if (uid == euid)
		INFO("Command is run with uid %d", uid);

	return 0;
}

static long int _real_caps_last_cap(void)
{
	int fd, result = -1;

	/* Try to get the maximum capability over the kernel interface
	 * introduced in v3.2.
	 */
	fd = open("/proc/sys/kernel/cap_last_cap", O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		ssize_t n;
		char *ptr;
		char buf[INTTYPE_TO_STRLEN(int)] = {0};

		n = lxc_read_nointr(fd, buf, STRARRAYLEN(buf));
		if (n >= 0) {
			errno = 0;
			result = strtol(buf, &ptr, 10);
			if (!ptr || (*ptr != '\0' && *ptr != '\n') || errno != 0)
				result = -1;
		}

		close(fd);
	} else {
		int cap = 0;

		/* Try to get it manually by trying to get the status of each
		 * capability individually from the kernel.
		 */
		while (prctl(PR_CAPBSET_READ, prctl_arg(cap)) >= 0)
			cap++;

		result = cap - 1;
	}

	return result;
}

int lxc_caps_last_cap(void)
{
	static long int last_cap = -1;

	if (last_cap < 0) {
		last_cap = _real_caps_last_cap();
		if (last_cap < 0 || last_cap > INT_MAX)
			last_cap = -1;
	}

	return last_cap;
}

static bool lxc_cap_is_set(cap_t caps, cap_value_t cap, cap_flag_t flag)
{
	int ret;
	cap_flag_value_t flagval;

	ret = cap_get_flag(caps, cap, flag, &flagval);
	if (ret < 0) {
		SYSERROR("Failed to retrieve current setting for capability %d", cap);
		return false;
	}

	return flagval == CAP_SET;
}

bool lxc_file_cap_is_set(const char *path, cap_value_t cap, cap_flag_t flag)
{
#if LIBCAP_SUPPORTS_FILE_CAPABILITIES
	bool cap_is_set;
	cap_t caps;

	caps = cap_get_file(path);
	if (!caps) {
		/* This is undocumented in the manpage but the source code show
		 * that cap_get_file() may return NULL when successful for the
		 * case where it didn't detect any file capabilities. In this
		 * case errno will be set to ENODATA.
		 */
		if (errno != ENODATA)
			SYSERROR("Failed to retrieve capabilities for file %s", path);

		return false;
	}

	cap_is_set = lxc_cap_is_set(caps, cap, flag);
	cap_free(caps);
	return cap_is_set;
#else
	errno = ENODATA;
	return false;
#endif
}

bool lxc_proc_cap_is_set(cap_value_t cap, cap_flag_t flag)
{
	bool cap_is_set;
	cap_t caps;

	caps = cap_get_proc();
	if (!caps) {
		SYSERROR("Failed to retrieve capabilities");
		return false;
	}

	cap_is_set = lxc_cap_is_set(caps, cap, flag);
	cap_free(caps);
	return cap_is_set;
}
#endif

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

#define _GNU_SOURCE
#include "config.h"

#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/prctl.h>

#include "caps.h"
#include "log.h"

lxc_log_define(lxc_caps, lxc);

#if HAVE_LIBCAP

#ifndef PR_CAPBSET_READ
#define PR_CAPBSET_READ 23
#endif

/* Control the ambient capability set */
#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT 47
#endif

#ifndef PR_CAP_AMBIENT_IS_SET
#define PR_CAP_AMBIENT_IS_SET 1
#endif

#ifndef PR_CAP_AMBIENT_RAISE
#define PR_CAP_AMBIENT_RAISE 2
#endif

#ifndef PR_CAP_AMBIENT_LOWER
#define PR_CAP_AMBIENT_LOWER 3
#endif

#ifndef PR_CAP_AMBIENT_CLEAR_ALL
#define PR_CAP_AMBIENT_CLEAR_ALL 4
#endif

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
		ERROR("failed to cap_get_proc: %s", strerror(errno));
		return -1;
	}

	ret = cap_clear_flag(caps, CAP_EFFECTIVE);
	if (ret) {
		ERROR("failed to cap_clear_flag: %s", strerror(errno));
		goto out;
	}

	ret = cap_set_proc(caps);
	if (ret) {
		ERROR("failed to cap_set_proc: %s", strerror(errno));
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
		ERROR("failed to cap_get_proc: %s", strerror(errno));
		return -1;
	}

	for (cap = 0; cap <= CAP_LAST_CAP; cap++) {

		cap_flag_value_t flag;

		ret = cap_get_flag(caps, cap, CAP_PERMITTED, &flag);
		if (ret) {
			if (errno == EINVAL) {
				INFO("Last supported cap was %d", cap-1);
				break;
			} else {
				ERROR("failed to cap_get_flag: %s",
				      strerror(errno));
				goto out;
			}
		}

		ret = cap_set_flag(caps, CAP_EFFECTIVE, 1, &cap, flag);
		if (ret) {
			ERROR("failed to cap_set_flag: %s", strerror(errno));
			goto out;
		}
	}

	ret = cap_set_proc(caps);
	if (ret) {
		ERROR("failed to cap_set_proc: %s", strerror(errno));
		goto out;
	}

out:
	cap_free(caps);
	return 0;
}

int lxc_ambient_caps_up(void)
{
	int ret;
	cap_t caps;
	cap_value_t cap;
	int last_cap = CAP_LAST_CAP;
	char *cap_names = NULL;

	/* When we are run as root, we don't want to play with the capabilities. */
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
		ret = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0);
		if (ret < 0) {
			WARN("%s - Failed to raise ambient capability %d",
			     strerror(errno), cap);
			goto out;
		}
	}

	cap_names = cap_to_text(caps, NULL);
	if (!cap_names)
		goto out;

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

	/* When we are run as root, we don't want to play with the capabilities. */
	if (!getuid())
		return 0;

	ret = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);
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
			ERROR("failed to 'PR_SET_KEEPCAPS': %s",
			      strerror(errno));
			return -1;
		}

		if (setresgid(gid, gid, gid)) {
			ERROR("failed to change gid to '%d': %s", gid,
			      strerror(errno));
			return -1;
		}

		if (setresuid(uid, uid, uid)) {
			ERROR("failed to change uid to '%d': %s", uid,
			      strerror(errno));
			return -1;
		}

		if (lxc_caps_up()) {
			ERROR("failed to restore capabilities: %s",
			      strerror(errno));
			return -1;
		}
	}

	if (uid == euid)
		INFO("command is run as user '%d'", uid);

	return 0;
}

static int _real_caps_last_cap(void)
{
	int fd;
	int result = -1;

	/* try to get the maximum capability over the kernel
	* interface introduced in v3.2 */
	fd = open("/proc/sys/kernel/cap_last_cap", O_RDONLY);
	if (fd >= 0) {
		char buf[32];
		char *ptr;
		int n;

		if ((n = read(fd, buf, 31)) >= 0) {
			buf[n] = '\0';
			errno = 0;
			result = strtol(buf, &ptr, 10);
			if (!ptr || (*ptr != '\0' && *ptr != '\n') || errno != 0)
				result = -1;
		}

		close(fd);
	}

	/* try to get it manually by trying to get the status of
	* each capability indiviually from the kernel */
	if (result < 0) {
		int cap = 0;
		while (prctl(PR_CAPBSET_READ, cap) >= 0) cap++;
		result = cap - 1;
	}

	return result;
}

int lxc_caps_last_cap(void)
{
	static int last_cap = -1;
	if (last_cap < 0) last_cap = _real_caps_last_cap();

	return last_cap;
}

static bool lxc_cap_is_set(cap_t caps, cap_value_t cap, cap_flag_t flag)
{
	int ret;
	cap_flag_value_t flagval;

	ret = cap_get_flag(caps, cap, flag, &flagval);
	if (ret < 0) {
		ERROR("Failed to perform cap_get_flag(): %s.", strerror(errno));
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
			ERROR("Failed to perform cap_get_file(): %s.\n", strerror(errno));
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
		ERROR("Failed to perform cap_get_proc(): %s.\n", strerror(errno));
		return false;
	}

	cap_is_set = lxc_cap_is_set(caps, cap, flag);
	cap_free(caps);
	return cap_is_set;
}

#endif

/* SPDX-License-Identifier: LGPL-2.1+ */

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
#include "memory_utils.h"

lxc_log_define(caps, lxc);

#if HAVE_LIBCAP

define_cleanup_function(cap_t, cap_free);

int lxc_caps_down(void)
{
	call_cleaner(cap_free) cap_t caps = NULL;
	int ret = -1;

	/* When we are root, we don't want to play with capabilities. */
	if (!getuid())
		return 0;

	caps = cap_get_proc();
	if (!caps)
		return log_error_errno(ret, errno, "Failed to retrieve capabilities");

	ret = cap_clear_flag(caps, CAP_EFFECTIVE);
	if (ret)
		return log_error_errno(ret, errno, "Failed to clear effective capabilities");

	ret = cap_set_proc(caps);
	if (ret)
		return log_error_errno(ret, errno, "Failed to change effective capabilities");

	return 0;
}

int lxc_caps_up(void)
{
	call_cleaner(cap_free) cap_t caps = NULL;
	cap_value_t cap;
	int ret = -1;

	/* When we are root, we don't want to play with capabilities. */
	if (!getuid())
		return 0;

	caps = cap_get_proc();
	if (!caps)
		return log_error_errno(ret, errno, "Failed to retrieve capabilities");

	for (cap = 0; cap <= CAP_LAST_CAP; cap++) {
		cap_flag_value_t flag;

		ret = cap_get_flag(caps, cap, CAP_PERMITTED, &flag);
		if (ret) {
			if (errno == EINVAL) {
				INFO("Last supported cap was %d", cap - 1);
				break;
			} else {
				return log_error_errno(ret, errno, "Failed to retrieve setting for permitted capability %d", cap - 1);
			}
		}

		ret = cap_set_flag(caps, CAP_EFFECTIVE, 1, &cap, flag);
		if (ret)
			return log_error_errno(ret, errno, "Failed to set effective capability %d", cap - 1);
	}

	ret = cap_set_proc(caps);
	if (ret)
		return log_error_errno(ret, errno, "Failed to change effective capabilities");

	return 0;
}

int lxc_ambient_caps_up(void)
{
	call_cleaner(cap_free) cap_t caps = NULL;
	__do_free char *cap_names = NULL;
	int ret;
	cap_value_t cap;
	int last_cap = CAP_LAST_CAP;

	if (!getuid() || geteuid())
		return 0;

	caps = cap_get_proc();
	if (!caps)
		return log_error_errno(-1, errno, "Failed to retrieve capabilities");

	for (cap = 0; cap <= CAP_LAST_CAP; cap++) {
		cap_flag_value_t flag;

		ret = cap_get_flag(caps, cap, CAP_PERMITTED, &flag);
		if (ret < 0) {
			if (errno == EINVAL) {
				last_cap = (cap - 1);
				INFO("Last supported cap was %d", last_cap);
				break;
			}

			return log_error_errno(ret, errno, "Failed to retrieve capability flag");
		}

		ret = cap_set_flag(caps, CAP_INHERITABLE, 1, &cap, flag);
		if (ret < 0)
			return log_error_errno(ret, errno, "Failed to set capability flag");
	}

	ret = cap_set_proc(caps);
	if (ret < 0)
		return log_error_errno(ret, errno, "Failed to set capabilities");

	for (cap = 0; cap <= last_cap; cap++) {
		ret = prctl(PR_CAP_AMBIENT, prctl_arg(PR_CAP_AMBIENT_RAISE),
			    prctl_arg(cap), prctl_arg(0), prctl_arg(0));
		if (ret < 0)
			return log_warn_errno(ret, errno, "Failed to raise ambient capability %d", cap);
	}

	cap_names = cap_to_text(caps, NULL);
	if (!cap_names)
		return log_warn_errno(0, errno, "Failed to convert capabilities %d", cap);

	TRACE("Raised %s in inheritable and ambient capability set", cap_names);
	return 0;
}

int lxc_ambient_caps_down(void)
{
	call_cleaner(cap_free) cap_t caps = NULL;
	int ret;
	cap_value_t cap;

	if (!getuid() || geteuid())
		return 0;

	ret = prctl(PR_CAP_AMBIENT, prctl_arg(PR_CAP_AMBIENT_CLEAR_ALL),
		    prctl_arg(0), prctl_arg(0), prctl_arg(0));
	if (ret < 0)
		return log_error_errno(-1, errno, "Failed to clear ambient capability set");

	caps = cap_get_proc();
	if (!caps)
		return log_error_errno(-1, errno, "Failed to retrieve capabilities");

	for (cap = 0; cap <= CAP_LAST_CAP; cap++) {
		ret = cap_set_flag(caps, CAP_INHERITABLE, 1, &cap, CAP_CLEAR);
		if (ret < 0)
			return log_error_errno(-1, errno, "Failed to clear capability");
	}

	ret = cap_set_proc(caps);
	if (ret < 0)
		return log_error_errno(ret, errno, "Failed to set capabilities");

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
		if (ret < 0)
			return log_error_errno(-1, errno, "Failed to set PR_SET_KEEPCAPS");

		gid = getgid();
		ret = setresgid(gid, gid, gid);
		if (ret < 0)
			return log_error_errno(-1, errno, "Failed to change rgid, egid, and sgid to %d", gid);

		ret = setresuid(uid, uid, uid);
		if (ret < 0)
			return log_error_errno(-1, errno, "Failed to change ruid, euid, and suid to %d", uid);

		ret = lxc_caps_up();
		if (ret < 0)
			return log_error_errno(-1, errno, "Failed to restore capabilities");
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
	if (ret < 0)
		return log_error_errno(false, errno, "Failed to retrieve current setting for capability %d", cap);

	return flagval == CAP_SET;
}

bool lxc_file_cap_is_set(const char *path, cap_value_t cap, cap_flag_t flag)
{
#if LIBCAP_SUPPORTS_FILE_CAPABILITIES
	call_cleaner(cap_free) cap_t caps = NULL;

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

	return lxc_cap_is_set(caps, cap, flag);
#else
	errno = ENODATA;
	return false;
#endif
}

bool lxc_proc_cap_is_set(cap_value_t cap, cap_flag_t flag)
{
	call_cleaner(cap_free) cap_t caps = NULL;

	caps = cap_get_proc();
	if (!caps)
		return log_error_errno(false, errno, "Failed to retrieve capabilities");

	return lxc_cap_is_set(caps, cap, flag);
}
#endif

/* liblxcapi
 *
 * Copyright © 2018 Christian Brauner <christian.brauner@ubuntu.com>.
 * Copyright © 2018 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define __STDC_FORMAT_MACROS /* Required for PRIu64 to work. */
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <linux/sched.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>

#if HAVE_SYS_PERSONALITY_H
#include <sys/personality.h>
#endif

#include <lxc/lxccontainer.h>

#include "tool_utils.h"

int lxc_fill_elevated_privileges(char *flaglist, int *flags)
{
	char *token, *saveptr = NULL;
	int i, aflag;
	struct {
		const char *token;
		int flag;
	} all_privs[] = {
		{ "CGROUP", LXC_ATTACH_MOVE_TO_CGROUP    },
		{ "CAP",    LXC_ATTACH_DROP_CAPABILITIES },
		{ "LSM",    LXC_ATTACH_LSM_EXEC          },
		{ NULL,     0                            }
	};

	if (!flaglist) {
		/* For the sake of backward compatibility, drop all privileges
		*  if none is specified.
		 */
		for (i = 0; all_privs[i].token; i++)
			*flags |= all_privs[i].flag;

		return 0;
	}

	token = strtok_r(flaglist, "|", &saveptr);
	while (token) {
		aflag = -1;
		for (i = 0; all_privs[i].token; i++)
			if (!strcmp(all_privs[i].token, token))
				aflag = all_privs[i].flag;
		if (aflag < 0)
			return -1;

		*flags |= aflag;

		token = strtok_r(NULL, "|", &saveptr);
	}

	return 0;
}

signed long lxc_config_parse_arch(const char *arch)
{
#if HAVE_SYS_PERSONALITY_H
	size_t i;
	struct per_name {
		char *name;
		unsigned long per;
	} pername[] = {
	    { "x86",       PER_LINUX32 },
	    { "linux32",   PER_LINUX32 },
	    { "i386",      PER_LINUX32 },
	    { "i486",      PER_LINUX32 },
	    { "i586",      PER_LINUX32 },
	    { "i686",      PER_LINUX32 },
	    { "athlon",    PER_LINUX32 },
	    { "mips",      PER_LINUX32 },
	    { "mipsel",    PER_LINUX32 },
	    { "ppc",       PER_LINUX32 },
	    { "arm",       PER_LINUX32 },
	    { "armv7l",    PER_LINUX32 },
	    { "armhf",     PER_LINUX32 },
	    { "armel",     PER_LINUX32 },
	    { "powerpc",   PER_LINUX32 },
	    { "linux64",   PER_LINUX   },
	    { "x86_64",    PER_LINUX   },
	    { "amd64",     PER_LINUX   },
	    { "mips64",    PER_LINUX   },
	    { "mips64el",  PER_LINUX   },
	    { "ppc64",     PER_LINUX   },
	    { "ppc64le",   PER_LINUX   },
	    { "ppc64el",   PER_LINUX   },
	    { "powerpc64", PER_LINUX   },
	    { "s390x",     PER_LINUX   },
	    { "aarch64",   PER_LINUX   },
	    { "arm64",     PER_LINUX   },
	};
	size_t len = sizeof(pername) / sizeof(pername[0]);

	for (i = 0; i < len; i++) {
		if (!strcmp(pername[i].name, arch))
			return pername[i].per;
	}
#endif

	return -1;
}

enum {
	LXC_NS_USER,
	LXC_NS_MNT,
	LXC_NS_PID,
	LXC_NS_UTS,
	LXC_NS_IPC,
	LXC_NS_NET,
	LXC_NS_CGROUP,
	LXC_NS_MAX
};

const static struct ns_info {
	const char *proc_name;
	int clone_flag;
} ns_info[LXC_NS_MAX]   = {
	[LXC_NS_USER]   = { "user",   CLONE_NEWUSER   },
	[LXC_NS_MNT]    = { "mnt",    CLONE_NEWNS     },
	[LXC_NS_PID]    = { "pid",    CLONE_NEWPID    },
	[LXC_NS_UTS]    = { "uts",    CLONE_NEWUTS    },
	[LXC_NS_IPC]    = { "ipc",    CLONE_NEWIPC    },
	[LXC_NS_NET]    = { "net",    CLONE_NEWNET    },
	[LXC_NS_CGROUP] = { "cgroup", CLONE_NEWCGROUP }
};

int lxc_namespace_2_cloneflag(const char *namespace)
{
	int i;
	for (i = 0; i < LXC_NS_MAX; i++)
		if (!strcasecmp(ns_info[i].proc_name, namespace))
			return ns_info[i].clone_flag;

	fprintf(stderr, "Invalid namespace name \"%s\"", namespace);
	return -EINVAL;
}

int lxc_fill_namespace_flags(char *flaglist, int *flags)
{
	char *token, *saveptr = NULL;
	int aflag;

	if (!flaglist) {
		fprintf(stderr, "At least one namespace is needed\n");
		return -1;
	}

	token = strtok_r(flaglist, "|", &saveptr);
	while (token) {

		aflag = lxc_namespace_2_cloneflag(token);
		if (aflag < 0)
			return -1;

		*flags |= aflag;

		token = strtok_r(NULL, "|", &saveptr);
	}

	return 0;
}

#if HAVE_LIBCAP

#ifndef PR_CAPBSET_READ
#define PR_CAPBSET_READ 23
#endif

int lxc_caps_init(void)
{
	uid_t uid = getuid();
	gid_t gid = getgid();
	uid_t euid = geteuid();

	if (!uid)
		return 0;

	if (uid && !euid) {
		if (prctl(PR_SET_KEEPCAPS, 1)) {
			fprintf(stderr, "%s - Failed to set PR_SET_KEEPCAPS\n", strerror(errno));
			return -1;
		}

		if (setresgid(gid, gid, gid)) {
			fprintf(stderr, "%s - Failed to change gid to %d\n", strerror(errno), gid);
			return -1;
		}

		if (setresuid(uid, uid, uid)) {
			fprintf(stderr, "%s - Failed to change uid to %d\n", strerror(errno), uid);
			return -1;
		}

		if (lxc_caps_up()) {
			fprintf(stderr, "%s - Failed to restore capabilities\n", strerror(errno));
			return -1;
		}
	}

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
		fprintf(stderr, "%s - Failed to cap_get_proc\n", strerror(errno));
		return -1;
	}

	for (cap = 0; cap <= CAP_LAST_CAP; cap++) {
		cap_flag_value_t flag;

		ret = cap_get_flag(caps, cap, CAP_PERMITTED, &flag);
		if (ret) {
			if (errno == EINVAL) {
				break;
			} else {
				fprintf(stderr, "%s- Failed to call cap_get_flag\n", strerror(errno));
				goto out;
			}
		}

		ret = cap_set_flag(caps, CAP_EFFECTIVE, 1, &cap, flag);
		if (ret) {
			fprintf(stderr, "%s - Failed to call cap_set_flag", strerror(errno));
			goto out;
		}
	}

	ret = cap_set_proc(caps);
	if (ret) {
		fprintf(stderr, "%s - Failed to cap_set_proc", strerror(errno));
		goto out;
	}

out:
	cap_free(caps);
	return 0;
}

#endif

int wait_for_pid(pid_t pid)
{
	int status, ret;

again:
	ret = waitpid(pid, &status, 0);
	if (ret == -1) {
		if (errno == EINTR)
			goto again;
		return -1;
	}
	if (ret != pid)
		goto again;
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return -1;
	return 0;
}

int lxc_wait_for_pid_status(pid_t pid)
{
	int status, ret;

again:
	ret = waitpid(pid, &status, 0);
	if (ret == -1) {
		if (errno == EINTR)
			goto again;
		return -1;
	}
	if (ret != pid)
		goto again;
	return status;
}

int lxc_safe_int(const char *numstr, int *converted)
{
	char *err = NULL;
	signed long int sli;

	errno = 0;
	sli = strtol(numstr, &err, 0);
	if (errno == ERANGE && (sli == LONG_MAX || sli == LONG_MIN))
		return -ERANGE;

	if (errno != 0 && sli == 0)
		return -EINVAL;

	if (err == numstr || *err != '\0')
		return -EINVAL;

	if (sli > INT_MAX || sli < INT_MIN)
		return -ERANGE;

	*converted = (int)sli;
	return 0;
}

int lxc_safe_long(const char *numstr, long int *converted)
{
	char *err = NULL;
	signed long int sli;

	errno = 0;
	sli = strtol(numstr, &err, 0);
	if (errno == ERANGE && (sli == LONG_MAX || sli == LONG_MIN))
		return -ERANGE;

	if (errno != 0 && sli == 0)
		return -EINVAL;

	if (err == numstr || *err != '\0')
		return -EINVAL;

	*converted = sli;
	return 0;
}

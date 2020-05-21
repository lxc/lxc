/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"
#include "log.h"
#include "macro.h"
#include "utils_no_static.h"

lxc_log_define(utils_no_static, lxc);

/* not thread-safe, do not use from api without first forking */
char *getgname(void)
{
	__do_free char *buf = NULL;
	struct group grent;
	struct group *grentp = NULL;
	size_t bufsize;
	int ret;

	bufsize = sysconf(_SC_GETGR_R_SIZE_MAX);
	if (bufsize == -1)
		bufsize = 1024;

	buf = malloc(bufsize);
	if (!buf)
		return NULL;

	ret = getgrgid_r(getegid(), &grent, buf, bufsize, &grentp);
	if (!grentp) {
		if (ret == 0)
			WARN("Could not find matched group record");

		return log_error(NULL, "Failed to get group record - %u", getegid());
	}

	return strdup(grent.gr_name);
}

/* not thread-safe, do not use from api without first forking */
char *getuname(void)
{
	__do_free char *buf = NULL;
	struct passwd pwent;
	struct passwd *pwentp = NULL;
	size_t bufsize;
	int ret;

	bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (bufsize == -1)
		bufsize = 1024;

	buf = malloc(bufsize);
	if (!buf)
		return NULL;

	ret = getpwuid_r(geteuid(), &pwent, buf, bufsize, &pwentp);
	if (!pwentp) {
		if (ret == 0)
			WARN("Could not find matched password record.");

		return log_error(NULL, "Failed to get password record - %u", geteuid());
	}

	return strdup(pwent.pw_name);
}

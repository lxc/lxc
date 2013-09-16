/*
 * lxc: linux Container library
 *
 * (C) Copyright Canonical, Inc. 2012
 *
 * Authors:
 * Serge Hallyn <serge.hallyn@canonical.com>
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
#include <stdio.h>
#include <stdlib.h>
#include <seccomp.h>
#include <errno.h>
#include <seccomp.h>
#include "config.h"
#include "lxcseccomp.h"
#include "lxclock.h"

#include "log.h"

lxc_log_define(lxc_seccomp, lxc);

/*
 * The first line of the config file has a policy language version
 * the second line has some directives
 * then comes policy subject to the directives
 * right now version must be '1'
 * the directives must include 'whitelist' (only type of policy currently
 * supported) and can include 'debug' (though debug is not yet supported).
 */
static int parse_config(FILE *f, struct lxc_conf *conf)
{
	char line[1024];
	int ret, version;

	ret = fscanf(f, "%d\n", &version);
	if (ret != 1 || version != 1) {
		ERROR("invalid version");
		return -1;
	}
	if (!fgets(line, 1024, f)) {
		ERROR("invalid config file");
		return -1;
	}
	if (!strstr(line, "whitelist")) {
		ERROR("only whitelist policy is supported");
		return -1;
	}
	if (strstr(line, "debug")) {
		ERROR("debug not yet implemented");
		return -1;
	}
	/* now read in the whitelist entries one per line */
	while (fgets(line, 1024, f)) {
		int nr;
		ret = sscanf(line, "%d", &nr);
		if (ret != 1)
			return -1;
		ret = seccomp_rule_add(
#if HAVE_SCMP_FILTER_CTX
			conf->seccomp_ctx,
#endif
			SCMP_ACT_ALLOW, nr, 0);
		if (ret < 0) {
			ERROR("failed loading allow rule for %d\n", nr);
			return ret;
		}
	}
	return 0;
}

int lxc_read_seccomp_config(struct lxc_conf *conf)
{
	FILE *f;
	int ret;

	if (!conf->seccomp)
		return 0;

#if HAVE_SCMP_FILTER_CTX
	/* XXX for debug, pass in SCMP_ACT_TRAP */
	conf->seccomp_ctx = seccomp_init(SCMP_ACT_ERRNO(31));
	ret = !conf->seccomp_ctx;
#else
	ret = seccomp_init(SCMP_ACT_ERRNO(31)) < 0;
#endif
	if (ret) {
		ERROR("failed initializing seccomp");
		return -1;
	}

	/* turn of no-new-privs.  We don't want it in lxc, and it breaks
	 * with apparmor */
	if (seccomp_attr_set(
#if HAVE_SCMP_FILTER_CTX
			conf->seccomp_ctx,
#endif
			SCMP_FLTATR_CTL_NNP, 0)) {
		ERROR("failed to turn off n-new-privs\n");
		return -1;
	}

	process_lock();
	f = fopen(conf->seccomp, "r");
	process_unlock();
	if (!f) {
		SYSERROR("failed to open seccomp policy file %s\n", conf->seccomp);
		return -1;
	}
	ret = parse_config(f, conf);
	process_lock();
	fclose(f);
	process_unlock();
	return ret;
}

int lxc_seccomp_load(struct lxc_conf *conf)
{
	int ret;
	if (!conf->seccomp)
		return 0;
	ret = seccomp_load(
#if HAVE_SCMP_FILTER_CTX
			conf->seccomp_ctx
#endif
	);
	if (ret < 0) {
		ERROR("Error loading the seccomp policy");
		return -1;
	}
	return 0;
}

void lxc_seccomp_free(struct lxc_conf *conf) {
	if (conf->seccomp) {
		free(conf->seccomp);
		conf->seccomp = NULL;
	}
#if HAVE_SCMP_FILTER_CTX
	if (conf->seccomp_ctx) {
		seccomp_release(conf->seccomp_ctx);
		conf->seccomp_ctx = NULL;
	}
#endif
}

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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <seccomp.h>
#include <errno.h>
#include <seccomp.h>
#include "lxcseccomp.h"

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
		ret = seccomp_rule_add(SCMP_ACT_ALLOW, nr, 0);
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

	if (seccomp_init(SCMP_ACT_ERRNO(31)) < 0)  { /* for debug, pass in SCMP_ACT_TRAP */
		ERROR("failed initializing seccomp");
		return -1;
	}
	if (!conf->seccomp)
		return 0;

	/* turn of no-new-privs.  We don't want it in lxc, and it breaks
	 * with apparmor */
	if (seccomp_attr_set(SCMP_FLTATR_CTL_NNP, 0)) {
		ERROR("failed to turn off n-new-privs\n");
		return -1;
	}

	f = fopen(conf->seccomp, "r");
	if (!f) {
		SYSERROR("failed to open seccomp policy file %s\n", conf->seccomp);
		return -1;
	}
	ret = parse_config(f, conf);
	fclose(f);
	return ret;
}

int lxc_seccomp_load(struct lxc_conf *conf)
{
	int ret;
	if (!conf->seccomp)
		return 0;
	ret = seccomp_load();
	if (ret < 0) {
		ERROR("Error loading the seccomp policy");
		return -1;
	}
	return 0;
}

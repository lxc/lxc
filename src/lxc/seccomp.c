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
#include "log.h"

lxc_log_define(lxc_seccomp, lxc);

static int parse_config_v1(FILE *f, struct lxc_conf *conf)
{
	char line[1024];
	int ret;

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
			ERROR("failed loading allow rule for %d", nr);
			return ret;
		}
	}
	return 0;
}

#if HAVE_DECL_SECCOMP_SYSCALL_RESOLVE_NAME_ARCH
static void remove_trailing_newlines(char *l)
{
	char *p = l;

	while (*p)
		p++;
	while (--p >= l && *p == '\n')
		*p = '\0';
}

static uint32_t get_v2_default_action(char *line)
{
	uint32_t ret_action = -1;

	while (*line == ' ') line++;
	// after 'whitelist' or 'blacklist' comes default behavior
	if (strncmp(line, "kill", 4) == 0)
		ret_action = SCMP_ACT_KILL;
	else if (strncmp(line, "errno", 5) == 0) {
		int e;
		if (sscanf(line+5, "%d", &e) != 1) {
			ERROR("Bad errno value in %s", line);
			return -2;
		}
		ret_action = SCMP_ACT_ERRNO(e);
	} else if (strncmp(line, "allow", 5) == 0)
		ret_action = SCMP_ACT_ALLOW;
	else if (strncmp(line, "trap", 4) == 0)
		ret_action = SCMP_ACT_TRAP;
	return ret_action;
}

static uint32_t get_and_clear_v2_action(char *line, uint32_t def_action)
{
	char *p = strchr(line, ' ');
	uint32_t ret;

	if (!p)
		return def_action;
	*p = '\0';
	p++;
	while (*p == ' ')
		p++;
	if (!*p || *p == '#')
		return def_action;
	ret = get_v2_default_action(p);
	switch(ret) {
	case -2: return -1;
	case -1: return def_action;
	default: return ret;
	}
}
#endif

/*
 * v2 consists of
 * [x86]
 * open
 * read
 * write
 * close
 * # a comment
 * [x86_64]
 * open
 * read
 * write
 * close
 */
static int parse_config_v2(FILE *f, char *line, struct lxc_conf *conf)
{
#if HAVE_DECL_SECCOMP_SYSCALL_RESOLVE_NAME_ARCH
	char *p;
	int ret;
	scmp_filter_ctx *ctx = NULL;
	bool blacklist = false;
	uint32_t default_policy_action = -1, default_rule_action = -1, action;
	uint32_t arch = SCMP_ARCH_NATIVE;

	if (strncmp(line, "blacklist", 9) == 0)
		blacklist = true;
	else if (strncmp(line, "whitelist", 9) != 0) {
		ERROR("Bad seccomp policy style: %s", line);
		return -1;
	}

	if ((p = strchr(line, ' '))) {
		default_policy_action = get_v2_default_action(p+1);
		if (default_policy_action == -2)
			return -1;
	}

	/* for blacklist, allow any syscall which has no rule */
	if (blacklist) {
		if (default_policy_action == -1)
			default_policy_action = SCMP_ACT_ALLOW;
		if (default_rule_action == -1)
			default_rule_action = SCMP_ACT_KILL;
	} else {
		if (default_policy_action == -1)
			default_policy_action = SCMP_ACT_KILL;
		if (default_rule_action == -1)
			default_rule_action = SCMP_ACT_ALLOW;
	}

	if (default_policy_action != SCMP_ACT_KILL) {
		ret = seccomp_reset(conf->seccomp_ctx, default_policy_action);
		if (ret != 0) {
			ERROR("Error re-initializing seccomp");
			return -1;
		}
		if (seccomp_attr_set(conf->seccomp_ctx, SCMP_FLTATR_CTL_NNP, 0)) {
			ERROR("failed to turn off n-new-privs");
			return -1;
		}
	}

	while (fgets(line, 1024, f)) {
		int nr;

		if (line[0] == '#')
			continue;
		if (strlen(line) == 0)
			continue;
		remove_trailing_newlines(line);
		INFO("processing: .%s.", line);
		if (line[0] == '[') {
			// read the architecture for next set of rules
			if (strcmp(line, "[x86]") == 0 ||
					strcmp(line, "[X86]") == 0)
				arch = SCMP_ARCH_X86;
			else if (strcmp(line, "[X86_64]") == 0 ||
					strcmp(line, "[x86_64]") == 0)
				arch = SCMP_ARCH_X86_64;
#ifdef SCMP_ARCH_ARM
			else if (strcmp(line, "[arm]") == 0 ||
					strcmp(line, "[ARM]") == 0)
				arch = SCMP_ARCH_ARM;
#endif
			else
				goto bad_arch;
			if (ctx) {
				ERROR("Only two arch sections per policy supported");
				goto bad_arch;
			}
			if ((ctx = seccomp_init(default_policy_action)) == NULL) {
				ERROR("Error initializing seccomp context");
				return -1;
			}
			if (seccomp_attr_set(ctx, SCMP_FLTATR_CTL_NNP, 0)) {
				ERROR("failed to turn off n-new-privs");
				seccomp_release(ctx);
				return -1;
			}
			ret = seccomp_arch_add(ctx, arch);
			if (ret == -EEXIST) {
				seccomp_release(ctx);
				ctx = NULL;
				continue;
			}
			if (ret != 0) {
				ERROR("Error %d adding arch: %s", ret, line);
				goto bad_arch;
			}
			if (seccomp_arch_remove(ctx, SCMP_ARCH_NATIVE) != 0) {
				ERROR("Error removing native arch from %s", line);
				goto bad_arch;
			}
			continue;
		}

		action = get_and_clear_v2_action(line, default_rule_action);
		if (action == -1) {
			ERROR("Failed to interpret action");
			goto bad_rule;
		}
		nr = seccomp_syscall_resolve_name_arch(arch, line);
		if (nr < 0) {
			ERROR("Failed to resolve syscall: %s", line);
			goto bad_rule;
		}
		ret = seccomp_rule_add(ctx ? ctx : conf->seccomp_ctx,
				action, nr, 0);
		if (ret < 0) {
			ERROR("failed (%d) loading rule for %s", ret, line);
			goto bad_rule;
		}
	}
	if (ctx) {
		if (seccomp_merge(conf->seccomp_ctx, ctx) != 0) {
			seccomp_release(ctx);
			ERROR("Error merging seccomp contexts");
			return -1;
		}
	}
	return 0;

bad_arch:
	ERROR("Unsupported arch: %s", line);
bad_rule:
	if (ctx)
		seccomp_release(ctx);
	return -1;
#else
	return -1;
#endif
}

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
	if (ret != 1 || (version != 1 && version != 2)) {
		ERROR("invalid version");
		return -1;
	}
	if (!fgets(line, 1024, f)) {
		ERROR("invalid config file");
		return -1;
	}
	if (version == 1 && !strstr(line, "whitelist")) {
		ERROR("only whitelist policy is supported");
		return -1;
	}

	if (strstr(line, "debug")) {
		ERROR("debug not yet implemented");
		return -1;
	}

	if (version == 1)
		return parse_config_v1(f, conf);
	return parse_config_v2(f, line, conf);
}

int lxc_read_seccomp_config(struct lxc_conf *conf)
{
	FILE *f;
	int ret;

	if (!conf->seccomp)
		return 0;

#if HAVE_SCMP_FILTER_CTX
	/* XXX for debug, pass in SCMP_ACT_TRAP */
	conf->seccomp_ctx = seccomp_init(SCMP_ACT_KILL);
	ret = !conf->seccomp_ctx;
#else
	ret = seccomp_init(SCMP_ACT_KILL) < 0;
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
		ERROR("failed to turn off n-new-privs");
		return -1;
	}

	f = fopen(conf->seccomp, "r");
	if (!f) {
		SYSERROR("failed to open seccomp policy file %s", conf->seccomp);
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

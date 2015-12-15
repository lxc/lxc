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
#include <sys/utsname.h>
#include <sys/mount.h>

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

#if HAVE_DECL_SECCOMP_SYSCALL_RESOLVE_NAME_ARCH
enum lxc_hostarch_t {
	lxc_seccomp_arch_all = 0,
	lxc_seccomp_arch_native,
	lxc_seccomp_arch_i386,
	lxc_seccomp_arch_amd64,
	lxc_seccomp_arch_arm,
	lxc_seccomp_arch_arm64,
	lxc_seccomp_arch_ppc64,
	lxc_seccomp_arch_ppc64le,
	lxc_seccomp_arch_ppc,
	lxc_seccomp_arch_unknown = 999,
};

int get_hostarch(void)
{
	struct utsname uts;
	if (uname(&uts) < 0) {
		SYSERROR("Failed to read host arch");
		return -1;
	}
	if (strcmp(uts.machine, "i686") == 0)
		return lxc_seccomp_arch_i386;
	else if (strcmp(uts.machine, "x86_64") == 0)
		return lxc_seccomp_arch_amd64;
	else if (strncmp(uts.machine, "armv7", 5) == 0)
		return lxc_seccomp_arch_arm;
	else if (strncmp(uts.machine, "aarch64", 7) == 0)
		return lxc_seccomp_arch_arm64;
	else if (strncmp(uts.machine, "ppc64le", 7) == 0)
		return lxc_seccomp_arch_ppc64le;
	else if (strncmp(uts.machine, "ppc64", 5) == 0)
		return lxc_seccomp_arch_ppc64;
	else if (strncmp(uts.machine, "ppc", 3) == 0)
		return lxc_seccomp_arch_ppc;
	return lxc_seccomp_arch_unknown;
}

scmp_filter_ctx get_new_ctx(enum lxc_hostarch_t n_arch, uint32_t default_policy_action)
{
	scmp_filter_ctx ctx;
	int ret;
	uint32_t arch;

	switch(n_arch) {
	case lxc_seccomp_arch_i386: arch = SCMP_ARCH_X86; break;
	case lxc_seccomp_arch_amd64: arch = SCMP_ARCH_X86_64; break;
	case lxc_seccomp_arch_arm: arch = SCMP_ARCH_ARM; break;
#ifdef SCMP_ARCH_AARCH64
	case lxc_seccomp_arch_arm64: arch = SCMP_ARCH_AARCH64; break;
#endif
#ifdef SCMP_ARCH_PPC64LE
	case lxc_seccomp_arch_ppc64le: arch = SCMP_ARCH_PPC64LE; break;
#endif
#ifdef SCMP_ARCH_PPC64
	case lxc_seccomp_arch_ppc64: arch = SCMP_ARCH_PPC64; break;
#endif
#ifdef SCMP_ARCH_PPC
	case lxc_seccomp_arch_ppc: arch = SCMP_ARCH_PPC; break;
#endif
	default: return NULL;
	}

	if ((ctx = seccomp_init(default_policy_action)) == NULL) {
		ERROR("Error initializing seccomp context");
		return NULL;
	}
	if (seccomp_attr_set(ctx, SCMP_FLTATR_CTL_NNP, 0)) {
		ERROR("failed to turn off n-new-privs");
		seccomp_release(ctx);
		return NULL;
	}
	ret = seccomp_arch_add(ctx, arch);
	if (ret != 0) {
		ERROR("Seccomp error %d (%s) adding arch: %d", ret,
				strerror(ret), (int)n_arch);
		seccomp_release(ctx);
		return NULL;
	}
	if (seccomp_arch_remove(ctx, SCMP_ARCH_NATIVE) != 0) {
		ERROR("Seccomp error removing native arch");
		seccomp_release(ctx);
		return NULL;
	}

	return ctx;
}

bool do_resolve_add_rule(uint32_t arch, char *line, scmp_filter_ctx ctx,
			uint32_t action)
{
	int nr, ret;

	if (arch && seccomp_arch_exist(ctx, arch) != 0) {
		ERROR("BUG: seccomp: rule and context arch do not match (arch %d)", arch);
		return false;
	}

	if (strncmp(line, "reject_force_umount", 19) == 0) {
		INFO("Setting seccomp rule to reject force umounts\n");
		ret = seccomp_rule_add_exact(ctx, SCMP_ACT_ERRNO(EACCES), SCMP_SYS(umount2),
				1, SCMP_A1(SCMP_CMP_MASKED_EQ , MNT_FORCE , MNT_FORCE ));
		if (ret < 0) {
			ERROR("failed (%d) loading rule to reject force umount", ret);
			return false;
		}
		return true;
	}

	nr = seccomp_syscall_resolve_name(line);
	if (nr == __NR_SCMP_ERROR) {
		WARN("Seccomp: failed to resolve syscall: %s", line);
		WARN("This syscall will NOT be blacklisted");
		return true;
	}
	if (nr < 0) {
		WARN("Seccomp: got negative # for syscall: %s", line);
		WARN("This syscall will NOT be blacklisted");
		return true;
	}
	ret = seccomp_rule_add_exact(ctx, action, nr, 0);
	if (ret < 0) {
		ERROR("failed (%d) loading rule for %s (nr %d action %d)", ret, line, nr, action);
		return false;
	}
	return true;
}

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
	char *p;
	int ret;
	scmp_filter_ctx compat_ctx = NULL;
	bool blacklist = false;
	uint32_t default_policy_action = -1, default_rule_action = -1, action;
	enum lxc_hostarch_t native_arch = get_hostarch(),
			    cur_rule_arch = native_arch;
	uint32_t compat_arch = SCMP_ARCH_NATIVE;

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

	if (native_arch == lxc_seccomp_arch_amd64) {
		cur_rule_arch = lxc_seccomp_arch_all;
		compat_arch = SCMP_ARCH_X86;
		compat_ctx = get_new_ctx(lxc_seccomp_arch_i386,
				default_policy_action);
		if (!compat_ctx)
			goto bad;
#ifdef SCMP_ARCH_PPC
	} else if (native_arch == lxc_seccomp_arch_ppc64) {
		cur_rule_arch = lxc_seccomp_arch_all;
		compat_arch = SCMP_ARCH_PPC;
		compat_ctx = get_new_ctx(lxc_seccomp_arch_ppc,
				default_policy_action);
		if (!compat_ctx)
			goto bad;
#endif
#ifdef SCMP_ARCH_ARM
	} else if (native_arch == lxc_seccomp_arch_arm64) {
		cur_rule_arch = lxc_seccomp_arch_all;
		compat_arch = SCMP_ARCH_ARM;
		compat_ctx = get_new_ctx(lxc_seccomp_arch_arm,
				default_policy_action);
		if (!compat_ctx)
			goto bad;
#endif
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

		if (line[0] == '#')
			continue;
		if (strlen(line) == 0)
			continue;
		remove_trailing_newlines(line);
		INFO("processing: .%s.", line);
		if (line[0] == '[') {
			// read the architecture for next set of rules
			if (strcmp(line, "[x86]") == 0 ||
					strcmp(line, "[X86]") == 0) {
				if (native_arch != lxc_seccomp_arch_i386 &&
						native_arch != lxc_seccomp_arch_amd64) {
					cur_rule_arch = lxc_seccomp_arch_unknown;
					continue;
				}
				cur_rule_arch = lxc_seccomp_arch_i386;
			} else if (strcmp(line, "[X86_64]") == 0 ||
					strcmp(line, "[x86_64]") == 0) {
				if (native_arch != lxc_seccomp_arch_amd64) {
					cur_rule_arch = lxc_seccomp_arch_unknown;
					continue;
				}
				cur_rule_arch = lxc_seccomp_arch_amd64;
			} else if (strcmp(line, "[all]") == 0 ||
					strcmp(line, "[ALL]") == 0) {
				cur_rule_arch = lxc_seccomp_arch_all;
			}
#ifdef SCMP_ARCH_ARM
			else if (strcmp(line, "[arm]") == 0 ||
					strcmp(line, "[ARM]") == 0) {
				if (native_arch != lxc_seccomp_arch_arm &&
						native_arch != lxc_seccomp_arch_arm64) {
					cur_rule_arch = lxc_seccomp_arch_unknown;
					continue;
				}
				cur_rule_arch = lxc_seccomp_arch_arm;
			}
#endif
#ifdef SCMP_ARCH_AARCH64
			else if (strcmp(line, "[arm64]") == 0 ||
					strcmp(line, "[ARM64]") == 0) {
				if (native_arch != lxc_seccomp_arch_arm64) {
					cur_rule_arch = lxc_seccomp_arch_unknown;
					continue;
				}
				cur_rule_arch = lxc_seccomp_arch_arm64;
			}
#endif
#ifdef SCMP_ARCH_PPC64LE
			else if (strcmp(line, "[ppc64le]") == 0 ||
					strcmp(line, "[PPC64LE]") == 0) {
				if (native_arch != lxc_seccomp_arch_ppc64le) {
					cur_rule_arch = lxc_seccomp_arch_unknown;
					continue;
				}
				cur_rule_arch = lxc_seccomp_arch_ppc64le;
			}
#endif
#ifdef SCMP_ARCH_PPC64
			else if (strcmp(line, "[ppc64]") == 0 ||
					strcmp(line, "[PPC64]") == 0) {
				if (native_arch != lxc_seccomp_arch_ppc64) {
					cur_rule_arch = lxc_seccomp_arch_unknown;
					continue;
				}
				cur_rule_arch = lxc_seccomp_arch_ppc64;
			}
#endif
#ifdef SCMP_ARCH_PPC
			else if (strcmp(line, "[ppc]") == 0 ||
					strcmp(line, "[PPC]") == 0) {
				if (native_arch != lxc_seccomp_arch_ppc &&
						native_arch != lxc_seccomp_arch_ppc64) {
					cur_rule_arch = lxc_seccomp_arch_unknown;
					continue;
				}
				cur_rule_arch = lxc_seccomp_arch_ppc;
			}
#endif
			else
				goto bad_arch;

			continue;
		}

		/* irrelevant arch - i.e. arm on i386 */
		if (cur_rule_arch == lxc_seccomp_arch_unknown)
			continue;

		/* read optional action which follows the syscall */
		action = get_and_clear_v2_action(line, default_rule_action);
		if (action == -1) {
			ERROR("Failed to interpret action");
			goto bad_rule;
		}

		if (cur_rule_arch == native_arch ||
		    cur_rule_arch == lxc_seccomp_arch_native ||
		    compat_arch == SCMP_ARCH_NATIVE) {
			INFO("Adding native rule for %s action %d", line, action);
			if (!do_resolve_add_rule(SCMP_ARCH_NATIVE, line, conf->seccomp_ctx, action))
				goto bad_rule;
		}
		else if (cur_rule_arch != lxc_seccomp_arch_all) {
			INFO("Adding compat-only rule for %s action %d", line, action);
			if (!do_resolve_add_rule(compat_arch, line, compat_ctx, action))
				goto bad_rule;
		}
		else {
			INFO("Adding native rule for %s action %d", line, action);
			if (!do_resolve_add_rule(SCMP_ARCH_NATIVE, line, conf->seccomp_ctx, action))
				goto bad_rule;
			INFO("Adding compat rule for %s action %d", line, action);
			if (!do_resolve_add_rule(compat_arch, line, compat_ctx, action))
				goto bad_rule;
		}
	}

	if (compat_ctx) {
		INFO("Merging in the compat seccomp ctx into the main one");
		if (seccomp_merge(conf->seccomp_ctx, compat_ctx) != 0) {
			ERROR("Error merging compat seccomp contexts");
			goto bad;
		}
	}

	return 0;

bad_arch:
	ERROR("Unsupported arch: %s", line);
bad_rule:
bad:
	if (compat_ctx)
		seccomp_release(compat_ctx);
	return -1;
}
#else /* HAVE_DECL_SECCOMP_SYSCALL_RESOLVE_NAME_ARCH */
static int parse_config_v2(FILE *f, char *line, struct lxc_conf *conf)
{
	return -1;
}
#endif /* HAVE_DECL_SECCOMP_SYSCALL_RESOLVE_NAME_ARCH */

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

/*
 * use_seccomp: return true if we should try and apply a seccomp policy
 * if defined for the container.
 * This will return false if
 *   1. seccomp is not enabled in the kernel
 *   2. a seccomp policy is already enabled for this task
 */
static bool use_seccomp(void)
{
	FILE *f = fopen("/proc/self/status", "r");
	char line[1024];
	bool already_enabled = false;
	bool found = false;
	int ret, v;

	if (!f)
		return true;

	while (fgets(line, 1024, f)) {
		if (strncmp(line, "Seccomp:", 8) == 0) {
			found = true;
			ret = sscanf(line+8, "%d", &v);
			if (ret == 1 && v != 0)
				already_enabled = true;
			break;
		}
	}

	fclose(f);
	if (!found) {  /* no Seccomp line, no seccomp in kernel */
		INFO("Seccomp is not enabled in the kernel");
		return false;
	}
	if (already_enabled) {  /* already seccomp-confined */
		INFO("Already seccomp-confined, not loading new policy");
		return false;
	}
	return true;
}

int lxc_read_seccomp_config(struct lxc_conf *conf)
{
	FILE *f;
	int ret;
	int check_seccomp_attr_set;

	if (!conf->seccomp)
		return 0;

	if (!use_seccomp())
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
#if HAVE_SCMP_FILTER_CTX
  check_seccomp_attr_set = seccomp_attr_set(conf->seccomp_ctx, SCMP_FLTATR_CTL_NNP, 0);
#else
  check_seccomp_attr_set = seccomp_attr_set(SCMP_FLTATR_CTL_NNP, 0);
#endif
	if (check_seccomp_attr_set) {
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
	if (!use_seccomp())
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
	free(conf->seccomp);
	conf->seccomp = NULL;
#if HAVE_SCMP_FILTER_CTX
	if (conf->seccomp_ctx) {
		seccomp_release(conf->seccomp_ctx);
		conf->seccomp_ctx = NULL;
	}
#endif
}

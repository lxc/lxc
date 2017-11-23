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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <seccomp.h>
#include <sys/mount.h>
#include <sys/utsname.h>

#include "config.h"
#include "log.h"
#include "lxcseccomp.h"

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
			ERROR("Failed loading allow rule for %d", nr);
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

	while (*line == ' ')
		line++;
	/* After 'whitelist' or 'blacklist' comes default behavior. */
	if (strncmp(line, "kill", 4) == 0)
		ret_action = SCMP_ACT_KILL;
	else if (strncmp(line, "errno", 5) == 0) {
		int e;
		if (sscanf(line + 5, "%d", &e) != 1) {
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

static const char *get_action_name(uint32_t action)
{
	/* The upper 16 bits indicate the type of the seccomp action. */
	switch(action & 0xffff0000){
	case SCMP_ACT_KILL:
		return "kill";
	case SCMP_ACT_ALLOW:
		return "allow";
	case SCMP_ACT_TRAP:
		return "trap";
	case SCMP_ACT_ERRNO(0):
		return "errno";
	default:
		return "invalid action";
	}
}

static uint32_t get_v2_action(char *line, uint32_t def_action)
{
	char *p = strchr(line, ' ');
	uint32_t ret;

	if (!p)
		return def_action;
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

struct v2_rule_args {
	uint32_t index;
	uint64_t value;
	uint64_t mask;
	enum scmp_compare op;
};

struct seccomp_v2_rule {
	uint32_t action;
	uint32_t args_num;
	struct v2_rule_args args_value[6];
};

static enum scmp_compare parse_v2_rule_op(char *s)
{
	enum scmp_compare ret;

	if (strcmp(s, "SCMP_CMP_NE") == 0 || strcmp(s, "!=") == 0)
		ret = SCMP_CMP_NE;
	else if (strcmp(s, "SCMP_CMP_LT") == 0 || strcmp(s, "<") == 0)
		ret = SCMP_CMP_LT;
	else if (strcmp(s, "SCMP_CMP_LE") == 0 || strcmp(s, "<=") == 0)
		ret = SCMP_CMP_LE;
	else if (strcmp(s, "SCMP_CMP_EQ") == 0 || strcmp(s, "==") == 0)
		ret = SCMP_CMP_EQ;
	else if (strcmp(s, "SCMP_CMP_GE") == 0 || strcmp(s, ">=") == 0)
		ret = SCMP_CMP_GE;
	else if (strcmp(s, "SCMP_CMP_GT") == 0 || strcmp(s, ">") == 0)
		ret = SCMP_CMP_GT;
	else if (strcmp(s, "SCMP_CMP_MASKED_EQ") == 0 || strcmp(s, "&=") == 0)
		ret = SCMP_CMP_MASKED_EQ;
	else
		ret = _SCMP_CMP_MAX;

	return ret;
}

/* This function is used to parse the args string into the structure.
 * args string format:[index,value,op,valueTwo] or [index,value,op]
 * For one arguments, [index,value,valueTwo,op]
 * index: the index for syscall arguments (type uint)
 * value: the value for syscall arguments (type uint64)
 * op: the operator for syscall arguments(string),
	 a valid list of constants as of libseccomp v2.3.2 is
	 SCMP_CMP_NE,SCMP_CMP_LE,SCMP_CMP_LE, SCMP_CMP_EQ, SCMP_CMP_GE,
	 SCMP_CMP_GT, SCMP_CMP_MASKED_EQ, or !=,<=,==,>=,>,&=
 * valueTwo: the value for syscall arguments only used for mask eq (type uint64, optional)
 * Returns 0 on success, < 0 otherwise.
 */
static int get_seccomp_arg_value(char *key, struct v2_rule_args *rule_args)
{
	int ret = 0;
	uint64_t value = 0;
	uint64_t mask = 0;
	enum scmp_compare op = 0;
	uint32_t index = 0;
	char s[30] = {0};
	char *tmp = NULL;

	memset(s, 0, sizeof(s));
	tmp = strchr(key, '[');
	if (!tmp) {
		ERROR("Failed to interpret args");
		return -1;
	}
	ret = sscanf(tmp, "[%i,%lli,%30[^0-9^,],%lli", &index, (long long unsigned int *)&value, s, (long long unsigned int *)&mask);
	if ((ret != 3 && ret != 4) || index >= 6) {
		ERROR("Failed to interpret args value");
		return -1;
	}

	op = parse_v2_rule_op(s);
	if (op == _SCMP_CMP_MAX) {
		ERROR("Failed to interpret args operator value");
		return -1;
	}

	rule_args->index = index;
	rule_args->value = value;
	rule_args->mask = mask;
	rule_args->op = op;
	return 0;
}

/* This function is used to parse the seccomp rule entry.
 * @line	: seccomp rule entry string.
 * @def_action	: default action used in the case if the 'line' contain non valid action.
 * @rules	: output struct.
 * Returns 0 on success, < 0 otherwise.
 */
static int parse_v2_rules(char *line, uint32_t def_action, struct seccomp_v2_rule *rules)
{
	int ret = 0 ;
	int i = 0;
	char *tmp = NULL;
	char *key = NULL;
	char *saveptr = NULL;

	tmp = strdup(line);
	if (!tmp)
		return -1;

	/* read optional action which follows the syscall */
	rules->action = get_v2_action(tmp, def_action);
	if (rules->action == -1) {
		ERROR("Failed to interpret action");
		ret = -1;
		goto out;
	}

	rules->args_num = 0;
	if (!strchr(tmp, '[')) {
		ret = 0;
		goto out;
	}

	for ((key = strtok_r(tmp, "]", &saveptr)), i = 0; key && i < 6; (key = strtok_r(NULL, "]", &saveptr)), i++) {
		ret = get_seccomp_arg_value(key, &rules->args_value[i]);
		if (ret < 0) {
			ret = -1;
			goto out;
		}
		rules->args_num++;
	}

	ret = 0;
out:
	free(tmp);
	return ret;
}

#endif

#if HAVE_DECL_SECCOMP_SYSCALL_RESOLVE_NAME_ARCH
enum lxc_hostarch_t {
	lxc_seccomp_arch_all = 0,
	lxc_seccomp_arch_native,
	lxc_seccomp_arch_i386,
	lxc_seccomp_arch_x32,
	lxc_seccomp_arch_amd64,
	lxc_seccomp_arch_arm,
	lxc_seccomp_arch_arm64,
	lxc_seccomp_arch_ppc64,
	lxc_seccomp_arch_ppc64le,
	lxc_seccomp_arch_ppc,
	lxc_seccomp_arch_mips,
	lxc_seccomp_arch_mips64,
	lxc_seccomp_arch_mips64n32,
	lxc_seccomp_arch_mipsel,
	lxc_seccomp_arch_mipsel64,
	lxc_seccomp_arch_mipsel64n32,
	lxc_seccomp_arch_s390x,
	lxc_seccomp_arch_unknown = 999,
};

#ifdef __MIPSEL__
# define MIPS_ARCH_O32 lxc_seccomp_arch_mipsel
# define MIPS_ARCH_N64 lxc_seccomp_arch_mipsel64
#else
# define MIPS_ARCH_O32 lxc_seccomp_arch_mips
# define MIPS_ARCH_N64 lxc_seccomp_arch_mips64
#endif

int get_hostarch(void)
{
	struct utsname uts;
	if (uname(&uts) < 0) {
		SYSERROR("Failed to read host arch");
		return -1;
	}
	if (strcmp(uts.machine, "i686") == 0)
		return lxc_seccomp_arch_i386;
	/* no x32 kernels */
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
	else if (strncmp(uts.machine, "mips64", 6) == 0)
		return MIPS_ARCH_N64;
	else if (strncmp(uts.machine, "mips", 4) == 0)
		return MIPS_ARCH_O32;
	else if (strncmp(uts.machine, "s390x", 5) == 0)
		return lxc_seccomp_arch_s390x;
	return lxc_seccomp_arch_unknown;
}

scmp_filter_ctx get_new_ctx(enum lxc_hostarch_t n_arch, uint32_t default_policy_action)
{
	scmp_filter_ctx ctx;
	int ret;
	uint32_t arch;

	switch(n_arch) {
	case lxc_seccomp_arch_i386: arch = SCMP_ARCH_X86; break;
	case lxc_seccomp_arch_x32: arch = SCMP_ARCH_X32; break;
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
#ifdef SCMP_ARCH_MIPS
	case lxc_seccomp_arch_mips: arch = SCMP_ARCH_MIPS; break;
	case lxc_seccomp_arch_mips64: arch = SCMP_ARCH_MIPS64; break;
	case lxc_seccomp_arch_mips64n32: arch = SCMP_ARCH_MIPS64N32; break;
	case lxc_seccomp_arch_mipsel: arch = SCMP_ARCH_MIPSEL; break;
	case lxc_seccomp_arch_mipsel64: arch = SCMP_ARCH_MIPSEL64; break;
	case lxc_seccomp_arch_mipsel64n32: arch = SCMP_ARCH_MIPSEL64N32; break;
#endif
#ifdef SCMP_ARCH_S390X
	case lxc_seccomp_arch_s390x: arch = SCMP_ARCH_S390X; break;
#endif
	default: return NULL;
	}

	if ((ctx = seccomp_init(default_policy_action)) == NULL) {
		ERROR("Error initializing seccomp context");
		return NULL;
	}
	if (seccomp_attr_set(ctx, SCMP_FLTATR_CTL_NNP, 0)) {
		ERROR("Failed to turn off no-new-privs");
		seccomp_release(ctx);
		return NULL;
	}
#ifdef SCMP_FLTATR_ATL_TSKIP
	if (seccomp_attr_set(ctx, SCMP_FLTATR_ATL_TSKIP, 1)) {
		WARN("Failed to turn on seccomp nop-skip, continuing");
	}
#endif
	ret = seccomp_arch_add(ctx, arch);
	if (ret != 0) {
		ERROR("Seccomp error %d (%s) adding arch: %d", ret,
		      strerror(-ret), (int)n_arch);
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
			struct seccomp_v2_rule *rule)
{
	int nr, ret, i;
	struct scmp_arg_cmp arg_cmp[6];

	memset(arg_cmp, 0 ,sizeof(arg_cmp));

	ret = seccomp_arch_exist(ctx, arch);
	if (arch && ret != 0) {
		ERROR("BUG: Seccomp: rule and context arch do not match (arch "
		      "%d): %s",
		      arch, strerror(-ret));
		return false;
	}

	/*get the syscall name*/
	char *p = strchr(line, ' ');
	if (p)
		*p = '\0';

	if (strncmp(line, "reject_force_umount", 19) == 0) {
		INFO("Setting Seccomp rule to reject force umounts");
		ret = seccomp_rule_add_exact(ctx, SCMP_ACT_ERRNO(EACCES), SCMP_SYS(umount2),
				1, SCMP_A1(SCMP_CMP_MASKED_EQ , MNT_FORCE , MNT_FORCE ));
		if (ret < 0) {
			ERROR("Failed (%d) loading rule to reject force "
			      "umount: %s",
			      ret, strerror(-ret));
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
		WARN("Seccomp: got negative for syscall: %d: %s", nr, line);
		WARN("This syscall will NOT be blacklisted");
		return true;
	}

	for (i = 0; i < rule->args_num; i++) {
		INFO("arg_cmp[%d]:SCMP_CMP(%u, %llu, %llu, %llu)", i,
		      rule->args_value[i].index,
		      (long long unsigned int)rule->args_value[i].op,
		      (long long unsigned int)rule->args_value[i].mask,
		      (long long unsigned int)rule->args_value[i].value);

		if (SCMP_CMP_MASKED_EQ == rule->args_value[i].op)
			arg_cmp[i] = SCMP_CMP(rule->args_value[i].index, rule->args_value[i].op, rule->args_value[i].mask, rule->args_value[i].value);
		else
			arg_cmp[i] = SCMP_CMP(rule->args_value[i].index, rule->args_value[i].op, rule->args_value[i].value);
	}

	ret = seccomp_rule_add_exact_array(ctx, rule->action, nr, rule->args_num, arg_cmp);
	if (ret < 0) {
		ERROR("Failed (%d) loading rule for %s (nr %d action %d(%s)): %s",
		      ret, line, nr, rule->action, get_action_name(rule->action), strerror(-ret));
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
	scmp_filter_ctx compat_ctx[2] = {NULL, NULL};
	bool blacklist = false;
	uint32_t default_policy_action = -1, default_rule_action = -1;
	enum lxc_hostarch_t native_arch = get_hostarch(),
			    cur_rule_arch = native_arch;
	uint32_t compat_arch[2] = {SCMP_ARCH_NATIVE, SCMP_ARCH_NATIVE};
	struct seccomp_v2_rule rule;

	if (strncmp(line, "blacklist", 9) == 0)
		blacklist = true;
	else if (strncmp(line, "whitelist", 9) != 0) {
		ERROR("Bad seccomp policy style: %s", line);
		return -1;
	}

	if ((p = strchr(line, ' '))) {
		default_policy_action = get_v2_default_action(p + 1);
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
		compat_arch[0] = SCMP_ARCH_X86;
		compat_ctx[0] = get_new_ctx(lxc_seccomp_arch_i386,
				default_policy_action);
		compat_arch[1] = SCMP_ARCH_X32;
		compat_ctx[1] = get_new_ctx(lxc_seccomp_arch_x32,
				default_policy_action);
		if (!compat_ctx[0] || !compat_ctx[1])
			goto bad;
#ifdef SCMP_ARCH_PPC
	} else if (native_arch == lxc_seccomp_arch_ppc64) {
		cur_rule_arch = lxc_seccomp_arch_all;
		compat_arch[0] = SCMP_ARCH_PPC;
		compat_ctx[0] = get_new_ctx(lxc_seccomp_arch_ppc,
				default_policy_action);
		if (!compat_ctx[0])
			goto bad;
#endif
#ifdef SCMP_ARCH_ARM
	} else if (native_arch == lxc_seccomp_arch_arm64) {
		cur_rule_arch = lxc_seccomp_arch_all;
		compat_arch[0] = SCMP_ARCH_ARM;
		compat_ctx[0] = get_new_ctx(lxc_seccomp_arch_arm,
				default_policy_action);
		if (!compat_ctx[0])
			goto bad;
#endif
#ifdef SCMP_ARCH_MIPS
	} else if (native_arch == lxc_seccomp_arch_mips64) {
		cur_rule_arch = lxc_seccomp_arch_all;
		compat_arch[0] = SCMP_ARCH_MIPS;
		compat_arch[1] = SCMP_ARCH_MIPS64N32;
		compat_ctx[0] = get_new_ctx(lxc_seccomp_arch_mips,
				default_policy_action);
		compat_ctx[1] = get_new_ctx(lxc_seccomp_arch_mips64n32,
				default_policy_action);
		if (!compat_ctx[0] || !compat_ctx[1])
			goto bad;
	} else if (native_arch == lxc_seccomp_arch_mipsel64) {
		cur_rule_arch = lxc_seccomp_arch_all;
		compat_arch[0] = SCMP_ARCH_MIPSEL;
		compat_arch[1] = SCMP_ARCH_MIPSEL64N32;
		compat_ctx[0] = get_new_ctx(lxc_seccomp_arch_mipsel,
				default_policy_action);
		compat_ctx[1] = get_new_ctx(lxc_seccomp_arch_mipsel64n32,
				default_policy_action);
		if (!compat_ctx[0] || !compat_ctx[1])
			goto bad;
#endif
	}

	if (default_policy_action != SCMP_ACT_KILL) {
		ret = seccomp_reset(conf->seccomp_ctx, default_policy_action);
		if (ret != 0) {
			ERROR("Error re-initializing Seccomp");
			return -1;
		}
		if (seccomp_attr_set(conf->seccomp_ctx, SCMP_FLTATR_CTL_NNP, 0)) {
			ERROR("Failed to turn off no-new-privs");
			return -1;
		}
#ifdef SCMP_FLTATR_ATL_TSKIP
		if (seccomp_attr_set(conf->seccomp_ctx, SCMP_FLTATR_ATL_TSKIP, 1)) {
			WARN("Failed to turn on seccomp nop-skip, continuing");
		}
#endif
	}

	while (fgets(line, 1024, f)) {

		if (line[0] == '#')
			continue;
		if (strlen(line) == 0)
			continue;
		remove_trailing_newlines(line);
		INFO("processing: .%s", line);
		if (line[0] == '[') {
			/* Read the architecture for next set of rules. */
			if (strcmp(line, "[x86]") == 0 ||
			    strcmp(line, "[X86]") == 0) {
				if (native_arch != lxc_seccomp_arch_i386 &&
						native_arch != lxc_seccomp_arch_amd64) {
					cur_rule_arch = lxc_seccomp_arch_unknown;
					continue;
				}
				cur_rule_arch = lxc_seccomp_arch_i386;
			} else if (strcmp(line, "[x32]") == 0 ||
				   strcmp(line, "[X32]") == 0) {
				if (native_arch != lxc_seccomp_arch_amd64) {
					cur_rule_arch = lxc_seccomp_arch_unknown;
					continue;
				}
				cur_rule_arch = lxc_seccomp_arch_x32;
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
#ifdef SCMP_ARCH_MIPS
			else if (strcmp(line, "[mips64]") == 0 ||
				 strcmp(line, "[MIPS64]") == 0) {
				if (native_arch != lxc_seccomp_arch_mips64) {
					cur_rule_arch = lxc_seccomp_arch_unknown;
					continue;
				}
				cur_rule_arch = lxc_seccomp_arch_mips64;
			} else if (strcmp(line, "[mips64n32]") == 0 ||
				   strcmp(line, "[MIPS64N32]") == 0) {
				if (native_arch != lxc_seccomp_arch_mips64) {
					cur_rule_arch = lxc_seccomp_arch_unknown;
					continue;
				}
				cur_rule_arch = lxc_seccomp_arch_mips64n32;
			} else if (strcmp(line, "[mips]") == 0 ||
				   strcmp(line, "[MIPS]") == 0) {
				if (native_arch != lxc_seccomp_arch_mips &&
						native_arch != lxc_seccomp_arch_mips64) {
					cur_rule_arch = lxc_seccomp_arch_unknown;
					continue;
				}
				cur_rule_arch = lxc_seccomp_arch_mips;
			} else if (strcmp(line, "[mipsel64]") == 0 ||
				   strcmp(line, "[MIPSEL64]") == 0) {
				if (native_arch != lxc_seccomp_arch_mipsel64) {
					cur_rule_arch = lxc_seccomp_arch_unknown;
					continue;
				}
				cur_rule_arch = lxc_seccomp_arch_mipsel64;
			} else if (strcmp(line, "[mipsel64n32]") == 0 ||
				   strcmp(line, "[MIPSEL64N32]") == 0) {
				if (native_arch != lxc_seccomp_arch_mipsel64) {
					cur_rule_arch = lxc_seccomp_arch_unknown;
					continue;
				}
				cur_rule_arch = lxc_seccomp_arch_mipsel64n32;
			} else if (strcmp(line, "[mipsel]") == 0 ||
				   strcmp(line, "[MIPSEL]") == 0) {
				if (native_arch != lxc_seccomp_arch_mipsel &&
						native_arch != lxc_seccomp_arch_mipsel64) {
					cur_rule_arch = lxc_seccomp_arch_unknown;
					continue;
				}
				cur_rule_arch = lxc_seccomp_arch_mipsel;
			}
#endif
#ifdef SCMP_ARCH_S390X
			else if (strcmp(line, "[s390x]") == 0 ||
				 strcmp(line, "[S390X]") == 0) {
				if (native_arch != lxc_seccomp_arch_s390x) {
					cur_rule_arch = lxc_seccomp_arch_unknown;
					continue;
				}
				cur_rule_arch = lxc_seccomp_arch_s390x;
			}
#endif
			else
				goto bad_arch;

			continue;
		}

		/* irrelevant arch - i.e. arm on i386 */
		if (cur_rule_arch == lxc_seccomp_arch_unknown)
			continue;

		memset(&rule, 0, sizeof(rule));
		/* read optional action which follows the syscall */
		ret = parse_v2_rules(line, default_rule_action, &rule);
		if (ret != 0) {
			ERROR("Failed to interpret seccomp rule");
			goto bad_rule;
		}

		if (cur_rule_arch == native_arch ||
		    cur_rule_arch == lxc_seccomp_arch_native ||
		    compat_arch[0] == SCMP_ARCH_NATIVE) {
			INFO("Adding native rule for %s action %d(%s)", line, rule.action,
			     get_action_name(rule.action));
			if (!do_resolve_add_rule(SCMP_ARCH_NATIVE, line, conf->seccomp_ctx, &rule))
				goto bad_rule;
		}
		else if (cur_rule_arch != lxc_seccomp_arch_all) {
			int arch_index =
				cur_rule_arch == lxc_seccomp_arch_mips64n32 ||
				cur_rule_arch == lxc_seccomp_arch_mipsel64n32 ? 1 : 0;

			INFO("Adding compat-only rule for %s action %d(%s)", line, rule.action,
			     get_action_name(rule.action));
			if (!do_resolve_add_rule(compat_arch[arch_index], line, compat_ctx[arch_index], &rule))
				goto bad_rule;
		}
		else {
			INFO("Adding native rule for %s action %d(%s)", line, rule.action,
			     get_action_name(rule.action));
			if (!do_resolve_add_rule(SCMP_ARCH_NATIVE, line, conf->seccomp_ctx, &rule))
				goto bad_rule;
			INFO("Adding compat rule for %s action %d(%s)", line, rule.action,
			     get_action_name(rule.action));
			if (!do_resolve_add_rule(compat_arch[0], line, compat_ctx[0], &rule))
				goto bad_rule;
			if (compat_arch[1] != SCMP_ARCH_NATIVE &&
				!do_resolve_add_rule(compat_arch[1], line, compat_ctx[1], &rule))
				goto bad_rule;
		}
	}

	if (compat_ctx[0]) {
		INFO("Merging in the compat Seccomp ctx into the main one");
		if (seccomp_merge(conf->seccomp_ctx, compat_ctx[0]) != 0 ||
			(compat_ctx[1] != NULL && seccomp_merge(conf->seccomp_ctx, compat_ctx[1]) != 0)) {
			ERROR("Error merging compat Seccomp contexts");
			goto bad;
		}
	}

	return 0;

bad_arch:
	ERROR("Unsupported arch: %s.", line);
bad_rule:
bad:
	if (compat_ctx[0])
		seccomp_release(compat_ctx[0]);
	if (compat_ctx[1])
		seccomp_release(compat_ctx[1]);
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
 * right now version must be '1' or '2'
 * the directives must include 'whitelist'(version == 1 or 2) or 'blacklist'
 * (version == 2) and can include 'debug' (though debug is not yet supported).
 */
static int parse_config(FILE *f, struct lxc_conf *conf)
{
	char line[1024];
	int ret, version;

	ret = fscanf(f, "%d\n", &version);
	if (ret != 1 || (version != 1 && version != 2)) {
		ERROR("Invalid version");
		return -1;
	}
	if (!fgets(line, 1024, f)) {
		ERROR("Invalid config file");
		return -1;
	}
	if (version == 1 && !strstr(line, "whitelist")) {
		ERROR("Only whitelist policy is supported");
		return -1;
	}

	if (strstr(line, "debug")) {
		ERROR("Debug not yet implemented");
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
			ret = sscanf(line + 8, "%d", &v);
			if (ret == 1 && v != 0)
				already_enabled = true;
			break;
		}
	}

	fclose(f);
	if (!found) { /* no Seccomp line, no seccomp in kernel */
		INFO("Seccomp is not enabled in the kernel");
		return false;
	}
	if (already_enabled) { /* already seccomp-confined */
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
		ERROR("Failed initializing seccomp");
		return -1;
	}

/* turn off no-new-privs.  We don't want it in lxc, and it breaks
 * with apparmor */
#if HAVE_SCMP_FILTER_CTX
	check_seccomp_attr_set = seccomp_attr_set(conf->seccomp_ctx, SCMP_FLTATR_CTL_NNP, 0);
#else
	check_seccomp_attr_set = seccomp_attr_set(SCMP_FLTATR_CTL_NNP, 0);
#endif
	if (check_seccomp_attr_set) {
		ERROR("Failed to turn off no-new-privs");
		return -1;
	}
#ifdef SCMP_FLTATR_ATL_TSKIP
	if (seccomp_attr_set(conf->seccomp_ctx, SCMP_FLTATR_ATL_TSKIP, 1)) {
		WARN("Failed to turn on seccomp nop-skip, continuing");
	}
#endif

	f = fopen(conf->seccomp, "r");
	if (!f) {
		SYSERROR("Failed to open seccomp policy file %s", conf->seccomp);
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
		ERROR("Error loading the seccomp policy: %s", strerror(-ret));
		return -1;
	}

/* After load seccomp filter into the kernel successfully, export the current seccomp
 * filter to log file */
#if HAVE_SCMP_FILTER_CTX
	if ((lxc_log_get_level() <= LXC_LOG_LEVEL_TRACE || conf->loglevel <= LXC_LOG_LEVEL_TRACE) &&
	    lxc_log_fd >= 0) {
		ret = seccomp_export_pfc(conf->seccomp_ctx, lxc_log_fd);
		/* Just give an warning when export error */
		if (ret < 0)
			WARN("Failed to export seccomp filter to log file: %s", strerror(-ret));
	}
#endif
	return 0;
}

void lxc_seccomp_free(struct lxc_conf *conf)
{
	free(conf->seccomp);
	conf->seccomp = NULL;
#if HAVE_SCMP_FILTER_CTX
	if (conf->seccomp_ctx) {
		seccomp_release(conf->seccomp_ctx);
		conf->seccomp_ctx = NULL;
	}
#endif
}

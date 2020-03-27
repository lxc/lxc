/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <errno.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/utsname.h>

#include "af_unix.h"
#include "commands.h"
#include "config.h"
#include "log.h"
#include "lxccontainer.h"
#include "lxcseccomp.h"
#include "mainloop.h"
#include "memory_utils.h"
#include "utils.h"

#ifdef __MIPSEL__
#define MIPS_ARCH_O32 lxc_seccomp_arch_mipsel
#define MIPS_ARCH_N64 lxc_seccomp_arch_mipsel64
#else
#define MIPS_ARCH_O32 lxc_seccomp_arch_mips
#define MIPS_ARCH_N64 lxc_seccomp_arch_mips64
#endif

#ifndef SECCOMP_GET_NOTIF_SIZES
#define SECCOMP_GET_NOTIF_SIZES 3
#endif

lxc_log_define(seccomp, lxc);

#if HAVE_DECL_SECCOMP_NOTIFY_FD
static inline int __seccomp(unsigned int operation, unsigned int flags,
			  void *args)
{
	return syscall(__NR_seccomp, operation, flags, args);
}
#endif

static int parse_config_v1(FILE *f, char *line, size_t *line_bufsz, struct lxc_conf *conf)
{
	int ret = 0;

	while (getline(&line, line_bufsz, f) != -1) {
		int nr;

		ret = sscanf(line, "%d", &nr);
		if (ret != 1) {
			ret = -1;
			break;
		}

#if HAVE_SCMP_FILTER_CTX
		ret = seccomp_rule_add(conf->seccomp.seccomp_ctx, SCMP_ACT_ALLOW, nr, 0);
#else
		ret = seccomp_rule_add(SCMP_ACT_ALLOW, nr, 0);
#endif
		if (ret < 0) {
			ERROR("Failed loading allow rule for %d", nr);
			break;
		}
	}
	free(line);

	return ret;
}

#if HAVE_DECL_SECCOMP_SYSCALL_RESOLVE_NAME_ARCH
static const char *get_action_name(uint32_t action)
{
	/* The upper 16 bits indicate the type of the seccomp action. */
	switch (action & 0xffff0000) {
	case SCMP_ACT_KILL:
		return "kill";
	case SCMP_ACT_ALLOW:
		return "allow";
	case SCMP_ACT_TRAP:
		return "trap";
	case SCMP_ACT_ERRNO(0):
		return "errno";
#if HAVE_DECL_SECCOMP_NOTIFY_FD
	case SCMP_ACT_NOTIFY:
		return "notify";
#endif
	}

	return "invalid action";
}

static uint32_t get_v2_default_action(char *line)
{
	uint32_t ret_action = -1;

	while (*line == ' ')
		line++;

	/* After 'whitelist' or 'blacklist' comes default behavior. */
	if (strncmp(line, "kill", 4) == 0) {
		ret_action = SCMP_ACT_KILL;
	} else if (strncmp(line, "errno", 5) == 0) {
		int e, ret;

		ret = sscanf(line + 5, "%d", &e);
		if (ret != 1) {
			ERROR("Failed to parse errno value from %s", line);
			return -2;
		}

		ret_action = SCMP_ACT_ERRNO(e);
	} else if (strncmp(line, "allow", 5) == 0) {
		ret_action = SCMP_ACT_ALLOW;
	} else if (strncmp(line, "trap", 4) == 0) {
		ret_action = SCMP_ACT_TRAP;
#if HAVE_DECL_SECCOMP_NOTIFY_FD
	} else if (strncmp(line, "notify", 6) == 0) {
		ret_action = SCMP_ACT_NOTIFY;
#endif
	} else if (line[0]) {
		ERROR("Unrecognized seccomp action \"%s\"", line);
		return -2;
	}

	return ret_action;
}

static uint32_t get_v2_action(char *line, uint32_t def_action)
{
	char *p;
	uint32_t ret;

	p = strchr(line, ' ');
	if (!p)
		return def_action;
	p++;

	while (*p == ' ')
		p++;

	if (!*p || *p == '#')
		return def_action;

	ret = get_v2_default_action(p);
	switch (ret) {
	case -2:
		return -1;
	case -1:
		return def_action;
	}

	return ret;
}

struct seccomp_v2_rule_args {
	uint32_t index;
	uint64_t value;
	uint64_t mask;
	enum scmp_compare op;
};

struct seccomp_v2_rule {
	uint32_t action;
	uint32_t args_num;
	struct seccomp_v2_rule_args args_value[6];
};

static enum scmp_compare parse_v2_rule_op(char *s)
{
	if (strcmp(s, "SCMP_CMP_NE") == 0 || strcmp(s, "!=") == 0)
		return SCMP_CMP_NE;
	else if (strcmp(s, "SCMP_CMP_LT") == 0 || strcmp(s, "<") == 0)
		return SCMP_CMP_LT;
	else if (strcmp(s, "SCMP_CMP_LE") == 0 || strcmp(s, "<=") == 0)
		return SCMP_CMP_LE;
	else if (strcmp(s, "SCMP_CMP_EQ") == 0 || strcmp(s, "==") == 0)
		return SCMP_CMP_EQ;
	else if (strcmp(s, "SCMP_CMP_GE") == 0 || strcmp(s, ">=") == 0)
		return SCMP_CMP_GE;
	else if (strcmp(s, "SCMP_CMP_GT") == 0 || strcmp(s, ">") == 0)
		return SCMP_CMP_GT;
	else if (strcmp(s, "SCMP_CMP_MASKED_EQ") == 0 || strcmp(s, "&=") == 0)
		return SCMP_CMP_MASKED_EQ;

	return _SCMP_CMP_MAX;
}

/*
 * This function is used to parse the args string into the structure.
 * args string format:[index,value,op,mask] or [index,value,op]
 * index: the index for syscall arguments (type uint)
 * value: the value for syscall arguments (type uint64)
 * op: the operator for syscall arguments(string),
	 a valid list of constants as of libseccomp v2.3.2 is
	 SCMP_CMP_NE,SCMP_CMP_LE,SCMP_CMP_LE, SCMP_CMP_EQ, SCMP_CMP_GE,
	 SCMP_CMP_GT, SCMP_CMP_MASKED_EQ, or !=,<=,==,>=,>,&=
 * mask: the mask to apply on "value" for SCMP_CMP_MASKED_EQ (type uint64, optional)
 * Returns 0 on success, < 0 otherwise.
 */
static int get_seccomp_arg_value(char *key, struct seccomp_v2_rule_args *rule_args)
{
	int ret = 0;
	uint32_t index = 0;
	uint64_t mask = 0, value = 0;
	enum scmp_compare op = 0;
	char *tmp = NULL;
	char s[31] = {0}, v[24] = {0}, m[24] = {'0'};

	tmp = strchr(key, '[');
	if (!tmp) {
		ERROR("Failed to interpret args");
		return -1;
	}

	ret = sscanf(tmp, "[%i,%23[^,],%30[^0-9^,],%23[^,]", &index, v, s, m);
	if ((ret != 3 && ret != 4) || index >= 6) {
		ERROR("Failed to interpret args value");
		return -1;
	}

	ret = lxc_safe_uint64(v, &value, 0);
	if (ret < 0) {
		ERROR("Invalid argument value");
		return -1;
	}

	ret = lxc_safe_uint64(m, &mask, 0);
	if (ret < 0) {
		ERROR("Invalid argument mask");
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
static int parse_v2_rules(char *line, uint32_t def_action,
			  struct seccomp_v2_rule *rules)
{
	int i = 0, ret = -1;
	char *key = NULL, *saveptr = NULL, *tmp = NULL;

	tmp = strdup(line);
	if (!tmp)
		return -1;

	/* read optional action which follows the syscall */
	rules->action = get_v2_action(tmp, def_action);
	if (rules->action == -1) {
		ERROR("Failed to interpret action");
		ret = -1;
		goto on_error;
	}

	ret = 0;
	rules->args_num = 0;
	if (!strchr(tmp, '['))
		goto on_error;

	ret = -1;
	for ((key = strtok_r(tmp, "]", &saveptr)), i = 0; key && i < 6;
	     (key = strtok_r(NULL, "]", &saveptr)), i++) {
		ret = get_seccomp_arg_value(key, &rules->args_value[i]);
		if (ret < 0)
			goto on_error;

		rules->args_num++;
	}

	ret = 0;

on_error:
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
	lxc_seccomp_arch_s390,
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
	else if (strncmp(uts.machine, "s390", 4) == 0)
		return lxc_seccomp_arch_s390;
	return lxc_seccomp_arch_unknown;
}

scmp_filter_ctx get_new_ctx(enum lxc_hostarch_t n_arch,
			    uint32_t default_policy_action, bool *needs_merge)
{
	int ret;
	uint32_t arch;
	scmp_filter_ctx ctx;

	switch (n_arch) {
	case lxc_seccomp_arch_i386:
		arch = SCMP_ARCH_X86;
		break;
	case lxc_seccomp_arch_x32:
		arch = SCMP_ARCH_X32;
		break;
	case lxc_seccomp_arch_amd64:
		arch = SCMP_ARCH_X86_64;
		break;
	case lxc_seccomp_arch_arm:
		arch = SCMP_ARCH_ARM;
		break;
#ifdef SCMP_ARCH_AARCH64
	case lxc_seccomp_arch_arm64:
		arch = SCMP_ARCH_AARCH64;
		break;
#endif
#ifdef SCMP_ARCH_PPC64LE
	case lxc_seccomp_arch_ppc64le:
		arch = SCMP_ARCH_PPC64LE;
		break;
#endif
#ifdef SCMP_ARCH_PPC64
	case lxc_seccomp_arch_ppc64:
		arch = SCMP_ARCH_PPC64;
		break;
#endif
#ifdef SCMP_ARCH_PPC
	case lxc_seccomp_arch_ppc:
		arch = SCMP_ARCH_PPC;
		break;
#endif
#ifdef SCMP_ARCH_MIPS
	case lxc_seccomp_arch_mips:
		arch = SCMP_ARCH_MIPS;
		break;
	case lxc_seccomp_arch_mips64:
		arch = SCMP_ARCH_MIPS64;
		break;
	case lxc_seccomp_arch_mips64n32:
		arch = SCMP_ARCH_MIPS64N32;
		break;
	case lxc_seccomp_arch_mipsel:
		arch = SCMP_ARCH_MIPSEL;
		break;
	case lxc_seccomp_arch_mipsel64:
		arch = SCMP_ARCH_MIPSEL64;
		break;
	case lxc_seccomp_arch_mipsel64n32:
		arch = SCMP_ARCH_MIPSEL64N32;
		break;
#endif
#ifdef SCMP_ARCH_S390X
	case lxc_seccomp_arch_s390x:
		arch = SCMP_ARCH_S390X;
		break;
#endif
#ifdef SCMP_ARCH_S390
	case lxc_seccomp_arch_s390:
		arch = SCMP_ARCH_S390;
		break;
#endif
	default:
		return NULL;
	}

	ctx = seccomp_init(default_policy_action);
	if (!ctx) {
		ERROR("Error initializing seccomp context");
		return NULL;
	}

	ret = seccomp_attr_set(ctx, SCMP_FLTATR_CTL_NNP, 0);
	if (ret < 0) {
		errno = -ret;
		SYSERROR("Failed to turn off no-new-privs");
		seccomp_release(ctx);
		return NULL;
	}

#ifdef SCMP_FLTATR_ATL_TSKIP
	ret = seccomp_attr_set(ctx, SCMP_FLTATR_ATL_TSKIP, 1);
	if (ret < 0) {
		errno = -ret;
		SYSWARN("Failed to turn on seccomp nop-skip, continuing");
	}
#endif

	ret = seccomp_arch_exist(ctx, arch);
	if (ret < 0) {
		if (ret != -EEXIST) {
			errno = -ret;
			SYSERROR("Failed to determine whether arch %d is "
			         "already present in the main seccomp context",
			         (int)n_arch);
			seccomp_release(ctx);
			return NULL;
		}

		ret = seccomp_arch_add(ctx, arch);
		if (ret != 0) {
			errno = -ret;
			SYSERROR("Failed to add arch %d to main seccomp context",
			         (int)n_arch);
			seccomp_release(ctx);
			return NULL;
		}
		TRACE("Added arch %d to main seccomp context", (int)n_arch);

		ret = seccomp_arch_remove(ctx, SCMP_ARCH_NATIVE);
		if (ret != 0) {
			ERROR("Failed to remove native arch from main seccomp context");
			seccomp_release(ctx);
			return NULL;
		}
		TRACE("Removed native arch from main seccomp context");

		*needs_merge = true;
	} else {
		*needs_merge = false;
		TRACE("Arch %d already present in main seccomp context", (int)n_arch);
	}

	return ctx;
}

bool do_resolve_add_rule(uint32_t arch, char *line, scmp_filter_ctx ctx,
			 struct seccomp_v2_rule *rule)
{
	int i, nr, ret;
	struct scmp_arg_cmp arg_cmp[6];

	ret = seccomp_arch_exist(ctx, arch);
	if (arch && ret != 0) {
		errno = -ret;
		SYSERROR("Seccomp: rule and context arch do not match (arch %d)", arch);
		return false;
	}

	/*get the syscall name*/
	char *p = strchr(line, ' ');
	if (p)
		*p = '\0';

	if (strncmp(line, "reject_force_umount", 19) == 0) {
		ret = seccomp_rule_add_exact(ctx, SCMP_ACT_ERRNO(EACCES),
					     SCMP_SYS(umount2), 1,
					     SCMP_A1(SCMP_CMP_MASKED_EQ, MNT_FORCE, MNT_FORCE));
		if (ret < 0) {
			errno = -ret;
			SYSERROR("Failed loading rule to reject force umount");
			return false;
		}

		INFO("Set seccomp rule to reject force umounts");
		return true;
	}

	nr = seccomp_syscall_resolve_name(line);
	if (nr == __NR_SCMP_ERROR) {
		WARN("Failed to resolve syscall \"%s\"", line);
		WARN("This syscall will NOT be handled by seccomp");
		return true;
	}

	if (nr < 0) {
		WARN("Got negative return value %d for syscall \"%s\"", nr, line);
		WARN("This syscall will NOT be handled by seccomp");
		return true;
	}

	memset(&arg_cmp, 0, sizeof(arg_cmp));
	for (i = 0; i < rule->args_num; i++) {
		INFO("arg_cmp[%d]: SCMP_CMP(%u, %llu, %llu, %llu)", i,
		     rule->args_value[i].index,
		     (long long unsigned int)rule->args_value[i].op,
		     (long long unsigned int)rule->args_value[i].mask,
		     (long long unsigned int)rule->args_value[i].value);

		if (SCMP_CMP_MASKED_EQ == rule->args_value[i].op)
			arg_cmp[i] = SCMP_CMP(rule->args_value[i].index,
					      rule->args_value[i].op,
					      rule->args_value[i].mask,
					      rule->args_value[i].value);
		else
			arg_cmp[i] = SCMP_CMP(rule->args_value[i].index,
					      rule->args_value[i].op,
					      rule->args_value[i].value);
	}

	ret = seccomp_rule_add_exact_array(ctx, rule->action, nr,
					   rule->args_num, arg_cmp);
	if (ret < 0) {
		errno = -ret;
		SYSERROR("Failed loading rule for %s (nr %d action %d (%s))",
		         line, nr, rule->action, get_action_name(rule->action));
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
static int parse_config_v2(FILE *f, char *line, size_t *line_bufsz, struct lxc_conf *conf)
{
	int ret;
	char *p;
	enum lxc_hostarch_t cur_rule_arch, native_arch;
	bool blacklist = false;
	uint32_t default_policy_action = -1, default_rule_action = -1;
	struct seccomp_v2_rule rule;
	struct scmp_ctx_info {
		uint32_t architectures[3];
		scmp_filter_ctx contexts[3];
		bool needs_merge[3];
	} ctx;

	if (strncmp(line, "blacklist", 9) == 0)
		blacklist = true;
	else if (strncmp(line, "whitelist", 9) != 0) {
		ERROR("Bad seccomp policy style \"%s\"", line);
		return -1;
	}

	p = strchr(line, ' ');
	if (p) {
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

	memset(&ctx, 0, sizeof(ctx));
	ctx.architectures[0] = SCMP_ARCH_NATIVE;
	ctx.architectures[1] = SCMP_ARCH_NATIVE;
	ctx.architectures[2] = SCMP_ARCH_NATIVE;
	native_arch = get_hostarch();
	cur_rule_arch = native_arch;
	if (native_arch == lxc_seccomp_arch_amd64) {
		cur_rule_arch = lxc_seccomp_arch_all;

		ctx.architectures[0] = SCMP_ARCH_X86;
		ctx.contexts[0] = get_new_ctx(lxc_seccomp_arch_i386,
					      default_policy_action,
					      &ctx.needs_merge[0]);
		if (!ctx.contexts[0])
			goto bad;

		ctx.architectures[1] = SCMP_ARCH_X32;
		ctx.contexts[1] = get_new_ctx(lxc_seccomp_arch_x32,
					      default_policy_action,
					      &ctx.needs_merge[1]);
		if (!ctx.contexts[1])
			goto bad;

		ctx.architectures[2] = SCMP_ARCH_X86_64;
		ctx.contexts[2] = get_new_ctx(lxc_seccomp_arch_amd64,
					      default_policy_action,
					      &ctx.needs_merge[2]);
		if (!ctx.contexts[2])
			goto bad;
#ifdef SCMP_ARCH_PPC
	} else if (native_arch == lxc_seccomp_arch_ppc64) {
		cur_rule_arch = lxc_seccomp_arch_all;

		ctx.architectures[0] = SCMP_ARCH_PPC;
		ctx.contexts[0] = get_new_ctx(lxc_seccomp_arch_ppc,
					      default_policy_action,
					      &ctx.needs_merge[0]);
		if (!ctx.contexts[0])
			goto bad;

		ctx.architectures[2] = SCMP_ARCH_PPC64;
		ctx.contexts[2] = get_new_ctx(lxc_seccomp_arch_ppc64,
					      default_policy_action,
					      &ctx.needs_merge[2]);
		if (!ctx.contexts[2])
			goto bad;
#endif
#ifdef SCMP_ARCH_ARM
	} else if (native_arch == lxc_seccomp_arch_arm64) {
		cur_rule_arch = lxc_seccomp_arch_all;

		ctx.architectures[0] = SCMP_ARCH_ARM;
		ctx.contexts[0] = get_new_ctx(lxc_seccomp_arch_arm,
					      default_policy_action,
					      &ctx.needs_merge[0]);
		if (!ctx.contexts[0])
			goto bad;

#ifdef SCMP_ARCH_AARCH64
		ctx.architectures[2] = SCMP_ARCH_AARCH64;
		ctx.contexts[2] = get_new_ctx(lxc_seccomp_arch_arm64,
					      default_policy_action,
					      &ctx.needs_merge[2]);
		if (!ctx.contexts[2])
			goto bad;
#endif
#endif
#ifdef SCMP_ARCH_MIPS
	} else if (native_arch == lxc_seccomp_arch_mips64) {
		cur_rule_arch = lxc_seccomp_arch_all;

		ctx.architectures[0] = SCMP_ARCH_MIPS;
		ctx.contexts[0] = get_new_ctx(lxc_seccomp_arch_mips,
					      default_policy_action,
					      &ctx.needs_merge[0]);
		if (!ctx.contexts[0])
			goto bad;

		ctx.architectures[1] = SCMP_ARCH_MIPS64N32;
		ctx.contexts[1] = get_new_ctx(lxc_seccomp_arch_mips64n32,
					      default_policy_action,
					      &ctx.needs_merge[1]);
		if (!ctx.contexts[1])
			goto bad;

		ctx.architectures[2] = SCMP_ARCH_MIPS64;
		ctx.contexts[2] = get_new_ctx(lxc_seccomp_arch_mips64,
					      default_policy_action,
					      &ctx.needs_merge[2]);
		if (!ctx.contexts[2])
			goto bad;
	} else if (native_arch == lxc_seccomp_arch_mipsel64) {
		cur_rule_arch = lxc_seccomp_arch_all;

		ctx.architectures[0] = SCMP_ARCH_MIPSEL;
		ctx.contexts[0] = get_new_ctx(lxc_seccomp_arch_mipsel,
					      default_policy_action,
					      &ctx.needs_merge[0]);
		if (!ctx.contexts[0])
			goto bad;

		ctx.architectures[1] = SCMP_ARCH_MIPSEL64N32;
		ctx.contexts[1] = get_new_ctx(lxc_seccomp_arch_mipsel64n32,
					      default_policy_action,
					      &ctx.needs_merge[1]);
		if (!ctx.contexts[1])
			goto bad;

		ctx.architectures[2] = SCMP_ARCH_MIPSEL64;
		ctx.contexts[2] = get_new_ctx(lxc_seccomp_arch_mipsel64,
					      default_policy_action,
					      &ctx.needs_merge[2]);
		if (!ctx.contexts[2])
			goto bad;
#endif
	}

	if (default_policy_action != SCMP_ACT_KILL) {
		ret = seccomp_reset(conf->seccomp.seccomp_ctx, default_policy_action);
		if (ret != 0) {
			ERROR("Error re-initializing Seccomp");
			return -1;
		}

		ret = seccomp_attr_set(conf->seccomp.seccomp_ctx, SCMP_FLTATR_CTL_NNP, 0);
		if (ret < 0) {
			errno = -ret;
			SYSERROR("Failed to turn off no-new-privs");
			return -1;
		}

#ifdef SCMP_FLTATR_ATL_TSKIP
		ret = seccomp_attr_set(conf->seccomp.seccomp_ctx, SCMP_FLTATR_ATL_TSKIP, 1);
		if (ret < 0) {
			errno = -ret;
			SYSWARN("Failed to turn on seccomp nop-skip, continuing");
		}
#endif
	}

	while (getline(&line, line_bufsz, f) != -1) {
		if (line[0] == '#')
			continue;

		if (line[0] == '\0')
			continue;

		remove_trailing_newlines(line);

		INFO("Processing \"%s\"", line);
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
#ifdef SCMP_ARCH_S390
			else if (strcmp(line, "[s390]") == 0 ||
				strcmp(line, "[S390]") == 0) {
				if (native_arch != lxc_seccomp_arch_s390) {
					cur_rule_arch = lxc_seccomp_arch_unknown;
					continue;
				}

				cur_rule_arch = lxc_seccomp_arch_s390;
			}
#endif
			else {
				goto bad_arch;
			}

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

#if HAVE_DECL_SECCOMP_NOTIFY_FD
		if ((rule.action == SCMP_ACT_NOTIFY) &&
		    !conf->seccomp.notifier.wants_supervision) {
			conf->seccomp.notifier.wants_supervision = true;
			TRACE("Set SECCOMP_FILTER_FLAG_NEW_LISTENER attribute");
		}
#endif

		if (!do_resolve_add_rule(SCMP_ARCH_NATIVE, line,
					 conf->seccomp.seccomp_ctx, &rule))
			goto bad_rule;

		INFO("Added native rule for arch %d for %s action %d(%s)",
		     SCMP_ARCH_NATIVE, line, rule.action,
		     get_action_name(rule.action));

		if (ctx.architectures[0] != SCMP_ARCH_NATIVE) {
			if (!do_resolve_add_rule(ctx.architectures[0], line,
						 ctx.contexts[0], &rule))
				goto bad_rule;

			INFO("Added compat rule for arch %d for %s action %d(%s)",
			     ctx.architectures[0], line, rule.action,
			     get_action_name(rule.action));
		}

		if (ctx.architectures[1] != SCMP_ARCH_NATIVE) {
			if (!do_resolve_add_rule(ctx.architectures[1], line,
						 ctx.contexts[1], &rule))
				goto bad_rule;

			INFO("Added compat rule for arch %d for %s action %d(%s)",
			     ctx.architectures[1], line, rule.action,
			     get_action_name(rule.action));
		}

		if (ctx.architectures[2] != SCMP_ARCH_NATIVE) {
			if (!do_resolve_add_rule(ctx.architectures[2], line,
						ctx.contexts[2], &rule))
				goto bad_rule;

			INFO("Added native rule for arch %d for %s action %d(%s)",
			     ctx.architectures[2], line, rule.action,
			     get_action_name(rule.action));
		}
	}

	INFO("Merging compat seccomp contexts into main context");
	if (ctx.contexts[0]) {
		if (ctx.needs_merge[0]) {
			ret = seccomp_merge(conf->seccomp.seccomp_ctx, ctx.contexts[0]);
			if (ret < 0) {
				ERROR("Failed to merge first compat seccomp "
				      "context into main context");
				goto bad;
			}

			TRACE("Merged first compat seccomp context into main context");
		} else {
			seccomp_release(ctx.contexts[0]);
			ctx.contexts[0] = NULL;
		}
	}

	if (ctx.contexts[1]) {
		if (ctx.needs_merge[1]) {
			ret = seccomp_merge(conf->seccomp.seccomp_ctx, ctx.contexts[1]);
			if (ret < 0) {
				ERROR("Failed to merge first compat seccomp "
				      "context into main context");
				goto bad;
			}

			TRACE("Merged second compat seccomp context into main context");
		} else {
			seccomp_release(ctx.contexts[1]);
			ctx.contexts[1] = NULL;
		}
	}

	if (ctx.contexts[2]) {
		if (ctx.needs_merge[2]) {
			ret = seccomp_merge(conf->seccomp.seccomp_ctx, ctx.contexts[2]);
			if (ret < 0) {
				ERROR("Failed to merge third compat seccomp "
				      "context into main context");
				goto bad;
			}

			TRACE("Merged third compat seccomp context into main context");
		} else {
			seccomp_release(ctx.contexts[2]);
			ctx.contexts[2] = NULL;
		}
	}

	free(line);
	return 0;

bad_arch:
	ERROR("Unsupported architecture \"%s\"", line);

bad_rule:
bad:
	if (ctx.contexts[0])
		seccomp_release(ctx.contexts[0]);

	if (ctx.contexts[1])
		seccomp_release(ctx.contexts[1]);

	if (ctx.contexts[2])
		seccomp_release(ctx.contexts[2]);

	free(line);

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
	char *line = NULL;
	size_t line_bufsz = 0;
	int ret, version;

	ret = fscanf(f, "%d\n", &version);
	if (ret != 1 || (version != 1 && version != 2)) {
		ERROR("Invalid version");
		return -1;
	}

	if (getline(&line, &line_bufsz, f) == -1) {
		ERROR("Invalid config file");
		goto bad_line;
	}

	if (version == 1 && !strstr(line, "whitelist")) {
		ERROR("Only whitelist policy is supported");
		goto bad_line;
	}

	if (strstr(line, "debug")) {
		ERROR("Debug not yet implemented");
		goto bad_line;
	}

	if (version == 1)
		return parse_config_v1(f, line, &line_bufsz, conf);

	return parse_config_v2(f, line, &line_bufsz, conf);

bad_line:
	free(line);
	return -1;
}

/*
 * use_seccomp: return true if we should try and apply a seccomp policy
 * if defined for the container.
 * This will return false if
 *   1. seccomp is not enabled in the kernel
 *   2. a seccomp policy is already enabled for this task
 */
static bool use_seccomp(const struct lxc_conf *conf)
{
	__do_free char *line = NULL;
	__do_fclose FILE *f = NULL;
	int ret, v;
	size_t line_bufsz = 0;
	bool already_enabled = false, found = false;

	if (conf->seccomp.allow_nesting > 0)
		return true;

	f = fopen("/proc/self/status", "re");
	if (!f)
		return true;

	while (getline(&line, &line_bufsz, f) != -1) {
		if (strncmp(line, "Seccomp:", 8) == 0) {
			found = true;

			ret = sscanf(line + 8, "%d", &v);
			if (ret == 1 && v != 0)
				already_enabled = true;

			break;
		}
	}

	if (!found) {
		INFO("Seccomp is not enabled in the kernel");
		return false;
	}

	if (already_enabled) {
		INFO("Already seccomp-confined, not loading new policy");
		return false;
	}

	return true;
}

int lxc_read_seccomp_config(struct lxc_conf *conf)
{
	__do_fclose FILE *f = NULL;
	int ret;

	if (!conf->seccomp.seccomp)
		return 0;

	if (!use_seccomp(conf))
		return 0;

#if HAVE_SCMP_FILTER_CTX
	/* XXX for debug, pass in SCMP_ACT_TRAP */
	conf->seccomp.seccomp_ctx = seccomp_init(SCMP_ACT_KILL);
	ret = !conf->seccomp.seccomp_ctx;
#else
	ret = seccomp_init(SCMP_ACT_KILL) < 0;
#endif
	if (ret) {
		ERROR("Failed initializing seccomp");
		return -1;
	}

/* turn off no-new-privs. We don't want it in lxc, and it breaks
 * with apparmor */
#if HAVE_SCMP_FILTER_CTX
	ret = seccomp_attr_set(conf->seccomp.seccomp_ctx, SCMP_FLTATR_CTL_NNP, 0);
#else
	ret = seccomp_attr_set(SCMP_FLTATR_CTL_NNP, 0);
#endif
	if (ret < 0) {
		errno = -ret;
		SYSERROR("Failed to turn off no-new-privs");
		return -1;
	}

#ifdef SCMP_FLTATR_ATL_TSKIP
	ret = seccomp_attr_set(conf->seccomp.seccomp_ctx, SCMP_FLTATR_ATL_TSKIP, 1);
	if (ret < 0) {
		errno = -ret;
		SYSWARN("Failed to turn on seccomp nop-skip, continuing");
	}
#endif

	f = fopen(conf->seccomp.seccomp, "re");
	if (!f) {
		SYSERROR("Failed to open seccomp policy file %s", conf->seccomp.seccomp);
		return -1;
	}

	return parse_config(f, conf);
}

int lxc_seccomp_load(struct lxc_conf *conf)
{
	int ret;

	if (!conf->seccomp.seccomp)
		return 0;

	if (!use_seccomp(conf))
		return 0;

#if HAVE_SCMP_FILTER_CTX
	ret = seccomp_load(conf->seccomp.seccomp_ctx);
#else
	ret = seccomp_load();
#endif
	if (ret < 0) {
		errno = -ret;
		SYSERROR("Error loading the seccomp policy");
		return -1;
	}

/* After load seccomp filter into the kernel successfully, export the current seccomp
 * filter to log file */
#if HAVE_SCMP_FILTER_CTX
	if ((lxc_log_get_level() <= LXC_LOG_LEVEL_TRACE ||
	     conf->loglevel <= LXC_LOG_LEVEL_TRACE) &&
	    lxc_log_fd >= 0) {
		ret = seccomp_export_pfc(conf->seccomp.seccomp_ctx, lxc_log_fd);
		/* Just give an warning when export error */
		if (ret < 0) {
			errno = -ret;
			SYSWARN("Failed to export seccomp filter to log file");
		}
	}
#endif

#if HAVE_DECL_SECCOMP_NOTIFY_FD
	if (conf->seccomp.notifier.wants_supervision) {
		ret = seccomp_notify_fd(conf->seccomp.seccomp_ctx);
		if (ret < 0) {
			errno = -ret;
			return -1;
		}

		conf->seccomp.notifier.notify_fd = ret;
		TRACE("Retrieved new seccomp listener fd %d", ret);
	}
#endif

	return 0;
}

void lxc_seccomp_free(struct lxc_seccomp *seccomp)
{
	free_disarm(seccomp->seccomp);

#if HAVE_SCMP_FILTER_CTX
	if (seccomp->seccomp_ctx) {
		seccomp_release(seccomp->seccomp_ctx);
		seccomp->seccomp_ctx = NULL;
	}
#endif

#if HAVE_DECL_SECCOMP_NOTIFY_FD
	close_prot_errno_disarm(seccomp->notifier.notify_fd);
	close_prot_errno_disarm(seccomp->notifier.proxy_fd);
	seccomp_notify_free(seccomp->notifier.req_buf, seccomp->notifier.rsp_buf);
	seccomp->notifier.req_buf = NULL;
	seccomp->notifier.rsp_buf = NULL;
#endif
}

#if HAVE_DECL_SECCOMP_NOTIFY_FD
static int seccomp_notify_reconnect(struct lxc_handler *handler)
{
	__do_close int notify_fd = -EBADF;

	close_prot_errno_disarm(handler->conf->seccomp.notifier.proxy_fd);

	notify_fd = lxc_unix_connect_type(
		&handler->conf->seccomp.notifier.proxy_addr, SOCK_SEQPACKET);
	if (notify_fd < 0) {
		SYSERROR("Failed to reconnect to seccomp proxy");
		return -1;
	}

	/* 30 second timeout */
	if (lxc_socket_set_timeout(notify_fd, 30, 30)) {
		SYSERROR("Failed to set socket timeout");
		return -1;
	}
	handler->conf->seccomp.notifier.proxy_fd = move_fd(notify_fd);
	return 0;
}
#endif

#if HAVE_DECL_SECCOMP_NOTIFY_FD
static void seccomp_notify_default_answer(int fd, struct seccomp_notif *req,
					  struct seccomp_notif_resp *resp,
					  struct lxc_handler *handler)
{
	resp->id = req->id;
	resp->error = -ENOSYS;

	if (seccomp_notify_respond(fd, resp))
		SYSERROR("Failed to send default message to seccomp");
}
#endif

int seccomp_notify_handler(int fd, uint32_t events, void *data,
			   struct lxc_epoll_descr *descr)
{

#if HAVE_DECL_SECCOMP_NOTIFY_FD
	__do_close int fd_pid = -EBADF;
	__do_close int fd_mem = -EBADF;
	int ret;
	ssize_t bytes;
	int send_fd_list[2];
	struct iovec iov[4];
	size_t iov_len, msg_base_size, msg_full_size;
	char mem_path[6 /* /proc/ */
		      + INTTYPE_TO_STRLEN(int64_t)
		      + 3 /* mem */
		      + 1 /* \0 */];
	bool reconnected = false;
	struct lxc_handler *hdlr = data;
	struct lxc_conf *conf = hdlr->conf;
	struct seccomp_notif *req = conf->seccomp.notifier.req_buf;
	struct seccomp_notif_resp *resp = conf->seccomp.notifier.rsp_buf;
	int listener_proxy_fd = conf->seccomp.notifier.proxy_fd;
	struct seccomp_notify_proxy_msg msg = {0};
	char *cookie = conf->seccomp.notifier.cookie;
	uint64_t req_id;

	ret = seccomp_notify_receive(fd, req);
	if (ret) {
		SYSERROR("Failed to read seccomp notification");
		goto out;
	}

	if (listener_proxy_fd < 0) {
		ret = -1;
		/* Same condition as for the initial setup_proxy() */
		if (conf->seccomp.notifier.wants_supervision &&
		    conf->seccomp.notifier.proxy_addr.sun_path[1] != '\0') {
			ret = seccomp_notify_reconnect(hdlr);
		}
		if (ret) {
			ERROR("No seccomp proxy registered");
			seccomp_notify_default_answer(fd, req, resp, hdlr);
			goto out;
		}
		listener_proxy_fd = conf->seccomp.notifier.proxy_fd;
	}

	/* remember the ID in case we receive garbage from the proxy */
	resp->id = req_id = req->id;

	snprintf(mem_path, sizeof(mem_path), "/proc/%d", req->pid);
	fd_pid = open(mem_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd_pid < 0) {
		seccomp_notify_default_answer(fd, req, resp, hdlr);
		SYSERROR("Failed to open process pidfd for seccomp notify request");
		goto out;
	}

	snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", req->pid);
	fd_mem = open(mem_path, O_RDWR | O_CLOEXEC);
	if (fd_mem < 0) {
		seccomp_notify_default_answer(fd, req, resp, hdlr);
		SYSERROR("Failed to open process memory for seccomp notify request");
		goto out;
	}

	/*
	 * Make sure that the fd for /proc/<pid>/mem we just opened still
	 * refers to the correct process's memory.
	 */
	ret = seccomp_notify_id_valid(fd, req->id);
	if (ret < 0) {
		seccomp_notify_default_answer(fd, req, resp, hdlr);
		SYSERROR("Invalid seccomp notify request id");
		goto out;
	}

	msg.monitor_pid = hdlr->monitor_pid;
	msg.init_pid = hdlr->pid;
	memcpy(&msg.sizes, &conf->seccomp.notifier.sizes, sizeof(msg.sizes));

	msg_base_size = 0;
	iov[0].iov_base = &msg;
	msg_base_size += (iov[0].iov_len = sizeof(msg));
	iov[1].iov_base = req;
	msg_base_size += (iov[1].iov_len = msg.sizes.seccomp_notif);
	iov[2].iov_base = resp;
	msg_base_size += (iov[2].iov_len = msg.sizes.seccomp_notif_resp);
	msg_full_size = msg_base_size;

	if (cookie) {
		size_t len = strlen(cookie);

		msg.cookie_len = (uint64_t)len;

		iov[3].iov_base = cookie;
		msg_full_size += (iov[3].iov_len = len);

		iov_len = 4;
	} else {
		iov_len = 3;
	}

	send_fd_list[0] = fd_pid;
	send_fd_list[1] = fd_mem;

retry:
	bytes = lxc_abstract_unix_send_fds_iov(listener_proxy_fd, send_fd_list,
					       2, iov, iov_len);
	if (bytes != (ssize_t)msg_full_size) {
		SYSERROR("Failed to forward message to seccomp proxy");
		if (!reconnected) {
			ret = seccomp_notify_reconnect(hdlr);
			if (ret == 0) {
				reconnected = true;
				goto retry;
			}
		}

		seccomp_notify_default_answer(fd, req, resp, hdlr);
		goto out;
	}

	close_prot_errno_disarm(fd_mem);

	if (msg.__reserved != 0) {
		ERROR("Proxy filled reserved data in response");
		seccomp_notify_default_answer(fd, req, resp, hdlr);
		goto out;
	}

	if (resp->id != req_id) {
		resp->id = req_id;
		ERROR("Proxy returned response with illegal id");
		seccomp_notify_default_answer(fd, req, resp, hdlr);
		goto out;
	}

	bytes = lxc_recvmsg_nointr_iov(listener_proxy_fd, iov, iov_len, MSG_TRUNC);
	if (bytes != (ssize_t)msg_base_size) {
		SYSERROR("Failed to receive message from seccomp proxy");
		seccomp_notify_default_answer(fd, req, resp, hdlr);
		goto out;
	}

	ret = seccomp_notify_respond(fd, resp);
	if (ret)
		SYSERROR("Failed to send seccomp notification");

out:
#endif
	return LXC_MAINLOOP_CONTINUE;
}

void seccomp_conf_init(struct lxc_conf *conf)
{
	conf->seccomp.seccomp = NULL;
#if HAVE_SCMP_FILTER_CTX
	conf->seccomp.allow_nesting = 0;
	memset(&conf->seccomp.seccomp_ctx, 0, sizeof(conf->seccomp.seccomp_ctx));
#endif /* HAVE_SCMP_FILTER_CTX */
#if HAVE_DECL_SECCOMP_NOTIFY_FD
	conf->seccomp.notifier.wants_supervision = false;
	conf->seccomp.notifier.notify_fd = -EBADF;
	conf->seccomp.notifier.proxy_fd = -EBADF;
	memset(&conf->seccomp.notifier.proxy_addr, 0,
	       sizeof(conf->seccomp.notifier.proxy_addr));
	conf->seccomp.notifier.req_buf = NULL;
	conf->seccomp.notifier.rsp_buf = NULL;
#endif
}

int lxc_seccomp_setup_proxy(struct lxc_seccomp *seccomp,
			    struct lxc_epoll_descr *descr,
			    struct lxc_handler *handler)
{
#if HAVE_DECL_SECCOMP_NOTIFY_FD
	if (seccomp->notifier.wants_supervision &&
	    seccomp->notifier.proxy_addr.sun_path[1] != '\0') {
		__do_close int notify_fd = -EBADF;
		int ret;

		notify_fd = lxc_unix_connect_type(&seccomp->notifier.proxy_addr,
					     SOCK_SEQPACKET);
		if (notify_fd < 0) {
			SYSERROR("Failed to connect to seccomp proxy");
			return -1;
		}

		/* 30 second timeout */
		ret = lxc_socket_set_timeout(notify_fd, 30, 30);
		if (ret) {
			SYSERROR("Failed to set timeouts for seccomp proxy");
			return -1;
		}

		ret = __seccomp(SECCOMP_GET_NOTIF_SIZES, 0,
				&seccomp->notifier.sizes);
		if (ret) {
			SYSERROR("Failed to query seccomp notify struct sizes");
			return -1;
		}

		ret = seccomp_notify_alloc(&seccomp->notifier.req_buf,
					  &seccomp->notifier.rsp_buf);
		if (ret) {
			ERROR("Failed to allocate seccomp notify request and response buffers");
			errno = ret;
			return -1;
		}

		ret = lxc_mainloop_add_handler(descr,
					       seccomp->notifier.notify_fd,
					       seccomp_notify_handler, handler);
		if (ret < 0) {
			ERROR("Failed to add seccomp notify handler for %d to mainloop",
			      notify_fd);
			return -1;
		}

		seccomp->notifier.proxy_fd = move_fd(notify_fd);
	}
#endif
	return 0;
}

int lxc_seccomp_send_notifier_fd(struct lxc_seccomp *seccomp, int socket_fd)
{
#if HAVE_DECL_SECCOMP_NOTIFY_FD
	if (seccomp->notifier.wants_supervision) {
		if (lxc_abstract_unix_send_fds(socket_fd,
					       &seccomp->notifier.notify_fd, 1,
					       NULL, 0) < 0)
			return -1;
		close_prot_errno_disarm(seccomp->notifier.notify_fd);
	}
#endif
	return 0;
}

int lxc_seccomp_recv_notifier_fd(struct lxc_seccomp *seccomp, int socket_fd)
{
#if HAVE_DECL_SECCOMP_NOTIFY_FD
	if (seccomp->notifier.wants_supervision) {
		int ret;

		ret = lxc_abstract_unix_recv_fds(socket_fd,
						 &seccomp->notifier.notify_fd,
						 1, NULL, 0);
		if (ret < 0)
			return -1;
	}
#endif
	return 0;
}

int lxc_seccomp_add_notifier(const char *name, const char *lxcpath,
			     struct lxc_seccomp *seccomp)
{

#if HAVE_DECL_SECCOMP_NOTIFY_FD
	if (seccomp->notifier.wants_supervision) {
		int ret;

		ret = lxc_cmd_seccomp_notify_add_listener(name, lxcpath,
							  seccomp->notifier.notify_fd,
							  -1, 0);
		close_prot_errno_disarm(seccomp->notifier.notify_fd);
		if (ret < 0)
			return -1;
	}
#endif
	return 0;
}

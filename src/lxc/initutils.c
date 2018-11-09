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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <sys/prctl.h>

#include "compiler.h"
#include "config.h"
#include "file_utils.h"
#include "initutils.h"
#include "log.h"
#include "macro.h"

#ifndef HAVE_STRLCPY
#include "include/strlcpy.h"
#endif

lxc_log_define(initutils, lxc);

static char *copy_global_config_value(char *p)
{
	int len = strlen(p);
	char *retbuf;

	if (len < 1)
		return NULL;

	if (p[len-1] == '\n') {
		p[len-1] = '\0';
		len--;
	}

	retbuf = malloc(len + 1);
	if (!retbuf)
		return NULL;

	(void)strlcpy(retbuf, p, len + 1);
	return retbuf;
}

const char *lxc_global_config_value(const char *option_name)
{
	static const char * const options[][2] = {
		{ "lxc.bdev.lvm.vg",        DEFAULT_VG      },
		{ "lxc.bdev.lvm.thin_pool", DEFAULT_THIN_POOL },
		{ "lxc.bdev.zfs.root",      DEFAULT_ZFSROOT },
		{ "lxc.bdev.rbd.rbdpool",   DEFAULT_RBDPOOL },
		{ "lxc.lxcpath",            NULL            },
		{ "lxc.default_config",     NULL            },
		{ "lxc.cgroup.pattern",     NULL            },
		{ "lxc.cgroup.use",         NULL            },
		{ NULL, NULL },
	};

	/* placed in the thread local storage pool for non-bionic targets */
#ifdef HAVE_TLS
	static thread_local const char *values[sizeof(options) / sizeof(options[0])] = {0};
#else
	static const char *values[sizeof(options) / sizeof(options[0])] = {0};
#endif

	/* user_config_path is freed as soon as it is used */
	char *user_config_path = NULL;

	/*
	 * The following variables are freed at bottom unconditionally.
	 * So NULL the value if it is to be returned to the caller
	 */
	char *user_default_config_path = NULL;
	char *user_lxc_path = NULL;
	char *user_cgroup_pattern = NULL;

	if (geteuid() > 0) {
		const char *user_home = getenv("HOME");
		if (!user_home)
			user_home = "/";

		user_config_path = malloc(sizeof(char) * (22 + strlen(user_home)));
		user_default_config_path = malloc(sizeof(char) * (26 + strlen(user_home)));
		user_lxc_path = malloc(sizeof(char) * (19 + strlen(user_home)));

		sprintf(user_config_path, "%s/.config/lxc/lxc.conf", user_home);
		sprintf(user_default_config_path, "%s/.config/lxc/default.conf", user_home);
		sprintf(user_lxc_path, "%s/.local/share/lxc/", user_home);
		user_cgroup_pattern = strdup("lxc/%n");
	}
	else {
		user_config_path = strdup(LXC_GLOBAL_CONF);
		user_default_config_path = strdup(LXC_DEFAULT_CONFIG);
		user_lxc_path = strdup(LXCPATH);
		user_cgroup_pattern = strdup(DEFAULT_CGROUP_PATTERN);
	}

	const char * const (*ptr)[2];
	size_t i;
	char buf[1024], *p, *p2;
	FILE *fin = NULL;

	for (i = 0, ptr = options; (*ptr)[0]; ptr++, i++) {
		if (!strcmp(option_name, (*ptr)[0]))
			break;
	}
	if (!(*ptr)[0]) {
		free(user_config_path);
		free(user_default_config_path);
		free(user_lxc_path);
		free(user_cgroup_pattern);
		errno = EINVAL;
		return NULL;
	}

	if (values[i]) {
		free(user_config_path);
		free(user_default_config_path);
		free(user_lxc_path);
		free(user_cgroup_pattern);
		return values[i];
	}

	fin = fopen_cloexec(user_config_path, "r");
	free(user_config_path);
	if (fin) {
		while (fgets(buf, 1024, fin)) {
			if (buf[0] == '#')
				continue;
			p = strstr(buf, option_name);
			if (!p)
				continue;
			/* see if there was just white space in front
			 * of the option name
			 */
			for (p2 = buf; p2 < p; p2++) {
				if (*p2 != ' ' && *p2 != '\t')
					break;
			}
			if (p2 < p)
				continue;
			p = strchr(p, '=');
			if (!p)
				continue;
			/* see if there was just white space after
			 * the option name
			 */
			for (p2 += strlen(option_name); p2 < p; p2++) {
				if (*p2 != ' ' && *p2 != '\t')
					break;
			}
			if (p2 < p)
				continue;
			p++;
			while (*p && (*p == ' ' || *p == '\t')) p++;
			if (!*p)
				continue;

			if (strcmp(option_name, "lxc.lxcpath") == 0) {
				free(user_lxc_path);
				user_lxc_path = copy_global_config_value(p);
				remove_trailing_slashes(user_lxc_path);
				values[i] = user_lxc_path;
				user_lxc_path = NULL;
				goto out;
			}

			values[i] = copy_global_config_value(p);
			goto out;
		}
	}
	/* could not find value, use default */
	if (strcmp(option_name, "lxc.lxcpath") == 0) {
		remove_trailing_slashes(user_lxc_path);
		values[i] = user_lxc_path;
		user_lxc_path = NULL;
	}
	else if (strcmp(option_name, "lxc.default_config") == 0) {
		values[i] = user_default_config_path;
		user_default_config_path = NULL;
	}
	else if (strcmp(option_name, "lxc.cgroup.pattern") == 0) {
		values[i] = user_cgroup_pattern;
		user_cgroup_pattern = NULL;
	}
	else
		values[i] = (*ptr)[1];

	/* special case: if default value is NULL,
	 * and there is no config, don't view that
	 * as an error... */
	if (!values[i])
		errno = 0;

out:
	if (fin)
		fclose(fin);

	free(user_cgroup_pattern);
	free(user_default_config_path);
	free(user_lxc_path);

	return values[i];
}

/*
 * Sets the process title to the specified title. Note that this may fail if
 * the kernel doesn't support PR_SET_MM_MAP (kernels <3.18).
 */
int setproctitle(char *title)
{
	static char *proctitle = NULL;
	char buf[2048], *tmp;
	FILE *f;
	int i, len, ret = 0;

	/* We don't really need to know all of this stuff, but unfortunately
	 * PR_SET_MM_MAP requires us to set it all at once, so we have to
	 * figure it out anyway.
	 */
	unsigned long start_data, end_data, start_brk, start_code, end_code,
			start_stack, arg_start, arg_end, env_start, env_end,
			brk_val;
	struct prctl_mm_map prctl_map;

	f = fopen_cloexec("/proc/self/stat", "r");
	if (!f) {
		return -1;
	}

	tmp = fgets(buf, sizeof(buf), f);
	fclose(f);
	if (!tmp) {
		return -1;
	}

	/* Skip the first 25 fields, column 26-28 are start_code, end_code,
	 * and start_stack */
	tmp = strchr(buf, ' ');
	for (i = 0; i < 24; i++) {
		if (!tmp)
			return -1;
		tmp = strchr(tmp+1, ' ');
	}
	if (!tmp)
		return -1;

	i = sscanf(tmp, "%lu %lu %lu", &start_code, &end_code, &start_stack);
	if (i != 3)
		return -1;

	/* Skip the next 19 fields, column 45-51 are start_data to arg_end */
	for (i = 0; i < 19; i++) {
		if (!tmp)
			return -1;
		tmp = strchr(tmp+1, ' ');
	}

	if (!tmp)
		return -1;

	i = sscanf(tmp, "%lu %lu %lu %*u %*u %lu %lu",
		&start_data,
		&end_data,
		&start_brk,
		&env_start,
		&env_end);
	if (i != 5)
		return -1;

	/* Include the null byte here, because in the calculations below we
	 * want to have room for it. */
	len = strlen(title) + 1;

	proctitle = realloc(proctitle, len);
	if (!proctitle)
		return -1;

	arg_start = (unsigned long) proctitle;
	arg_end = arg_start + len;

	brk_val = syscall(__NR_brk, 0);

	prctl_map = (struct prctl_mm_map) {
		.start_code = start_code,
		.end_code = end_code,
		.start_stack = start_stack,
		.start_data = start_data,
		.end_data = end_data,
		.start_brk = start_brk,
		.brk = brk_val,
		.arg_start = arg_start,
		.arg_end = arg_end,
		.env_start = env_start,
		.env_end = env_end,
		.auxv = NULL,
		.auxv_size = 0,
		.exe_fd = -1,
	};

	ret = prctl(PR_SET_MM, prctl_arg(PR_SET_MM_MAP), prctl_arg(&prctl_map),
		    prctl_arg(sizeof(prctl_map)), prctl_arg(0));
	if (ret == 0)
		(void)strlcpy((char*)arg_start, title, len);
	else
		SYSWARN("Failed to set cmdline");

	return ret;
}

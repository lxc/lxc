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

#include "initutils.h"
#include "log.h"

lxc_log_define(lxc_initutils, lxc);

static int mount_fs(const char *source, const char *target, const char *type)
{
	/* the umount may fail */
	if (umount(target))
		WARN("failed to unmount %s : %s", target, strerror(errno));

	if (mount(source, target, type, 0, NULL)) {
		ERROR("failed to mount %s : %s", target, strerror(errno));
		return -1;
	}

	DEBUG("'%s' mounted on '%s'", source, target);

	return 0;
}

extern void lxc_setup_fs(void)
{
	if (mount_fs("proc", "/proc", "proc"))
		INFO("failed to remount proc");

	/* if /dev has been populated by us, /dev/shm does not exist */
	if (access("/dev/shm", F_OK) && mkdir("/dev/shm", 0777))
		INFO("failed to create /dev/shm");

	/* if we can't mount /dev/shm, continue anyway */
	if (mount_fs("shmfs", "/dev/shm", "tmpfs"))
		INFO("failed to mount /dev/shm");

	/* If we were able to mount /dev/shm, then /dev exists */
	/* Sure, but it's read-only per config :) */
	if (access("/dev/mqueue", F_OK) && mkdir("/dev/mqueue", 0666)) {
		DEBUG("failed to create '/dev/mqueue'");
		return;
	}

	/* continue even without posix message queue support */
	if (mount_fs("mqueue", "/dev/mqueue", "mqueue"))
		INFO("failed to mount /dev/mqueue");
}

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
	retbuf = malloc(len+1);
	if (!retbuf)
		return NULL;
	strcpy(retbuf, p);
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
	static __thread const char *values[sizeof(options) / sizeof(options[0])] = { 0 };
#else
	static const char *values[sizeof(options) / sizeof(options[0])] = { 0 };
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

extern void remove_trailing_slashes(char *p)
{
	int l = strlen(p);
	while (--l >= 0 && (p[l] == '/' || p[l] == '\n'))
		p[l] = '\0';
}

FILE *fopen_cloexec(const char *path, const char *mode)
{
	int open_mode = 0;
	int step = 0;
	int fd;
	int saved_errno = 0;
	FILE *ret;

	if (!strncmp(mode, "r+", 2)) {
		open_mode = O_RDWR;
		step = 2;
	} else if (!strncmp(mode, "r", 1)) {
		open_mode = O_RDONLY;
		step = 1;
	} else if (!strncmp(mode, "w+", 2)) {
		open_mode = O_RDWR | O_TRUNC | O_CREAT;
		step = 2;
	} else if (!strncmp(mode, "w", 1)) {
		open_mode = O_WRONLY | O_TRUNC | O_CREAT;
		step = 1;
	} else if (!strncmp(mode, "a+", 2)) {
		open_mode = O_RDWR | O_CREAT | O_APPEND;
		step = 2;
	} else if (!strncmp(mode, "a", 1)) {
		open_mode = O_WRONLY | O_CREAT | O_APPEND;
		step = 1;
	}
	for (; mode[step]; step++)
		if (mode[step] == 'x')
			open_mode |= O_EXCL;
	open_mode |= O_CLOEXEC;

	fd = open(path, open_mode, 0666);
	if (fd < 0)
		return NULL;

	ret = fdopen(fd, mode);
	saved_errno = errno;
	if (!ret)
		close(fd);
	errno = saved_errno;
	return ret;
}

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

#define _GNU_SOURCE
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>

#ifdef HAVE_STATVFS
#include <sys/statvfs.h>
#endif

#if HAVE_PTY_H
#include <pty.h>
#else
#include <../include/openpty.h>
#endif

#include <linux/loop.h>

#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/mount.h>
#include <sys/mman.h>
#include <sys/prctl.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <libgen.h>

#include "network.h"
#include "error.h"
#include "af_unix.h"
#include "parse.h"
#include "utils.h"
#include "conf.h"
#include "log.h"
#include "caps.h"       /* for lxc_caps_last_cap() */
#include "bdev/bdev.h"
#include "bdev/lxcaufs.h"
#include "bdev/lxcoverlay.h"
#include "cgroup.h"
#include "lxclock.h"
#include "namespace.h"
#include "lsm/lsm.h"

#if HAVE_SYS_CAPABILITY_H
#include <sys/capability.h>
#endif

#if HAVE_SYS_PERSONALITY_H
#include <sys/personality.h>
#endif

#if IS_BIONIC
#include <../include/lxcmntent.h>
#else
#include <mntent.h>
#endif

#include "lxcseccomp.h"

lxc_log_define(lxc_conf, lxc);

#define LINELEN 4096

#if HAVE_SYS_CAPABILITY_H
#ifndef CAP_SETFCAP
#define CAP_SETFCAP 31
#endif

#ifndef CAP_MAC_OVERRIDE
#define CAP_MAC_OVERRIDE 32
#endif

#ifndef CAP_MAC_ADMIN
#define CAP_MAC_ADMIN 33
#endif
#endif

#ifndef PR_CAPBSET_DROP
#define PR_CAPBSET_DROP 24
#endif

#ifndef LO_FLAGS_AUTOCLEAR
#define LO_FLAGS_AUTOCLEAR 4
#endif

/* needed for cgroup automount checks, regardless of whether we
 * have included linux/capability.h or not */
#ifndef CAP_SYS_ADMIN
#define CAP_SYS_ADMIN 21
#endif

/* Define pivot_root() if missing from the C library */
#ifndef HAVE_PIVOT_ROOT
static int pivot_root(const char * new_root, const char * put_old)
{
#ifdef __NR_pivot_root
return syscall(__NR_pivot_root, new_root, put_old);
#else
errno = ENOSYS;
return -1;
#endif
}
#else
extern int pivot_root(const char * new_root, const char * put_old);
#endif

/* Define sethostname() if missing from the C library */
#ifndef HAVE_SETHOSTNAME
static int sethostname(const char * name, size_t len)
{
#ifdef __NR_sethostname
return syscall(__NR_sethostname, name, len);
#else
errno = ENOSYS;
return -1;
#endif
}
#endif

/* Define __S_ISTYPE if missing from the C library */
#ifndef __S_ISTYPE
#define        __S_ISTYPE(mode, mask)  (((mode) & S_IFMT) == (mask))
#endif

#ifndef MS_PRIVATE
#define MS_PRIVATE (1<<18)
#endif

char *lxchook_names[NUM_LXC_HOOKS] = {
	"pre-start", "pre-mount", "mount", "autodev", "start", "stop", "post-stop", "clone", "destroy" };

typedef int (*instantiate_cb)(struct lxc_handler *, struct lxc_netdev *);

struct mount_opt {
	char *name;
	int clear;
	int flag;
};

struct caps_opt {
	char *name;
	int value;
};

/*
 * The lxc_conf of the container currently being worked on in an
 * API call
 * This is used in the error calls
 */
#ifdef HAVE_TLS
__thread struct lxc_conf *current_config;
#else
struct lxc_conf *current_config;
#endif

/* Declare this here, since we don't want to reshuffle the whole file. */
static int in_caplist(int cap, struct lxc_list *caps);

static int instantiate_veth(struct lxc_handler *, struct lxc_netdev *);
static int instantiate_macvlan(struct lxc_handler *, struct lxc_netdev *);
static int instantiate_vlan(struct lxc_handler *, struct lxc_netdev *);
static int instantiate_phys(struct lxc_handler *, struct lxc_netdev *);
static int instantiate_empty(struct lxc_handler *, struct lxc_netdev *);
static int instantiate_none(struct lxc_handler *, struct lxc_netdev *);

static  instantiate_cb netdev_conf[LXC_NET_MAXCONFTYPE + 1] = {
	[LXC_NET_VETH]    = instantiate_veth,
	[LXC_NET_MACVLAN] = instantiate_macvlan,
	[LXC_NET_VLAN]    = instantiate_vlan,
	[LXC_NET_PHYS]    = instantiate_phys,
	[LXC_NET_EMPTY]   = instantiate_empty,
	[LXC_NET_NONE]    = instantiate_none,
};

static int shutdown_veth(struct lxc_handler *, struct lxc_netdev *);
static int shutdown_macvlan(struct lxc_handler *, struct lxc_netdev *);
static int shutdown_vlan(struct lxc_handler *, struct lxc_netdev *);
static int shutdown_phys(struct lxc_handler *, struct lxc_netdev *);
static int shutdown_empty(struct lxc_handler *, struct lxc_netdev *);
static int shutdown_none(struct lxc_handler *, struct lxc_netdev *);

static  instantiate_cb netdev_deconf[LXC_NET_MAXCONFTYPE + 1] = {
	[LXC_NET_VETH]    = shutdown_veth,
	[LXC_NET_MACVLAN] = shutdown_macvlan,
	[LXC_NET_VLAN]    = shutdown_vlan,
	[LXC_NET_PHYS]    = shutdown_phys,
	[LXC_NET_EMPTY]   = shutdown_empty,
	[LXC_NET_NONE]    = shutdown_none,
};

static struct mount_opt mount_opt[] = {
	{ "defaults",      0, 0              },
	{ "ro",            0, MS_RDONLY      },
	{ "rw",            1, MS_RDONLY      },
	{ "suid",          1, MS_NOSUID      },
	{ "nosuid",        0, MS_NOSUID      },
	{ "dev",           1, MS_NODEV       },
	{ "nodev",         0, MS_NODEV       },
	{ "exec",          1, MS_NOEXEC      },
	{ "noexec",        0, MS_NOEXEC      },
	{ "sync",          0, MS_SYNCHRONOUS },
	{ "async",         1, MS_SYNCHRONOUS },
	{ "dirsync",       0, MS_DIRSYNC     },
	{ "remount",       0, MS_REMOUNT     },
	{ "mand",          0, MS_MANDLOCK    },
	{ "nomand",        1, MS_MANDLOCK    },
	{ "atime",         1, MS_NOATIME     },
	{ "noatime",       0, MS_NOATIME     },
	{ "diratime",      1, MS_NODIRATIME  },
	{ "nodiratime",    0, MS_NODIRATIME  },
	{ "bind",          0, MS_BIND        },
	{ "rbind",         0, MS_BIND|MS_REC },
	{ "relatime",      0, MS_RELATIME    },
	{ "norelatime",    1, MS_RELATIME    },
	{ "strictatime",   0, MS_STRICTATIME },
	{ "nostrictatime", 1, MS_STRICTATIME },
	{ NULL,            0, 0              },
};

#if HAVE_SYS_CAPABILITY_H
static struct caps_opt caps_opt[] = {
	{ "chown",             CAP_CHOWN             },
	{ "dac_override",      CAP_DAC_OVERRIDE      },
	{ "dac_read_search",   CAP_DAC_READ_SEARCH   },
	{ "fowner",            CAP_FOWNER            },
	{ "fsetid",            CAP_FSETID            },
	{ "kill",              CAP_KILL              },
	{ "setgid",            CAP_SETGID            },
	{ "setuid",            CAP_SETUID            },
	{ "setpcap",           CAP_SETPCAP           },
	{ "linux_immutable",   CAP_LINUX_IMMUTABLE   },
	{ "net_bind_service",  CAP_NET_BIND_SERVICE  },
	{ "net_broadcast",     CAP_NET_BROADCAST     },
	{ "net_admin",         CAP_NET_ADMIN         },
	{ "net_raw",           CAP_NET_RAW           },
	{ "ipc_lock",          CAP_IPC_LOCK          },
	{ "ipc_owner",         CAP_IPC_OWNER         },
	{ "sys_module",        CAP_SYS_MODULE        },
	{ "sys_rawio",         CAP_SYS_RAWIO         },
	{ "sys_chroot",        CAP_SYS_CHROOT        },
	{ "sys_ptrace",        CAP_SYS_PTRACE        },
	{ "sys_pacct",         CAP_SYS_PACCT         },
	{ "sys_admin",         CAP_SYS_ADMIN         },
	{ "sys_boot",          CAP_SYS_BOOT          },
	{ "sys_nice",          CAP_SYS_NICE          },
	{ "sys_resource",      CAP_SYS_RESOURCE      },
	{ "sys_time",          CAP_SYS_TIME          },
	{ "sys_tty_config",    CAP_SYS_TTY_CONFIG    },
	{ "mknod",             CAP_MKNOD             },
	{ "lease",             CAP_LEASE             },
#ifdef CAP_AUDIT_READ
	{ "audit_read",        CAP_AUDIT_READ        },
#endif
#ifdef CAP_AUDIT_WRITE
	{ "audit_write",       CAP_AUDIT_WRITE       },
#endif
#ifdef CAP_AUDIT_CONTROL
	{ "audit_control",     CAP_AUDIT_CONTROL     },
#endif
	{ "setfcap",           CAP_SETFCAP           },
	{ "mac_override",      CAP_MAC_OVERRIDE      },
	{ "mac_admin",         CAP_MAC_ADMIN         },
#ifdef CAP_SYSLOG
	{ "syslog",            CAP_SYSLOG            },
#endif
#ifdef CAP_WAKE_ALARM
	{ "wake_alarm",        CAP_WAKE_ALARM        },
#endif
#ifdef CAP_BLOCK_SUSPEND
	{ "block_suspend",     CAP_BLOCK_SUSPEND     },
#endif
};
#else
static struct caps_opt caps_opt[] = {};
#endif

static int run_buffer(char *buffer)
{
	struct lxc_popen_FILE *f;
	char *output;
	int ret;

	f = lxc_popen(buffer);
	if (!f) {
		SYSERROR("popen failed");
		return -1;
	}

	output = malloc(LXC_LOG_BUFFER_SIZE);
	if (!output) {
		ERROR("failed to allocate memory for script output");
		lxc_pclose(f);
		return -1;
	}

	while(fgets(output, LXC_LOG_BUFFER_SIZE, f->f))
		DEBUG("script output: %s", output);

	free(output);

	ret = lxc_pclose(f);
	if (ret == -1) {
		SYSERROR("Script exited on error");
		return -1;
	} else if (WIFEXITED(ret) && WEXITSTATUS(ret) != 0) {
		ERROR("Script exited with status %d", WEXITSTATUS(ret));
		return -1;
	} else if (WIFSIGNALED(ret)) {
		ERROR("Script terminated by signal %d (%s)", WTERMSIG(ret),
		      strsignal(WTERMSIG(ret)));
		return -1;
	}

	return 0;
}

static int run_script_argv(const char *name, const char *section,
		      const char *script, const char *hook, const char *lxcpath,
		      char **argsin)
{
	int ret, i;
	char *buffer;
	size_t size = 0;

	INFO("Executing script '%s' for container '%s', config section '%s'",
	     script, name, section);

	for (i=0; argsin && argsin[i]; i++)
		size += strlen(argsin[i]) + 1;

	size += strlen(hook) + 1;

	size += strlen(script);
	size += strlen(name);
	size += strlen(section);
	size += 3;

	if (size > INT_MAX)
		return -1;

	buffer = alloca(size);
	if (!buffer) {
		ERROR("failed to allocate memory");
		return -1;
	}

	ret = snprintf(buffer, size, "%s %s %s %s", script, name, section, hook);
	if (ret < 0 || ret >= size) {
		ERROR("Script name too long");
		return -1;
	}

	for (i=0; argsin && argsin[i]; i++) {
		int len = size-ret;
		int rc;
		rc = snprintf(buffer + ret, len, " %s", argsin[i]);
		if (rc < 0 || rc >= len) {
			ERROR("Script args too long");
			return -1;
		}
		ret += rc;
	}

	return run_buffer(buffer);
}

static int run_script(const char *name, const char *section,
		      const char *script, ...)
{
	int ret;
	char *buffer, *p;
	size_t size = 0;
	va_list ap;

	INFO("Executing script '%s' for container '%s', config section '%s'",
	     script, name, section);

	va_start(ap, script);
	while ((p = va_arg(ap, char *)))
		size += strlen(p) + 1;
	va_end(ap);

	size += strlen(script);
	size += strlen(name);
	size += strlen(section);
	size += 3;

	if (size > INT_MAX)
		return -1;

	buffer = alloca(size);
	if (!buffer) {
		ERROR("failed to allocate memory");
		return -1;
	}

	ret = snprintf(buffer, size, "%s %s %s", script, name, section);
	if (ret < 0 || ret >= size) {
		ERROR("Script name too long");
		return -1;
	}

	va_start(ap, script);
	while ((p = va_arg(ap, char *))) {
		int len = size-ret;
		int rc;
		rc = snprintf(buffer + ret, len, " %s", p);
		if (rc < 0 || rc >= len) {
			ERROR("Script args too long");
			return -1;
		}
		ret += rc;
	}
	va_end(ap);

	return run_buffer(buffer);
}

static int mount_rootfs_dir(const char *rootfs, const char *target,
			                const char *options)
{
	unsigned long mntflags;
	char *mntdata;
	int ret;

	if (parse_mntopts(options, &mntflags, &mntdata) < 0) {
		free(mntdata);
		return -1;
	}

	ret = mount(rootfs, target, "none", MS_BIND | MS_REC | mntflags, mntdata);
	free(mntdata);

	return ret;
}

static int setup_lodev(const char *rootfs, int fd, struct loop_info64 *loinfo)
{
	int rfd;
	int ret = -1;

	rfd = open(rootfs, O_RDWR);
	if (rfd < 0) {
		SYSERROR("failed to open '%s'", rootfs);
		return -1;
	}

	memset(loinfo, 0, sizeof(*loinfo));

	loinfo->lo_flags = LO_FLAGS_AUTOCLEAR;

	if (ioctl(fd, LOOP_SET_FD, rfd)) {
		SYSERROR("failed to LOOP_SET_FD");
		goto out;
	}

	if (ioctl(fd, LOOP_SET_STATUS64, loinfo)) {
		SYSERROR("failed to LOOP_SET_STATUS64");
		goto out;
	}

	ret = 0;
out:
	close(rfd);

	return ret;
}

static int mount_rootfs_file(const char *rootfs, const char *target,
				             const char *options)
{
	struct dirent dirent, *direntp;
	struct loop_info64 loinfo;
	int ret = -1, fd = -1, rc;
	DIR *dir;
	char path[MAXPATHLEN];

	dir = opendir("/dev");
	if (!dir) {
		SYSERROR("failed to open '/dev'");
		return -1;
	}

	while (!readdir_r(dir, &dirent, &direntp)) {

		if (!direntp)
			break;

		if (!strcmp(direntp->d_name, "."))
			continue;

		if (!strcmp(direntp->d_name, ".."))
			continue;

		if (strncmp(direntp->d_name, "loop", 4))
			continue;

		rc = snprintf(path, MAXPATHLEN, "/dev/%s", direntp->d_name);
		if (rc < 0 || rc >= MAXPATHLEN)
			continue;

		fd = open(path, O_RDWR);
		if (fd < 0)
			continue;

		if (ioctl(fd, LOOP_GET_STATUS64, &loinfo) == 0) {
			close(fd);
			continue;
		}

		if (errno != ENXIO) {
			WARN("unexpected error for ioctl on '%s': %m",
			     direntp->d_name);
			close(fd);
			continue;
		}

		DEBUG("found '%s' free lodev", path);

		ret = setup_lodev(rootfs, fd, &loinfo);
		if (!ret)
			ret = mount_unknown_fs(path, target, options);
		close(fd);

		break;
	}

	if (closedir(dir))
		WARN("failed to close directory");

	return ret;
}

static int mount_rootfs_block(const char *rootfs, const char *target,
			                  const char *options)
{
	return mount_unknown_fs(rootfs, target, options);
}

/*
 * pin_rootfs
 * if rootfs is a directory, then open ${rootfs}/lxc.hold for writing for
 * the duration of the container run, to prevent the container from marking
 * the underlying fs readonly on shutdown. unlink the file immediately so
 * no name pollution is happens
 * return -1 on error.
 * return -2 if nothing needed to be pinned.
 * return an open fd (>=0) if we pinned it.
 */
int pin_rootfs(const char *rootfs)
{
	char absrootfs[MAXPATHLEN];
	char absrootfspin[MAXPATHLEN];
	struct stat s;
	int ret, fd;

	if (rootfs == NULL || strlen(rootfs) == 0)
		return -2;

	if (!realpath(rootfs, absrootfs))
		return -2;

	if (access(absrootfs, F_OK))
		return -1;

	if (stat(absrootfs, &s))
		return -1;

	if (!S_ISDIR(s.st_mode))
		return -2;

	ret = snprintf(absrootfspin, MAXPATHLEN, "%s/lxc.hold", absrootfs);
	if (ret >= MAXPATHLEN)
		return -1;

	fd = open(absrootfspin, O_CREAT | O_RDWR, S_IWUSR|S_IRUSR);
	if (fd < 0)
		return fd;
	(void)unlink(absrootfspin);
	return fd;
}

/*
 * If we are asking to remount something, make sure that any
 * NOEXEC etc are honored.
 */
static unsigned long add_required_remount_flags(const char *s, const char *d,
		unsigned long flags)
{
#ifdef HAVE_STATVFS
	struct statvfs sb;
	unsigned long required_flags = 0;

	if (!(flags & MS_REMOUNT))
		return flags;

	if (!s)
		s = d;

	if (!s)
		return flags;
	if (statvfs(s, &sb) < 0)
		return flags;

	if (sb.f_flag & MS_NOSUID)
		required_flags |= MS_NOSUID;
	if (sb.f_flag & MS_NODEV)
		required_flags |= MS_NODEV;
	if (sb.f_flag & MS_RDONLY)
		required_flags |= MS_RDONLY;
	if (sb.f_flag & MS_NOEXEC)
		required_flags |= MS_NOEXEC;

	return flags | required_flags;
#else
	return flags;
#endif
}

static int lxc_mount_auto_mounts(struct lxc_conf *conf, int flags, struct lxc_handler *handler)
{
	int r;
	int i;
	static struct {
		int match_mask;
		int match_flag;
		const char *source;
		const char *destination;
		const char *fstype;
		unsigned long flags;
		const char *options;
	} default_mounts[] = {
		/* Read-only bind-mounting... In older kernels, doing that required
		 * to do one MS_BIND mount and then MS_REMOUNT|MS_RDONLY the same
		 * one. According to mount(2) manpage, MS_BIND honors MS_RDONLY from
		 * kernel 2.6.26 onwards. However, this apparently does not work on
		 * kernel 3.8. Unfortunately, on that very same kernel, doing the
		 * same trick as above doesn't seem to work either, there one needs
		 * to ALSO specify MS_BIND for the remount, otherwise the entire
		 * fs is remounted read-only or the mount fails because it's busy...
		 * MS_REMOUNT|MS_BIND|MS_RDONLY seems to work for kernels as low as
		 * 2.6.32...
		 */
		{ LXC_AUTO_PROC_MASK, LXC_AUTO_PROC_MIXED, "proc",                                              "%r/proc",                      "proc",     MS_NODEV|MS_NOEXEC|MS_NOSUID,   NULL },
		/* proc/tty is used as a temporary placeholder for proc/sys/net which we'll move back in a few steps */
		{ LXC_AUTO_PROC_MASK, LXC_AUTO_PROC_MIXED, "%r/proc/sys/net",                                   "%r/proc/tty",                  NULL,       MS_BIND,                        NULL },
		{ LXC_AUTO_PROC_MASK, LXC_AUTO_PROC_MIXED, "%r/proc/sys",                                       "%r/proc/sys",                  NULL,       MS_BIND,                        NULL },
		{ LXC_AUTO_PROC_MASK, LXC_AUTO_PROC_MIXED, NULL,                                                "%r/proc/sys",                  NULL,       MS_REMOUNT|MS_BIND|MS_RDONLY,   NULL },
		{ LXC_AUTO_PROC_MASK, LXC_AUTO_PROC_MIXED, "%r/proc/tty",                                       "%r/proc/sys/net",              NULL,       MS_MOVE,                        NULL },
		{ LXC_AUTO_PROC_MASK, LXC_AUTO_PROC_MIXED, "%r/proc/sysrq-trigger",                             "%r/proc/sysrq-trigger",        NULL,       MS_BIND,                        NULL },
		{ LXC_AUTO_PROC_MASK, LXC_AUTO_PROC_MIXED, NULL,                                                "%r/proc/sysrq-trigger",        NULL,       MS_REMOUNT|MS_BIND|MS_RDONLY,   NULL },
		{ LXC_AUTO_PROC_MASK, LXC_AUTO_PROC_RW,    "proc",                                              "%r/proc",                      "proc",     MS_NODEV|MS_NOEXEC|MS_NOSUID,   NULL },
		{ LXC_AUTO_SYS_MASK,  LXC_AUTO_SYS_RW,     "sysfs",                                             "%r/sys",                       "sysfs",    0,                              NULL },
		{ LXC_AUTO_SYS_MASK,  LXC_AUTO_SYS_RO,     "sysfs",                                             "%r/sys",                       "sysfs",    MS_RDONLY,                      NULL },
		{ LXC_AUTO_SYS_MASK,  LXC_AUTO_SYS_MIXED,  "sysfs",                                             "%r/sys",                       "sysfs",    MS_NODEV|MS_NOEXEC|MS_NOSUID,   NULL },
		{ LXC_AUTO_SYS_MASK,  LXC_AUTO_SYS_MIXED,  "%r/sys",                                            "%r/sys",                       NULL,       MS_BIND,                        NULL },
		{ LXC_AUTO_SYS_MASK,  LXC_AUTO_SYS_MIXED,  NULL,                                                "%r/sys",                       NULL,       MS_REMOUNT|MS_BIND|MS_RDONLY,   NULL },
		{ LXC_AUTO_SYS_MASK,  LXC_AUTO_SYS_MIXED,  "sysfs",                                             "%r/sys/devices/virtual/net",   "sysfs",    0,                              NULL },
		{ LXC_AUTO_SYS_MASK,  LXC_AUTO_SYS_MIXED,  "%r/sys/devices/virtual/net/devices/virtual/net",    "%r/sys/devices/virtual/net",   NULL,       MS_BIND,                        NULL },
		{ LXC_AUTO_SYS_MASK,  LXC_AUTO_SYS_MIXED,  NULL,                                                "%r/sys/devices/virtual/net",   NULL,       MS_REMOUNT|MS_BIND|MS_NOSUID|MS_NODEV|MS_NOEXEC,   NULL },
		{ 0,                  0,                   NULL,                                                NULL,                           NULL,       0,                              NULL }
	};

	for (i = 0; default_mounts[i].match_mask; i++) {
		if ((flags & default_mounts[i].match_mask) == default_mounts[i].match_flag) {
			char *source = NULL;
			char *destination = NULL;
			int saved_errno;
			unsigned long mflags;

			if (default_mounts[i].source) {
				/* will act like strdup if %r is not present */
				source = lxc_string_replace("%r", conf->rootfs.path ? conf->rootfs.mount : "", default_mounts[i].source);
				if (!source) {
					SYSERROR("memory allocation error");
					return -1;
				}
			}
			if (!default_mounts[i].destination) {
				ERROR("BUG: auto mounts destination %d was NULL", i);
				free(source);
				return -1;
			}
			/* will act like strdup if %r is not present */
			destination = lxc_string_replace("%r", conf->rootfs.path ? conf->rootfs.mount : "", default_mounts[i].destination);
			if (!destination) {
				saved_errno = errno;
				SYSERROR("memory allocation error");
				free(source);
				errno = saved_errno;
				return -1;
			}
			mflags = add_required_remount_flags(source, destination,
					default_mounts[i].flags);
			r = safe_mount(source, destination, default_mounts[i].fstype, mflags, default_mounts[i].options, conf->rootfs.path ? conf->rootfs.mount : NULL);
			saved_errno = errno;
			if (r < 0 && errno == ENOENT) {
				INFO("Mount source or target for %s on %s doesn't exist. Skipping.", source, destination);
				r = 0;
			}
			else if (r < 0)
				SYSERROR("error mounting %s on %s flags %lu", source, destination, mflags);

			free(source);
			free(destination);
			if (r < 0) {
				errno = saved_errno;
				return -1;
			}
		}
	}

	if (flags & LXC_AUTO_CGROUP_MASK) {
		int cg_flags;

		cg_flags = flags & LXC_AUTO_CGROUP_MASK;
		/* If the type of cgroup mount was not specified, it depends on the
		 * container's capabilities as to what makes sense: if we have
		 * CAP_SYS_ADMIN, the read-only part can be remounted read-write
		 * anyway, so we may as well default to read-write; then the admin
		 * will not be given a false sense of security. (And if they really
		 * want mixed r/o r/w, then they can explicitly specify :mixed.)
		 * OTOH, if the container lacks CAP_SYS_ADMIN, do only default to
		 * :mixed, because then the container can't remount it read-write. */
		if (cg_flags == LXC_AUTO_CGROUP_NOSPEC || cg_flags == LXC_AUTO_CGROUP_FULL_NOSPEC) {
			int has_sys_admin = 0;
			if (!lxc_list_empty(&conf->keepcaps)) {
				has_sys_admin = in_caplist(CAP_SYS_ADMIN, &conf->keepcaps);
			} else {
				has_sys_admin = !in_caplist(CAP_SYS_ADMIN, &conf->caps);
			}
			if (cg_flags == LXC_AUTO_CGROUP_NOSPEC) {
				cg_flags = has_sys_admin ? LXC_AUTO_CGROUP_RW : LXC_AUTO_CGROUP_MIXED;
			} else {
				cg_flags = has_sys_admin ? LXC_AUTO_CGROUP_FULL_RW : LXC_AUTO_CGROUP_FULL_MIXED;
			}
		}

		if (!cgroup_mount(conf->rootfs.path ? conf->rootfs.mount : "", handler, cg_flags)) {
			SYSERROR("error mounting /sys/fs/cgroup");
			return -1;
		}
	}

	return 0;
}

static int mount_rootfs(const char *rootfs, const char *target, const char *options)
{
	char absrootfs[MAXPATHLEN];
	struct stat s;
	int i;

	typedef int (*rootfs_cb)(const char *, const char *, const char *);

	struct rootfs_type {
		int type;
		rootfs_cb cb;
	} rtfs_type[] = {
		{ S_IFDIR, mount_rootfs_dir },
		{ S_IFBLK, mount_rootfs_block },
		{ S_IFREG, mount_rootfs_file },
	};

	if (!realpath(rootfs, absrootfs)) {
		SYSERROR("failed to get real path for '%s'", rootfs);
		return -1;
	}

	if (access(absrootfs, F_OK)) {
		SYSERROR("'%s' is not accessible", absrootfs);
		return -1;
	}

	if (stat(absrootfs, &s)) {
		SYSERROR("failed to stat '%s'", absrootfs);
		return -1;
	}

	for (i = 0; i < sizeof(rtfs_type)/sizeof(rtfs_type[0]); i++) {

		if (!__S_ISTYPE(s.st_mode, rtfs_type[i].type))
			continue;

		return rtfs_type[i].cb(absrootfs, target, options);
	}

	ERROR("unsupported rootfs type for '%s'", absrootfs);
	return -1;
}

static int setup_utsname(struct utsname *utsname)
{
	if (!utsname)
		return 0;

	if (sethostname(utsname->nodename, strlen(utsname->nodename))) {
		SYSERROR("failed to set the hostname to '%s'", utsname->nodename);
		return -1;
	}

	INFO("'%s' hostname has been setup", utsname->nodename);

	return 0;
}

struct dev_symlinks {
	const char *oldpath;
	const char *name;
};

static const struct dev_symlinks dev_symlinks[] = {
	{"/proc/self/fd",	"fd"},
	{"/proc/self/fd/0",	"stdin"},
	{"/proc/self/fd/1",	"stdout"},
	{"/proc/self/fd/2",	"stderr"},
};

static int setup_dev_symlinks(const struct lxc_rootfs *rootfs)
{
	char path[MAXPATHLEN];
	int ret,i;
	struct stat s;


	for (i = 0; i < sizeof(dev_symlinks) / sizeof(dev_symlinks[0]); i++) {
		const struct dev_symlinks *d = &dev_symlinks[i];
		ret = snprintf(path, sizeof(path), "%s/dev/%s", rootfs->path ? rootfs->mount : "", d->name);
		if (ret < 0 || ret >= MAXPATHLEN)
			return -1;

		/*
		 * Stat the path first.  If we don't get an error
		 * accept it as is and don't try to create it
		 */
		if (!stat(path, &s)) {
			continue;
		}

		ret = symlink(d->oldpath, path);

		if (ret && errno != EEXIST) {
			if ( errno == EROFS ) {
				WARN("Warning: Read Only file system while creating %s", path);
			} else {
				SYSERROR("Error creating %s", path);
				return -1;
			}
		}
	}
	return 0;
}

/*
 * Build a space-separate list of ptys to pass to systemd.
 */
static bool append_ptyname(char **pp, char *name)
{
	char *p;

	if (!*pp) {
		*pp = malloc(strlen(name) + strlen("container_ttys=") + 1);
		if (!*pp)
			return false;
		sprintf(*pp, "container_ttys=%s", name);
		return true;
	}
	p = realloc(*pp, strlen(*pp) + strlen(name) + 2);
	if (!p)
		return false;
	*pp = p;
	strcat(p, " ");
	strcat(p, name);
	return true;
}

static int setup_tty(struct lxc_conf *conf)
{
	const struct lxc_tty_info *tty_info = &conf->tty_info;
	char *ttydir = conf->ttydir;
	char path[MAXPATHLEN], lxcpath[MAXPATHLEN];
	int i, ret;

	if (!conf->rootfs.path)
		return 0;

	for (i = 0; i < tty_info->nbtty; i++) {

		struct lxc_pty_info *pty_info = &tty_info->pty_info[i];

		ret = snprintf(path, sizeof(path), "/dev/tty%d", i + 1);
		if (ret >= sizeof(path)) {
			ERROR("pathname too long for ttys");
			return -1;
		}
		if (ttydir) {
			/* create dev/lxc/tty%d" */
			ret = snprintf(lxcpath, sizeof(lxcpath), "/dev/%s/tty%d", ttydir, i + 1);
			if (ret >= sizeof(lxcpath)) {
				ERROR("pathname too long for ttys");
				return -1;
			}
			ret = creat(lxcpath, 0660);
			if (ret==-1 && errno != EEXIST) {
				SYSERROR("error creating %s", lxcpath);
				return -1;
			}
			if (ret >= 0)
				close(ret);
			ret = unlink(path);
			if (ret && errno != ENOENT) {
				SYSERROR("error unlinking %s", path);
				return -1;
			}

			if (mount(pty_info->name, lxcpath, "none", MS_BIND, 0)) {
				WARN("failed to mount '%s'->'%s'",
				     pty_info->name, path);
				continue;
			}

			ret = snprintf(lxcpath, sizeof(lxcpath), "%s/tty%d", ttydir, i+1);
			if (ret >= sizeof(lxcpath)) {
				ERROR("tty pathname too long");
				return -1;
			}
			ret = symlink(lxcpath, path);
			if (ret) {
				SYSERROR("failed to create symlink for tty %d", i+1);
				return -1;
			}
		} else {
			/* If we populated /dev, then we need to create /dev/ttyN */
			if (access(path, F_OK)) {
				ret = creat(path, 0660);
				if (ret==-1) {
					SYSERROR("error creating %s", path);
					/* this isn't fatal, continue */
				} else {
					close(ret);
				}
			}
			if (mount(pty_info->name, path, "none", MS_BIND, 0)) {
				SYSERROR("failed to mount '%s'->'%s'", pty_info->name, path);
				continue;
			}
		}
		if (!append_ptyname(&conf->pty_names, pty_info->name)) {
			ERROR("Error setting up container_ttys string");
			return -1;
		}
	}

	INFO("%d tty(s) has been setup", tty_info->nbtty);

	return 0;
}


static int setup_rootfs_pivot_root(const char *rootfs)
{
	int oldroot = -1, newroot = -1;

	oldroot = open("/", O_DIRECTORY | O_RDONLY);
	if (oldroot < 0) {
		SYSERROR("Error opening old-/ for fchdir");
		return -1;
	}
	newroot = open(rootfs, O_DIRECTORY | O_RDONLY);
	if (newroot < 0) {
		SYSERROR("Error opening new-/ for fchdir");
		goto fail;
	}

	/* change into new root fs */
	if (fchdir(newroot)) {
		SYSERROR("can't chdir to new rootfs '%s'", rootfs);
		goto fail;
	}

	/* pivot_root into our new root fs */
	if (pivot_root(".", ".")) {
		SYSERROR("pivot_root syscall failed");
		goto fail;
	}

	/*
	 * at this point the old-root is mounted on top of our new-root
	 * To unmounted it we must not be chdir'd into it, so escape back
	 * to old-root
	 */
	if (fchdir(oldroot) < 0) {
		SYSERROR("Error entering oldroot");
		goto fail;
	}
	if (umount2(".", MNT_DETACH) < 0) {
		SYSERROR("Error detaching old root");
		goto fail;
	}

	if (fchdir(newroot) < 0) {
		SYSERROR("Error re-entering newroot");
		goto fail;
	}

	close(oldroot);
	close(newroot);

	DEBUG("pivot_root syscall to '%s' successful", rootfs);

	return 0;

fail:
	if (oldroot != -1)
		close(oldroot);
	if (newroot != -1)
		close(newroot);
	return -1;
}

/*
 * Just create a path for /dev under $lxcpath/$name and in rootfs
 * If we hit an error, log it but don't fail yet.
 */
static int mount_autodev(const char *name, const struct lxc_rootfs *rootfs, const char *lxcpath)
{
	int ret;
	size_t clen;
	char *path;

	INFO("Mounting container /dev");

	/* $(rootfs->mount) + "/dev/pts" + '\0' */
	clen = (rootfs->path ? strlen(rootfs->mount) : 0) + 9;
	path = alloca(clen);

	ret = snprintf(path, clen, "%s/dev", rootfs->path ? rootfs->mount : "");
	if (ret < 0 || ret >= clen)
		return -1;

	if (!dir_exists(path)) {
		WARN("No /dev in container.");
		WARN("Proceeding without autodev setup");
		return 0;
	}

	ret = safe_mount("none", path, "tmpfs", 0, "size=500000,mode=755",
			rootfs->path ? rootfs->mount : NULL);
	if (ret != 0) {
		SYSERROR("Failed mounting tmpfs onto %s\n", path);
		return -1;
	}

	INFO("Mounted tmpfs onto %s",  path);

	ret = snprintf(path, clen, "%s/dev/pts", rootfs->path ? rootfs->mount : "");
	if (ret < 0 || ret >= clen)
		return -1;

	/*
	 * If we are running on a devtmpfs mapping, dev/pts may already exist.
	 * If not, then create it and exit if that fails...
	 */
	if (!dir_exists(path)) {
		ret = mkdir(path, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
		if (ret) {
			SYSERROR("Failed to create /dev/pts in container");
			return -1;
		}
	}

	INFO("Mounted container /dev");
	return 0;
}

struct lxc_devs {
	const char *name;
	mode_t mode;
	int maj;
	int min;
};

static const struct lxc_devs lxc_devs[] = {
	{ "null",	S_IFCHR | S_IRWXU | S_IRWXG | S_IRWXO, 1, 3	},
	{ "zero",	S_IFCHR | S_IRWXU | S_IRWXG | S_IRWXO, 1, 5	},
	{ "full",	S_IFCHR | S_IRWXU | S_IRWXG | S_IRWXO, 1, 7	},
	{ "urandom",	S_IFCHR | S_IRWXU | S_IRWXG | S_IRWXO, 1, 9	},
	{ "random",	S_IFCHR | S_IRWXU | S_IRWXG | S_IRWXO, 1, 8	},
	{ "tty",	S_IFCHR | S_IRWXU | S_IRWXG | S_IRWXO, 5, 0	},
	{ "console",	S_IFCHR | S_IRUSR | S_IWUSR,	       5, 1	},
};

static int fill_autodev(const struct lxc_rootfs *rootfs, bool mount_console)
{
	int ret;
	char path[MAXPATHLEN];
	int i;
	mode_t cmask;

	INFO("Creating initial consoles under container /dev");

	ret = snprintf(path, MAXPATHLEN, "%s/dev", rootfs->path ? rootfs->mount : "");
	if (ret < 0 || ret >= MAXPATHLEN) {
		ERROR("Error calculating container /dev location");
		return -1;
	}

	if (!dir_exists(path)) // ignore, just don't try to fill in
		return 0;

	INFO("Populating container /dev");
	cmask = umask(S_IXUSR | S_IXGRP | S_IXOTH);
	for (i = 0; i < sizeof(lxc_devs) / sizeof(lxc_devs[0]); i++) {
		const struct lxc_devs *d = &lxc_devs[i];

		if (!strcmp(d->name, "console") && !mount_console)
			continue;

		ret = snprintf(path, MAXPATHLEN, "%s/dev/%s", rootfs->path ? rootfs->mount : "", d->name);
		if (ret < 0 || ret >= MAXPATHLEN)
			return -1;
		ret = mknod(path, d->mode, makedev(d->maj, d->min));
		if (ret && errno != EEXIST) {
			char hostpath[MAXPATHLEN];
			FILE *pathfile;

			// Unprivileged containers cannot create devices, so
			// bind mount the device from the host
			ret = snprintf(hostpath, MAXPATHLEN, "/dev/%s", d->name);
			if (ret < 0 || ret >= MAXPATHLEN)
				return -1;
			pathfile = fopen(path, "wb");
			if (!pathfile) {
				SYSERROR("Failed to create device mount target '%s'", path);
				return -1;
			}
			fclose(pathfile);
			if (safe_mount(hostpath, path, 0, MS_BIND, NULL,
						rootfs->path ? rootfs->mount : NULL) != 0) {
				SYSERROR("Failed bind mounting device %s from host into container",
					d->name);
				return -1;
			}
		}
	}
	umask(cmask);

	INFO("Populated container /dev");
	return 0;
}

static int setup_rootfs(struct lxc_conf *conf)
{
	const struct lxc_rootfs *rootfs = &conf->rootfs;

	if (!rootfs->path) {
		if (mount("", "/", NULL, MS_SLAVE|MS_REC, 0)) {
			SYSERROR("Failed to make / rslave");
			return -1;
		}
		return 0;
	}

	if (access(rootfs->mount, F_OK)) {
		SYSERROR("failed to access to '%s', check it is present",
			 rootfs->mount);
		return -1;
	}

	// First try mounting rootfs using a bdev
	struct bdev *bdev = bdev_init(conf, rootfs->path, rootfs->mount, rootfs->options);
	if (bdev && bdev->ops->mount(bdev) == 0) {
		bdev_put(bdev);
		DEBUG("mounted '%s' on '%s'", rootfs->path, rootfs->mount);
		return 0;
	}
	if (bdev)
		bdev_put(bdev);
	if (mount_rootfs(rootfs->path, rootfs->mount, rootfs->options)) {
		ERROR("failed to mount rootfs");
		return -1;
	}

	DEBUG("mounted '%s' on '%s'", rootfs->path, rootfs->mount);

	return 0;
}

int prepare_ramfs_root(char *root)
{
	char buf[LINELEN], *p;
	char nroot[PATH_MAX];
	FILE *f;
	int i;
	char *p2;

	if (realpath(root, nroot) == NULL)
		return -1;

	if (chdir("/") == -1)
		return -1;

	/*
	 * We could use here MS_MOVE, but in userns this mount is
	 * locked and can't be moved.
	 */
	if (mount(root, "/", NULL, MS_REC | MS_BIND, NULL)) {
		SYSERROR("Failed to move %s into /", root);
		return -1;
	}

	if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)) {
		SYSERROR("Failed to make . rprivate");
		return -1;
	}

	/*
	 * The following code cleans up inhereted mounts which are not
	 * required for CT.
	 *
	 * The mountinfo file shows not all mounts, if a few points have been
	 * unmounted between read operations from the mountinfo. So we need to
	 * read mountinfo a few times.
	 *
	 * This loop can be skipped if a container uses unserns, because all
	 * inherited mounts are locked and we should live with all this trash.
	 */
	while (1) {
		int progress = 0;

		f = fopen("./proc/self/mountinfo", "r");
		if (!f) {
			SYSERROR("Unable to open /proc/self/mountinfo");
			return -1;
		}
		while (fgets(buf, LINELEN, f)) {
			for (p = buf, i=0; p && i < 4; i++)
				p = strchr(p+1, ' ');
			if (!p)
				continue;
			p2 = strchr(p+1, ' ');
			if (!p2)
				continue;

			*p2 = '\0';
			*p = '.';

			if (strcmp(p + 1, "/") == 0)
				continue;
			if (strcmp(p + 1, "/proc") == 0)
				continue;

			if (umount2(p, MNT_DETACH) == 0)
				progress++;
		}
		fclose(f);
		if (!progress)
			break;
	}

	/* This also can be skipped if a container uses unserns */
	umount2("./proc", MNT_DETACH);

	/* It is weird, but chdir("..") moves us in a new root */
	if (chdir("..") == -1) {
		SYSERROR("Unable to change working directory");
		return -1;
	}

	if (chroot(".") == -1) {
		SYSERROR("Unable to chroot");
		return -1;
	}

	return 0;
}

static int setup_pivot_root(const struct lxc_rootfs *rootfs)
{
	if (!rootfs->path)
		return 0;

	if (detect_ramfs_rootfs()) {
		if (prepare_ramfs_root(rootfs->mount))
			return -1;
	} else if (setup_rootfs_pivot_root(rootfs->mount)) {
		ERROR("failed to setup pivot root");
		return -1;
	}

	return 0;
}

static int setup_pts(int pts)
{
	char target[PATH_MAX];

	if (!pts)
		return 0;

	if (!access("/dev/pts/ptmx", F_OK) && umount("/dev/pts")) {
		SYSERROR("failed to umount 'dev/pts'");
		return -1;
	}

	if (mkdir("/dev/pts", 0755)) {
		if ( errno != EEXIST ) {
		    SYSERROR("failed to create '/dev/pts'");
		    return -1;
		}
	}

	if (mount("devpts", "/dev/pts", "devpts", MS_MGC_VAL,
		  "newinstance,ptmxmode=0666,mode=0620,gid=5")) {
		SYSERROR("failed to mount a new instance of '/dev/pts'");
		return -1;
	}

	if (access("/dev/ptmx", F_OK)) {
		if (!symlink("/dev/pts/ptmx", "/dev/ptmx"))
			goto out;
		SYSERROR("failed to symlink '/dev/pts/ptmx'->'/dev/ptmx'");
		return -1;
	}

	if (realpath("/dev/ptmx", target) && !strcmp(target, "/dev/pts/ptmx"))
		goto out;

	/* fallback here, /dev/pts/ptmx exists just mount bind */
	if (mount("/dev/pts/ptmx", "/dev/ptmx", "none", MS_BIND, 0)) {
		SYSERROR("mount failed '/dev/pts/ptmx'->'/dev/ptmx'");
		return -1;
	}

	INFO("created new pts instance");

out:
	return 0;
}

static int setup_personality(int persona)
{
	#if HAVE_SYS_PERSONALITY_H
	if (persona == -1)
		return 0;

	if (personality(persona) < 0) {
		SYSERROR("failed to set personality to '0x%x'", persona);
		return -1;
	}

	INFO("set personality to '0x%x'", persona);
	#endif

	return 0;
}

static int setup_dev_console(const struct lxc_rootfs *rootfs,
			 const struct lxc_console *console)
{
	char path[MAXPATHLEN];
	int ret, fd;

	ret = snprintf(path, sizeof(path), "%s/dev/console", rootfs->mount);
	if (ret >= sizeof(path)) {
		ERROR("console path too long");
		return -1;
	}

	fd = open(path, O_CREAT | O_EXCL, S_IXUSR | S_IXGRP | S_IXOTH);
	if (fd < 0) {
		if (errno != EEXIST) {
			SYSERROR("failed to create console");
			return -1;
		}
	} else {
		close(fd);
	}

	if (console->master < 0) {
		INFO("no console");
		return 0;
	}

	if (chmod(console->name, S_IXUSR | S_IXGRP | S_IXOTH)) {
		SYSERROR("failed to set mode '0%o' to '%s'",
			 S_IXUSR | S_IXGRP | S_IXOTH, console->name);
		return -1;
	}

	if (safe_mount(console->name, path, "none", MS_BIND, 0, rootfs->mount)) {
		ERROR("failed to mount '%s' on '%s'", console->name, path);
		return -1;
	}

	INFO("console has been setup");
	return 0;
}

static int setup_ttydir_console(const struct lxc_rootfs *rootfs,
			 const struct lxc_console *console,
			 char *ttydir)
{
	char path[MAXPATHLEN], lxcpath[MAXPATHLEN];
	int ret;

	/* create rootfs/dev/<ttydir> directory */
	ret = snprintf(path, sizeof(path), "%s/dev/%s", rootfs->mount,
		       ttydir);
	if (ret >= sizeof(path))
		return -1;
	ret = mkdir(path, 0755);
	if (ret && errno != EEXIST) {
		SYSERROR("failed with errno %d to create %s", errno, path);
		return -1;
	}
	INFO("created %s", path);

	ret = snprintf(lxcpath, sizeof(lxcpath), "%s/dev/%s/console",
		       rootfs->mount, ttydir);
	if (ret >= sizeof(lxcpath)) {
		ERROR("console path too long");
		return -1;
	}

	snprintf(path, sizeof(path), "%s/dev/console", rootfs->mount);
	ret = unlink(path);
	if (ret && errno != ENOENT) {
		SYSERROR("error unlinking %s", path);
		return -1;
	}

	ret = creat(lxcpath, 0660);
	if (ret==-1 && errno != EEXIST) {
		SYSERROR("error %d creating %s", errno, lxcpath);
		return -1;
	}
	if (ret >= 0)
		close(ret);

	if (console->master < 0) {
		INFO("no console");
		return 0;
	}

	if (safe_mount(console->name, lxcpath, "none", MS_BIND, 0, rootfs->mount)) {
		ERROR("failed to mount '%s' on '%s'", console->name, lxcpath);
		return -1;
	}

	/* create symlink from rootfs/dev/console to 'lxc/console' */
	ret = snprintf(lxcpath, sizeof(lxcpath), "%s/console", ttydir);
	if (ret >= sizeof(lxcpath)) {
		ERROR("lxc/console path too long");
		return -1;
	}
	ret = symlink(lxcpath, path);
	if (ret) {
		SYSERROR("failed to create symlink for console");
		return -1;
	}

	INFO("console has been setup on %s", lxcpath);

	return 0;
}

static int setup_console(const struct lxc_rootfs *rootfs,
			 const struct lxc_console *console,
			 char *ttydir)
{
	/* We don't have a rootfs, /dev/console will be shared */
	if (!rootfs->path)
		return 0;
	if (!ttydir)
		return setup_dev_console(rootfs, console);

	return setup_ttydir_console(rootfs, console, ttydir);
}

static int setup_kmsg(const struct lxc_rootfs *rootfs,
		       const struct lxc_console *console)
{
	char kpath[MAXPATHLEN];
	int ret;

	if (!rootfs->path)
		return 0;
	ret = snprintf(kpath, sizeof(kpath), "%s/dev/kmsg", rootfs->mount);
	if (ret < 0 || ret >= sizeof(kpath))
		return -1;

	ret = unlink(kpath);
	if (ret && errno != ENOENT) {
		SYSERROR("error unlinking %s", kpath);
		return -1;
	}

	ret = symlink("console", kpath);
	if (ret) {
		SYSERROR("failed to create symlink for kmsg");
		return -1;
	}

	return 0;
}

static void parse_mntopt(char *opt, unsigned long *flags, char **data)
{
	struct mount_opt *mo;

	/* If opt is found in mount_opt, set or clear flags.
	 * Otherwise append it to data. */

	for (mo = &mount_opt[0]; mo->name != NULL; mo++) {
		if (!strncmp(opt, mo->name, strlen(mo->name))) {
			if (mo->clear)
				*flags &= ~mo->flag;
			else
				*flags |= mo->flag;
			return;
		}
	}

	if (strlen(*data))
		strcat(*data, ",");
	strcat(*data, opt);
}

int parse_mntopts(const char *mntopts, unsigned long *mntflags,
			 char **mntdata)
{
	char *s, *data;
	char *p, *saveptr = NULL;

	*mntdata = NULL;
	*mntflags = 0L;

	if (!mntopts)
		return 0;

	s = strdup(mntopts);
	if (!s) {
		SYSERROR("failed to allocate memory");
		return -1;
	}

	data = malloc(strlen(s) + 1);
	if (!data) {
		SYSERROR("failed to allocate memory");
		free(s);
		return -1;
	}
	*data = 0;

	for (p = strtok_r(s, ",", &saveptr); p != NULL;
	     p = strtok_r(NULL, ",", &saveptr))
		parse_mntopt(p, mntflags, &data);

	if (*data)
		*mntdata = data;
	else
		free(data);
	free(s);

	return 0;
}

static void null_endofword(char *word)
{
	while (*word && *word != ' ' && *word != '\t')
		word++;
	*word = '\0';
}

/*
 * skip @nfields spaces in @src
 */
static char *get_field(char *src, int nfields)
{
	char *p = src;
	int i;

	for (i = 0; i < nfields; i++) {
		while (*p && *p != ' ' && *p != '\t')
			p++;
		if (!*p)
			break;
		p++;
	}
	return p;
}

static int mount_entry(const char *fsname, const char *target,
		       const char *fstype, unsigned long mountflags,
		       const char *data, int optional, int dev, const char *rootfs)
{
#ifdef HAVE_STATVFS
	struct statvfs sb;
#endif

	if (safe_mount(fsname, target, fstype, mountflags & ~MS_REMOUNT, data, rootfs)) {
		if (optional) {
			INFO("failed to mount '%s' on '%s' (optional): %s", fsname,
			     target, strerror(errno));
			return 0;
		}
		else {
			SYSERROR("failed to mount '%s' on '%s'", fsname, target);
			return -1;
		}
	}

	if ((mountflags & MS_REMOUNT) || (mountflags & MS_BIND)) {
		DEBUG("remounting %s on %s to respect bind or remount options",
		      fsname ? fsname : "(none)", target ? target : "(none)");
		unsigned long rqd_flags = 0;
		if (mountflags & MS_RDONLY)
			rqd_flags |= MS_RDONLY;
#ifdef HAVE_STATVFS
		if (statvfs(fsname, &sb) == 0) {
			unsigned long required_flags = rqd_flags;
			if (sb.f_flag & MS_NOSUID)
				required_flags |= MS_NOSUID;
			if (sb.f_flag & MS_NODEV && !dev)
				required_flags |= MS_NODEV;
			if (sb.f_flag & MS_RDONLY)
				required_flags |= MS_RDONLY;
			if (sb.f_flag & MS_NOEXEC)
				required_flags |= MS_NOEXEC;
			DEBUG("(at remount) flags for %s was %lu, required extra flags are %lu", fsname, sb.f_flag, required_flags);
			/*
			 * If this was a bind mount request, and required_flags
			 * does not have any flags which are not already in
			 * mountflags, then skip the remount
			 */
			if (!(mountflags & MS_REMOUNT)) {
				if (!(required_flags & ~mountflags) && rqd_flags == 0) {
					DEBUG("mountflags already was %lu, skipping remount",
						mountflags);
					goto skipremount;
				}
			}
			mountflags |= required_flags;
		}
#endif

		if (mount(fsname, target, fstype,
			  mountflags | MS_REMOUNT, data) < 0) {
			if (optional) {
				INFO("failed to mount '%s' on '%s' (optional): %s",
					 fsname, target, strerror(errno));
				return 0;
			}
			else {
				SYSERROR("failed to mount '%s' on '%s'",
					 fsname, target);
				return -1;
			}
		}
	}

#ifdef HAVE_STATVFS
skipremount:
#endif
	DEBUG("mounted '%s' on '%s', type '%s'", fsname, target, fstype);

	return 0;
}

/*
 * Remove 'optional', 'create=dir', and 'create=file' from mntopt
 */
static void cull_mntent_opt(struct mntent *mntent)
{
	int i;
	char *p, *p2;
	char *list[] = {"create=dir",
			"create=file",
			"optional",
			NULL };

	for (i=0; list[i]; i++) {
		if (!(p = strstr(mntent->mnt_opts, list[i])))
			continue;
		p2 = strchr(p, ',');
		if (!p2) {
			/* no more mntopts, so just chop it here */
			*p = '\0';
			continue;
		}
		memmove(p, p2+1, strlen(p2+1)+1);
	}
}

static int mount_entry_create_dir_file(const struct mntent *mntent,
				       const char* path, const struct lxc_rootfs *rootfs,
				       const char *lxc_name, const char *lxc_path)
{
	char *pathdirname = NULL;
	int ret = 0;
	FILE *pathfile = NULL;

	if (strncmp(mntent->mnt_type, "overlay", 7) == 0) {
		if (ovl_mkdir(mntent, rootfs, lxc_name, lxc_path) < 0)
			return -1;
	} else if (strncmp(mntent->mnt_type, "aufs", 4) == 0) {
		if (aufs_mkdir(mntent, rootfs, lxc_name, lxc_path) < 0)
			return -1;
	}

	if (hasmntopt(mntent, "create=dir")) {
		if (mkdir_p(path, 0755) < 0) {
			WARN("Failed to create mount target '%s'", path);
			ret = -1;
		}
	}

	if (hasmntopt(mntent, "create=file") && access(path, F_OK)) {
		pathdirname = strdup(path);
		pathdirname = dirname(pathdirname);
		if (mkdir_p(pathdirname, 0755) < 0) {
			WARN("Failed to create target directory");
		}
		pathfile = fopen(path, "wb");
		if (!pathfile) {
			WARN("Failed to create mount target '%s'", path);
			ret = -1;
		} else {
			fclose(pathfile);
		}
	}
	free(pathdirname);
	return ret;
}

/* rootfs, lxc_name, and lxc_path can be NULL when the container is created
 * without a rootfs. */
static inline int mount_entry_on_generic(struct mntent *mntent,
                 const char* path, const struct lxc_rootfs *rootfs,
		 const char *lxc_name, const char *lxc_path)
{
	unsigned long mntflags;
	char *mntdata;
	int ret;
	bool optional = hasmntopt(mntent, "optional") != NULL;
	bool dev = hasmntopt(mntent, "dev") != NULL;

	char *rootfs_path = NULL;
	if (rootfs && rootfs->path)
		rootfs_path = rootfs->mount;

	ret = mount_entry_create_dir_file(mntent, path, rootfs, lxc_name, lxc_path);

	if (ret < 0)
		return optional ? 0 : -1;

	cull_mntent_opt(mntent);

	if (parse_mntopts(mntent->mnt_opts, &mntflags, &mntdata) < 0) {
		free(mntdata);
		return -1;
	}

	ret = mount_entry(mntent->mnt_fsname, path, mntent->mnt_type, mntflags,
			  mntdata, optional, dev, rootfs_path);

	free(mntdata);
	return ret;
}

static inline int mount_entry_on_systemfs(struct mntent *mntent)
{
	char path[MAXPATHLEN];
	int ret;

	/* For containers created without a rootfs all mounts are treated as
	 * absolute paths starting at / on the host. */
	if (mntent->mnt_dir[0] != '/')
		ret = snprintf(path, sizeof(path), "/%s", mntent->mnt_dir);
	else
		ret = snprintf(path, sizeof(path), "%s", mntent->mnt_dir);

	if (ret < 0 || ret >= sizeof(path)) {
		ERROR("path name too long");
		return -1;
	}

	return mount_entry_on_generic(mntent, path, NULL, NULL, NULL);
}

static int mount_entry_on_absolute_rootfs(struct mntent *mntent,
					  const struct lxc_rootfs *rootfs,
					  const char *lxc_name,
					  const char *lxc_path)
{
	char *aux;
	char path[MAXPATHLEN];
	int r, ret = 0, offset;
	const char *lxcpath;

	lxcpath = lxc_global_config_value("lxc.lxcpath");
	if (!lxcpath) {
		ERROR("Out of memory");
		return -1;
	}

	/* if rootfs->path is a blockdev path, allow container fstab to
	 * use $lxcpath/CN/rootfs as the target prefix */
	r = snprintf(path, MAXPATHLEN, "%s/%s/rootfs", lxcpath, lxc_name);
	if (r < 0 || r >= MAXPATHLEN)
		goto skipvarlib;

	aux = strstr(mntent->mnt_dir, path);
	if (aux) {
		offset = strlen(path);
		goto skipabs;
	}

skipvarlib:
	aux = strstr(mntent->mnt_dir, rootfs->path);
	if (!aux) {
		WARN("ignoring mount point '%s'", mntent->mnt_dir);
		return ret;
	}
	offset = strlen(rootfs->path);

skipabs:

	r = snprintf(path, MAXPATHLEN, "%s/%s", rootfs->mount,
		 aux + offset);
	if (r < 0 || r >= MAXPATHLEN) {
		WARN("pathnme too long for '%s'", mntent->mnt_dir);
		return -1;
	}

	return mount_entry_on_generic(mntent, path, rootfs, lxc_name, lxc_path);
}

static int mount_entry_on_relative_rootfs(struct mntent *mntent,
					  const struct lxc_rootfs *rootfs,
					  const char *lxc_name,
					  const char *lxc_path)
{
	char path[MAXPATHLEN];
	int ret;

	/* relative to root mount point */
	ret = snprintf(path, sizeof(path), "%s/%s", rootfs->mount, mntent->mnt_dir);
	if (ret < 0 || ret >= sizeof(path)) {
		ERROR("path name too long");
		return -1;
	}

	return mount_entry_on_generic(mntent, path, rootfs, lxc_name, lxc_path);
}

static int mount_file_entries(const struct lxc_rootfs *rootfs, FILE *file,
	const char *lxc_name, const char *lxc_path)
{
	struct mntent mntent;
	char buf[4096];
	int ret = -1;

	while (getmntent_r(file, &mntent, buf, sizeof(buf))) {

		if (!rootfs->path) {
			if (mount_entry_on_systemfs(&mntent))
				goto out;
			continue;
		}

		/* We have a separate root, mounts are relative to it */
		if (mntent.mnt_dir[0] != '/') {
			if (mount_entry_on_relative_rootfs(&mntent, rootfs, lxc_name, lxc_path))
				goto out;
			continue;
		}

		if (mount_entry_on_absolute_rootfs(&mntent, rootfs, lxc_name, lxc_path))
			goto out;
	}

	ret = 0;

	INFO("mount points have been setup");
out:
	return ret;
}

static int setup_mount(const struct lxc_rootfs *rootfs, const char *fstab,
	const char *lxc_name, const char *lxc_path)
{
	FILE *file;
	int ret;

	if (!fstab)
		return 0;

	file = setmntent(fstab, "r");
	if (!file) {
		SYSERROR("failed to use '%s'", fstab);
		return -1;
	}

	ret = mount_file_entries(rootfs, file, lxc_name, lxc_path);

	endmntent(file);
	return ret;
}

FILE *write_mount_file(struct lxc_list *mount)
{
	FILE *file;
	struct lxc_list *iterator;
	char *mount_entry;

	file = tmpfile();
	if (!file) {
		ERROR("tmpfile error: %m");
		return NULL;
	}

	lxc_list_for_each(iterator, mount) {
		mount_entry = iterator->elem;
		fprintf(file, "%s\n", mount_entry);
	}

	rewind(file);
	return file;
}

static int setup_mount_entries(const struct lxc_rootfs *rootfs, struct lxc_list *mount,
	const char *lxc_name, const char *lxc_path)
{
	FILE *file;
	int ret;

	file = write_mount_file(mount);
	if (!file)
		return -1;

	ret = mount_file_entries(rootfs, file, lxc_name, lxc_path);

	fclose(file);
	return ret;
}

static int parse_cap(const char *cap)
{
	char *ptr = NULL;
	size_t i;
	int capid = -1;

	if (!strcmp(cap, "none"))
		return -2;

	for (i = 0; i < sizeof(caps_opt)/sizeof(caps_opt[0]); i++) {

		if (strcmp(cap, caps_opt[i].name))
			continue;

		capid = caps_opt[i].value;
		break;
	}

	if (capid < 0) {
		/* try to see if it's numeric, so the user may specify
		 * capabilities  that the running kernel knows about but
		 * we don't */
		errno = 0;
		capid = strtol(cap, &ptr, 10);
		if (!ptr || *ptr != '\0' || errno != 0)
			/* not a valid number */
			capid = -1;
		else if (capid > lxc_caps_last_cap())
			/* we have a number but it's not a valid
			 * capability */
			capid = -1;
	}

	return capid;
}

int in_caplist(int cap, struct lxc_list *caps)
{
	struct lxc_list *iterator;
	int capid;

	lxc_list_for_each(iterator, caps) {
		capid = parse_cap(iterator->elem);
		if (capid == cap)
			return 1;
	}

	return 0;
}

static int setup_caps(struct lxc_list *caps)
{
	struct lxc_list *iterator;
	char *drop_entry;
	int capid;

	lxc_list_for_each(iterator, caps) {

		drop_entry = iterator->elem;

		capid = parse_cap(drop_entry);

	        if (capid < 0) {
			ERROR("unknown capability %s", drop_entry);
			return -1;
		}

		DEBUG("drop capability '%s' (%d)", drop_entry, capid);

		if (prctl(PR_CAPBSET_DROP, capid, 0, 0, 0)) {
			SYSERROR("failed to remove %s capability", drop_entry);
			return -1;
		}

	}

	DEBUG("capabilities have been setup");

	return 0;
}

static int dropcaps_except(struct lxc_list *caps)
{
	struct lxc_list *iterator;
	char *keep_entry;
	int i, capid;
	int numcaps = lxc_caps_last_cap() + 1;
	INFO("found %d capabilities", numcaps);

	if (numcaps <= 0 || numcaps > 200)
		return -1;

	// caplist[i] is 1 if we keep capability i
	int *caplist = alloca(numcaps * sizeof(int));
	memset(caplist, 0, numcaps * sizeof(int));

	lxc_list_for_each(iterator, caps) {

		keep_entry = iterator->elem;

		capid = parse_cap(keep_entry);

		if (capid == -2)
			continue;

	        if (capid < 0) {
			ERROR("unknown capability %s", keep_entry);
			return -1;
		}

		DEBUG("keep capability '%s' (%d)", keep_entry, capid);

		caplist[capid] = 1;
	}
	for (i=0; i<numcaps; i++) {
		if (caplist[i])
			continue;
		if (prctl(PR_CAPBSET_DROP, i, 0, 0, 0)) {
			SYSERROR("failed to remove capability %d", i);
			return -1;
		}
	}

	DEBUG("capabilities have been setup");

	return 0;
}

static int setup_hw_addr(char *hwaddr, const char *ifname)
{
	struct sockaddr sockaddr;
	struct ifreq ifr;
	int ret, fd;

	ret = lxc_convert_mac(hwaddr, &sockaddr);
	if (ret) {
		ERROR("mac address '%s' conversion failed : %s",
		      hwaddr, strerror(-ret));
		return -1;
	}

	memcpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_name[IFNAMSIZ-1] = '\0';
	memcpy((char *) &ifr.ifr_hwaddr, (char *) &sockaddr, sizeof(sockaddr));

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		ERROR("socket failure : %s", strerror(errno));
		return -1;
	}

	ret = ioctl(fd, SIOCSIFHWADDR, &ifr);
	close(fd);
	if (ret)
		ERROR("ioctl failure : %s", strerror(errno));

	DEBUG("mac address '%s' on '%s' has been setup", hwaddr, ifr.ifr_name);

	return ret;
}

static int setup_ipv4_addr(struct lxc_list *ip, int ifindex)
{
	struct lxc_list *iterator;
	struct lxc_inetdev *inetdev;
	int err;

	lxc_list_for_each(iterator, ip) {

		inetdev = iterator->elem;

		err = lxc_ipv4_addr_add(ifindex, &inetdev->addr,
					&inetdev->bcast, inetdev->prefix);
		if (err) {
			ERROR("failed to setup_ipv4_addr ifindex %d : %s",
			      ifindex, strerror(-err));
			return -1;
		}
	}

	return 0;
}

static int setup_ipv6_addr(struct lxc_list *ip, int ifindex)
{
	struct lxc_list *iterator;
	struct lxc_inet6dev *inet6dev;
	int err;

	lxc_list_for_each(iterator, ip) {

		inet6dev = iterator->elem;

		err = lxc_ipv6_addr_add(ifindex, &inet6dev->addr,
					&inet6dev->mcast, &inet6dev->acast,
					inet6dev->prefix);
		if (err) {
			ERROR("failed to setup_ipv6_addr ifindex %d : %s",
			      ifindex, strerror(-err));
			return -1;
		}
	}

	return 0;
}

static int setup_netdev(struct lxc_netdev *netdev)
{
	char ifname[IFNAMSIZ];
	char *current_ifname = ifname;
	int err;

	/* empty network namespace */
	if (!netdev->ifindex) {
		if (netdev->flags & IFF_UP) {
			err = lxc_netdev_up("lo");
			if (err) {
				ERROR("failed to set the loopback up : %s",
				      strerror(-err));
				return -1;
			}
		}
		if (netdev->type != LXC_NET_VETH)
			return 0;
		netdev->ifindex = if_nametoindex(netdev->name);
	}

	/* get the new ifindex in case of physical netdev */
	if (netdev->type == LXC_NET_PHYS) {
		if (!(netdev->ifindex = if_nametoindex(netdev->link))) {
			ERROR("failed to get ifindex for %s",
				netdev->link);
			return -1;
		}
	}

	/* retrieve the name of the interface */
	if (!if_indextoname(netdev->ifindex, current_ifname)) {
		ERROR("no interface corresponding to index '%d'",
		      netdev->ifindex);
		return -1;
	}

	/* default: let the system to choose one interface name */
	if (!netdev->name)
		netdev->name = netdev->type == LXC_NET_PHYS ?
			netdev->link : "eth%d";

	/* rename the interface name */
	if (strcmp(ifname, netdev->name) != 0) {
		err = lxc_netdev_rename_by_name(ifname, netdev->name);
		if (err) {
			ERROR("failed to rename %s->%s : %s", ifname, netdev->name,
			      strerror(-err));
			return -1;
		}
	}

	/* Re-read the name of the interface because its name has changed
	 * and would be automatically allocated by the system
	 */
	if (!if_indextoname(netdev->ifindex, current_ifname)) {
		ERROR("no interface corresponding to index '%d'",
		      netdev->ifindex);
		return -1;
	}

	/* set a mac address */
	if (netdev->hwaddr) {
		if (setup_hw_addr(netdev->hwaddr, current_ifname)) {
			ERROR("failed to setup hw address for '%s'",
			      current_ifname);
			return -1;
		}
	}

	/* setup ipv4 addresses on the interface */
	if (setup_ipv4_addr(&netdev->ipv4, netdev->ifindex)) {
		ERROR("failed to setup ip addresses for '%s'",
			      ifname);
		return -1;
	}

	/* setup ipv6 addresses on the interface */
	if (setup_ipv6_addr(&netdev->ipv6, netdev->ifindex)) {
		ERROR("failed to setup ipv6 addresses for '%s'",
			      ifname);
		return -1;
	}

	/* set the network device up */
	if (netdev->flags & IFF_UP) {
		int err;

		err = lxc_netdev_up(current_ifname);
		if (err) {
			ERROR("failed to set '%s' up : %s", current_ifname,
			      strerror(-err));
			return -1;
		}

		/* the network is up, make the loopback up too */
		err = lxc_netdev_up("lo");
		if (err) {
			ERROR("failed to set the loopback up : %s",
			      strerror(-err));
			return -1;
		}
	}

	/* We can only set up the default routes after bringing
	 * up the interface, sine bringing up the interface adds
	 * the link-local routes and we can't add a default
	 * route if the gateway is not reachable. */

	/* setup ipv4 gateway on the interface */
	if (netdev->ipv4_gateway) {
		if (!(netdev->flags & IFF_UP)) {
			ERROR("Cannot add ipv4 gateway for %s when not bringing up the interface", ifname);
			return -1;
		}

		if (lxc_list_empty(&netdev->ipv4)) {
			ERROR("Cannot add ipv4 gateway for %s when not assigning an address", ifname);
			return -1;
		}

		err = lxc_ipv4_gateway_add(netdev->ifindex, netdev->ipv4_gateway);
		if (err) {
			err = lxc_ipv4_dest_add(netdev->ifindex, netdev->ipv4_gateway);
			if (err) {
				ERROR("failed to add ipv4 dest for '%s': %s",
					      ifname, strerror(-err));
			}

			err = lxc_ipv4_gateway_add(netdev->ifindex, netdev->ipv4_gateway);
			if (err) {
				ERROR("failed to setup ipv4 gateway for '%s': %s",
					      ifname, strerror(-err));
				if (netdev->ipv4_gateway_auto) {
					char buf[INET_ADDRSTRLEN];
					inet_ntop(AF_INET, netdev->ipv4_gateway, buf, sizeof(buf));
					ERROR("tried to set autodetected ipv4 gateway '%s'", buf);
				}
				return -1;
			}
		}
	}

	/* setup ipv6 gateway on the interface */
	if (netdev->ipv6_gateway) {
		if (!(netdev->flags & IFF_UP)) {
			ERROR("Cannot add ipv6 gateway for %s when not bringing up the interface", ifname);
			return -1;
		}

		if (lxc_list_empty(&netdev->ipv6) && !IN6_IS_ADDR_LINKLOCAL(netdev->ipv6_gateway)) {
			ERROR("Cannot add ipv6 gateway for %s when not assigning an address", ifname);
			return -1;
		}

		err = lxc_ipv6_gateway_add(netdev->ifindex, netdev->ipv6_gateway);
		if (err) {
			err = lxc_ipv6_dest_add(netdev->ifindex, netdev->ipv6_gateway);
			if (err) {
				ERROR("failed to add ipv6 dest for '%s': %s",
				      ifname, strerror(-err));
			}

			err = lxc_ipv6_gateway_add(netdev->ifindex, netdev->ipv6_gateway);
			if (err) {
				ERROR("failed to setup ipv6 gateway for '%s': %s",
					      ifname, strerror(-err));
				if (netdev->ipv6_gateway_auto) {
					char buf[INET6_ADDRSTRLEN];
					inet_ntop(AF_INET6, netdev->ipv6_gateway, buf, sizeof(buf));
					ERROR("tried to set autodetected ipv6 gateway '%s'", buf);
				}
				return -1;
			}
		}
	}

	DEBUG("'%s' has been setup", current_ifname);

	return 0;
}

static int setup_network(struct lxc_list *network)
{
	struct lxc_list *iterator;
	struct lxc_netdev *netdev;

	lxc_list_for_each(iterator, network) {

		netdev = iterator->elem;

		if (setup_netdev(netdev)) {
			ERROR("failed to setup netdev");
			return -1;
		}
	}

	if (!lxc_list_empty(network))
		INFO("network has been setup");

	return 0;
}

/* try to move physical nics to the init netns */
void restore_phys_nics_to_netns(int netnsfd, struct lxc_conf *conf)
{
	int i, ret, oldfd;
	char path[MAXPATHLEN];
	char ifname[IFNAMSIZ];

	if (netnsfd < 0)
		return;

	ret = snprintf(path, MAXPATHLEN, "/proc/self/ns/net");
	if (ret < 0 || ret >= MAXPATHLEN) {
		WARN("Failed to open monitor netns fd");
		return;
	}
	if ((oldfd = open(path, O_RDONLY)) < 0) {
		SYSERROR("Failed to open monitor netns fd");
		return;
	}
	if (setns(netnsfd, 0) != 0) {
		SYSERROR("Failed to enter container netns to reset nics");
		close(oldfd);
		return;
	}
	for (i=0; i<conf->num_savednics; i++) {
		struct saved_nic *s = &conf->saved_nics[i];
		/* retrieve the name of the interface */
		if (!if_indextoname(s->ifindex, ifname)) {
			WARN("no interface corresponding to index '%d'", s->ifindex);
			continue;
		}
		if (lxc_netdev_move_by_name(ifname, 1, NULL))
			WARN("Error moving nic name:%s back to host netns", ifname);
	}
	if (setns(oldfd, 0) != 0)
		SYSERROR("Failed to re-enter monitor's netns");
	close(oldfd);
}

void lxc_rename_phys_nics_on_shutdown(int netnsfd, struct lxc_conf *conf)
{
	int i;

	if (conf->num_savednics == 0)
		return;

	INFO("running to reset %d nic names", conf->num_savednics);
	restore_phys_nics_to_netns(netnsfd, conf);
	for (i=0; i<conf->num_savednics; i++) {
		struct saved_nic *s = &conf->saved_nics[i];
		INFO("resetting nic %d to %s", s->ifindex, s->orig_name);
		lxc_netdev_rename_by_index(s->ifindex, s->orig_name);
		free(s->orig_name);
	}
	conf->num_savednics = 0;
}

static char *default_rootfs_mount = LXCROOTFSMOUNT;

struct lxc_conf *lxc_conf_init(void)
{
	struct lxc_conf *new;
	int i;

	new = 	malloc(sizeof(*new));
	if (!new) {
		ERROR("lxc_conf_init : %m");
		return NULL;
	}
	memset(new, 0, sizeof(*new));

	new->loglevel = LXC_LOG_PRIORITY_NOTSET;
	new->personality = -1;
	new->autodev = 1;
	new->console.log_path = NULL;
	new->console.log_fd = -1;
	new->console.path = NULL;
	new->console.peer = -1;
	new->console.peerpty.busy = -1;
	new->console.peerpty.master = -1;
	new->console.peerpty.slave = -1;
	new->console.master = -1;
	new->console.slave = -1;
	new->console.name[0] = '\0';
	new->maincmd_fd = -1;
	new->nbd_idx = -1;
	new->rootfs.mount = strdup(default_rootfs_mount);
	if (!new->rootfs.mount) {
		ERROR("lxc_conf_init : %m");
		free(new);
		return NULL;
	}
	new->kmsg = 0;
	new->logfd = -1;
	lxc_list_init(&new->cgroup);
	lxc_list_init(&new->network);
	lxc_list_init(&new->mount_list);
	lxc_list_init(&new->caps);
	lxc_list_init(&new->keepcaps);
	lxc_list_init(&new->id_map);
	lxc_list_init(&new->includes);
	lxc_list_init(&new->aliens);
	lxc_list_init(&new->environment);
	for (i=0; i<NUM_LXC_HOOKS; i++)
		lxc_list_init(&new->hooks[i]);
	lxc_list_init(&new->groups);
	new->lsm_aa_profile = NULL;
	new->lsm_se_context = NULL;
	new->tmp_umount_proc = 0;

	for (i = 0; i < LXC_NS_MAX; i++)
		new->inherit_ns_fd[i] = -1;

	/* if running in a new user namespace, init and COMMAND
	 * default to running as UID/GID 0 when using lxc-execute */
	new->init_uid = 0;
	new->init_gid = 0;

	return new;
}

static int instantiate_veth(struct lxc_handler *handler, struct lxc_netdev *netdev)
{
	char veth1buf[IFNAMSIZ], *veth1;
	char veth2buf[IFNAMSIZ], *veth2;
	int err, mtu = 0;

	if (netdev->priv.veth_attr.pair) {
		veth1 = netdev->priv.veth_attr.pair;
		if (handler->conf->reboot)
			lxc_netdev_delete_by_name(veth1);
	} else {
		err = snprintf(veth1buf, sizeof(veth1buf), "vethXXXXXX");
		if (err >= sizeof(veth1buf)) { /* can't *really* happen, but... */
			ERROR("veth1 name too long");
			return -1;
		}
		veth1 = lxc_mkifname(veth1buf);
		if (!veth1) {
			ERROR("failed to allocate a temporary name");
			return -1;
		}
		/* store away for deconf */
		memcpy(netdev->priv.veth_attr.veth1, veth1, IFNAMSIZ);
	}

	snprintf(veth2buf, sizeof(veth2buf), "vethXXXXXX");
	veth2 = lxc_mkifname(veth2buf);
	if (!veth2) {
		ERROR("failed to allocate a temporary name");
		goto out_delete;
	}

	err = lxc_veth_create(veth1, veth2);
	if (err) {
		ERROR("failed to create veth pair (%s and %s): %s", veth1, veth2,
		      strerror(-err));
		goto out_delete;
	}

	/* changing the high byte of the mac address to 0xfe, the bridge interface
	 * will always keep the host's mac address and not take the mac address
	 * of a container */
	err = setup_private_host_hw_addr(veth1);
	if (err) {
		ERROR("failed to change mac address of host interface '%s': %s",
			veth1, strerror(-err));
		goto out_delete;
	}

	netdev->ifindex = if_nametoindex(veth2);
	if (!netdev->ifindex) {
		ERROR("failed to retrieve the index for %s", veth2);
		goto out_delete;
	}

	if (netdev->mtu) {
		mtu = atoi(netdev->mtu);
	} else if (netdev->link) {
		mtu = netdev_get_mtu(netdev->ifindex);
	}

	if (mtu) {
		err = lxc_netdev_set_mtu(veth1, mtu);
		if (!err)
			err = lxc_netdev_set_mtu(veth2, mtu);
		if (err) {
			ERROR("failed to set mtu '%i' for veth pair (%s and %s): %s",
			      mtu, veth1, veth2, strerror(-err));
			goto out_delete;
		}
	}

	if (netdev->link) {
		err = lxc_bridge_attach(handler->lxcpath, handler->name, netdev->link, veth1);
		if (err) {
			ERROR("failed to attach '%s' to the bridge '%s': %s",
				      veth1, netdev->link, strerror(-err));
			goto out_delete;
		}
	}

	err = lxc_netdev_up(veth1);
	if (err) {
		ERROR("failed to set %s up : %s", veth1, strerror(-err));
		goto out_delete;
	}

	if (netdev->upscript) {
		err = run_script(handler->name, "net", netdev->upscript, "up",
				 "veth", veth1, (char*) NULL);
		if (err)
			goto out_delete;
	}

	DEBUG("instantiated veth '%s/%s', index is '%d'",
	      veth1, veth2, netdev->ifindex);

	return 0;

out_delete:
	lxc_netdev_delete_by_name(veth1);
	if (!netdev->priv.veth_attr.pair)
		free(veth1);
	free(veth2);
	return -1;
}

static int shutdown_veth(struct lxc_handler *handler, struct lxc_netdev *netdev)
{
	char *veth1;
	int err;

	if (netdev->priv.veth_attr.pair)
		veth1 = netdev->priv.veth_attr.pair;
	else
		veth1 = netdev->priv.veth_attr.veth1;

	if (netdev->downscript) {
		err = run_script(handler->name, "net", netdev->downscript,
				 "down", "veth", veth1, (char*) NULL);
		if (err)
			return -1;
	}
	return 0;
}

static int instantiate_macvlan(struct lxc_handler *handler, struct lxc_netdev *netdev)
{
	char peerbuf[IFNAMSIZ], *peer;
	int err;

	if (!netdev->link) {
		ERROR("no link specified for macvlan netdev");
		return -1;
	}

	err = snprintf(peerbuf, sizeof(peerbuf), "mcXXXXXX");
	if (err >= sizeof(peerbuf))
		return -1;

	peer = lxc_mkifname(peerbuf);
	if (!peer) {
		ERROR("failed to make a temporary name");
		return -1;
	}

	err = lxc_macvlan_create(netdev->link, peer,
				 netdev->priv.macvlan_attr.mode);
	if (err) {
		ERROR("failed to create macvlan interface '%s' on '%s' : %s",
		      peer, netdev->link, strerror(-err));
		goto out;
	}

	netdev->ifindex = if_nametoindex(peer);
	if (!netdev->ifindex) {
		ERROR("failed to retrieve the index for %s", peer);
		goto out;
	}

	if (netdev->upscript) {
		err = run_script(handler->name, "net", netdev->upscript, "up",
				 "macvlan", netdev->link, (char*) NULL);
		if (err)
			goto out;
	}

	DEBUG("instantiated macvlan '%s', index is '%d' and mode '%d'",
	      peer, netdev->ifindex, netdev->priv.macvlan_attr.mode);

	return 0;
out:
	lxc_netdev_delete_by_name(peer);
	free(peer);
	return -1;
}

static int shutdown_macvlan(struct lxc_handler *handler, struct lxc_netdev *netdev)
{
	int err;

	if (netdev->downscript) {
		err = run_script(handler->name, "net", netdev->downscript,
				 "down", "macvlan", netdev->link,
				 (char*) NULL);
		if (err)
			return -1;
	}
	return 0;
}

/* XXX: merge with instantiate_macvlan */
static int instantiate_vlan(struct lxc_handler *handler, struct lxc_netdev *netdev)
{
	char peer[IFNAMSIZ];
	int err;
	static uint16_t vlan_cntr = 0;

	if (!netdev->link) {
		ERROR("no link specified for vlan netdev");
		return -1;
	}

	err = snprintf(peer, sizeof(peer), "vlan%d-%d", netdev->priv.vlan_attr.vid, vlan_cntr++);
	if (err >= sizeof(peer)) {
		ERROR("peer name too long");
		return -1;
	}

	err = lxc_vlan_create(netdev->link, peer, netdev->priv.vlan_attr.vid);
	if (err) {
		ERROR("failed to create vlan interface '%s' on '%s' : %s",
		      peer, netdev->link, strerror(-err));
		return -1;
	}

	netdev->ifindex = if_nametoindex(peer);
	if (!netdev->ifindex) {
		ERROR("failed to retrieve the ifindex for %s", peer);
		lxc_netdev_delete_by_name(peer);
		return -1;
	}

	DEBUG("instantiated vlan '%s', ifindex is '%d'", " vlan1000",
	      netdev->ifindex);
	if (netdev->mtu) {
		err = lxc_netdev_set_mtu(peer, atoi(netdev->mtu));
		if (err) {
			ERROR("failed to set mtu '%s' for %s : %s",
			      netdev->mtu, peer, strerror(-err));
			lxc_netdev_delete_by_name(peer);
			return -1;
		}
	}

	return 0;
}

static int shutdown_vlan(struct lxc_handler *handler, struct lxc_netdev *netdev)
{
	return 0;
}

static int instantiate_phys(struct lxc_handler *handler, struct lxc_netdev *netdev)
{
	if (!netdev->link) {
		ERROR("no link specified for the physical interface");
		return -1;
	}

	netdev->ifindex = if_nametoindex(netdev->link);
	if (!netdev->ifindex) {
		ERROR("failed to retrieve the index for %s", netdev->link);
		return -1;
	}

	if (netdev->upscript) {
		int err;
		err = run_script(handler->name, "net", netdev->upscript,
				 "up", "phys", netdev->link, (char*) NULL);
		if (err)
			return -1;
	}

	return 0;
}

static int shutdown_phys(struct lxc_handler *handler, struct lxc_netdev *netdev)
{
	int err;

	if (netdev->downscript) {
		err = run_script(handler->name, "net", netdev->downscript,
				 "down", "phys", netdev->link, (char*) NULL);
		if (err)
			return -1;
	}
	return 0;
}

static int instantiate_none(struct lxc_handler *handler, struct lxc_netdev *netdev)
{
	netdev->ifindex = 0;
	return 0;
}

static int instantiate_empty(struct lxc_handler *handler, struct lxc_netdev *netdev)
{
	netdev->ifindex = 0;
	if (netdev->upscript) {
		int err;
		err = run_script(handler->name, "net", netdev->upscript,
				 "up", "empty", (char*) NULL);
		if (err)
			return -1;
	}
	return 0;
}

static int shutdown_empty(struct lxc_handler *handler, struct lxc_netdev *netdev)
{
	int err;

	if (netdev->downscript) {
		err = run_script(handler->name, "net", netdev->downscript,
				 "down", "empty", (char*) NULL);
		if (err)
			return -1;
	}
	return 0;
}

static int shutdown_none(struct lxc_handler *handler, struct lxc_netdev *netdev)
{
	return 0;
}

int lxc_requests_empty_network(struct lxc_handler *handler)
{
	struct lxc_list *network = &handler->conf->network;
	struct lxc_list *iterator;
	struct lxc_netdev *netdev;
	bool found_none = false, found_nic = false;

	if (lxc_list_empty(network))
		return 0;

	lxc_list_for_each(iterator, network) {

		netdev = iterator->elem;

		if (netdev->type == LXC_NET_NONE)
			found_none = true;
		else
			found_nic = true;
	}
	if (found_none && !found_nic)
		return 1;
	return 0;
}

int lxc_create_network(struct lxc_handler *handler)
{
	struct lxc_list *network = &handler->conf->network;
	struct lxc_list *iterator;
	struct lxc_netdev *netdev;
	int am_root = (getuid() == 0);

	if (!am_root)
		return 0;

	lxc_list_for_each(iterator, network) {

		netdev = iterator->elem;

		if (netdev->type < 0 || netdev->type > LXC_NET_MAXCONFTYPE) {
			ERROR("invalid network configuration type '%d'",
			      netdev->type);
			return -1;
		}

		if (netdev_conf[netdev->type](handler, netdev)) {
			ERROR("failed to create netdev");
			return -1;
		}

	}

	return 0;
}

void lxc_delete_network(struct lxc_handler *handler)
{
	struct lxc_list *network = &handler->conf->network;
	struct lxc_list *iterator;
	struct lxc_netdev *netdev;

	lxc_list_for_each(iterator, network) {
		netdev = iterator->elem;

		if (netdev->ifindex != 0 && netdev->type == LXC_NET_PHYS) {
			if (lxc_netdev_rename_by_index(netdev->ifindex, netdev->link))
				WARN("failed to rename to the initial name the " \
				     "netdev '%s'", netdev->link);
			continue;
		}

		if (netdev_deconf[netdev->type](handler, netdev)) {
			WARN("failed to destroy netdev");
		}

		/* Recent kernel remove the virtual interfaces when the network
		 * namespace is destroyed but in case we did not moved the
		 * interface to the network namespace, we have to destroy it
		 */
		if (netdev->ifindex != 0 &&
		    lxc_netdev_delete_by_index(netdev->ifindex))
			WARN("failed to remove interface %d '%s'",
				netdev->ifindex,
				netdev->name ? netdev->name : "(null)");
	}
}

#define LXC_USERNIC_PATH LIBEXECDIR "/lxc/lxc-user-nic"

/* lxc-user-nic returns "interface_name:interface_name\n" */
#define MAX_BUFFER_SIZE IFNAMSIZ*2 + 2
static int unpriv_assign_nic(const char *lxcpath, char *lxcname,
			     struct lxc_netdev *netdev, pid_t pid)
{
	pid_t child;
	int bytes, pipefd[2];
	char *token, *saveptr = NULL;
	char buffer[MAX_BUFFER_SIZE];
	char netdev_link[IFNAMSIZ+1];

	if (netdev->type != LXC_NET_VETH) {
		ERROR("nic type %d not support for unprivileged use",
			netdev->type);
		return -1;
	}

	if(pipe(pipefd) < 0) {
		SYSERROR("pipe failed");
		return -1;
	}

	if ((child = fork()) < 0) {
		SYSERROR("fork");
		close(pipefd[0]);
		close(pipefd[1]);
		return -1;
	}

	if (child == 0) { // child
		/* close the read-end of the pipe */
		close(pipefd[0]);
		/* redirect the stdout to write-end of the pipe */
		dup2(pipefd[1], STDOUT_FILENO);
		/* close the write-end of the pipe */
		close(pipefd[1]);

		// Call lxc-user-nic pid type bridge
		char pidstr[20];
		if (netdev->link) {
			strncpy(netdev_link, netdev->link, IFNAMSIZ);
		} else {
			strncpy(netdev_link, "none", IFNAMSIZ);
		}
		snprintf(pidstr, 19, "%lu", (unsigned long) pid);
		pidstr[19] = '\0';
		execlp(LXC_USERNIC_PATH, LXC_USERNIC_PATH, lxcpath, lxcname,
				pidstr, "veth", netdev_link, netdev->name, NULL);
		SYSERROR("execvp lxc-user-nic");
		exit(1);
	}

	/* close the write-end of the pipe */
	close(pipefd[1]);

	bytes = read(pipefd[0], &buffer, MAX_BUFFER_SIZE);
	if (bytes < 0) {
		SYSERROR("read failed");
	}
	buffer[bytes - 1] = '\0';

	if (wait_for_pid(child) != 0) {
		close(pipefd[0]);
		return -1;
	}

	/* close the read-end of the pipe */
	close(pipefd[0]);

	/* fill netdev->name field */
	token = strtok_r(buffer, ":", &saveptr);
	if (!token)
		return -1;
	netdev->name = malloc(IFNAMSIZ+1);
	if (!netdev->name) {
		ERROR("Out of memory");
		return -1;
	}
	memset(netdev->name, 0, IFNAMSIZ+1);
	strncpy(netdev->name, token, IFNAMSIZ);

	/* fill netdev->veth_attr.pair field */
	token = strtok_r(NULL, ":", &saveptr);
	if (!token)
		return -1;
	netdev->priv.veth_attr.pair = strdup(token);
	if (!netdev->priv.veth_attr.pair) {
		ERROR("Out of memory");
		return -1;
	}

	return 0;
}

int lxc_assign_network(const char *lxcpath, char *lxcname,
		       struct lxc_list *network, pid_t pid)
{
	struct lxc_list *iterator;
	struct lxc_netdev *netdev;
	char ifname[IFNAMSIZ];
	int am_root = (getuid() == 0);
	int err;

	lxc_list_for_each(iterator, network) {

		netdev = iterator->elem;

		if (netdev->type == LXC_NET_VETH && !am_root) {
			if (unpriv_assign_nic(lxcpath, lxcname, netdev, pid))
				return -1;
			// lxc-user-nic has moved the nic to the new ns.
			// unpriv_assign_nic() fills in netdev->name.
			// netdev->ifindex will be filed in at setup_netdev.
			continue;
		}

		/* empty network namespace, nothing to move */
		if (!netdev->ifindex)
			continue;

		/* retrieve the name of the interface */
		if (!if_indextoname(netdev->ifindex, ifname)) {
			ERROR("no interface corresponding to index '%d'", netdev->ifindex);
			return -1;
		}

		err = lxc_netdev_move_by_name(ifname, pid, NULL);
		if (err) {
			ERROR("failed to move '%s' to the container : %s",
			      netdev->link, strerror(-err));
			return -1;
		}

		DEBUG("move '%s' to '%d'", netdev->name, pid);
	}

	return 0;
}

static int write_id_mapping(enum idtype idtype, pid_t pid, const char *buf,
			    size_t buf_size)
{
	char path[PATH_MAX];
	int ret, closeret;
	FILE *f;

	ret = snprintf(path, PATH_MAX, "/proc/%d/%cid_map", pid, idtype == ID_TYPE_UID ? 'u' : 'g');
	if (ret < 0 || ret >= PATH_MAX) {
		fprintf(stderr, "%s: path name too long\n", __func__);
		return -E2BIG;
	}
	f = fopen(path, "w");
	if (!f) {
		perror("open");
		return -EINVAL;
	}
	ret = fwrite(buf, buf_size, 1, f);
	if (ret < 0)
		SYSERROR("writing id mapping");
	closeret = fclose(f);
	if (closeret)
		SYSERROR("writing id mapping");
	return ret < 0 ? ret : closeret;
}

int lxc_map_ids(struct lxc_list *idmap, pid_t pid)
{
	struct lxc_list *iterator;
	struct id_map *map;
	int ret = 0, use_shadow = 0;
	enum idtype type;
	char *buf = NULL, *pos, *cmdpath = NULL;

	/*
	 * If newuidmap exists, that is, if shadow is handing out subuid
	 * ranges, then insist that root also reserve ranges in subuid.  This
	 * will protected it by preventing another user from being handed the
	 * range by shadow.
	 */
	cmdpath = on_path("newuidmap", NULL);
	if (cmdpath) {
		use_shadow = 1;
		free(cmdpath);
	}

	if (!use_shadow && geteuid()) {
		ERROR("Missing newuidmap/newgidmap");
		return -1;
	}

	for(type = ID_TYPE_UID; type <= ID_TYPE_GID; type++) {
		int left, fill;
		int had_entry = 0;
		if (!buf) {
			buf = pos = malloc(4096);
			if (!buf)
				return -ENOMEM;
		}
		pos = buf;
		if (use_shadow)
			pos += sprintf(buf, "new%cidmap %d",
				type == ID_TYPE_UID ? 'u' : 'g',
				pid);

		lxc_list_for_each(iterator, idmap) {
			/* The kernel only takes <= 4k for writes to /proc/<nr>/[ug]id_map */
			map = iterator->elem;
			if (map->idtype != type)
				continue;

			had_entry = 1;
			left = 4096 - (pos - buf);
			fill = snprintf(pos, left, "%s%lu %lu %lu%s",
					use_shadow ? " " : "",
					map->nsid, map->hostid, map->range,
					use_shadow ? "" : "\n");
			if (fill <= 0 || fill >= left)
				SYSERROR("snprintf failed, too many mappings");
			pos += fill;
		}
		if (!had_entry)
			continue;

		if (!use_shadow) {
			ret = write_id_mapping(type, pid, buf, pos-buf);
		} else {
			left = 4096 - (pos - buf);
			fill = snprintf(pos, left, "\n");
			if (fill <= 0 || fill >= left)
				SYSERROR("snprintf failed, too many mappings");
			pos += fill;
			ret = system(buf);
		}

		if (ret)
			break;
	}

	free(buf);
	return ret;
}

/*
 * return the host uid/gid to which the container root is mapped in
 * *val.
 * Return true if id was found, false otherwise.
 */
bool get_mapped_rootid(struct lxc_conf *conf, enum idtype idtype,
			unsigned long *val)
{
	struct lxc_list *it;
	struct id_map *map;

	lxc_list_for_each(it, &conf->id_map) {
		map = it->elem;
		if (map->idtype != idtype)
			continue;
		if (map->nsid != 0)
			continue;
		*val = map->hostid;
		return true;
	}
	return false;
}

int mapped_hostid(unsigned id, struct lxc_conf *conf, enum idtype idtype)
{
	struct lxc_list *it;
	struct id_map *map;
	lxc_list_for_each(it, &conf->id_map) {
		map = it->elem;
		if (map->idtype != idtype)
			continue;
		if (id >= map->hostid && id < map->hostid + map->range)
			return (id - map->hostid) + map->nsid;
	}
	return -1;
}

int find_unmapped_nsuid(struct lxc_conf *conf, enum idtype idtype)
{
	struct lxc_list *it;
	struct id_map *map;
	unsigned int freeid = 0;
again:
	lxc_list_for_each(it, &conf->id_map) {
		map = it->elem;
		if (map->idtype != idtype)
			continue;
		if (freeid >= map->nsid && freeid < map->nsid + map->range) {
			freeid = map->nsid + map->range;
			goto again;
		}
	}
	return freeid;
}

int lxc_find_gateway_addresses(struct lxc_handler *handler)
{
	struct lxc_list *network = &handler->conf->network;
	struct lxc_list *iterator;
	struct lxc_netdev *netdev;
	int link_index;

	lxc_list_for_each(iterator, network) {
		netdev = iterator->elem;

		if (!netdev->ipv4_gateway_auto && !netdev->ipv6_gateway_auto)
			continue;

		if (netdev->type != LXC_NET_VETH && netdev->type != LXC_NET_MACVLAN) {
			ERROR("gateway = auto only supported for "
			      "veth and macvlan");
			return -1;
		}

		if (!netdev->link) {
			ERROR("gateway = auto needs a link interface");
			return -1;
		}

		link_index = if_nametoindex(netdev->link);
		if (!link_index)
			return -EINVAL;

		if (netdev->ipv4_gateway_auto) {
			if (lxc_ipv4_addr_get(link_index, &netdev->ipv4_gateway)) {
				ERROR("failed to automatically find ipv4 gateway "
				      "address from link interface '%s'", netdev->link);
				return -1;
			}
		}

		if (netdev->ipv6_gateway_auto) {
			if (lxc_ipv6_addr_get(link_index, &netdev->ipv6_gateway)) {
				ERROR("failed to automatically find ipv6 gateway "
				      "address from link interface '%s'", netdev->link);
				return -1;
			}
		}
	}

	return 0;
}

int lxc_create_tty(const char *name, struct lxc_conf *conf)
{
	struct lxc_tty_info *tty_info = &conf->tty_info;
	int i, ret;

	/* no tty in the configuration */
	if (!conf->tty)
		return 0;

	tty_info->pty_info =
		malloc(sizeof(*tty_info->pty_info)*conf->tty);
	if (!tty_info->pty_info) {
		SYSERROR("failed to allocate pty_info");
		return -1;
	}

	for (i = 0; i < conf->tty; i++) {

		struct lxc_pty_info *pty_info = &tty_info->pty_info[i];

		process_lock();
		ret = openpty(&pty_info->master, &pty_info->slave,
			    pty_info->name, NULL, NULL);
		process_unlock();
		if (ret) {
			SYSERROR("failed to create pty #%d", i);
			tty_info->nbtty = i;
			lxc_delete_tty(tty_info);
			return -1;
		}

		DEBUG("allocated pty '%s' (%d/%d)",
		      pty_info->name, pty_info->master, pty_info->slave);

		/* Prevent leaking the file descriptors to the container */
		fcntl(pty_info->master, F_SETFD, FD_CLOEXEC);
		fcntl(pty_info->slave, F_SETFD, FD_CLOEXEC);

		pty_info->busy = 0;
	}

	tty_info->nbtty = conf->tty;

	INFO("tty's configured");

	return 0;
}

void lxc_delete_tty(struct lxc_tty_info *tty_info)
{
	int i;

	for (i = 0; i < tty_info->nbtty; i++) {
		struct lxc_pty_info *pty_info = &tty_info->pty_info[i];

		close(pty_info->master);
		close(pty_info->slave);
	}

	free(tty_info->pty_info);
	tty_info->nbtty = 0;
}

/*
 * chown_mapped_root: for an unprivileged user with uid/gid X to
 * chown a dir to subuid/subgid Y, he needs to run chown as root
 * in a userns where nsid 0 is mapped to hostuid/hostgid Y, and
 * nsid Y is mapped to hostuid/hostgid X.  That way, the container
 * root is privileged with respect to hostuid/hostgid X, allowing
 * him to do the chown.
 */
int chown_mapped_root(char *path, struct lxc_conf *conf)
{
	uid_t rootuid;
	gid_t rootgid;
	pid_t pid;
	unsigned long val;
	char *chownpath = path;

	if (!get_mapped_rootid(conf, ID_TYPE_UID, &val)) {
		ERROR("No mapping for container root");
		return -1;
	}
	rootuid = (uid_t) val;
	if (!get_mapped_rootid(conf, ID_TYPE_GID, &val)) {
		ERROR("No mapping for container root");
		return -1;
	}
	rootgid = (gid_t) val;

	/*
	 * In case of overlay, we want only the writeable layer
	 * to be chowned
	 */
	if (strncmp(path, "overlayfs:", 10) == 0 || strncmp(path, "aufs:", 5) == 0) {
		chownpath = strchr(path, ':');
		if (!chownpath) {
			ERROR("Bad overlay path: %s", path);
			return -1;
		}
		chownpath = strchr(chownpath+1, ':');
		if (!chownpath) {
			ERROR("Bad overlay path: %s", path);
			return -1;
		}
		chownpath++;
	}
	path = chownpath;
	if (geteuid() == 0) {
		if (chown(path, rootuid, rootgid) < 0) {
			ERROR("Error chowning %s", path);
			return -1;
		}
		return 0;
	}

	if (rootuid == geteuid()) {
		// nothing to do
		INFO("%s: container root is our uid;  no need to chown" ,__func__);
		return 0;
	}

	pid = fork();
	if (pid < 0) {
		SYSERROR("Failed forking");
		return -1;
	}
	if (!pid) {
		int hostuid = geteuid(), hostgid = getegid(), ret;
		struct stat sb;
		char map1[100], map2[100], map3[100], map4[100], map5[100];
		char ugid[100];
		char *args1[] = { "lxc-usernsexec", "-m", map1, "-m", map2,
				"-m", map3, "-m", map5,
				"--", "chown", ugid, path, NULL };
		char *args2[] = { "lxc-usernsexec", "-m", map1, "-m", map2,
				"-m", map3, "-m", map4, "-m", map5,
				"--", "chown", ugid, path, NULL };

		// save the current gid of "path"
		if (stat(path, &sb) < 0) {
			ERROR("Error stat %s", path);
			return -1;
		}

		/*
		 * A file has to be group-owned by a gid mapped into the
		 * container, or the container won't be privileged over it.
		 */
		if (sb.st_uid == geteuid() &&
				mapped_hostid(sb.st_gid, conf, ID_TYPE_GID) < 0 &&
				chown(path, -1, hostgid) < 0) {
			ERROR("Failed chgrping %s", path);
			return -1;
		}

		// "u:0:rootuid:1"
		ret = snprintf(map1, 100, "u:0:%d:1", rootuid);
		if (ret < 0 || ret >= 100) {
			ERROR("Error uid printing map string");
			return -1;
		}

		// "u:hostuid:hostuid:1"
		ret = snprintf(map2, 100, "u:%d:%d:1", hostuid, hostuid);
		if (ret < 0 || ret >= 100) {
			ERROR("Error uid printing map string");
			return -1;
		}

		// "g:0:rootgid:1"
		ret = snprintf(map3, 100, "g:0:%d:1", rootgid);
		if (ret < 0 || ret >= 100) {
			ERROR("Error gid printing map string");
			return -1;
		}

		// "g:pathgid:rootgid+pathgid:1"
		ret = snprintf(map4, 100, "g:%d:%d:1", (gid_t)sb.st_gid,
				rootgid + (gid_t)sb.st_gid);
		if (ret < 0 || ret >= 100) {
			ERROR("Error gid printing map string");
			return -1;
		}

		// "g:hostgid:hostgid:1"
		ret = snprintf(map5, 100, "g:%d:%d:1", hostgid, hostgid);
		if (ret < 0 || ret >= 100) {
			ERROR("Error gid printing map string");
			return -1;
		}

		// "0:pathgid" (chown)
		ret = snprintf(ugid, 100, "0:%d", (gid_t)sb.st_gid);
		if (ret < 0 || ret >= 100) {
			ERROR("Error owner printing format string for chown");
			return -1;
		}

		if (hostgid == sb.st_gid)
			ret = execvp("lxc-usernsexec", args1);
		else
			ret = execvp("lxc-usernsexec", args2);
		SYSERROR("Failed executing usernsexec");
		exit(1);
	}
	return wait_for_pid(pid);
}

int ttys_shift_ids(struct lxc_conf *c)
{
	if (lxc_list_empty(&c->id_map))
		return 0;

	if (strcmp(c->console.name, "") !=0 && chown_mapped_root(c->console.name, c) < 0) {
		ERROR("Failed to chown %s", c->console.name);
		return -1;
	}

	return 0;
}

/* NOTE: not to be called from inside the container namespace! */
int tmp_proc_mount(struct lxc_conf *lxc_conf)
{
	int mounted;

	mounted = mount_proc_if_needed(lxc_conf->rootfs.path ? lxc_conf->rootfs.mount : "");
	if (mounted == -1) {
		SYSERROR("failed to mount /proc in the container.");
		/* continue only if there is no rootfs */
		if (lxc_conf->rootfs.path)
			return -1;
	} else if (mounted == 1) {
		lxc_conf->tmp_umount_proc = 1;
	}
	return 0;
}

void tmp_proc_unmount(struct lxc_conf *lxc_conf)
{
	if (lxc_conf->tmp_umount_proc == 1) {
		umount("/proc");
		lxc_conf->tmp_umount_proc = 0;
	}
}

void remount_all_slave(void)
{
	/* walk /proc/mounts and change any shared entries to slave */
	FILE *f = fopen("/proc/self/mountinfo", "r");
	char *line = NULL;
	size_t len = 0;

	if (!f) {
		SYSERROR("Failed to open /proc/self/mountinfo to mark all shared");
		ERROR("Continuing container startup...");
		return;
	}

	while (getline(&line, &len, f) != -1) {
		char *target, *opts;
		target = get_field(line, 4);
		if (!target)
			continue;
		opts = get_field(target, 2);
		if (!opts)
			continue;
		null_endofword(opts);
		if (!strstr(opts, "shared"))
			continue;
		null_endofword(target);
		if (mount(NULL, target, NULL, MS_SLAVE, NULL)) {
			SYSERROR("Failed to make %s rslave", target);
			ERROR("Continuing...");
		}
	}
	fclose(f);
	free(line);
}

void lxc_execute_bind_init(struct lxc_conf *conf)
{
	int ret;
	char path[PATH_MAX], destpath[PATH_MAX], *p;

	/* If init exists in the container, don't bind mount a static one */
	p = choose_init(conf->rootfs.mount);
	if (p) {
		free(p);
		return;
	}

	ret = snprintf(path, PATH_MAX, SBINDIR "/init.lxc.static");
	if (ret < 0 || ret >= PATH_MAX) {
		WARN("Path name too long searching for lxc.init.static");
		return;
	}

	if (!file_exists(path)) {
		INFO("%s does not exist on host", path);
		return;
	}

	ret = snprintf(destpath, PATH_MAX, "%s%s", conf->rootfs.mount, "/init.lxc.static");
	if (ret < 0 || ret >= PATH_MAX) {
		WARN("Path name too long for container's lxc.init.static");
		return;
	}

	if (!file_exists(destpath)) {
		FILE * pathfile = fopen(destpath, "wb");
		if (!pathfile) {
			SYSERROR("Failed to create mount target '%s'", destpath);
			return;
		}
		fclose(pathfile);
	}

	ret = safe_mount(path, destpath, "none", MS_BIND, NULL, conf->rootfs.mount);
	if (ret < 0)
		SYSERROR("Failed to bind lxc.init.static into container");
	INFO("lxc.init.static bound into container at %s", path);
}

/*
 * This does the work of remounting / if it is shared, calling the
 * container pre-mount hooks, and mounting the rootfs.
 */
int do_rootfs_setup(struct lxc_conf *conf, const char *name, const char *lxcpath)
{
	if (conf->rootfs_setup) {
		/*
		 * rootfs was set up in another namespace.  bind-mount it
		 * to give us a mount in our own ns so we can pivot_root to it
		 */
		const char *path = conf->rootfs.mount;
		if (mount(path, path, "rootfs", MS_BIND, NULL) < 0) {
			ERROR("Failed to bind-mount container / onto itself");
			return -1;
		}
		return 0;
	}

	remount_all_slave();

	if (run_lxc_hooks(name, "pre-mount", conf, lxcpath, NULL)) {
		ERROR("failed to run pre-mount hooks for container '%s'.", name);
		return -1;
	}

	if (setup_rootfs(conf)) {
		ERROR("failed to setup rootfs for '%s'", name);
		return -1;
	}

	conf->rootfs_setup = true;
	return 0;
}

static bool verify_start_hooks(struct lxc_conf *conf)
{
	struct lxc_list *it;
	char path[MAXPATHLEN];
	lxc_list_for_each(it, &conf->hooks[LXCHOOK_START]) {
		char *hookname = it->elem;
		struct stat st;
		int ret;

		ret = snprintf(path, MAXPATHLEN, "%s%s",
			conf->rootfs.path ? conf->rootfs.mount : "", hookname);
		if (ret < 0 || ret >= MAXPATHLEN)
			return false;
		ret = stat(path, &st);
		if (ret) {
			SYSERROR("Start hook %s not found in container",
					hookname);
			return false;
		}
		return true;
	}

	return true;
}

static int send_fd(int sock, int fd)
{
	int ret = lxc_abstract_unix_send_fd(sock, fd, NULL, 0);


	if (ret < 0) {
		SYSERROR("Error sending tty fd to parent");
		return -1;
	}

	return 0;
}

static int send_ttys_to_parent(struct lxc_handler *handler)
{
	struct lxc_conf *conf = handler->conf;
	const struct lxc_tty_info *tty_info = &conf->tty_info;
	int i;
	int sock = handler->ttysock[0];

	for (i = 0; i < tty_info->nbtty; i++) {
		struct lxc_pty_info *pty_info = &tty_info->pty_info[i];
		if (send_fd(sock, pty_info->slave) < 0)
			goto bad;
		close(pty_info->slave);
		pty_info->slave = -1;
		if (send_fd(sock, pty_info->master) < 0)
			goto bad;
		close(pty_info->master);
		pty_info->master = -1;
	}

	close(handler->ttysock[0]);
	close(handler->ttysock[1]);

	return 0;

bad:
	ERROR("Error writing tty fd to parent");
	return -1;
}

int lxc_setup(struct lxc_handler *handler)
{
	const char *name = handler->name;
	struct lxc_conf *lxc_conf = handler->conf;
	const char *lxcpath = handler->lxcpath;

	if (do_rootfs_setup(lxc_conf, name, lxcpath) < 0) {
		ERROR("Error setting up rootfs mount after spawn");
		return -1;
	}

	if (lxc_conf->inherit_ns_fd[LXC_NS_UTS] == -1) {
		if (setup_utsname(lxc_conf->utsname)) {
			ERROR("failed to setup the utsname for '%s'", name);
			return -1;
		}
	}

	if (setup_network(&lxc_conf->network)) {
		ERROR("failed to setup the network for '%s'", name);
		return -1;
	}

	if (lxc_conf->autodev > 0) {
		if (mount_autodev(name, &lxc_conf->rootfs, lxcpath)) {
			ERROR("failed to mount /dev in the container");
			return -1;
		}
	}

	/* do automatic mounts (mainly /proc and /sys), but exclude
	 * those that need to wait until other stuff has finished
	 */
	if (lxc_mount_auto_mounts(lxc_conf, lxc_conf->auto_mounts & ~LXC_AUTO_CGROUP_MASK, handler) < 0) {
		ERROR("failed to setup the automatic mounts for '%s'", name);
		return -1;
	}

	if (setup_mount(&lxc_conf->rootfs, lxc_conf->fstab, name, lxcpath)) {
		ERROR("failed to setup the mounts for '%s'", name);
		return -1;
	}

	if (!lxc_list_empty(&lxc_conf->mount_list) && setup_mount_entries(&lxc_conf->rootfs, &lxc_conf->mount_list, name, lxcpath)) {
		ERROR("failed to setup the mount entries for '%s'", name);
		return -1;
	}

	/* Make sure any start hooks are in the container */
	if (!verify_start_hooks(lxc_conf))
		return -1;

	if (lxc_conf->is_execute)
		lxc_execute_bind_init(lxc_conf);

	/* now mount only cgroup, if wanted;
	 * before, /sys could not have been mounted
	 * (is either mounted automatically or via fstab entries)
	 */
	if (lxc_mount_auto_mounts(lxc_conf, lxc_conf->auto_mounts & LXC_AUTO_CGROUP_MASK, handler) < 0) {
		ERROR("failed to setup the automatic mounts for '%s'", name);
		return -1;
	}

	if (run_lxc_hooks(name, "mount", lxc_conf, lxcpath, NULL)) {
		ERROR("failed to run mount hooks for container '%s'.", name);
		return -1;
	}

	if (lxc_conf->autodev > 0) {
		bool mount_console = lxc_conf->console.path && !strcmp(lxc_conf->console.path, "none");

		if (run_lxc_hooks(name, "autodev", lxc_conf, lxcpath, NULL)) {
			ERROR("failed to run autodev hooks for container '%s'.", name);
			return -1;
		}
		if (fill_autodev(&lxc_conf->rootfs, mount_console)) {
			ERROR("failed to populate /dev in the container");
			return -1;
		}
	}

	if (!lxc_conf->is_execute && setup_console(&lxc_conf->rootfs, &lxc_conf->console, lxc_conf->ttydir)) {
		ERROR("failed to setup the console for '%s'", name);
		return -1;
	}

	if (lxc_conf->kmsg) {
		if (setup_kmsg(&lxc_conf->rootfs, &lxc_conf->console))  // don't fail
			ERROR("failed to setup kmsg for '%s'", name);
	}

	if (!lxc_conf->is_execute && setup_dev_symlinks(&lxc_conf->rootfs)) {
		ERROR("failed to setup /dev symlinks for '%s'", name);
		return -1;
	}

	/* mount /proc if it's not already there */
	if (tmp_proc_mount(lxc_conf) < 0) {
		ERROR("failed to LSM mount proc for '%s'", name);
		return -1;
	}

	if (setup_pivot_root(&lxc_conf->rootfs)) {
		ERROR("failed to set rootfs for '%s'", name);
		return -1;
	}

	if (setup_pts(lxc_conf->pts)) {
		ERROR("failed to setup the new pts instance");
		return -1;
	}

	if (lxc_create_tty(name, lxc_conf)) {
		ERROR("failed to create the ttys");
		return -1;
	}

	if (send_ttys_to_parent(handler) < 0) {
		ERROR("failure sending console info to parent");
		return -1;
	}


	if (!lxc_conf->is_execute && setup_tty(lxc_conf)) {
		ERROR("failed to setup the ttys for '%s'", name);
		return -1;
	}

	if (lxc_conf->pty_names && setenv("container_ttys", lxc_conf->pty_names, 1))
		SYSERROR("failed to set environment variable for container ptys");


	if (setup_personality(lxc_conf->personality)) {
		ERROR("failed to setup personality");
		return -1;
	}

	if (!lxc_list_empty(&lxc_conf->keepcaps)) {
		if (!lxc_list_empty(&lxc_conf->caps)) {
			ERROR("Simultaneously requested dropping and keeping caps");
			return -1;
		}
		if (dropcaps_except(&lxc_conf->keepcaps)) {
			ERROR("failed to keep requested caps");
			return -1;
		}
	} else if (setup_caps(&lxc_conf->caps)) {
		ERROR("failed to drop capabilities");
		return -1;
	}

	NOTICE("'%s' is setup.", name);

	return 0;
}

int run_lxc_hooks(const char *name, char *hook, struct lxc_conf *conf,
		  const char *lxcpath, char *argv[])
{
	int which = -1;
	struct lxc_list *it;

	if (strcmp(hook, "pre-start") == 0)
		which = LXCHOOK_PRESTART;
	else if (strcmp(hook, "pre-mount") == 0)
		which = LXCHOOK_PREMOUNT;
	else if (strcmp(hook, "mount") == 0)
		which = LXCHOOK_MOUNT;
	else if (strcmp(hook, "autodev") == 0)
		which = LXCHOOK_AUTODEV;
	else if (strcmp(hook, "start") == 0)
		which = LXCHOOK_START;
	else if (strcmp(hook, "stop") == 0)
		which = LXCHOOK_STOP;
	else if (strcmp(hook, "post-stop") == 0)
		which = LXCHOOK_POSTSTOP;
	else if (strcmp(hook, "clone") == 0)
		which = LXCHOOK_CLONE;
	else if (strcmp(hook, "destroy") == 0)
		which = LXCHOOK_DESTROY;
	else
		return -1;
	lxc_list_for_each(it, &conf->hooks[which]) {
		int ret;
		char *hookname = it->elem;
		ret = run_script_argv(name, "lxc", hookname, hook, lxcpath, argv);
		if (ret)
			return ret;
	}
	return 0;
}

static void lxc_remove_nic(struct lxc_list *it)
{
	struct lxc_netdev *netdev = it->elem;
	struct lxc_list *it2,*next;

	lxc_list_del(it);

	free(netdev->link);
	free(netdev->name);
	if (netdev->type == LXC_NET_VETH)
		free(netdev->priv.veth_attr.pair);
	free(netdev->upscript);
	free(netdev->hwaddr);
	free(netdev->mtu);
	free(netdev->ipv4_gateway);
	free(netdev->ipv6_gateway);
	lxc_list_for_each_safe(it2, &netdev->ipv4, next) {
		lxc_list_del(it2);
		free(it2->elem);
		free(it2);
	}
	lxc_list_for_each_safe(it2, &netdev->ipv6, next) {
		lxc_list_del(it2);
		free(it2->elem);
		free(it2);
	}
	free(netdev);
	free(it);
}

/* we get passed in something like '0', '0.ipv4' or '1.ipv6' */
int lxc_clear_nic(struct lxc_conf *c, const char *key)
{
	char *p1;
	int ret, idx, i;
	struct lxc_list *it;
	struct lxc_netdev *netdev;

	p1 = strchr(key, '.');
	if (!p1 || *(p1+1) == '\0')
		p1 = NULL;

	ret = sscanf(key, "%d", &idx);
	if (ret != 1) return -1;
	if (idx < 0)
		return -1;

	i = 0;
	lxc_list_for_each(it, &c->network) {
		if (i == idx)
			break;
		i++;
	}
	if (i < idx)  // we don't have that many nics defined
		return -1;

	if (!it || !it->elem)
		return -1;

	netdev = it->elem;

	if (!p1) {
		lxc_remove_nic(it);
	} else if (strcmp(p1, ".ipv4") == 0) {
		struct lxc_list *it2,*next;
		lxc_list_for_each_safe(it2, &netdev->ipv4, next) {
			lxc_list_del(it2);
			free(it2->elem);
			free(it2);
		}
	} else if (strcmp(p1, ".ipv6") == 0) {
		struct lxc_list *it2,*next;
		lxc_list_for_each_safe(it2, &netdev->ipv6, next) {
			lxc_list_del(it2);
			free(it2->elem);
			free(it2);
		}
	}
		else return -1;

	return 0;
}

int lxc_clear_config_network(struct lxc_conf *c)
{
	struct lxc_list *it,*next;
	lxc_list_for_each_safe(it, &c->network, next) {
		lxc_remove_nic(it);
	}
	return 0;
}

int lxc_clear_config_caps(struct lxc_conf *c)
{
	struct lxc_list *it,*next;

	lxc_list_for_each_safe(it, &c->caps, next) {
		lxc_list_del(it);
		free(it->elem);
		free(it);
	}
	return 0;
}

static int lxc_free_idmap(struct lxc_list *id_map) {
	struct lxc_list *it, *next;

	lxc_list_for_each_safe(it, id_map, next) {
		lxc_list_del(it);
		free(it->elem);
		free(it);
	}
	return 0;
}

int lxc_clear_idmaps(struct lxc_conf *c)
{
	return lxc_free_idmap(&c->id_map);
}

int lxc_clear_config_keepcaps(struct lxc_conf *c)
{
	struct lxc_list *it,*next;

	lxc_list_for_each_safe(it, &c->keepcaps, next) {
		lxc_list_del(it);
		free(it->elem);
		free(it);
	}
	return 0;
}

int lxc_clear_cgroups(struct lxc_conf *c, const char *key)
{
	struct lxc_list *it,*next;
	bool all = false;
	const char *k = key + 11;

	if (strcmp(key, "lxc.cgroup") == 0)
		all = true;

	lxc_list_for_each_safe(it, &c->cgroup, next) {
		struct lxc_cgroup *cg = it->elem;
		if (!all && strcmp(cg->subsystem, k) != 0)
			continue;
		lxc_list_del(it);
		free(cg->subsystem);
		free(cg->value);
		free(cg);
		free(it);
	}
	return 0;
}

int lxc_clear_groups(struct lxc_conf *c)
{
	struct lxc_list *it,*next;

	lxc_list_for_each_safe(it, &c->groups, next) {
		lxc_list_del(it);
		free(it->elem);
		free(it);
	}
	return 0;
}

int lxc_clear_environment(struct lxc_conf *c)
{
	struct lxc_list *it,*next;

	lxc_list_for_each_safe(it, &c->environment, next) {
		lxc_list_del(it);
		free(it->elem);
		free(it);
	}
	return 0;
}


int lxc_clear_mount_entries(struct lxc_conf *c)
{
	struct lxc_list *it,*next;

	lxc_list_for_each_safe(it, &c->mount_list, next) {
		lxc_list_del(it);
		free(it->elem);
		free(it);
	}
	return 0;
}

int lxc_clear_automounts(struct lxc_conf *c)
{
	c->auto_mounts = 0;
	return 0;
}

int lxc_clear_hooks(struct lxc_conf *c, const char *key)
{
	struct lxc_list *it,*next;
	bool all = false, done = false;
	const char *k = key + 9;
	int i;

	if (strcmp(key, "lxc.hook") == 0)
		all = true;

	for (i=0; i<NUM_LXC_HOOKS; i++) {
		if (all || strcmp(k, lxchook_names[i]) == 0) {
			lxc_list_for_each_safe(it, &c->hooks[i], next) {
				lxc_list_del(it);
				free(it->elem);
				free(it);
			}
			done = true;
		}
	}

	if (!done) {
		ERROR("Invalid hook key: %s", key);
		return -1;
	}
	return 0;
}

static void lxc_clear_saved_nics(struct lxc_conf *conf)
{
	int i;

	if (!conf->saved_nics)
		return;
	for (i=0; i < conf->num_savednics; i++)
		free(conf->saved_nics[i].orig_name);
	free(conf->saved_nics);
}

static inline void lxc_clear_aliens(struct lxc_conf *conf)
{
	struct lxc_list *it,*next;

	lxc_list_for_each_safe(it, &conf->aliens, next) {
		lxc_list_del(it);
		free(it->elem);
		free(it);
	}
}

static inline void lxc_clear_includes(struct lxc_conf *conf)
{
	struct lxc_list *it,*next;

	lxc_list_for_each_safe(it, &conf->includes, next) {
		lxc_list_del(it);
		free(it->elem);
		free(it);
	}
}

void lxc_conf_free(struct lxc_conf *conf)
{
	if (!conf)
		return;
	if (current_config == conf)
		current_config = NULL;
	free(conf->console.log_path);
	free(conf->console.path);
	free(conf->rootfs.mount);
	free(conf->rootfs.bdev_type);
	free(conf->rootfs.options);
	free(conf->rootfs.path);
	free(conf->logfile);
	if (conf->logfd != -1)
		close(conf->logfd);
	free(conf->utsname);
	free(conf->ttydir);
	free(conf->fstab);
	free(conf->rcfile);
	free(conf->init_cmd);
	free(conf->unexpanded_config);
	free(conf->pty_names);
	lxc_clear_config_network(conf);
	free(conf->lsm_aa_profile);
	free(conf->lsm_se_context);
	lxc_seccomp_free(conf);
	lxc_clear_config_caps(conf);
	lxc_clear_config_keepcaps(conf);
	lxc_clear_cgroups(conf, "lxc.cgroup");
	lxc_clear_hooks(conf, "lxc.hook");
	lxc_clear_mount_entries(conf);
	lxc_clear_saved_nics(conf);
	lxc_clear_idmaps(conf);
	lxc_clear_groups(conf);
	lxc_clear_includes(conf);
	lxc_clear_aliens(conf);
	lxc_clear_environment(conf);
	free(conf);
}

struct userns_fn_data {
	int (*fn)(void *);
	void *arg;
	int p[2];
};

static int run_userns_fn(void *data)
{
	struct userns_fn_data *d = data;
	char c;
	// we're not sharing with the parent any more, if it was a thread

	close(d->p[1]);
	if (read(d->p[0], &c, 1) != 1)
		return -1;
	close(d->p[0]);
	return d->fn(d->arg);
}

/*
 * Add ID_TYPE_UID/ID_TYPE_GID entries to an existing lxc_conf,
 * if they are not already there.
 */
static struct lxc_list *idmap_add_id(struct lxc_conf *conf,
		uid_t uid, gid_t gid)
{
	int hostuid_mapped = mapped_hostid(uid, conf, ID_TYPE_UID);
	int hostgid_mapped = mapped_hostid(gid, conf, ID_TYPE_GID);
	struct lxc_list *new = NULL, *tmp, *it, *next;
	struct id_map *entry;

	new = malloc(sizeof(*new));
	if (!new) {
		ERROR("Out of memory building id map");
		return NULL;
	}
	lxc_list_init(new);

	if (hostuid_mapped < 0) {
		hostuid_mapped = find_unmapped_nsuid(conf, ID_TYPE_UID);
		if (hostuid_mapped < 0)
			goto err;
		tmp = malloc(sizeof(*tmp));
		if (!tmp)
			goto err;
		entry = malloc(sizeof(*entry));
		if (!entry) {
			free(tmp);
			goto err;
		}
		tmp->elem = entry;
		entry->idtype = ID_TYPE_UID;
		entry->nsid = hostuid_mapped;
		entry->hostid = (unsigned long) uid;
		entry->range = 1;
		lxc_list_add_tail(new, tmp);
	}
	if (hostgid_mapped < 0) {
		hostgid_mapped = find_unmapped_nsuid(conf, ID_TYPE_GID);
		if (hostgid_mapped < 0)
			goto err;
		tmp = malloc(sizeof(*tmp));
		if (!tmp)
			goto err;
		entry = malloc(sizeof(*entry));
		if (!entry) {
			free(tmp);
			goto err;
		}
		tmp->elem = entry;
		entry->idtype = ID_TYPE_GID;
		entry->nsid = hostgid_mapped;
		entry->hostid = (unsigned long) gid;
		entry->range = 1;
		lxc_list_add_tail(new, tmp);
	}
	lxc_list_for_each_safe(it, &conf->id_map, next) {
		tmp = malloc(sizeof(*tmp));
		if (!tmp)
			goto err;
		entry = malloc(sizeof(*entry));
		if (!entry) {
			free(tmp);
			goto err;
		}
		memset(entry, 0, sizeof(*entry));
		memcpy(entry, it->elem, sizeof(*entry));
		tmp->elem = entry;
		lxc_list_add_tail(new, tmp);
	}

	return new;

err:
	ERROR("Out of memory building a new uid/gid map");
	if (new)
		lxc_free_idmap(new);
	free(new);
	return NULL;
}

/*
 * Run a function in a new user namespace.
 * The caller's euid/egid will be mapped in if it is not already.
 */
int userns_exec_1(struct lxc_conf *conf, int (*fn)(void *), void *data)
{
	int ret, pid;
	struct userns_fn_data d;
	char c = '1';
	int p[2];
	struct lxc_list *idmap;

	ret = pipe(p);
	if (ret < 0) {
		SYSERROR("opening pipe");
		return -1;
	}
	d.fn = fn;
	d.arg = data;
	d.p[0] = p[0];
	d.p[1] = p[1];
	pid = lxc_clone(run_userns_fn, &d, CLONE_NEWUSER);
	if (pid < 0)
		goto err;
	close(p[0]);
	p[0] = -1;

	if ((idmap = idmap_add_id(conf, geteuid(), getegid())) == NULL) {
		ERROR("Error adding self to container uid/gid map");
		goto err;
	}

	ret = lxc_map_ids(idmap, pid);
	lxc_free_idmap(idmap);
	free(idmap);
	if (ret) {
		ERROR("Error setting up child mappings");
		goto err;
	}

	// kick the child
	if (write(p[1], &c, 1) != 1) {
		SYSERROR("writing to pipe to child");
		goto err;
	}

	ret = wait_for_pid(pid);

	close(p[1]);
	return ret;

err:
	if (p[0] != -1)
		close(p[0]);
	close(p[1]);
	return -1;
}

/* not thread-safe, do not use from api without first forking */
static char* getuname(void)
{
	struct passwd *result;

	result = getpwuid(geteuid());
	if (!result)
		return NULL;

	return strdup(result->pw_name);
}

/* not thread-safe, do not use from api without first forking */
static char *getgname(void)
{
	struct group *result;

	result = getgrgid(getegid());
	if (!result)
		return NULL;

	return strdup(result->gr_name);
}

/* not thread-safe, do not use from api without first forking */
void suggest_default_idmap(void)
{
	FILE *f;
	unsigned int uid = 0, urange = 0, gid = 0, grange = 0;
	char *line = NULL;
	char *uname, *gname;
	size_t len = 0;

	if (!(uname = getuname()))
		return;

	if (!(gname = getgname())) {
		free(uname);
		return;
	}

	f = fopen(subuidfile, "r");
	if (!f) {
		ERROR("Your system is not configured with subuids");
		free(gname);
		free(uname);
		return;
	}
	while (getline(&line, &len, f) != -1) {
		char *p = strchr(line, ':'), *p2;
		if (*line == '#')
			continue;
		if (!p)
			continue;
		*p = '\0';
		p++;
		if (strcmp(line, uname))
			continue;
		p2 = strchr(p, ':');
		if (!p2)
			continue;
		*p2 = '\0';
		p2++;
		if (!*p2)
			continue;
		uid = atoi(p);
		urange = atoi(p2);
	}
	fclose(f);

	f = fopen(subuidfile, "r");
	if (!f) {
		ERROR("Your system is not configured with subgids");
		free(gname);
		free(uname);
		return;
	}
	while (getline(&line, &len, f) != -1) {
		char *p = strchr(line, ':'), *p2;
		if (*line == '#')
			continue;
		if (!p)
			continue;
		*p = '\0';
		p++;
		if (strcmp(line, uname))
			continue;
		p2 = strchr(p, ':');
		if (!p2)
			continue;
		*p2 = '\0';
		p2++;
		if (!*p2)
			continue;
		gid = atoi(p);
		grange = atoi(p2);
	}
	fclose(f);

	free(line);

	if (!urange || !grange) {
		ERROR("You do not have subuids or subgids allocated");
		ERROR("Unprivileged containers require subuids and subgids");
		return;
	}

	ERROR("You must either run as root, or define uid mappings");
	ERROR("To pass uid mappings to lxc-create, you could create");
	ERROR("~/.config/lxc/default.conf:");
	ERROR("lxc.include = %s", LXC_DEFAULT_CONFIG);
	ERROR("lxc.id_map = u 0 %u %u", uid, urange);
	ERROR("lxc.id_map = g 0 %u %u", gid, grange);

	free(gname);
	free(uname);
}

static void free_cgroup_settings(struct lxc_list *result)
{
	struct lxc_list *iterator, *next;

	lxc_list_for_each_safe(iterator, result, next) {
		lxc_list_del(iterator);
		free(iterator);
	}
	free(result);
}

/*
 * Return the list of cgroup_settings sorted according to the following rules
 * 1. Put memory.limit_in_bytes before memory.memsw.limit_in_bytes
 */
struct lxc_list *sort_cgroup_settings(struct lxc_list* cgroup_settings)
{
	struct lxc_list *result;
	struct lxc_list *memsw_limit = NULL;
	struct lxc_list *it = NULL;
	struct lxc_cgroup *cg = NULL;
	struct lxc_list *item = NULL;

	result = malloc(sizeof(*result));
	if (!result) {
		ERROR("failed to allocate memory to sort cgroup settings");
		return NULL;
	}
	lxc_list_init(result);

	/*Iterate over the cgroup settings and copy them to the output list*/
	lxc_list_for_each(it, cgroup_settings) {
		item = malloc(sizeof(*item));
		if (!item) {
			ERROR("failed to allocate memory to sort cgroup settings");
			free_cgroup_settings(result);
			return NULL;
		}
		item->elem = it->elem;
		cg = it->elem;
		if (strcmp(cg->subsystem, "memory.memsw.limit_in_bytes") == 0) {
			/* Store the memsw_limit location */
			memsw_limit = item;
		} else if (strcmp(cg->subsystem, "memory.limit_in_bytes") == 0 && memsw_limit != NULL) {
			/* lxc.cgroup.memory.memsw.limit_in_bytes is found before
			 * lxc.cgroup.memory.limit_in_bytes, swap these two items */
			item->elem = memsw_limit->elem;
			memsw_limit->elem = it->elem;
		}
		lxc_list_add_tail(result, item);
	}

	return result;
}

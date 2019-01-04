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
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <libgen.h>
#include <linux/loop.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/prctl.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "af_unix.h"
#include "caps.h"
#include "cgroup.h"
#include "conf.h"
#include "config.h"
#include "confile.h"
#include "confile_utils.h"
#include "error.h"
#include "log.h"
#include "lsm/lsm.h"
#include "lxclock.h"
#include "lxcseccomp.h"
#include "macro.h"
#include "namespace.h"
#include "network.h"
#include "parse.h"
#include "raw_syscalls.h"
#include "ringbuf.h"
#include "start.h"
#include "storage.h"
#include "storage/overlay.h"
#include "syscall_wrappers.h"
#include "terminal.h"
#include "utils.h"

#ifdef MAJOR_IN_MKDEV
#include <sys/mkdev.h>
#endif

#ifdef HAVE_STATVFS
#include <sys/statvfs.h>
#endif

#if HAVE_PTY_H
#include <pty.h>
#else
#include <../include/openpty.h>
#endif

#if HAVE_LIBCAP
#include <sys/capability.h>
#endif

#if HAVE_SYS_PERSONALITY_H
#include <sys/personality.h>
#endif

#ifndef HAVE_STRLCAT
#include "include/strlcat.h"
#endif

#if IS_BIONIC
#include <../include/lxcmntent.h>
#else
#include <mntent.h>
#endif

#if !defined(HAVE_PRLIMIT) && defined(HAVE_PRLIMIT64)
#include <../include/prlimit.h>
#endif

lxc_log_define(conf, lxc);

/* The lxc_conf of the container currently being worked on in an API call.
 * This is used in the error calls.
 */
#ifdef HAVE_TLS
thread_local struct lxc_conf *current_config;
#else
struct lxc_conf *current_config;
#endif

char *lxchook_names[NUM_LXC_HOOKS] = {
	"pre-start",
	"pre-mount",
	"mount",
	"autodev",
	"start",
	"stop",
	"post-stop",
	"clone",
	"destroy",
	"start-host"
};

struct mount_opt {
	char *name;
	int clear;
	int flag;
};

struct caps_opt {
	char *name;
	int value;
};

struct limit_opt {
	char *name;
	int value;
};

static struct mount_opt mount_opt[] = {
	{ "async",         1, MS_SYNCHRONOUS },
	{ "atime",         1, MS_NOATIME     },
	{ "bind",          0, MS_BIND        },
	{ "defaults",      0, 0              },
	{ "dev",           1, MS_NODEV       },
	{ "diratime",      1, MS_NODIRATIME  },
	{ "dirsync",       0, MS_DIRSYNC     },
	{ "exec",          1, MS_NOEXEC      },
	{ "lazytime",	   0, MS_LAZYTIME    },
	{ "mand",          0, MS_MANDLOCK    },
	{ "noatime",       0, MS_NOATIME     },
	{ "nodev",         0, MS_NODEV       },
	{ "nodiratime",    0, MS_NODIRATIME  },
	{ "noexec",        0, MS_NOEXEC      },
	{ "nomand",        1, MS_MANDLOCK    },
	{ "norelatime",    1, MS_RELATIME    },
	{ "nostrictatime", 1, MS_STRICTATIME },
	{ "nosuid",        0, MS_NOSUID      },
	{ "rbind",         0, MS_BIND|MS_REC },
	{ "relatime",      0, MS_RELATIME    },
	{ "remount",       0, MS_REMOUNT     },
	{ "ro",            0, MS_RDONLY      },
	{ "rw",            1, MS_RDONLY      },
	{ "strictatime",   0, MS_STRICTATIME },
	{ "suid",          1, MS_NOSUID      },
	{ "sync",          0, MS_SYNCHRONOUS },
	{ NULL,            0, 0              },
};

static struct mount_opt propagation_opt[] = {
	{ "private",     0, MS_PRIVATE           },
	{ "shared",      0, MS_SHARED            },
	{ "slave",       0, MS_SLAVE             },
	{ "unbindable",  0, MS_UNBINDABLE        },
	{ "rprivate",    0, MS_PRIVATE|MS_REC    },
	{ "rshared",     0, MS_SHARED|MS_REC     },
	{ "rslave",      0, MS_SLAVE|MS_REC      },
	{ "runbindable", 0, MS_UNBINDABLE|MS_REC },
	{ NULL,          0, 0                    },
};

static struct caps_opt caps_opt[] = {
#if HAVE_LIBCAP
	{ "chown",            CAP_CHOWN            },
	{ "dac_override",     CAP_DAC_OVERRIDE     },
	{ "dac_read_search",  CAP_DAC_READ_SEARCH  },
	{ "fowner",           CAP_FOWNER           },
	{ "fsetid",           CAP_FSETID           },
	{ "kill",             CAP_KILL             },
	{ "setgid",           CAP_SETGID           },
	{ "setuid",           CAP_SETUID           },
	{ "setpcap",          CAP_SETPCAP          },
	{ "linux_immutable",  CAP_LINUX_IMMUTABLE  },
	{ "net_bind_service", CAP_NET_BIND_SERVICE },
	{ "net_broadcast",    CAP_NET_BROADCAST    },
	{ "net_admin",        CAP_NET_ADMIN        },
	{ "net_raw",          CAP_NET_RAW          },
	{ "ipc_lock",         CAP_IPC_LOCK         },
	{ "ipc_owner",        CAP_IPC_OWNER        },
	{ "sys_module",       CAP_SYS_MODULE       },
	{ "sys_rawio",        CAP_SYS_RAWIO        },
	{ "sys_chroot",       CAP_SYS_CHROOT       },
	{ "sys_ptrace",       CAP_SYS_PTRACE       },
	{ "sys_pacct",        CAP_SYS_PACCT        },
	{ "sys_admin",        CAP_SYS_ADMIN        },
	{ "sys_boot",         CAP_SYS_BOOT         },
	{ "sys_nice",         CAP_SYS_NICE         },
	{ "sys_resource",     CAP_SYS_RESOURCE     },
	{ "sys_time",         CAP_SYS_TIME         },
	{ "sys_tty_config",   CAP_SYS_TTY_CONFIG   },
	{ "mknod",            CAP_MKNOD            },
	{ "lease",            CAP_LEASE            },
#ifdef CAP_AUDIT_READ
	{ "audit_read",       CAP_AUDIT_READ       },
#endif
#ifdef CAP_AUDIT_WRITE
	{ "audit_write",      CAP_AUDIT_WRITE      },
#endif
#ifdef CAP_AUDIT_CONTROL
	{ "audit_control",    CAP_AUDIT_CONTROL    },
#endif
	{ "setfcap",          CAP_SETFCAP          },
	{ "mac_override",     CAP_MAC_OVERRIDE     },
	{ "mac_admin",        CAP_MAC_ADMIN        },
#ifdef CAP_SYSLOG
	{ "syslog",           CAP_SYSLOG           },
#endif
#ifdef CAP_WAKE_ALARM
	{ "wake_alarm",       CAP_WAKE_ALARM       },
#endif
#ifdef CAP_BLOCK_SUSPEND
	{ "block_suspend",    CAP_BLOCK_SUSPEND    },
#endif
#endif
};

static struct limit_opt limit_opt[] = {
#ifdef RLIMIT_AS
	{ "as",          RLIMIT_AS          },
#endif
#ifdef RLIMIT_CORE
	{ "core",        RLIMIT_CORE        },
#endif
#ifdef RLIMIT_CPU
	{ "cpu",         RLIMIT_CPU         },
#endif
#ifdef RLIMIT_DATA
	{ "data",        RLIMIT_DATA        },
#endif
#ifdef RLIMIT_FSIZE
	{ "fsize",       RLIMIT_FSIZE       },
#endif
#ifdef RLIMIT_LOCKS
	{ "locks",       RLIMIT_LOCKS       },
#endif
#ifdef RLIMIT_MEMLOCK
	{ "memlock",     RLIMIT_MEMLOCK     },
#endif
#ifdef RLIMIT_MSGQUEUE
	{ "msgqueue",    RLIMIT_MSGQUEUE    },
#endif
#ifdef RLIMIT_NICE
	{ "nice",        RLIMIT_NICE        },
#endif
#ifdef RLIMIT_NOFILE
	{ "nofile",      RLIMIT_NOFILE      },
#endif
#ifdef RLIMIT_NPROC
	{ "nproc",       RLIMIT_NPROC       },
#endif
#ifdef RLIMIT_RSS
	{ "rss",         RLIMIT_RSS         },
#endif
#ifdef RLIMIT_RTPRIO
	{ "rtprio",      RLIMIT_RTPRIO      },
#endif
#ifdef RLIMIT_RTTIME
	{ "rttime",      RLIMIT_RTTIME      },
#endif
#ifdef RLIMIT_SIGPENDING
	{ "sigpending",  RLIMIT_SIGPENDING  },
#endif
#ifdef RLIMIT_STACK
	{ "stack",       RLIMIT_STACK       },
#endif
};

static int run_buffer(char *buffer)
{
	int ret;
	char *output;
	struct lxc_popen_FILE *f;

	f = lxc_popen(buffer);
	if (!f) {
		SYSERROR("Failed to popen() %s", buffer);
		return -1;
	}

	output = malloc(LXC_LOG_BUFFER_SIZE);
	if (!output) {
		ERROR("Failed to allocate memory for %s", buffer);
		lxc_pclose(f);
		return -1;
	}

	while (fgets(output, LXC_LOG_BUFFER_SIZE, f->f))
		DEBUG("Script %s with output: %s", buffer, output);

	free(output);

	ret = lxc_pclose(f);
	if (ret == -1) {
		SYSERROR("Script exited with error");
		return -1;
	} else if (WIFEXITED(ret) && WEXITSTATUS(ret) != 0) {
		ERROR("Script exited with status %d", WEXITSTATUS(ret));
		return -1;
	} else if (WIFSIGNALED(ret)) {
		ERROR("Script terminated by signal %d", WTERMSIG(ret));
		return -1;
	}

	return 0;
}

int run_script_argv(const char *name, unsigned int hook_version,
		    const char *section, const char *script,
		    const char *hookname, char **argv)
{
	int buf_pos, i, ret;
	char *buffer;
	int fret = -1;
	size_t size = 0;

	if (hook_version == 0)
		INFO("Executing script \"%s\" for container \"%s\", config "
		     "section \"%s\"", script, name, section);
	else
		INFO("Executing script \"%s\" for container \"%s\"", script, name);

	for (i = 0; argv && argv[i]; i++)
		size += strlen(argv[i]) + 1;

	size += STRLITERALLEN("exec");
	size++;
	size += strlen(script);
	size++;

	if (size > INT_MAX)
		return -EFBIG;

	if (hook_version == 0) {
		size += strlen(hookname);
		size++;

		size += strlen(name);
		size++;

		size += strlen(section);
		size++;

		if (size > INT_MAX)
			return -EFBIG;
	}

	buffer = malloc(size);
	if (!buffer)
		return -ENOMEM;

	if (hook_version == 0)
		buf_pos = snprintf(buffer, size, "exec %s %s %s %s", script, name, section, hookname);
	else
		buf_pos = snprintf(buffer, size, "exec %s", script);
	if (buf_pos < 0 || (size_t)buf_pos >= size) {
		ERROR("Failed to create command line for script \"%s\"", script);
		goto on_error;
	}

	if (hook_version == 1) {
		ret = setenv("LXC_HOOK_TYPE", hookname, 1);
		if (ret < 0) {
			SYSERROR("Failed to set environment variable: "
				 "LXC_HOOK_TYPE=%s", hookname);
			goto on_error;
		}
		TRACE("Set environment variable: LXC_HOOK_TYPE=%s", hookname);

		ret = setenv("LXC_HOOK_SECTION", section, 1);
		if (ret < 0) {
			SYSERROR("Failed to set environment variable: "
				 "LXC_HOOK_SECTION=%s", section);
			goto on_error;
		}
		TRACE("Set environment variable: LXC_HOOK_SECTION=%s", section);

		if (strcmp(section, "net") == 0) {
			char *parent;

			if (!argv || !argv[0])
				goto on_error;

			ret = setenv("LXC_NET_TYPE", argv[0], 1);
			if (ret < 0) {
				SYSERROR("Failed to set environment variable: "
					 "LXC_NET_TYPE=%s", argv[0]);
				goto on_error;
			}
			TRACE("Set environment variable: LXC_NET_TYPE=%s", argv[0]);

			parent = argv[1] ? argv[1] : "";

			if (strcmp(argv[0], "macvlan") == 0) {
				ret = setenv("LXC_NET_PARENT", parent, 1);
				if (ret < 0) {
					SYSERROR("Failed to set environment "
						 "variable: LXC_NET_PARENT=%s", parent);
					goto on_error;
				}
				TRACE("Set environment variable: LXC_NET_PARENT=%s", parent);
			} else if (strcmp(argv[0], "phys") == 0) {
				ret = setenv("LXC_NET_PARENT", parent, 1);
				if (ret < 0) {
					SYSERROR("Failed to set environment "
						 "variable: LXC_NET_PARENT=%s", parent);
					goto on_error;
				}
				TRACE("Set environment variable: LXC_NET_PARENT=%s", parent);
			} else if (strcmp(argv[0], "veth") == 0) {
				char *peer = argv[2] ? argv[2] : "";

				ret = setenv("LXC_NET_PEER", peer, 1);
				if (ret < 0) {
					SYSERROR("Failed to set environment "
						 "variable: LXC_NET_PEER=%s", peer);
					goto on_error;
				}
				TRACE("Set environment variable: LXC_NET_PEER=%s", peer);

				ret = setenv("LXC_NET_PARENT", parent, 1);
				if (ret < 0) {
					SYSERROR("Failed to set environment "
						 "variable: LXC_NET_PARENT=%s", parent);
					goto on_error;
				}
				TRACE("Set environment variable: LXC_NET_PARENT=%s", parent);
			}
		}
	}

	for (i = 0; argv && argv[i]; i++) {
		size_t len = size - buf_pos;

		ret = snprintf(buffer + buf_pos, len, " %s", argv[i]);
		if (ret < 0 || (size_t)ret >= len) {
			ERROR("Failed to create command line for script \"%s\"", script);
			goto on_error;
		}
		buf_pos += ret;
	}

	fret = run_buffer(buffer);

on_error:
	free(buffer);
	return fret;
}

int run_script(const char *name, const char *section, const char *script, ...)
{
	int ret;
	char *buffer, *p;
	va_list ap;
	size_t size = 0;

	INFO("Executing script \"%s\" for container \"%s\", config section \"%s\"",
	     script, name, section);

	va_start(ap, script);
	while ((p = va_arg(ap, char *)))
		size += strlen(p) + 1;
	va_end(ap);

	size += STRLITERALLEN("exec");
	size += strlen(script);
	size += strlen(name);
	size += strlen(section);
	size += 4;

	if (size > INT_MAX)
		return -1;

	buffer = alloca(size);
	ret = snprintf(buffer, size, "exec %s %s %s", script, name, section);
	if (ret < 0 || ret >= size)
		return -1;

	va_start(ap, script);
	while ((p = va_arg(ap, char *))) {
		int len = size - ret;
		int rc;
		rc = snprintf(buffer + ret, len, " %s", p);
		if (rc < 0 || rc >= len) {
			va_end(ap);
			return -1;
		}
		ret += rc;
	}
	va_end(ap);

	return run_buffer(buffer);
}

/* pin_rootfs
 * if rootfs is a directory, then open ${rootfs}/.lxc-keep for writing for
 * the duration of the container run, to prevent the container from marking
 * the underlying fs readonly on shutdown. unlink the file immediately so
 * no name pollution is happens.
 * don't unlink on NFS to avoid random named stale handles.
 * return -1 on error.
 * return -2 if nothing needed to be pinned.
 * return an open fd (>=0) if we pinned it.
 */
int pin_rootfs(const char *rootfs)
{
	int fd, ret;
	char absrootfspin[PATH_MAX];
	char *absrootfs;
	struct stat s;
	struct statfs sfs;

	if (rootfs == NULL || strlen(rootfs) == 0)
		return -2;

	absrootfs = realpath(rootfs, NULL);
	if (!absrootfs)
		return -2;

	ret = stat(absrootfs, &s);
	if (ret < 0) {
		free(absrootfs);
		return -1;
	}

	if (!S_ISDIR(s.st_mode)) {
		free(absrootfs);
		return -2;
	}

	ret = snprintf(absrootfspin, PATH_MAX, "%s/.lxc-keep", absrootfs);
	free(absrootfs);
	if (ret < 0 || ret >= PATH_MAX)
		return -1;

	fd = open(absrootfspin, O_CREAT | O_RDWR, S_IWUSR | S_IRUSR);
	if (fd < 0)
		return fd;

	ret = fstatfs (fd, &sfs);
	if (ret < 0)
		return fd;

	if (sfs.f_type == NFS_SUPER_MAGIC) {
		DEBUG("Rootfs on NFS, not unlinking pin file \"%s\"", absrootfspin);
		return fd;
	}

	(void)unlink(absrootfspin);

	return fd;
}

/* If we are asking to remount something, make sure that any NOEXEC etc are
 * honored.
 */
unsigned long add_required_remount_flags(const char *s, const char *d,
					 unsigned long flags)
{
#ifdef HAVE_STATVFS
	int ret;
	struct statvfs sb;
	unsigned long required_flags = 0;

	if (!s)
		s = d;

	if (!s)
		return flags;

	ret = statvfs(s, &sb);
	if (ret < 0)
		return flags;

	if (flags & MS_REMOUNT) {
		if (sb.f_flag & MS_NOSUID)
			required_flags |= MS_NOSUID;
		if (sb.f_flag & MS_NODEV)
			required_flags |= MS_NODEV;
		if (sb.f_flag & MS_RDONLY)
			required_flags |= MS_RDONLY;
		if (sb.f_flag & MS_NOEXEC)
			required_flags |= MS_NOEXEC;
	}

	if (sb.f_flag & MS_NOATIME)
		required_flags |= MS_NOATIME;
	if (sb.f_flag & MS_NODIRATIME)
		required_flags |= MS_NODIRATIME;
	if (sb.f_flag & MS_LAZYTIME)
		required_flags |= MS_LAZYTIME;
	if (sb.f_flag & MS_RELATIME)
		required_flags |= MS_RELATIME;
	if (sb.f_flag & MS_STRICTATIME)
		required_flags |= MS_STRICTATIME;

	return flags | required_flags;
#else
	return flags;
#endif
}

static int add_shmount_to_list(struct lxc_conf *conf)
{
	char new_mount[PATH_MAX];
	/* Offset for the leading '/' since the path_cont
	 * is absolute inside the container.
	 */
	int offset = 1, ret = -1;

	ret = snprintf(new_mount, sizeof(new_mount),
		       "%s %s none bind,create=dir 0 0", conf->shmount.path_host,
		       conf->shmount.path_cont + offset);
	if (ret < 0 || (size_t)ret >= sizeof(new_mount))
		return -1;

	return add_elem_to_mount_list(new_mount, conf);
}

static int lxc_mount_auto_mounts(struct lxc_conf *conf, int flags, struct lxc_handler *handler)
{
	int i, r;
	static struct {
		int match_mask;
		int match_flag;
		const char *source;
		const char *destination;
		const char *fstype;
		unsigned long flags;
		const char *options;
	} default_mounts[] = {
		/* Read-only bind-mounting... In older kernels, doing that
		 * required to do one MS_BIND mount and then
		 * MS_REMOUNT|MS_RDONLY the same one. According to mount(2)
		 * manpage, MS_BIND honors MS_RDONLY from kernel 2.6.26
		 * onwards. However, this apparently does not work on kernel
		 * 3.8. Unfortunately, on that very same kernel, doing the same
		 * trick as above doesn't seem to work either, there one needs
		 * to ALSO specify MS_BIND for the remount, otherwise the
		 * entire fs is remounted read-only or the mount fails because
		 * it's busy...  MS_REMOUNT|MS_BIND|MS_RDONLY seems to work for
		 * kernels as low as 2.6.32...
		 */
		{ LXC_AUTO_PROC_MASK, LXC_AUTO_PROC_MIXED, "proc",                                           "%r/proc",                    "proc",  MS_NODEV|MS_NOEXEC|MS_NOSUID,                    NULL },
		/* proc/tty is used as a temporary placeholder for proc/sys/net which we'll move back in a few steps */
		{ LXC_AUTO_PROC_MASK, LXC_AUTO_PROC_MIXED, "%r/proc/sys/net",                                "%r/proc/tty",                NULL,    MS_BIND,                                         NULL },
		{ LXC_AUTO_PROC_MASK, LXC_AUTO_PROC_MIXED, "%r/proc/sys",                                    "%r/proc/sys",                NULL,    MS_BIND,                                         NULL },
		{ LXC_AUTO_PROC_MASK, LXC_AUTO_PROC_MIXED, NULL,                                             "%r/proc/sys",                NULL,    MS_REMOUNT|MS_BIND|MS_RDONLY,                    NULL },
		{ LXC_AUTO_PROC_MASK, LXC_AUTO_PROC_MIXED, "%r/proc/tty",                                    "%r/proc/sys/net",            NULL,    MS_MOVE,                                         NULL },
		{ LXC_AUTO_PROC_MASK, LXC_AUTO_PROC_MIXED, "%r/proc/sysrq-trigger",                          "%r/proc/sysrq-trigger",      NULL,    MS_BIND,                                         NULL },
		{ LXC_AUTO_PROC_MASK, LXC_AUTO_PROC_MIXED, NULL,                                             "%r/proc/sysrq-trigger",      NULL,    MS_REMOUNT|MS_BIND|MS_RDONLY,                    NULL },
		{ LXC_AUTO_PROC_MASK, LXC_AUTO_PROC_RW,    "proc",                                           "%r/proc",                    "proc",  MS_NODEV|MS_NOEXEC|MS_NOSUID,                    NULL },
		{ LXC_AUTO_SYS_MASK,  LXC_AUTO_SYS_RW,     "sysfs",                                          "%r/sys",                     "sysfs", 0,                                               NULL },
		{ LXC_AUTO_SYS_MASK,  LXC_AUTO_SYS_RO,     "sysfs",                                          "%r/sys",                     "sysfs", MS_RDONLY,                                       NULL },
		{ LXC_AUTO_SYS_MASK,  LXC_AUTO_SYS_MIXED,  "sysfs",                                          "%r/sys",                     "sysfs", MS_NODEV|MS_NOEXEC|MS_NOSUID,                    NULL },
		{ LXC_AUTO_SYS_MASK,  LXC_AUTO_SYS_MIXED,  NULL,                                             "%r/sys",                     NULL,    MS_REMOUNT|MS_BIND|MS_RDONLY,                    NULL },
		{ LXC_AUTO_SYS_MASK,  LXC_AUTO_SYS_MIXED,  "sysfs",                                          "%r/sys/devices/virtual/net", "sysfs", 0,                                               NULL },
		{ LXC_AUTO_SYS_MASK,  LXC_AUTO_SYS_MIXED,  "%r/sys/devices/virtual/net/devices/virtual/net", "%r/sys/devices/virtual/net", NULL,    MS_BIND,                                         NULL },
		{ LXC_AUTO_SYS_MASK,  LXC_AUTO_SYS_MIXED,  NULL,                                             "%r/sys/devices/virtual/net", NULL,    MS_REMOUNT|MS_BIND|MS_NOSUID|MS_NODEV|MS_NOEXEC, NULL },
		{ 0,                  0,                   NULL,                                             NULL,                         NULL,    0,                                               NULL }
	};

	for (i = 0; default_mounts[i].match_mask; i++) {
		int saved_errno;
		unsigned long mflags;
		char *destination = NULL;
		char *source = NULL;
		if ((flags & default_mounts[i].match_mask) != default_mounts[i].match_flag)
			continue;

		if (default_mounts[i].source) {
			/* will act like strdup if %r is not present */
			source = lxc_string_replace("%r", conf->rootfs.path ? conf->rootfs.mount : "", default_mounts[i].source);
			if (!source)
				return -1;
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
			free(source);
			errno = saved_errno;
			return -1;
		}

		mflags = add_required_remount_flags(source, destination,
						    default_mounts[i].flags);
		r = safe_mount(source, destination, default_mounts[i].fstype,
			       mflags, default_mounts[i].options,
			       conf->rootfs.path ? conf->rootfs.mount : NULL);
		saved_errno = errno;
		if (r < 0 && errno == ENOENT) {
			INFO("Mount source or target for \"%s\" on \"%s\" does "
			     "not exist. Skipping", source, destination);
			r = 0;
		} else if (r < 0) {
			SYSERROR("Failed to mount \"%s\" on \"%s\" with flags %lu", source, destination, mflags);
		}

		free(source);
		free(destination);
		if (r < 0) {
			errno = saved_errno;
			return -1;
		}
	}

	if (flags & LXC_AUTO_CGROUP_MASK) {
		int cg_flags;

		cg_flags = flags & (LXC_AUTO_CGROUP_MASK & ~LXC_AUTO_CGROUP_FORCE);
		/* If the type of cgroup mount was not specified, it depends on
		 * the container's capabilities as to what makes sense: if we
		 * have CAP_SYS_ADMIN, the read-only part can be remounted
		 * read-write anyway, so we may as well default to read-write;
		 * then the admin will not be given a false sense of security.
		 * (And if they really want mixed r/o r/w, then they can
		 * explicitly specify :mixed.) OTOH, if the container lacks
		 * CAP_SYS_ADMIN, do only default to :mixed, because then the
		 * container can't remount it read-write.
		 */
		if (cg_flags == LXC_AUTO_CGROUP_NOSPEC || cg_flags == LXC_AUTO_CGROUP_FULL_NOSPEC) {
			int has_sys_admin = 0;

			if (!lxc_list_empty(&conf->keepcaps))
				has_sys_admin = in_caplist(CAP_SYS_ADMIN, &conf->keepcaps);
			else
				has_sys_admin = !in_caplist(CAP_SYS_ADMIN, &conf->caps);

			if (cg_flags == LXC_AUTO_CGROUP_NOSPEC)
				cg_flags = has_sys_admin ? LXC_AUTO_CGROUP_RW : LXC_AUTO_CGROUP_MIXED;
			else
				cg_flags = has_sys_admin ? LXC_AUTO_CGROUP_FULL_RW : LXC_AUTO_CGROUP_FULL_MIXED;
		}

		if (flags & LXC_AUTO_CGROUP_FORCE)
			cg_flags |= LXC_AUTO_CGROUP_FORCE;

		if (!handler->cgroup_ops->mount(handler->cgroup_ops,
						handler,
						conf->rootfs.path ? conf->rootfs.mount : "",
						cg_flags)) {
			SYSERROR("Failed to mount \"/sys/fs/cgroup\"");
			return -1;
		}
	}

	if (flags & LXC_AUTO_SHMOUNTS_MASK) {
		int ret = add_shmount_to_list(conf);
		if (ret < 0) {
			ERROR("Failed to add shmount entry to container config");
			return -1;
		}
	}

	return 0;
}

static int setup_utsname(struct utsname *utsname)
{
	int ret;

	if (!utsname)
		return 0;

	ret = sethostname(utsname->nodename, strlen(utsname->nodename));
	if (ret < 0) {
		SYSERROR("Failed to set the hostname to \"%s\"", utsname->nodename);
		return -1;
	}

	INFO("Set hostname to \"%s\"", utsname->nodename);

	return 0;
}

struct dev_symlinks {
	const char *oldpath;
	const char *name;
};

static const struct dev_symlinks dev_symlinks[] = {
	{ "/proc/self/fd",   "fd"     },
	{ "/proc/self/fd/0", "stdin"  },
	{ "/proc/self/fd/1", "stdout" },
	{ "/proc/self/fd/2", "stderr" },
};

static int lxc_setup_dev_symlinks(const struct lxc_rootfs *rootfs)
{
	int i, ret;
	char path[PATH_MAX];
	struct stat s;

	for (i = 0; i < sizeof(dev_symlinks) / sizeof(dev_symlinks[0]); i++) {
		const struct dev_symlinks *d = &dev_symlinks[i];

		ret = snprintf(path, sizeof(path), "%s/dev/%s",
			       rootfs->path ? rootfs->mount : "", d->name);
		if (ret < 0 || ret >= PATH_MAX)
			return -1;

		/* Stat the path first. If we don't get an error accept it as
		 * is and don't try to create it
		 */
		ret = stat(path, &s);
		if (ret == 0)
			continue;

		ret = symlink(d->oldpath, path);
		if (ret && errno != EEXIST) {
			if (errno == EROFS) {
				WARN("Failed to create \"%s\". Read-only filesystem", path);
			} else {
				SYSERROR("Failed to create \"%s\"", path);
				return -1;
			}
		}
	}

	return 0;
}

/* Build a space-separate list of ptys to pass to systemd. */
static bool append_ttyname(char **pp, char *name)
{
	char *p;
	size_t size;

	if (!*pp) {
		*pp = malloc(strlen(name) + strlen("container_ttys=") + 1);
		if (!*pp)
			return false;

		sprintf(*pp, "container_ttys=%s", name);
		return true;
	}

	size = strlen(*pp) + strlen(name) + 2;
	p = realloc(*pp, size);
	if (!p)
		return false;

	*pp = p;
	(void)strlcat(p, " ", size);
	(void)strlcat(p, name, size);

	return true;
}

static int lxc_setup_ttys(struct lxc_conf *conf)
{
	int i, ret;
	const struct lxc_tty_info *ttys = &conf->ttys;
	char *ttydir = ttys->dir;
	char path[PATH_MAX], lxcpath[PATH_MAX];

	if (!conf->rootfs.path)
		return 0;

	for (i = 0; i < ttys->max; i++) {
		struct lxc_terminal_info *tty = &ttys->tty[i];

		ret = snprintf(path, sizeof(path), "/dev/tty%d", i + 1);
		if (ret < 0 || (size_t)ret >= sizeof(path))
			return -1;

		if (ttydir) {
			/* create dev/lxc/tty%d" */
			ret = snprintf(lxcpath, sizeof(lxcpath),
				       "/dev/%s/tty%d", ttydir, i + 1);
			if (ret < 0 || (size_t)ret >= sizeof(lxcpath))
				return -1;

			ret = mknod(lxcpath, S_IFREG | 0000, 0);
			if (ret < 0 && errno != EEXIST) {
				SYSERROR("Failed to create \"%s\"", lxcpath);
				return -1;
			}

			ret = unlink(path);
			if (ret < 0 && errno != ENOENT) {
				SYSERROR("Failed to unlink \"%s\"", path);
				return -1;
			}

			ret = mount(tty->name, lxcpath, "none", MS_BIND, 0);
			if (ret < 0) {
				SYSWARN("Failed to bind mount \"%s\" onto \"%s\"",
				     tty->name, lxcpath);
				continue;
			}
			DEBUG("Bind mounted \"%s\" onto \"%s\"", tty->name,
			      lxcpath);

			ret = snprintf(lxcpath, sizeof(lxcpath), "%s/tty%d",
				       ttydir, i + 1);
			if (ret < 0 || (size_t)ret >= sizeof(lxcpath))
				return -1;

			ret = symlink(lxcpath, path);
			if (ret < 0) {
				SYSERROR("Failed to create symlink \"%s\" -> \"%s\"",
				         path, lxcpath);
				return -1;
			}
		} else {
			/* If we populated /dev, then we need to create
			 * /dev/ttyN
			 */
			ret = mknod(path, S_IFREG | 0000, 0);
			if (ret < 0) /* this isn't fatal, continue */
				SYSERROR("Failed to create \"%s\"", path);

			ret = mount(tty->name, path, "none", MS_BIND, 0);
			if (ret < 0) {
				SYSERROR("Failed to mount '%s'->'%s'", tty->name, path);
				continue;
			}

			DEBUG("Bind mounted \"%s\" onto \"%s\"", tty->name, path);
		}

		if (!append_ttyname(&conf->ttys.tty_names, tty->name)) {
			ERROR("Error setting up container_ttys string");
			return -1;
		}
	}

	INFO("Finished setting up %zu /dev/tty<N> device(s)", ttys->max);
	return 0;
}

int lxc_allocate_ttys(struct lxc_conf *conf)
{
	size_t i;
	int ret;
	struct lxc_tty_info *ttys = &conf->ttys;

	/* no tty in the configuration */
	if (ttys->max == 0)
		return 0;

	ttys->tty = malloc(sizeof(*ttys->tty) * ttys->max);
	if (!ttys->tty)
		return -ENOMEM;

	for (i = 0; i < ttys->max; i++) {
		struct lxc_terminal_info *tty = &ttys->tty[i];

		tty->master = -EBADF;
		tty->slave = -EBADF;
		ret = openpty(&tty->master, &tty->slave, NULL, NULL, NULL);
		if (ret < 0) {
			SYSERROR("Failed to create tty %zu", i);
			ttys->max = i;
			lxc_delete_tty(ttys);
			return -ENOTTY;
		}

		ret = ttyname_r(tty->slave, tty->name, sizeof(tty->name));
		if (ret < 0) {
			SYSERROR("Failed to retrieve name of tty %zu slave", i);
			ttys->max = i;
			lxc_delete_tty(ttys);
			return -ENOTTY;
		}

		DEBUG("Created tty \"%s\" with master fd %d and slave fd %d",
		      tty->name, tty->master, tty->slave);

		/* Prevent leaking the file descriptors to the container */
		ret = fd_cloexec(tty->master, true);
		if (ret < 0)
			SYSWARN("Failed to set FD_CLOEXEC flag on master fd %d of "
			        "tty device \"%s\"", tty->master, tty->name);

		ret = fd_cloexec(tty->slave, true);
		if (ret < 0)
			SYSWARN("Failed to set FD_CLOEXEC flag on slave fd %d of "
			        "tty device \"%s\"", tty->slave, tty->name);

		tty->busy = 0;
	}

	INFO("Finished creating %zu tty devices", ttys->max);
	return 0;
}

void lxc_delete_tty(struct lxc_tty_info *ttys)
{
	int i;

	if (!ttys->tty)
		return;

	for (i = 0; i < ttys->max; i++) {
		struct lxc_terminal_info *tty = &ttys->tty[i];

		if (tty->master >= 0) {
			close(tty->master);
			tty->master = -EBADF;
		}

		if (tty->slave >= 0) {
			close(tty->slave);
			tty->slave = -EBADF;
		}
	}

	free(ttys->tty);
	ttys->tty = NULL;
}

static int lxc_send_ttys_to_parent(struct lxc_handler *handler)
{
	int i;
	int ret = -1;
	struct lxc_conf *conf = handler->conf;
	struct lxc_tty_info *ttys = &conf->ttys;
	int sock = handler->data_sock[0];

	if (ttys->max == 0)
		return 0;

	for (i = 0; i < ttys->max; i++) {
		int ttyfds[2];
		struct lxc_terminal_info *tty = &ttys->tty[i];

		ttyfds[0] = tty->master;
		ttyfds[1] = tty->slave;

		ret = lxc_abstract_unix_send_fds(sock, ttyfds, 2, NULL, 0);
		if (ret < 0)
			break;

		TRACE("Sent tty \"%s\" with master fd %d and slave fd %d to "
		      "parent", tty->name, tty->master, tty->slave);
	}

	if (ret < 0)
		SYSERROR("Failed to send %zu ttys to parent", ttys->max);
	else
		TRACE("Sent %zu ttys to parent", ttys->max);

	return ret;
}

static int lxc_create_ttys(struct lxc_handler *handler)
{
	int ret = -1;
	struct lxc_conf *conf = handler->conf;

	ret = lxc_allocate_ttys(conf);
	if (ret < 0) {
		ERROR("Failed to allocate ttys");
		goto on_error;
	}

	ret = lxc_send_ttys_to_parent(handler);
	if (ret < 0) {
		ERROR("Failed to send ttys to parent");
		goto on_error;
	}

	if (!conf->is_execute) {
		ret = lxc_setup_ttys(conf);
		if (ret < 0) {
			ERROR("Failed to setup ttys");
			goto on_error;
		}
	}

	if (conf->ttys.tty_names) {
		ret = setenv("container_ttys", conf->ttys.tty_names, 1);
		if (ret < 0)
			SYSERROR("Failed to set \"container_ttys=%s\"", conf->ttys.tty_names);
	}

	ret = 0;

on_error:
	lxc_delete_tty(&conf->ttys);

	return ret;
}

/* Just create a path for /dev under $lxcpath/$name and in rootfs If we hit an
 * error, log it but don't fail yet.
 */
static int mount_autodev(const char *name, const struct lxc_rootfs *rootfs,
			 const char *lxcpath)
{
	int ret;
	size_t clen;
	char *path;
	mode_t cur_mask;

	INFO("Preparing \"/dev\"");

	/* $(rootfs->mount) + "/dev/pts" + '\0' */
	clen = (rootfs->path ? strlen(rootfs->mount) : 0) + 9;
	path = alloca(clen);

	ret = snprintf(path, clen, "%s/dev", rootfs->path ? rootfs->mount : "");
	if (ret < 0 || (size_t)ret >= clen)
		return -1;

	cur_mask = umask(S_IXUSR | S_IXGRP | S_IXOTH);
	ret = mkdir(path, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
	if (ret < 0 && errno != EEXIST) {
		SYSERROR("Failed to create \"/dev\" directory");
		ret = -errno;
		goto reset_umask;
	}

	ret = safe_mount("none", path, "tmpfs", 0, "size=500000,mode=755",
			 rootfs->path ? rootfs->mount : NULL);
	if (ret < 0) {
		SYSERROR("Failed to mount tmpfs on \"%s\"", path);
		goto reset_umask;
	}
	TRACE("Mounted tmpfs on \"%s\"", path);

	ret = snprintf(path, clen, "%s/dev/pts", rootfs->path ? rootfs->mount : "");
	if (ret < 0 || (size_t)ret >= clen) {
		ret = -1;
		goto reset_umask;
	}

	/* If we are running on a devtmpfs mapping, dev/pts may already exist.
	 * If not, then create it and exit if that fails...
	 */
	ret = mkdir(path, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
	if (ret < 0 && errno != EEXIST) {
		SYSERROR("Failed to create directory \"%s\"", path);
		ret = -errno;
		goto reset_umask;
	}

	ret = 0;

reset_umask:
	(void)umask(cur_mask);

	INFO("Prepared \"/dev\"");
	return ret;
}

struct lxc_device_node {
	const char *name;
	const mode_t mode;
	const int maj;
	const int min;
};

static const struct lxc_device_node lxc_devices[] = {
	{ "full",    S_IFCHR | S_IRWXU | S_IRWXG | S_IRWXO, 1, 7 },
	{ "null",    S_IFCHR | S_IRWXU | S_IRWXG | S_IRWXO, 1, 3 },
	{ "random",  S_IFCHR | S_IRWXU | S_IRWXG | S_IRWXO, 1, 8 },
	{ "tty",     S_IFCHR | S_IRWXU | S_IRWXG | S_IRWXO, 5, 0 },
	{ "urandom", S_IFCHR | S_IRWXU | S_IRWXG | S_IRWXO, 1, 9 },
	{ "zero",    S_IFCHR | S_IRWXU | S_IRWXG | S_IRWXO, 1, 5 },
};


enum {
	LXC_DEVNODE_BIND,
	LXC_DEVNODE_MKNOD,
	LXC_DEVNODE_PARTIAL,
	LXC_DEVNODE_OPEN,
};

static int lxc_fill_autodev(const struct lxc_rootfs *rootfs)
{
	int i, ret;
	char path[PATH_MAX];
	mode_t cmask;
	int use_mknod = LXC_DEVNODE_MKNOD;

	ret = snprintf(path, PATH_MAX, "%s/dev",
		       rootfs->path ? rootfs->mount : "");
	if (ret < 0 || ret >= PATH_MAX)
		return -1;

	/* ignore, just don't try to fill in */
	if (!dir_exists(path))
		return 0;

	INFO("Populating \"/dev\"");

	cmask = umask(S_IXUSR | S_IXGRP | S_IXOTH);
	for (i = 0; i < sizeof(lxc_devices) / sizeof(lxc_devices[0]); i++) {
		char hostpath[PATH_MAX];
		const struct lxc_device_node *device = &lxc_devices[i];

		ret = snprintf(path, PATH_MAX, "%s/dev/%s",
			       rootfs->path ? rootfs->mount : "", device->name);
		if (ret < 0 || ret >= PATH_MAX)
			return -1;

		if (use_mknod >= LXC_DEVNODE_MKNOD) {
			ret = mknod(path, device->mode, makedev(device->maj, device->min));
			if (ret == 0 || (ret < 0 && errno == EEXIST)) {
				DEBUG("Created device node \"%s\"", path);
			} else if (ret < 0) {
				if (errno != EPERM) {
					SYSERROR("Failed to create device node \"%s\"", path);
					return -1;
				}

				use_mknod = LXC_DEVNODE_BIND;
			}

			/* Device nodes are fully useable. */
			if (use_mknod == LXC_DEVNODE_OPEN)
				continue;

			if (use_mknod == LXC_DEVNODE_MKNOD) {
				/* See
				 * - https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=55956b59df336f6738da916dbb520b6e37df9fbd
				 * - https://lists.linuxfoundation.org/pipermail/containers/2018-June/039176.html
				 */
				ret = open(path, O_RDONLY | O_CLOEXEC);
				if (ret >= 0) {
					close(ret);
					/* Device nodes are fully useable. */
					use_mknod = LXC_DEVNODE_OPEN;
					continue;
				}

				SYSTRACE("Failed to open \"%s\" device", path);
				/* Device nodes are only partially useable. */
				use_mknod = LXC_DEVNODE_PARTIAL;
			}
		}

		if (use_mknod != LXC_DEVNODE_PARTIAL) {
			/* If we are dealing with partially functional device
			 * nodes the prio mknod() call will have created the
			 * device node so we can use it as a bind-mount target.
			 */
			ret = mknod(path, S_IFREG | 0000, 0);
			if (ret < 0 && errno != EEXIST) {
				SYSERROR("Failed to create file \"%s\"", path);
				return -1;
			}
		}

		/* Fallback to bind-mounting the device from the host. */
		ret = snprintf(hostpath, PATH_MAX, "/dev/%s", device->name);
		if (ret < 0 || ret >= PATH_MAX)
			return -1;

		ret = safe_mount(hostpath, path, 0, MS_BIND, NULL,
				 rootfs->path ? rootfs->mount : NULL);
		if (ret < 0) {
			SYSERROR("Failed to bind mount host device node \"%s\" "
				 "onto \"%s\"", hostpath, path);
			return -1;
		}
		DEBUG("Bind mounted host device node \"%s\" onto \"%s\"",
		      hostpath, path);
	}
	(void)umask(cmask);

	INFO("Populated \"/dev\"");
	return 0;
}

static int lxc_mount_rootfs(struct lxc_conf *conf)
{
	int ret;
	struct lxc_storage *bdev;
	const struct lxc_rootfs *rootfs = &conf->rootfs;

	if (!rootfs->path) {
		ret = mount("", "/", NULL, MS_SLAVE | MS_REC, 0);
		if (ret < 0) {
			SYSERROR("Failed to remount \"/\" MS_REC | MS_SLAVE");
			return -1;
		}

		return 0;
	}

	ret = access(rootfs->mount, F_OK);
	if (ret != 0) {
		SYSERROR("Failed to access to \"%s\". Check it is present",
			 rootfs->mount);
		return -1;
	}

	bdev = storage_init(conf);
	if (!bdev) {
		ERROR("Failed to mount rootfs \"%s\" onto \"%s\" with options \"%s\"",
		      rootfs->path, rootfs->mount,
		      rootfs->options ? rootfs->options : "(null)");
		return -1;
	}

	ret = bdev->ops->mount(bdev);
	storage_put(bdev);
	if (ret < 0) {
		ERROR("Failed to mount rootfs \"%s\" onto \"%s\" with options \"%s\"",
		      rootfs->path, rootfs->mount,
		      rootfs->options ? rootfs->options : "(null)");
		return -1;
	}

	DEBUG("Mounted rootfs \"%s\" onto \"%s\" with options \"%s\"",
	      rootfs->path, rootfs->mount,
	      rootfs->options ? rootfs->options : "(null)");

	return 0;
}

int lxc_chroot(const struct lxc_rootfs *rootfs)
{
	int i, ret;
	char *p, *p2;
	char buf[LXC_LINELEN];
	char *nroot;
	FILE *f;
	char *root = rootfs->mount;

	nroot = realpath(root, NULL);
	if (!nroot) {
		SYSERROR("Failed to resolve \"%s\"", root);
		return -1;
	}

	ret = chdir("/");
	if (ret < 0) {
		free(nroot);
		return -1;
	}

	/* We could use here MS_MOVE, but in userns this mount is locked and
	 * can't be moved.
	 */
	ret = mount(nroot, "/", NULL, MS_REC | MS_BIND, NULL);
	if (ret < 0) {
		SYSERROR("Failed to mount \"%s\" onto \"/\" as MS_REC | MS_BIND", nroot);
		free(nroot);
		return -1;
	}
	free(nroot);

	ret = mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);
	if (ret < 0) {
		SYSERROR("Failed to remount \"/\"");
		return -1;
	}

	/* The following code cleans up inherited mounts which are not required
	 * for CT.
	 *
	 * The mountinfo file shows not all mounts, if a few points have been
	 * unmounted between read operations from the mountinfo. So we need to
	 * read mountinfo a few times.
	 *
	 * This loop can be skipped if a container uses userns, because all
	 * inherited mounts are locked and we should live with all this trash.
	 */
	for (;;) {
		int progress = 0;

		f = fopen("./proc/self/mountinfo", "r");
		if (!f) {
			SYSERROR("Failed to open \"/proc/self/mountinfo\"");
			return -1;
		}

		while (fgets(buf, LXC_LINELEN, f)) {
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

			ret = umount2(p, MNT_DETACH);
			if (ret == 0)
				progress++;
		}

		fclose(f);

		if (!progress)
			break;
	}

	/* This also can be skipped if a container uses userns. */
	(void)umount2("./proc", MNT_DETACH);

	/* It is weird, but chdir("..") moves us in a new root */
	ret = chdir("..");
	if (ret < 0) {
		SYSERROR("Failed to chdir(\"..\")");
		return -1;
	}

	ret = chroot(".");
	if (ret < 0) {
		SYSERROR("Failed to chroot(\".\")");
		return -1;
	}

	return 0;
}

/* (The following explanation is copied verbatim from the kernel.)
 *
 * pivot_root Semantics:
 * Moves the root file system of the current process to the directory put_old,
 * makes new_root as the new root file system of the current process, and sets
 * root/cwd of all processes which had them on the current root to new_root.
 *
 * Restrictions:
 * The new_root and put_old must be directories, and  must not be on the
 * same file  system as the current process root. The put_old  must  be
 * underneath new_root,  i.e. adding a non-zero number of /.. to the string
 * pointed to by put_old must yield the same directory as new_root. No other
 * file system may be mounted on put_old. After all, new_root is a mountpoint.
 *
 * Also, the current root cannot be on the 'rootfs' (initial ramfs) filesystem.
 * See Documentation/filesystems/ramfs-rootfs-initramfs.txt for alternatives
 * in this situation.
 *
 * Notes:
 *  - we don't move root/cwd if they are not at the root (reason: if something
 *    cared enough to change them, it's probably wrong to force them elsewhere)
 *  - it's okay to pick a root that isn't the root of a file system, e.g.
 *    /nfs/my_root where /nfs is the mount point. It must be a mountpoint,
 *    though, so you may need to say mount --bind /nfs/my_root /nfs/my_root
 *    first.
 */
static int lxc_pivot_root(const char *rootfs)
{
	int oldroot;
	int newroot = -1, ret = -1;

	oldroot = open("/", O_DIRECTORY | O_RDONLY | O_CLOEXEC);
	if (oldroot < 0) {
		SYSERROR("Failed to open old root directory");
		return -1;
	}

	newroot = open(rootfs, O_DIRECTORY | O_RDONLY | O_CLOEXEC);
	if (newroot < 0) {
		SYSERROR("Failed to open new root directory");
		goto on_error;
	}

	/* change into new root fs */
	ret = fchdir(newroot);
	if (ret < 0) {
		ret = -1;
		SYSERROR("Failed to change to new rootfs \"%s\"", rootfs);
		goto on_error;
	}

	/* pivot_root into our new root fs */
	ret = pivot_root(".", ".");
	if (ret < 0) {
		ret = -1;
		SYSERROR("Failed to pivot_root()");
		goto on_error;
	}

	/* At this point the old-root is mounted on top of our new-root. To
	 * unmounted it we must not be chdir'd into it, so escape back to
	 * old-root.
	 */
	ret = fchdir(oldroot);
	if (ret < 0) {
		ret = -1;
		SYSERROR("Failed to enter old root directory");
		goto on_error;
	}

	/* Make oldroot rslave to make sure our umounts don't propagate to the
	 * host.
	 */
	ret = mount("", ".", "", MS_SLAVE | MS_REC, NULL);
	if (ret < 0) {
		ret = -1;
		SYSERROR("Failed to make oldroot rslave");
		goto on_error;
	}

	ret = umount2(".", MNT_DETACH);
	if (ret < 0) {
		ret = -1;
		SYSERROR("Failed to detach old root directory");
		goto on_error;
	}

	ret = fchdir(newroot);
	if (ret < 0) {
		ret = -1;
		SYSERROR("Failed to re-enter new root directory");
		goto on_error;
	}

	ret = 0;

	TRACE("pivot_root(\"%s\") successful", rootfs);

on_error:
	close(oldroot);

	if (newroot >= 0)
		close(newroot);

	return ret;
}

static int lxc_setup_rootfs_switch_root(const struct lxc_rootfs *rootfs)
{
	if (!rootfs->path) {
		DEBUG("Container does not have a rootfs");
		return 0;
	}

	if (detect_ramfs_rootfs())
		return lxc_chroot(rootfs);

	return lxc_pivot_root(rootfs->mount);
}

static const struct id_map *find_mapped_nsid_entry(struct lxc_conf *conf,
						   unsigned id,
						   enum idtype idtype)
{
	struct lxc_list *it;
	struct id_map *map;
	struct id_map *retmap = NULL;

	/* Shortcut for container's root mappings. */
	if (id == 0) {
		if (idtype == ID_TYPE_UID)
			return conf->root_nsuid_map;

		if (idtype == ID_TYPE_GID)
			return conf->root_nsgid_map;
	}

	lxc_list_for_each(it, &conf->id_map) {
		map = it->elem;
		if (map->idtype != idtype)
			continue;

		if (id >= map->nsid && id < map->nsid + map->range) {
			retmap = map;
			break;
		}
	}

	return retmap;
}

static int lxc_setup_devpts(struct lxc_conf *conf)
{
	int ret;
	char **opts;
	char devpts_mntopts[256];
	char *mntopt_sets[5];
	char default_devpts_mntopts[256] = "gid=5,newinstance,ptmxmode=0666,mode=0620";

	if (conf->pty_max <= 0) {
		DEBUG("No new devpts instance will be mounted since no pts "
		      "devices are requested");
		return 0;
	}

	ret = snprintf(devpts_mntopts, sizeof(devpts_mntopts), "%s,max=%zu",
		       default_devpts_mntopts, conf->pty_max);
	if (ret < 0 || (size_t)ret >= sizeof(devpts_mntopts))
		return -1;

	ret = umount2("/dev/pts", MNT_DETACH);
	if (ret < 0)
		SYSWARN("Failed to unmount old devpts instance");
	else
		DEBUG("Unmounted old devpts instance");

	/* Create mountpoint for devpts instance. */
	ret = mkdir("/dev/pts", 0755);
	if (ret < 0 && errno != EEXIST) {
		SYSERROR("Failed to create \"/dev/pts\" directory");
		return -1;
	}

	/* gid=5 && max= */
	mntopt_sets[0] = devpts_mntopts;

	/* !gid=5 && max= */
	mntopt_sets[1] = devpts_mntopts + STRLITERALLEN("gid=5") + 1;

	/* gid=5 && !max= */
	mntopt_sets[2] = default_devpts_mntopts;

	/* !gid=5 && !max= */
	mntopt_sets[3] = default_devpts_mntopts + STRLITERALLEN("gid=5") + 1;

	/* end */
	mntopt_sets[4] = NULL;

	for (ret = -1, opts = mntopt_sets; opts && *opts; opts++) {
		/* mount new devpts instance */
		ret = mount("devpts", "/dev/pts", "devpts", MS_NOSUID | MS_NOEXEC, *opts);
		if (ret == 0)
			break;
	}

	if (ret < 0) {
		SYSERROR("Failed to mount new devpts instance");
		return -1;
	}
	DEBUG("Mount new devpts instance with options \"%s\"", *opts);

	/* Remove any pre-existing /dev/ptmx file. */
	ret = remove("/dev/ptmx");
	if (ret < 0) {
		if (errno != ENOENT) {
			SYSERROR("Failed to remove existing \"/dev/ptmx\" file");
			return -1;
		}
	} else {
		DEBUG("Removed existing \"/dev/ptmx\" file");
	}

	/* Create dummy /dev/ptmx file as bind mountpoint for /dev/pts/ptmx. */
	ret = mknod("/dev/ptmx", S_IFREG | 0000, 0);
	if (ret < 0 && errno != EEXIST) {
		SYSERROR("Failed to create dummy \"/dev/ptmx\" file as bind mount target");
		return -1;
	}
	DEBUG("Created dummy \"/dev/ptmx\" file as bind mount target");

	/* Fallback option: create symlink /dev/ptmx -> /dev/pts/ptmx  */
	ret = mount("/dev/pts/ptmx", "/dev/ptmx", NULL, MS_BIND, NULL);
	if (!ret) {
		DEBUG("Bind mounted \"/dev/pts/ptmx\" to \"/dev/ptmx\"");
		return 0;
	} else {
		/* Fallthrough and try to create a symlink. */
		ERROR("Failed to bind mount \"/dev/pts/ptmx\" to \"/dev/ptmx\"");
	}

	/* Remove the dummy /dev/ptmx file we created above. */
	ret = remove("/dev/ptmx");
	if (ret < 0) {
		SYSERROR("Failed to remove existing \"/dev/ptmx\"");
		return -1;
	}

	/* Fallback option: Create symlink /dev/ptmx -> /dev/pts/ptmx. */
	ret = symlink("/dev/pts/ptmx", "/dev/ptmx");
	if (ret < 0) {
		SYSERROR("Failed to create symlink from \"/dev/ptmx\" to \"/dev/pts/ptmx\"");
		return -1;
	}
	DEBUG("Created symlink from \"/dev/ptmx\" to \"/dev/pts/ptmx\"");

	return 0;
}

static int setup_personality(int persona)
{
	int ret;

#if HAVE_SYS_PERSONALITY_H
	if (persona == -1)
		return 0;

	ret = personality(persona);
	if (ret < 0) {
		SYSERROR("Failed to set personality to \"0x%x\"", persona);
		return -1;
	}

	INFO("Set personality to \"0x%x\"", persona);
#endif

	return 0;
}

static int lxc_setup_dev_console(const struct lxc_rootfs *rootfs,
				 const struct lxc_terminal *console)
{
	int ret;
	char path[PATH_MAX];
	char *rootfs_path = rootfs->path ? rootfs->mount : "";

	if (console->path && !strcmp(console->path, "none"))
		return 0;

	ret = snprintf(path, sizeof(path), "%s/dev/console", rootfs_path);
	if (ret < 0 || (size_t)ret >= sizeof(path))
		return -1;

	/* When we are asked to setup a console we remove any previous
	 * /dev/console bind-mounts.
	 */
	if (file_exists(path)) {
		ret = lxc_unstack_mountpoint(path, false);
		if (ret < 0) {
			SYSERROR("Failed to unmount \"%s\"", path);
			return -ret;
		} else {
			DEBUG("Cleared all (%d) mounts from \"%s\"", ret, path);
		}
	}

	/* For unprivileged containers autodev or automounts will already have
	 * taken care of creating /dev/console.
	 */
	ret = mknod(path, S_IFREG | 0000, 0);
	if (ret < 0 && errno != EEXIST) {
		SYSERROR("Failed to create console");
		return -errno;
	}

	ret = fchmod(console->slave, S_IXUSR | S_IXGRP);
	if (ret < 0) {
		SYSERROR("Failed to set mode \"0%o\" to \"%s\"",
			 S_IXUSR | S_IXGRP, console->name);
		return -errno;
	}

	ret = safe_mount(console->name, path, "none", MS_BIND, 0, rootfs_path);
	if (ret < 0) {
		ERROR("Failed to mount \"%s\" on \"%s\"", console->name, path);
		return -1;
	}

	DEBUG("Mounted pts device \"%s\" onto \"%s\"", console->name, path);
	return 0;
}

static int lxc_setup_ttydir_console(const struct lxc_rootfs *rootfs,
				    const struct lxc_terminal *console,
				    char *ttydir)
{
	int ret;
	char path[PATH_MAX], lxcpath[PATH_MAX];
	char *rootfs_path = rootfs->path ? rootfs->mount : "";

	if (console->path && !strcmp(console->path, "none"))
		return 0;

	/* create rootfs/dev/<ttydir> directory */
	ret = snprintf(path, sizeof(path), "%s/dev/%s", rootfs_path, ttydir);
	if (ret < 0 || (size_t)ret >= sizeof(path))
		return -1;

	ret = mkdir(path, 0755);
	if (ret && errno != EEXIST) {
		SYSERROR("Failed to create \"%s\"", path);
		return -errno;
	}
 	DEBUG("Created directory for console and tty devices at \"%s\"", path);

	ret = snprintf(lxcpath, sizeof(lxcpath), "%s/dev/%s/console", rootfs_path, ttydir);
	if (ret < 0 || (size_t)ret >= sizeof(lxcpath))
		return -1;

	ret = mknod(lxcpath, S_IFREG | 0000, 0);
	if (ret < 0 && errno != EEXIST) {
		SYSERROR("Failed to create \"%s\"", lxcpath);
		return -errno;
	}

	ret = snprintf(path, sizeof(path), "%s/dev/console", rootfs_path);
	if (ret < 0 || (size_t)ret >= sizeof(path))
		return -1;

	if (file_exists(path)) {
		ret = lxc_unstack_mountpoint(path, false);
		if (ret < 0) {
			SYSERROR("Failed to unmount \"%s\"", path);
			return -ret;
		} else {
			DEBUG("Cleared all (%d) mounts from \"%s\"", ret, path);
		}
	}

	ret = mknod(path, S_IFREG | 0000, 0);
	if (ret < 0 && errno != EEXIST) {
		SYSERROR("Failed to create console");
		return -errno;
	}

	ret = fchmod(console->slave, S_IXUSR | S_IXGRP);
	if (ret < 0) {
		SYSERROR("Failed to set mode \"0%o\" to \"%s\"",
			 S_IXUSR | S_IXGRP, console->name);
		return -errno;
	}

	/* bind mount console->name to '/dev/<ttydir>/console' */
	ret = safe_mount(console->name, lxcpath, "none", MS_BIND, 0, rootfs_path);
	if (ret < 0) {
		ERROR("Failed to mount \"%s\" on \"%s\"", console->name, lxcpath);
		return -1;
	}
	DEBUG("Mounted \"%s\" onto \"%s\"", console->name, lxcpath);

	/* bind mount '/dev/<ttydir>/console'  to '/dev/console'  */
	ret = safe_mount(lxcpath, path, "none", MS_BIND, 0, rootfs_path);
	if (ret < 0) {
		ERROR("Failed to mount \"%s\" on \"%s\"", console->name, lxcpath);
		return -1;
	}
	DEBUG("Mounted \"%s\" onto \"%s\"", console->name, lxcpath);

	DEBUG("Console has been setup under \"%s\" and mounted to \"%s\"", lxcpath, path);
	return 0;
}

static int lxc_setup_console(const struct lxc_rootfs *rootfs,
			     const struct lxc_terminal *console, char *ttydir)
{

	if (!ttydir)
		return lxc_setup_dev_console(rootfs, console);

	return lxc_setup_ttydir_console(rootfs, console, ttydir);
}

static void parse_mntopt(char *opt, unsigned long *flags, char **data, size_t size)
{
	struct mount_opt *mo;

	/* If opt is found in mount_opt, set or clear flags.
	 * Otherwise append it to data. */

	for (mo = &mount_opt[0]; mo->name != NULL; mo++) {
		if (strncmp(opt, mo->name, strlen(mo->name)) == 0) {
			if (mo->clear)
				*flags &= ~mo->flag;
			else
				*flags |= mo->flag;
			return;
		}
	}

	if (strlen(*data))
		(void)strlcat(*data, ",", size);

	(void)strlcat(*data, opt, size);
}

int parse_mntopts(const char *mntopts, unsigned long *mntflags, char **mntdata)
{
	char *data, *p, *s;
	size_t size;

	*mntdata = NULL;
	*mntflags = 0L;

	if (!mntopts)
		return 0;

	s = strdup(mntopts);
	if (!s)
		return -1;

	size = strlen(s) + 1;
	data = malloc(size);
	if (!data) {
		free(s);
		return -1;
	}
	*data = 0;

	lxc_iterate_parts(p, s, ",")
		parse_mntopt(p, mntflags, &data, size);

	if (*data)
		*mntdata = data;
	else
		free(data);
	free(s);

	return 0;
}

static void parse_propagationopt(char *opt, unsigned long *flags)
{
	struct mount_opt *mo;

	/* If opt is found in propagation_opt, set or clear flags. */
	for (mo = &propagation_opt[0]; mo->name != NULL; mo++) {
		if (strncmp(opt, mo->name, strlen(mo->name)) != 0)
			continue;

		if (mo->clear)
			*flags &= ~mo->flag;
		else
			*flags |= mo->flag;

		return;
	}
}

int parse_propagationopts(const char *mntopts, unsigned long *pflags)
{
	char *p, *s;

	if (!mntopts)
		return 0;

	s = strdup(mntopts);
	if (!s) {
		SYSERROR("Failed to allocate memory");
		return -ENOMEM;
	}

	*pflags = 0L;
	lxc_iterate_parts(p, s, ",")
		parse_propagationopt(p, pflags);
	free(s);

	return 0;
}

static void null_endofword(char *word)
{
	while (*word && *word != ' ' && *word != '\t')
		word++;
	*word = '\0';
}

/* skip @nfields spaces in @src */
static char *get_field(char *src, int nfields)
{
	int i;
	char *p = src;

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
		       unsigned long pflags, const char *data, bool optional,
		       bool dev, bool relative, const char *rootfs)
{
	int ret;
	char srcbuf[PATH_MAX];
	const char *srcpath = fsname;
#ifdef HAVE_STATVFS
	struct statvfs sb;
#endif

	if (relative) {
		ret = snprintf(srcbuf, PATH_MAX, "%s/%s", rootfs ? rootfs : "/", fsname ? fsname : "");
		if (ret < 0 || ret >= PATH_MAX) {
			ERROR("source path is too long");
			return -1;
		}
		srcpath = srcbuf;
	}

	ret = safe_mount(srcpath, target, fstype, mountflags & ~MS_REMOUNT, data,
			 rootfs);
	if (ret < 0) {
		if (optional) {
			SYSINFO("Failed to mount \"%s\" on \"%s\" (optional)",
			        srcpath ? srcpath : "(null)", target);
			return 0;
		}

		SYSERROR("Failed to mount \"%s\" on \"%s\"",
			 srcpath ? srcpath : "(null)", target);
		return -1;
	}

	if ((mountflags & MS_REMOUNT) || (mountflags & MS_BIND)) {
		unsigned long rqd_flags = 0;

		DEBUG("Remounting \"%s\" on \"%s\" to respect bind or remount "
		      "options", srcpath ? srcpath : "(none)", target ? target : "(none)");

		if (mountflags & MS_RDONLY)
			rqd_flags |= MS_RDONLY;
#ifdef HAVE_STATVFS
		if (srcpath && statvfs(srcpath, &sb) == 0) {
			unsigned long required_flags = rqd_flags;

			if (sb.f_flag & MS_NOSUID)
				required_flags |= MS_NOSUID;

			if (sb.f_flag & MS_NODEV && !dev)
				required_flags |= MS_NODEV;

			if (sb.f_flag & MS_RDONLY)
				required_flags |= MS_RDONLY;

			if (sb.f_flag & MS_NOEXEC)
				required_flags |= MS_NOEXEC;

			DEBUG("Flags for \"%s\" were %lu, required extra flags "
			      "are %lu", srcpath, sb.f_flag, required_flags);

			/* If this was a bind mount request, and required_flags
			 * does not have any flags which are not already in
			 * mountflags, then skip the remount.
			 */
			if (!(mountflags & MS_REMOUNT)) {
				if (!(required_flags & ~mountflags) &&
				    rqd_flags == 0) {
					DEBUG("Mountflags already were %lu, "
					      "skipping remount", mountflags);
					goto skipremount;
				}
			}

			mountflags |= required_flags;
		}
#endif

		ret = mount(srcpath, target, fstype, mountflags | MS_REMOUNT, data);
		if (ret < 0) {
			if (optional) {
				SYSINFO("Failed to mount \"%s\" on \"%s\" (optional)",
				        srcpath ? srcpath : "(null)", target);
				return 0;
			}

			SYSERROR("Failed to mount \"%s\" on \"%s\"",
				 srcpath ? srcpath : "(null)", target);
			return -1;
		}
	}

	if (pflags) {
		ret = mount(NULL, target, NULL, pflags, NULL);
		if (ret < 0) {
			if (optional) {
				SYSINFO("Failed to change mount propagation "
				        "for \"%s\" (optional)", target);
				return 0;
			} else {
				SYSERROR("Failed to change mount propagation "
					 "for \"%s\" (optional)", target);
				return -1;
			}
		}
		DEBUG("Changed mount propagation for \"%s\"", target);
	}


#ifdef HAVE_STATVFS
skipremount:
#endif
	DEBUG("Mounted \"%s\" on \"%s\" with filesystem type \"%s\"",
	      srcpath ? srcpath : "(null)", target, fstype);

	return 0;
}

/* Remove "optional", "create=dir", and "create=file" from mntopt */
static void cull_mntent_opt(struct mntent *mntent)
{
	int i;
	char *list[] = {
		"create=dir",
		"create=file",
		"optional",
		"relative",
		NULL
	};

	for (i = 0; list[i]; i++) {
		char *p, *p2;

		p = strstr(mntent->mnt_opts, list[i]);
		if (!p)
			continue;

		p2 = strchr(p, ',');
		if (!p2) {
			/* no more mntopts, so just chop it here */
			*p = '\0';
			continue;
		}

		memmove(p, p2 + 1, strlen(p2 + 1) + 1);
	}
}

static int mount_entry_create_dir_file(const struct mntent *mntent,
				       const char *path,
				       const struct lxc_rootfs *rootfs,
				       const char *lxc_name, const char *lxc_path)
{
	int ret;
	char *p1, *p2;

	if (strncmp(mntent->mnt_type, "overlay", 7) == 0) {
		ret = ovl_mkdir(mntent, rootfs, lxc_name, lxc_path);
		if (ret < 0)
			return -1;
	}

	if (hasmntopt(mntent, "create=dir")) {
		ret = mkdir_p(path, 0755);
		if (ret < 0 && errno != EEXIST) {
			SYSERROR("Failed to create directory \"%s\"", path);
			return -1;
		}
	}

	if (!hasmntopt(mntent, "create=file"))
		return 0;

	ret = access(path, F_OK);
	if (ret == 0)
		return 0;

	p1 = strdup(path);
	if (!p1)
		return -1;

	p2 = dirname(p1);

	ret = mkdir_p(p2, 0755);
	free(p1);
	if (ret < 0 && errno != EEXIST) {
		SYSERROR("Failed to create directory \"%s\"", path);
		return -1;
	}

	ret = mknod(path, S_IFREG | 0000, 0);
	if (ret < 0 && errno != EEXIST)
		return -errno;

	return 0;
}

/* rootfs, lxc_name, and lxc_path can be NULL when the container is created
 * without a rootfs. */
static inline int mount_entry_on_generic(struct mntent *mntent,
					 const char *path,
					 const struct lxc_rootfs *rootfs,
					 const char *lxc_name,
					 const char *lxc_path)
{
	int ret;
	unsigned long mntflags;
	char *mntdata;
	bool dev, optional, relative;
	unsigned long pflags = 0;
	char *rootfs_path = NULL;

	optional = hasmntopt(mntent, "optional") != NULL;
	dev = hasmntopt(mntent, "dev") != NULL;
	relative = hasmntopt(mntent, "relative") != NULL;

	if (rootfs && rootfs->path)
		rootfs_path = rootfs->mount;

	ret = mount_entry_create_dir_file(mntent, path, rootfs, lxc_name,
					  lxc_path);
	if (ret < 0) {
		if (optional)
			return 0;

		return -1;
	}
	cull_mntent_opt(mntent);

	ret = parse_propagationopts(mntent->mnt_opts, &pflags);
	if (ret < 0)
		return -1;

	ret = parse_mntopts(mntent->mnt_opts, &mntflags, &mntdata);
	if (ret < 0)
		return -1;

	ret = mount_entry(mntent->mnt_fsname, path, mntent->mnt_type, mntflags,
			  pflags, mntdata, optional, dev, relative, rootfs_path);

	free(mntdata);
	return ret;
}

static inline int mount_entry_on_systemfs(struct mntent *mntent)
{
	int ret;
	char path[PATH_MAX];

	/* For containers created without a rootfs all mounts are treated as
	 * absolute paths starting at / on the host.
	 */
	if (mntent->mnt_dir[0] != '/')
		ret = snprintf(path, sizeof(path), "/%s", mntent->mnt_dir);
	else
		ret = snprintf(path, sizeof(path), "%s", mntent->mnt_dir);
	if (ret < 0 || ret >= sizeof(path))
		return -1;

	return mount_entry_on_generic(mntent, path, NULL, NULL, NULL);
}

static int mount_entry_on_absolute_rootfs(struct mntent *mntent,
					  const struct lxc_rootfs *rootfs,
					  const char *lxc_name,
					  const char *lxc_path)
{
	int offset;
	char *aux;
	const char *lxcpath;
	char path[PATH_MAX];
	int ret = 0;

	lxcpath = lxc_global_config_value("lxc.lxcpath");
	if (!lxcpath)
		return -1;

	/* If rootfs->path is a blockdev path, allow container fstab to use
	 * <lxcpath>/<name>/rootfs" as the target prefix.
	 */
	ret = snprintf(path, PATH_MAX, "%s/%s/rootfs", lxcpath, lxc_name);
	if (ret < 0 || ret >= PATH_MAX)
		goto skipvarlib;

	aux = strstr(mntent->mnt_dir, path);
	if (aux) {
		offset = strlen(path);
		goto skipabs;
	}

skipvarlib:
	aux = strstr(mntent->mnt_dir, rootfs->path);
	if (!aux) {
		WARN("Ignoring mount point \"%s\"", mntent->mnt_dir);
		return ret;
	}
	offset = strlen(rootfs->path);

skipabs:
	ret = snprintf(path, PATH_MAX, "%s/%s", rootfs->mount, aux + offset);
	if (ret < 0 || ret >= PATH_MAX)
		return -1;

	return mount_entry_on_generic(mntent, path, rootfs, lxc_name, lxc_path);
}

static int mount_entry_on_relative_rootfs(struct mntent *mntent,
					  const struct lxc_rootfs *rootfs,
					  const char *lxc_name,
					  const char *lxc_path)
{
	int ret;
	char path[PATH_MAX];

	/* relative to root mount point */
	ret = snprintf(path, sizeof(path), "%s/%s", rootfs->mount, mntent->mnt_dir);
	if (ret < 0 || (size_t)ret >= sizeof(path))
		return -1;

	return mount_entry_on_generic(mntent, path, rootfs, lxc_name, lxc_path);
}

static int mount_file_entries(const struct lxc_conf *conf,
			      const struct lxc_rootfs *rootfs, FILE *file,
			      const char *lxc_name, const char *lxc_path)
{
	char buf[4096];
	struct mntent mntent;
	int ret = -1;

	while (getmntent_r(file, &mntent, buf, sizeof(buf))) {
		if (!rootfs->path)
			ret = mount_entry_on_systemfs(&mntent);
		else if (mntent.mnt_dir[0] != '/')
			ret = mount_entry_on_relative_rootfs(&mntent, rootfs,
							     lxc_name, lxc_path);
		else
			ret = mount_entry_on_absolute_rootfs(&mntent, rootfs,
					                     lxc_name, lxc_path);
		if (ret < 0)
			return -1;
	}
	ret = 0;

	INFO("Finished setting up mounts");
	return ret;
}

static int setup_mount(const struct lxc_conf *conf,
		       const struct lxc_rootfs *rootfs, const char *fstab,
		       const char *lxc_name, const char *lxc_path)
{
	FILE *f;
	int ret;

	if (!fstab)
		return 0;

	f = setmntent(fstab, "r");
	if (!f) {
		SYSERROR("Failed to open \"%s\"", fstab);
		return -1;
	}

	ret = mount_file_entries(conf, rootfs, f, lxc_name, lxc_path);
	if (ret < 0)
		ERROR("Failed to set up mount entries");

	endmntent(f);
	return ret;
}

/*
 * In order for nested containers to be able to mount /proc and /sys they need
 * to see a "pure" proc and sysfs mount points with nothing mounted on top
 * (like lxcfs).
 * For this we provide proc and sysfs in /dev/.lxc/{proc,sys} while using an
 * apparmor rule to deny access to them. This is mostly for convenience: The
 * container's root user can mount them anyway and thus has access to the two
 * file systems. But a non-root user in the container should not be allowed to
 * access them as a side effect without explicitly allowing it.
 */
static const char nesting_helpers[] =
"proc dev/.lxc/proc proc create=dir,optional\n"
"sys dev/.lxc/sys sysfs create=dir,optional\n";

FILE *make_anonymous_mount_file(struct lxc_list *mount,
				bool include_nesting_helpers)
{
	int ret;
	char *mount_entry;
	struct lxc_list *iterator;
	int fd = -1;

	fd = memfd_create(".lxc_mount_file", MFD_CLOEXEC);
	if (fd < 0) {
		char template[] = P_tmpdir "/.lxc_mount_file_XXXXXX";

		if (errno != ENOSYS)
			return NULL;

		fd = lxc_make_tmpfile(template, true);
		if (fd < 0) {
			SYSERROR("Could not create temporary mount file");
			return NULL;
		}

		TRACE("Created temporary mount file");
	}

	lxc_list_for_each (iterator, mount) {
		size_t len;

		mount_entry = iterator->elem;
		len = strlen(mount_entry);

		ret = lxc_write_nointr(fd, mount_entry, len);
		if (ret != len)
			goto on_error;

		ret = lxc_write_nointr(fd, "\n", 1);
		if (ret != 1)
			goto on_error;
	}

	if (include_nesting_helpers) {
		ret = lxc_write_nointr(fd, nesting_helpers,
				       STRARRAYLEN(nesting_helpers));
		if (ret != STRARRAYLEN(nesting_helpers))
			goto on_error;
	}

	ret = lseek(fd, 0, SEEK_SET);
	if (ret < 0)
		goto on_error;

	return fdopen(fd, "r+");

on_error:
	SYSERROR("Failed to write mount entry to temporary mount file");
	close(fd);
	return NULL;
}

static int setup_mount_entries(const struct lxc_conf *conf,
			       const struct lxc_rootfs *rootfs,
			       struct lxc_list *mount, const char *lxc_name,
			       const char *lxc_path)
{
	int ret;
	FILE *f;

	f = make_anonymous_mount_file(mount, conf->lsm_aa_allow_nesting);
	if (!f)
		return -1;

	ret = mount_file_entries(conf, rootfs, f, lxc_name, lxc_path);
	fclose(f);

	return ret;
}

static int parse_cap(const char *cap)
{
	size_t i;
	int capid = -1;
	size_t end = sizeof(caps_opt) / sizeof(caps_opt[0]);
	char *ptr = NULL;

	if (strcmp(cap, "none") == 0)
		return -2;

	for (i = 0; i < end; i++) {
		if (strcmp(cap, caps_opt[i].name))
			continue;

		capid = caps_opt[i].value;
		break;
	}

	if (capid < 0) {
		/* Try to see if it's numeric, so the user may specify
		 * capabilities that the running kernel knows about but we
		 * don't
		 */
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
	int capid;
	struct lxc_list *iterator;

	lxc_list_for_each (iterator, caps) {
		capid = parse_cap(iterator->elem);
		if (capid == cap)
			return 1;
	}

	return 0;
}

static int setup_caps(struct lxc_list *caps)
{
	int capid;
	char *drop_entry;
	struct lxc_list *iterator;

	lxc_list_for_each (iterator, caps) {
		int ret;

		drop_entry = iterator->elem;

		capid = parse_cap(drop_entry);
		if (capid < 0) {
			ERROR("unknown capability %s", drop_entry);
			return -1;
		}

		ret = prctl(PR_CAPBSET_DROP, prctl_arg(capid), prctl_arg(0),
			    prctl_arg(0), prctl_arg(0));
		if (ret < 0) {
			SYSERROR("Failed to remove %s capability", drop_entry);
			return -1;
		}
		DEBUG("Dropped %s (%d) capability", drop_entry, capid);
	}

	DEBUG("Capabilities have been setup");
	return 0;
}

static int dropcaps_except(struct lxc_list *caps)
{
	int i, capid, numcaps;
	char *keep_entry;
	struct lxc_list *iterator;

	numcaps = lxc_caps_last_cap() + 1;
	if (numcaps <= 0 || numcaps > 200)
		return -1;
	TRACE("Found %d capabilities", numcaps);

	/* caplist[i] is 1 if we keep capability i */
	int *caplist = alloca(numcaps * sizeof(int));
	memset(caplist, 0, numcaps * sizeof(int));

	lxc_list_for_each (iterator, caps) {
		keep_entry = iterator->elem;

		capid = parse_cap(keep_entry);
		if (capid == -2)
			continue;

		if (capid < 0) {
			ERROR("Unknown capability %s", keep_entry);
			return -1;
		}

		DEBUG("Keep capability %s (%d)", keep_entry, capid);
		caplist[capid] = 1;
	}

	for (i = 0; i < numcaps; i++) {
		int ret;

		if (caplist[i])
			continue;

		ret = prctl(PR_CAPBSET_DROP, prctl_arg(i), prctl_arg(0),
			    prctl_arg(0), prctl_arg(0));
		if (ret < 0) {
			SYSERROR("Failed to remove capability %d", i);
			return -1;
		}
	}

	DEBUG("Capabilities have been setup");
	return 0;
}

static int parse_resource(const char *res)
{
	int ret;
	size_t i;
	int resid = -1;

	for (i = 0; i < sizeof(limit_opt) / sizeof(limit_opt[0]); ++i)
		if (strcmp(res, limit_opt[i].name) == 0)
			return limit_opt[i].value;

	/* Try to see if it's numeric, so the user may specify
	 * resources that the running kernel knows about but
	 * we don't.
	 */
	ret = lxc_safe_int(res, &resid);
	if (ret < 0)
		return -1;

	return resid;
}

int setup_resource_limits(struct lxc_list *limits, pid_t pid)
{
	int resid;
	struct lxc_list *it;
	struct lxc_limit *lim;

	lxc_list_for_each (it, limits) {
		lim = it->elem;

		resid = parse_resource(lim->resource);
		if (resid < 0) {
			ERROR("Unknown resource %s", lim->resource);
			return -1;
		}

#if HAVE_PRLIMIT || HAVE_PRLIMIT64
		if (prlimit(pid, resid, &lim->limit, NULL) != 0) {
			SYSERROR("Failed to set limit %s", lim->resource);
			return -1;
		}

		TRACE("Setup \"%s\" limit", lim->resource);
#else
		ERROR("Cannot set limit \"%s\" as prlimit is missing", lim->resource);
		return -1;
#endif
	}

	return 0;
}

int setup_sysctl_parameters(struct lxc_list *sysctls)
{
	struct lxc_list *it;
	struct lxc_sysctl *elem;
	int ret = 0;
	char *tmp = NULL;
	char filename[PATH_MAX] = {0};

	lxc_list_for_each (it, sysctls) {
		elem = it->elem;
		tmp = lxc_string_replace(".", "/", elem->key);
		if (!tmp) {
			ERROR("Failed to replace key %s", elem->key);
			return -1;
		}

		ret = snprintf(filename, sizeof(filename), "/proc/sys/%s", tmp);
		free(tmp);
		if (ret < 0 || (size_t)ret >= sizeof(filename)) {
			ERROR("Error setting up sysctl parameters path");
			return -1;
		}

		ret = lxc_write_to_file(filename, elem->value,
					strlen(elem->value), false, 0666);
		if (ret < 0) {
			SYSERROR("Failed to setup sysctl parameters %s to %s",
			         elem->key, elem->value);
			return -1;
		}
	}

	return 0;
}

int setup_proc_filesystem(struct lxc_list *procs, pid_t pid)
{
	struct lxc_list *it;
	struct lxc_proc *elem;
	int ret = 0;
	char *tmp = NULL;
	char filename[PATH_MAX] = {0};

	lxc_list_for_each (it, procs) {
		elem = it->elem;
		tmp = lxc_string_replace(".", "/", elem->filename);
		if (!tmp) {
			ERROR("Failed to replace key %s", elem->filename);
			return -1;
		}

		ret = snprintf(filename, sizeof(filename), "/proc/%d/%s", pid, tmp);
		free(tmp);
		if (ret < 0 || (size_t)ret >= sizeof(filename)) {
			ERROR("Error setting up proc filesystem path");
			return -1;
		}

		ret = lxc_write_to_file(filename, elem->value,
					strlen(elem->value), false, 0666);
		if (ret < 0) {
			SYSERROR("Failed to setup proc filesystem %s to %s",
			         elem->filename, elem->value);
			return -1;
		}
	}

	return 0;
}

static char *default_rootfs_mount = LXCROOTFSMOUNT;

struct lxc_conf *lxc_conf_init(void)
{
	int i;
	struct lxc_conf *new;

	new = malloc(sizeof(*new));
	if (!new)
		return NULL;
	memset(new, 0, sizeof(*new));

	new->loglevel = LXC_LOG_LEVEL_NOTSET;
	new->personality = -1;
	new->autodev = 1;
	new->console.buffer_size = 0;
	new->console.log_path = NULL;
	new->console.log_fd = -1;
	new->console.log_size = 0;
	new->console.path = NULL;
	new->console.peer = -1;
	new->console.proxy.busy = -1;
	new->console.proxy.master = -1;
	new->console.proxy.slave = -1;
	new->console.master = -1;
	new->console.slave = -1;
	new->console.name[0] = '\0';
	memset(&new->console.ringbuf, 0, sizeof(struct lxc_ringbuf));
	new->maincmd_fd = -1;
	new->monitor_signal_pdeath = SIGKILL;
	new->nbd_idx = -1;
	new->rootfs.mount = strdup(default_rootfs_mount);
	if (!new->rootfs.mount) {
		free(new);
		return NULL;
	}
	new->rootfs.managed = true;
	new->logfd = -1;
	lxc_list_init(&new->cgroup);
	lxc_list_init(&new->cgroup2);
	lxc_list_init(&new->network);
	lxc_list_init(&new->mount_list);
	lxc_list_init(&new->caps);
	lxc_list_init(&new->keepcaps);
	lxc_list_init(&new->id_map);
	new->root_nsuid_map = NULL;
	new->root_nsgid_map = NULL;
	lxc_list_init(&new->includes);
	lxc_list_init(&new->aliens);
	lxc_list_init(&new->environment);
	lxc_list_init(&new->limits);
	lxc_list_init(&new->sysctls);
	lxc_list_init(&new->procs);
	new->hooks_version = 0;
	for (i = 0; i < NUM_LXC_HOOKS; i++)
		lxc_list_init(&new->hooks[i]);
	lxc_list_init(&new->groups);
	lxc_list_init(&new->state_clients);
	new->lsm_aa_profile = NULL;
	lxc_list_init(&new->lsm_aa_raw);
	new->lsm_se_context = NULL;
	new->tmp_umount_proc = false;
	new->tmp_umount_proc = 0;
	new->shmount.path_host = NULL;
	new->shmount.path_cont = NULL;

	/* if running in a new user namespace, init and COMMAND
	 * default to running as UID/GID 0 when using lxc-execute */
	new->init_uid = 0;
	new->init_gid = 0;
	memset(&new->cgroup_meta, 0, sizeof(struct lxc_cgroup));
	memset(&new->ns_share, 0, sizeof(char *) * LXC_NS_MAX);

	return new;
}

int write_id_mapping(enum idtype idtype, pid_t pid, const char *buf,
		     size_t buf_size)
{
	int fd, ret;
	char path[PATH_MAX];

	if (geteuid() != 0 && idtype == ID_TYPE_GID) {
		size_t buflen;

		ret = snprintf(path, PATH_MAX, "/proc/%d/setgroups", pid);
		if (ret < 0 || ret >= PATH_MAX)
			return -E2BIG;

		fd = open(path, O_WRONLY);
		if (fd < 0 && errno != ENOENT) {
			SYSERROR("Failed to open \"%s\"", path);
			return -1;
		}

		if (fd >= 0) {
			buflen = STRLITERALLEN("deny\n");
			errno = 0;
			ret = lxc_write_nointr(fd, "deny\n", buflen);
			close(fd);
			if (ret != buflen) {
				SYSERROR("Failed to write \"deny\" to "
					 "\"/proc/%d/setgroups\"", pid);
				return -1;
			}
			TRACE("Wrote \"deny\" to \"/proc/%d/setgroups\"", pid);
		}
	}

	ret = snprintf(path, PATH_MAX, "/proc/%d/%cid_map", pid,
		       idtype == ID_TYPE_UID ? 'u' : 'g');
	if (ret < 0 || ret >= PATH_MAX)
		return -E2BIG;

	fd = open(path, O_WRONLY);
	if (fd < 0) {
		SYSERROR("Failed to open \"%s\"", path);
		return -1;
	}

	errno = 0;
	ret = lxc_write_nointr(fd, buf, buf_size);
	close(fd);
	if (ret != buf_size) {
		SYSERROR("Failed to write %cid mapping to \"%s\"",
			 idtype == ID_TYPE_UID ? 'u' : 'g', path);
		return -1;
	}

	return 0;
}

/* Check whether a binary exist and has either CAP_SETUID, CAP_SETGID or both.
 *
 * @return  1      if functional binary was found
 * @return  0      if binary exists but is lacking privilege
 * @return -ENOENT if binary does not exist
 * @return -EINVAL if cap to check is neither CAP_SETUID nor CAP_SETGID
 */
static int idmaptool_on_path_and_privileged(const char *binary, cap_value_t cap)
{
	char *path;
	int ret;
	struct stat st;
	int fret = 0;

	if (cap != CAP_SETUID && cap != CAP_SETGID)
		return -EINVAL;

	path = on_path(binary, NULL);
	if (!path)
		return -ENOENT;

	ret = stat(path, &st);
	if (ret < 0) {
		fret = -errno;
		goto cleanup;
	}

	/* Check if the binary is setuid. */
	if (st.st_mode & S_ISUID) {
		DEBUG("The binary \"%s\" does have the setuid bit set", path);
		fret = 1;
		goto cleanup;
	}

#if HAVE_LIBCAP && LIBCAP_SUPPORTS_FILE_CAPABILITIES
	/* Check if it has the CAP_SETUID capability. */
	if ((cap & CAP_SETUID) &&
	    lxc_file_cap_is_set(path, CAP_SETUID, CAP_EFFECTIVE) &&
	    lxc_file_cap_is_set(path, CAP_SETUID, CAP_PERMITTED)) {
		DEBUG("The binary \"%s\" has CAP_SETUID in its CAP_EFFECTIVE "
		      "and CAP_PERMITTED sets", path);
		fret = 1;
		goto cleanup;
	}

	/* Check if it has the CAP_SETGID capability. */
	if ((cap & CAP_SETGID) &&
	    lxc_file_cap_is_set(path, CAP_SETGID, CAP_EFFECTIVE) &&
	    lxc_file_cap_is_set(path, CAP_SETGID, CAP_PERMITTED)) {
		DEBUG("The binary \"%s\" has CAP_SETGID in its CAP_EFFECTIVE "
		      "and CAP_PERMITTED sets", path);
		fret = 1;
		goto cleanup;
	}
#else
	/* If we cannot check for file capabilities we need to give the benefit
	 * of the doubt. Otherwise we might fail even though all the necessary
	 * file capabilities are set.
	 */
	DEBUG("Cannot check for file capabilities as full capability support is "
	      "missing. Manual intervention needed");
	fret = 1;
#endif

cleanup:
	free(path);
	return fret;
}

int lxc_map_ids_exec_wrapper(void *args)
{
	execl("/bin/sh", "sh", "-c", (char *)args, (char *)NULL);
	return -1;
}

int lxc_map_ids(struct lxc_list *idmap, pid_t pid)
{
	int fill, left;
	char u_or_g;
	char *pos;
	char cmd_output[PATH_MAX];
	struct id_map *map;
	struct lxc_list *iterator;
	enum idtype type;
	/* strlen("new@idmap") = 9
	 * +
	 * strlen(" ") = 1
	 * +
	 * INTTYPE_TO_STRLEN(uint32_t)
	 * +
	 * strlen(" ") = 1
	 *
	 * We add some additional space to make sure that we really have
	 * LXC_IDMAPLEN bytes available for our the {g,u]id mapping.
	 */
	int ret = 0, gidmap = 0, uidmap = 0;
	char mapbuf[9 + 1 + INTTYPE_TO_STRLEN(uint32_t) + 1 + LXC_IDMAPLEN] = {0};
	bool had_entry = false, use_shadow = false;
	int hostuid, hostgid;

	hostuid = geteuid();
	hostgid = getegid();

	/* If new{g,u}idmap exists, that is, if shadow is handing out subuid
	 * ranges, then insist that root also reserve ranges in subuid. This
	 * will protected it by preventing another user from being handed the
	 * range by shadow.
	 */
	uidmap = idmaptool_on_path_and_privileged("newuidmap", CAP_SETUID);
	if (uidmap == -ENOENT)
		WARN("newuidmap binary is missing");
	else if (!uidmap)
		WARN("newuidmap is lacking necessary privileges");

	gidmap = idmaptool_on_path_and_privileged("newgidmap", CAP_SETGID);
	if (gidmap == -ENOENT)
		WARN("newgidmap binary is missing");
	else if (!gidmap)
		WARN("newgidmap is lacking necessary privileges");

	if (uidmap > 0 && gidmap > 0) {
		DEBUG("Functional newuidmap and newgidmap binary found");
		use_shadow = true;
	} else {
		/* In case unprivileged users run application containers via
		 * execute() or a start*() there are valid cases where they may
		 * only want to map their own {g,u}id. Let's not block them from
		 * doing so by requiring geteuid() == 0.
		 */
		DEBUG("No newuidmap and newgidmap binary found. Trying to "
		      "write directly with euid %d", hostuid);
	}

	/* Check if we really need to use newuidmap and newgidmap.
	* If the user is only remapping his own {g,u}id, we don't need it.
	*/
	if (use_shadow && lxc_list_len(idmap) == 2) {
		use_shadow = false;
		lxc_list_for_each(iterator, idmap) {
			map = iterator->elem;
			if (map->idtype == ID_TYPE_UID && map->range == 1 &&
			    map->nsid == hostuid && map->hostid == hostuid)
				continue;
			if (map->idtype == ID_TYPE_GID && map->range == 1 &&
			    map->nsid == hostgid && map->hostid == hostgid)
				continue;
			use_shadow = true;
			break;
		}
	}

	for (type = ID_TYPE_UID, u_or_g = 'u'; type <= ID_TYPE_GID;
	     type++, u_or_g = 'g') {
		pos = mapbuf;

		if (use_shadow)
			pos += sprintf(mapbuf, "new%cidmap %d", u_or_g, pid);

		lxc_list_for_each(iterator, idmap) {
			map = iterator->elem;
			if (map->idtype != type)
				continue;

			had_entry = true;

			left = LXC_IDMAPLEN - (pos - mapbuf);
			fill = snprintf(pos, left, "%s%lu %lu %lu%s",
					use_shadow ? " " : "", map->nsid,
					map->hostid, map->range,
					use_shadow ? "" : "\n");
			if (fill <= 0 || fill >= left) {
				/* The kernel only takes <= 4k for writes to
				 * /proc/<pid>/{g,u}id_map
				 */
				SYSERROR("Too many %cid mappings defined", u_or_g);
				return -1;
			}

			pos += fill;
		}
		if (!had_entry)
			continue;

		/* Try to catch the output of new{g,u}idmap to make debugging
		 * easier.
		 */
		if (use_shadow) {
			ret = run_command(cmd_output, sizeof(cmd_output),
					  lxc_map_ids_exec_wrapper,
					  (void *)mapbuf);
			if (ret < 0) {
				ERROR("new%cidmap failed to write mapping \"%s\": %s",
				      u_or_g, cmd_output, mapbuf);
				return -1;
			}
			TRACE("new%cidmap wrote mapping \"%s\"", u_or_g, mapbuf);
		} else {
			ret = write_id_mapping(type, pid, mapbuf, pos - mapbuf);
			if (ret < 0) {
				ERROR("Failed to write mapping: %s", mapbuf);
				return -1;
			}
			TRACE("Wrote mapping \"%s\"", mapbuf);
		}

		memset(mapbuf, 0, sizeof(mapbuf));
	}

	return 0;
}

/* Return the host uid/gid to which the container root is mapped in val.
 * Return true if id was found, false otherwise.
 */
bool get_mapped_rootid(struct lxc_conf *conf, enum idtype idtype,
		       unsigned long *val)
{
	unsigned nsid;
	struct id_map *map;
	struct lxc_list *it;

	if (idtype == ID_TYPE_UID)
		nsid = (conf->root_nsuid_map != NULL) ? 0 : conf->init_uid;
	else
		nsid = (conf->root_nsgid_map != NULL) ? 0 : conf->init_gid;

	lxc_list_for_each (it, &conf->id_map) {
		map = it->elem;
		if (map->idtype != idtype)
			continue;
		if (map->nsid != nsid)
			continue;
		*val = map->hostid;
		return true;
	}

	return false;
}

int mapped_hostid(unsigned id, struct lxc_conf *conf, enum idtype idtype)
{
	struct id_map *map;
	struct lxc_list *it;

	lxc_list_for_each (it, &conf->id_map) {
		map = it->elem;
		if (map->idtype != idtype)
			continue;

		if (id >= map->hostid && id < map->hostid + map->range)
			return (id - map->hostid) + map->nsid;
	}

	return -1;
}

int find_unmapped_nsid(struct lxc_conf *conf, enum idtype idtype)
{
	struct id_map *map;
	struct lxc_list *it;
	unsigned int freeid = 0;

again:
	lxc_list_for_each (it, &conf->id_map) {
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

int chown_mapped_root_exec_wrapper(void *args)
{
	execvp("lxc-usernsexec", args);
	return -1;
}

/* chown_mapped_root: for an unprivileged user with uid/gid X to
 * chown a dir to subuid/subgid Y, he needs to run chown as root
 * in a userns where nsid 0 is mapped to hostuid/hostgid Y, and
 * nsid Y is mapped to hostuid/hostgid X.  That way, the container
 * root is privileged with respect to hostuid/hostgid X, allowing
 * him to do the chown.
 */
int chown_mapped_root(const char *path, struct lxc_conf *conf)
{
	uid_t rootuid, rootgid;
	unsigned long val;
	int hostuid, hostgid, ret;
	struct stat sb;
	char map1[100], map2[100], map3[100], map4[100], map5[100];
	char ugid[100];
	const char *args1[] = {"lxc-usernsexec",
			 "-m", map1,
			 "-m", map2,
			 "-m", map3,
			 "-m", map5,
			 "--", "chown", ugid, path,
			 NULL};
	const char *args2[] = {"lxc-usernsexec",
			 "-m", map1,
			 "-m", map2,
			 "-m", map3,
			 "-m", map4,
			 "-m", map5,
			 "--", "chown", ugid, path,
			 NULL};
	char cmd_output[PATH_MAX];

	hostuid = geteuid();
	hostgid = getegid();

	if (!get_mapped_rootid(conf, ID_TYPE_UID, &val)) {
		ERROR("No uid mapping for container root");
		return -1;
	}
	rootuid = (uid_t)val;

	if (!get_mapped_rootid(conf, ID_TYPE_GID, &val)) {
		ERROR("No gid mapping for container root");
		return -1;
	}
	rootgid = (gid_t)val;

	if (hostuid == 0) {
		if (chown(path, rootuid, rootgid) < 0) {
			ERROR("Error chowning %s", path);
			return -1;
		}

		return 0;
	}

	if (rootuid == hostuid) {
		/* nothing to do */
		INFO("Container root is our uid; no need to chown");
		return 0;
	}

	/* save the current gid of "path" */
	if (stat(path, &sb) < 0) {
		ERROR("Error stat %s", path);
		return -1;
	}

	/* Update the path argument in case this was overlayfs. */
	args1[sizeof(args1) / sizeof(args1[0]) - 2] = path;
	args2[sizeof(args2) / sizeof(args2[0]) - 2] = path;

	/*
	 * A file has to be group-owned by a gid mapped into the
	 * container, or the container won't be privileged over it.
	 */
	DEBUG("trying to chown \"%s\" to %d", path, hostgid);
	if (sb.st_uid == hostuid &&
	    mapped_hostid(sb.st_gid, conf, ID_TYPE_GID) < 0 &&
	    chown(path, -1, hostgid) < 0) {
		ERROR("Failed chgrping %s", path);
		return -1;
	}

	/* "u:0:rootuid:1" */
	ret = snprintf(map1, 100, "u:0:%d:1", rootuid);
	if (ret < 0 || ret >= 100) {
		ERROR("Error uid printing map string");
		return -1;
	}

	/* "u:hostuid:hostuid:1" */
	ret = snprintf(map2, 100, "u:%d:%d:1", hostuid, hostuid);
	if (ret < 0 || ret >= 100) {
		ERROR("Error uid printing map string");
		return -1;
	}

	/* "g:0:rootgid:1" */
	ret = snprintf(map3, 100, "g:0:%d:1", rootgid);
	if (ret < 0 || ret >= 100) {
		ERROR("Error gid printing map string");
		return -1;
	}

	/* "g:pathgid:rootgid+pathgid:1" */
	ret = snprintf(map4, 100, "g:%d:%d:1", (gid_t)sb.st_gid,
		       rootgid + (gid_t)sb.st_gid);
	if (ret < 0 || ret >= 100) {
		ERROR("Error gid printing map string");
		return -1;
	}

	/* "g:hostgid:hostgid:1" */
	ret = snprintf(map5, 100, "g:%d:%d:1", hostgid, hostgid);
	if (ret < 0 || ret >= 100) {
		ERROR("Error gid printing map string");
		return -1;
	}

	/* "0:pathgid" (chown) */
	ret = snprintf(ugid, 100, "0:%d", (gid_t)sb.st_gid);
	if (ret < 0 || ret >= 100) {
		ERROR("Error owner printing format string for chown");
		return -1;
	}

	if (hostgid == sb.st_gid)
		ret = run_command(cmd_output, sizeof(cmd_output),
				  chown_mapped_root_exec_wrapper,
				  (void *)args1);
	else
		ret = run_command(cmd_output, sizeof(cmd_output),
				  chown_mapped_root_exec_wrapper,
				  (void *)args2);
	if (ret < 0)
		ERROR("lxc-usernsexec failed: %s", cmd_output);

	return ret;
}

/* NOTE: Must not be called from inside the container namespace! */
int lxc_create_tmp_proc_mount(struct lxc_conf *conf)
{
	int mounted;

	mounted = lxc_mount_proc_if_needed(conf->rootfs.path ? conf->rootfs.mount : "");
	if (mounted == -1) {
		SYSERROR("Failed to mount proc in the container");
		/* continue only if there is no rootfs */
		if (conf->rootfs.path)
			return -1;
	} else if (mounted == 1) {
		conf->tmp_umount_proc = true;
	}

	return 0;
}

void tmp_proc_unmount(struct lxc_conf *lxc_conf)
{
	if (!lxc_conf->tmp_umount_proc)
		return;

	(void)umount2("/proc", MNT_DETACH);
	lxc_conf->tmp_umount_proc = false;
}

/* Walk /proc/mounts and change any shared entries to slave. */
void remount_all_slave(void)
{
	int memfd, mntinfo_fd, ret;
	ssize_t copied;
	FILE *f;
	size_t len = 0;
	char *line = NULL;

	mntinfo_fd = open("/proc/self/mountinfo", O_RDONLY | O_CLOEXEC);
	if (mntinfo_fd < 0) {
		SYSERROR("Failed to open \"/proc/self/mountinfo\"");
		return;
	}

	memfd = memfd_create(".lxc_mountinfo", MFD_CLOEXEC);
	if (memfd < 0) {
		char template[] = P_tmpdir "/.lxc_mountinfo_XXXXXX";

		if (errno != ENOSYS) {
			SYSERROR("Failed to create temporary in-memory file");
			close(mntinfo_fd);
			return;
		}

		memfd = lxc_make_tmpfile(template, true);
		if (memfd < 0) {
			close(mntinfo_fd);
			WARN("Failed to create temporary file");
			return;
		}
	}

again:
	copied = lxc_sendfile_nointr(memfd, mntinfo_fd, NULL, LXC_SENDFILE_MAX);
	if (copied < 0) {
		if (errno == EINTR)
			goto again;

		SYSERROR("Failed to copy \"/proc/self/mountinfo\"");
		close(mntinfo_fd);
		close(memfd);
		return;
	}
	close(mntinfo_fd);

	/* After a successful fdopen() memfd will be closed when calling
	 * fclose(f). Calling close(memfd) afterwards is undefined.
	 */
	ret = lseek(memfd, 0, SEEK_SET);
	if (ret < 0) {
		SYSERROR("Failed to reset file descriptor offset");
		close(memfd);
		return;
	}

	f = fdopen(memfd, "r");
	if (!f) {
		SYSERROR("Failed to open copy of \"/proc/self/mountinfo\" to mark "
				"all shared. Continuing");
		close(memfd);
		return;
	}

	while (getline(&line, &len, f) != -1) {
		int ret;
		char *opts, *target;

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
		ret = mount(NULL, target, NULL, MS_SLAVE, NULL);
		if (ret < 0) {
			SYSERROR("Failed to make \"%s\" MS_SLAVE", target);
			ERROR("Continuing...");
			continue;
		}
		TRACE("Remounted \"%s\" as MS_SLAVE", target);
	}
	fclose(f);
	free(line);
	TRACE("Remounted all mount table entries as MS_SLAVE");
}

static int lxc_execute_bind_init(struct lxc_handler *handler)
{
	int ret;
	char *p;
	char path[PATH_MAX], destpath[PATH_MAX];
	struct lxc_conf *conf = handler->conf;

	/* If init exists in the container, don't bind mount a static one */
	p = choose_init(conf->rootfs.mount);
	if (p) {
		char *old = p;

		p = strdup(old + strlen(conf->rootfs.mount));
		free(old);
		if (!p)
			return -ENOMEM;

		INFO("Found existing init at \"%s\"", p);
		goto out;
	}

	ret = snprintf(path, PATH_MAX, SBINDIR "/init.lxc.static");
	if (ret < 0 || ret >= PATH_MAX)
		return -1;

	if (!file_exists(path)) {
		ERROR("The file \"%s\" does not exist on host", path);
		return -1;
	}

	ret = snprintf(destpath, PATH_MAX, "%s" P_tmpdir "%s", conf->rootfs.mount, "/.lxc-init");
	if (ret < 0 || ret >= PATH_MAX)
		return -1;

	if (!file_exists(destpath)) {
		ret = mknod(destpath, S_IFREG | 0000, 0);
		if (ret < 0 && errno != EEXIST) {
			SYSERROR("Failed to create dummy \"%s\" file as bind mount target", destpath);
			return -1;
		}
	}

	ret = safe_mount(path, destpath, "none", MS_BIND, NULL, conf->rootfs.mount);
	if (ret < 0) {
		SYSERROR("Failed to bind mount lxc.init.static into container");
		return -1;
	}

	p = strdup(destpath + strlen(conf->rootfs.mount));
	if (!p)
		return -ENOMEM;

	INFO("Bind mounted lxc.init.static into container at \"%s\"", path);
out:
	((struct execute_args *)handler->data)->init_fd = -1;
	((struct execute_args *)handler->data)->init_path = p;
	return 0;
}

/* This does the work of remounting / if it is shared, calling the container
 * pre-mount hooks, and mounting the rootfs.
 */
int lxc_setup_rootfs_prepare_root(struct lxc_conf *conf, const char *name,
				  const char *lxcpath)
{
	int ret;

	if (conf->rootfs_setup) {
		const char *path = conf->rootfs.mount;

		/* The rootfs was set up in another namespace. bind-mount it to
		 * give us a mount in our own ns so we can pivot_root to it
		 */
		ret = mount(path, path, "rootfs", MS_BIND, NULL);
		if (ret < 0) {
			ERROR("Failed to bind mount container / onto itself");
			return -1;
		}

		TRACE("Bind mounted container / onto itself");
		return 0;
	}

	remount_all_slave();

	ret = run_lxc_hooks(name, "pre-mount", conf, NULL);
	if (ret < 0) {
		ERROR("Failed to run pre-mount hooks");
		return -1;
	}

	ret = lxc_mount_rootfs(conf);
	if (ret < 0) {
		ERROR("Failed to setup rootfs for");
		return -1;
	}

	conf->rootfs_setup = true;
	return 0;
}

static bool verify_start_hooks(struct lxc_conf *conf)
{
	char path[PATH_MAX];
	struct lxc_list *it;

	lxc_list_for_each (it, &conf->hooks[LXCHOOK_START]) {
		int ret;
		char *hookname = it->elem;

		ret = snprintf(path, PATH_MAX, "%s%s",
			       conf->rootfs.path ? conf->rootfs.mount : "",
			       hookname);
		if (ret < 0 || ret >= PATH_MAX)
			return false;

		ret = access(path, X_OK);
		if (ret < 0) {
			SYSERROR("Start hook \"%s\" not found in container",
				 hookname);
			return false;
		}

		return true;
	}

	return true;
}

static bool execveat_supported(void)
{
	lxc_raw_execveat(-1, "", NULL, NULL, AT_EMPTY_PATH);
	if (errno == ENOSYS)
		return false;

	return true;
}

int lxc_setup(struct lxc_handler *handler)
{
	int ret;
	const char *lxcpath = handler->lxcpath, *name = handler->name;
	struct lxc_conf *lxc_conf = handler->conf;

	ret = lxc_setup_rootfs_prepare_root(lxc_conf, name, lxcpath);
	if (ret < 0) {
		ERROR("Failed to setup rootfs");
		return -1;
	}

	if (handler->nsfd[LXC_NS_UTS] == -1) {
		ret = setup_utsname(lxc_conf->utsname);
		if (ret < 0) {
			ERROR("Failed to setup the utsname %s", name);
			return -1;
		}
	}

	ret = lxc_setup_keyring();
	if (ret < 0)
		return -1;

	ret = lxc_setup_network_in_child_namespaces(lxc_conf, &lxc_conf->network);
	if (ret < 0) {
		ERROR("Failed to setup network");
		return -1;
	}

	ret = lxc_network_send_name_and_ifindex_to_parent(handler);
	if (ret < 0) {
		ERROR("Failed to send network device names and ifindices to parent");
		return -1;
	}

	if (lxc_conf->autodev > 0) {
		ret = mount_autodev(name, &lxc_conf->rootfs, lxcpath);
		if (ret < 0) {
			ERROR("Failed to mount \"/dev\"");
			return -1;
		}
	}

	/* Do automatic mounts (mainly /proc and /sys), but exclude those that
	 * need to wait until other stuff has finished.
	 */
	ret = lxc_mount_auto_mounts(lxc_conf, lxc_conf->auto_mounts & ~LXC_AUTO_CGROUP_MASK, handler);
	if (ret < 0) {
		ERROR("Failed to setup first automatic mounts");
		return -1;
	}

	ret = setup_mount(lxc_conf, &lxc_conf->rootfs, lxc_conf->fstab, name, lxcpath);
	if (ret < 0) {
		ERROR("Failed to setup mounts");
		return -1;
	}

	if (lxc_conf->is_execute) {
		if (execveat_supported()) {
			int fd;
			char path[PATH_MAX];

			ret = snprintf(path, PATH_MAX, SBINDIR "/init.lxc.static");
			if (ret < 0 || ret >= PATH_MAX) {
				ERROR("Path to init.lxc.static too long");
				return -1;
			}

			fd = open(path, O_PATH | O_CLOEXEC);
			if (fd < 0) {
				SYSERROR("Unable to open lxc.init.static");
				return -1;
			}

			((struct execute_args *)handler->data)->init_fd = fd;
			((struct execute_args *)handler->data)->init_path = NULL;
		} else {
			ret = lxc_execute_bind_init(handler);
			if (ret < 0) {
				ERROR("Failed to bind-mount the lxc init system");
				return -1;
			}
		}
	}

	/* Now mount only cgroups, if wanted. Before, /sys could not have been
	 * mounted. It is guaranteed to be mounted now either through
	 * automatically or via fstab entries.
	 */
	ret = lxc_mount_auto_mounts(lxc_conf, lxc_conf->auto_mounts & LXC_AUTO_CGROUP_MASK, handler);
	if (ret < 0) {
		ERROR("Failed to setup remaining automatic mounts");
		return -1;
	}

	ret = run_lxc_hooks(name, "mount", lxc_conf, NULL);
	if (ret < 0) {
		ERROR("Failed to run mount hooks");
		return -1;
	}

	if (lxc_conf->autodev > 0) {
		ret = run_lxc_hooks(name, "autodev", lxc_conf, NULL);
		if (ret < 0) {
			ERROR("Failed to run autodev hooks");
			return -1;
		}

		ret = lxc_fill_autodev(&lxc_conf->rootfs);
		if (ret < 0) {
			ERROR("Failed to populate \"/dev\"");
			return -1;
		}
	}

	if (!lxc_list_empty(&lxc_conf->mount_list)) {
		ret = setup_mount_entries(lxc_conf, &lxc_conf->rootfs,
					  &lxc_conf->mount_list, name, lxcpath);
		if (ret < 0) {
			ERROR("Failed to setup mount entries");
			return -1;
		}
	}

	/* Make sure any start hooks are in the container */
	if (!verify_start_hooks(lxc_conf)) {
		ERROR("Failed to verify start hooks");
		return -1;
	}

	ret = lxc_setup_console(&lxc_conf->rootfs, &lxc_conf->console,
				lxc_conf->ttys.dir);
	if (ret < 0) {
		ERROR("Failed to setup console");
		return -1;
	}

	ret = lxc_setup_dev_symlinks(&lxc_conf->rootfs);
	if (ret < 0) {
		ERROR("Failed to setup \"/dev\" symlinks");
		return -1;
	}

	ret = lxc_create_tmp_proc_mount(lxc_conf);
	if (ret < 0) {
		ERROR("Failed to \"/proc\" LSMs");
		return -1;
	}

	ret = lxc_setup_rootfs_switch_root(&lxc_conf->rootfs);
	if (ret < 0) {
		ERROR("Failed to pivot root into rootfs");
		return -1;
	}

	ret = lxc_setup_devpts(lxc_conf);
	if (ret < 0) {
		ERROR("Failed to setup new devpts instance");
		return -1;
	}

	ret = lxc_create_ttys(handler);
	if (ret < 0)
		return -1;

	ret = setup_personality(lxc_conf->personality);
	if (ret < 0) {
		ERROR("Failed to set personality");
		return -1;
	}

	/* Set sysctl value to a path under /proc/sys as determined from the
	 * key. For e.g. net.ipv4.ip_forward translated to
	 * /proc/sys/net/ipv4/ip_forward.
	 */
	if (!lxc_list_empty(&lxc_conf->sysctls)) {
		ret = setup_sysctl_parameters(&lxc_conf->sysctls);
		if (ret < 0) {
			ERROR("Failed to setup sysctl parameters");
			return -1;
		}
	}

	if (!lxc_list_empty(&lxc_conf->keepcaps)) {
		if (!lxc_list_empty(&lxc_conf->caps)) {
			ERROR("Container requests lxc.cap.drop and "
			      "lxc.cap.keep: either use lxc.cap.drop or "
			      "lxc.cap.keep, not both");
			return -1;
		}

		if (dropcaps_except(&lxc_conf->keepcaps)) {
			ERROR("Failed to keep capabilities");
			return -1;
		}
	} else if (setup_caps(&lxc_conf->caps)) {
		ERROR("Failed to drop capabilities");
		return -1;
	}

	NOTICE("The container \"%s\" is set up", name);

	return 0;
}

int run_lxc_hooks(const char *name, char *hookname, struct lxc_conf *conf,
		  char *argv[])
{
	struct lxc_list *it;
	int which = -1;

	if (strcmp(hookname, "pre-start") == 0)
		which = LXCHOOK_PRESTART;
	else if (strcmp(hookname, "start-host") == 0)
		which = LXCHOOK_START_HOST;
	else if (strcmp(hookname, "pre-mount") == 0)
		which = LXCHOOK_PREMOUNT;
	else if (strcmp(hookname, "mount") == 0)
		which = LXCHOOK_MOUNT;
	else if (strcmp(hookname, "autodev") == 0)
		which = LXCHOOK_AUTODEV;
	else if (strcmp(hookname, "start") == 0)
		which = LXCHOOK_START;
	else if (strcmp(hookname, "stop") == 0)
		which = LXCHOOK_STOP;
	else if (strcmp(hookname, "post-stop") == 0)
		which = LXCHOOK_POSTSTOP;
	else if (strcmp(hookname, "clone") == 0)
		which = LXCHOOK_CLONE;
	else if (strcmp(hookname, "destroy") == 0)
		which = LXCHOOK_DESTROY;
	else
		return -1;

	lxc_list_for_each (it, &conf->hooks[which]) {
		int ret;
		char *hook = it->elem;

		ret = run_script_argv(name, conf->hooks_version, "lxc", hook,
				      hookname, argv);
		if (ret < 0)
			return -1;
	}

	return 0;
}

int lxc_clear_config_caps(struct lxc_conf *c)
{
	struct lxc_list *it, *next;

	lxc_list_for_each_safe (it, &c->caps, next) {
		lxc_list_del(it);
		free(it->elem);
		free(it);
	}

	return 0;
}

static int lxc_free_idmap(struct lxc_list *id_map)
{
	struct lxc_list *it, *next;

	lxc_list_for_each_safe (it, id_map, next) {
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
	struct lxc_list *it, *next;

	lxc_list_for_each_safe (it, &c->keepcaps, next) {
		lxc_list_del(it);
		free(it->elem);
		free(it);
	}

	return 0;
}

int lxc_clear_cgroups(struct lxc_conf *c, const char *key, int version)
{
	char *global_token, *namespaced_token;
	size_t namespaced_token_len;
	struct lxc_list *it, *next, *list;
	const char *k = key;
	bool all = false;

	if (version == CGROUP2_SUPER_MAGIC) {
		global_token = "lxc.cgroup2";
		namespaced_token = "lxc.cgroup2.";
		namespaced_token_len = STRLITERALLEN("lxc.cgroup2.");
		list = &c->cgroup2;
	} else if (version == CGROUP_SUPER_MAGIC) {
		global_token = "lxc.cgroup";
		namespaced_token = "lxc.cgroup.";
		namespaced_token_len = STRLITERALLEN("lxc.cgroup.");
		list = &c->cgroup;
	} else {
		return -EINVAL;
	}

	if (strcmp(key, global_token) == 0)
		all = true;
	else if (strncmp(key, namespaced_token, namespaced_token_len) == 0)
		k += namespaced_token_len;
	else
		return -EINVAL;

	lxc_list_for_each_safe (it, list, next) {
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

int lxc_clear_limits(struct lxc_conf *c, const char *key)
{
	struct lxc_list *it, *next;
	const char *k = NULL;
	bool all = false;

	if (strcmp(key, "lxc.limit") == 0 || strcmp(key, "lxc.prlimit") == 0)
		all = true;
	else if (strncmp(key, "lxc.limit.", STRLITERALLEN("lxc.limit.")) == 0)
		k = key + STRLITERALLEN("lxc.limit.");
	else if (strncmp(key, "lxc.prlimit.", STRLITERALLEN("lxc.prlimit.")) == 0)
		k = key + STRLITERALLEN("lxc.prlimit.");
	else
		return -1;

	lxc_list_for_each_safe (it, &c->limits, next) {
		struct lxc_limit *lim = it->elem;

		if (!all && strcmp(lim->resource, k) != 0)
			continue;

		lxc_list_del(it);
		free(lim->resource);
		free(lim);
		free(it);
	}

	return 0;
}

int lxc_clear_sysctls(struct lxc_conf *c, const char *key)
{
	struct lxc_list *it, *next;
	const char *k = NULL;
	bool all = false;

	if (strcmp(key, "lxc.sysctl") == 0)
		all = true;
	else if (strncmp(key, "lxc.sysctl.", STRLITERALLEN("lxc.sysctl.")) == 0)
		k = key + STRLITERALLEN("lxc.sysctl.");
	else
		return -1;

	lxc_list_for_each_safe (it, &c->sysctls, next) {
		struct lxc_sysctl *elem = it->elem;

		if (!all && strcmp(elem->key, k) != 0)
			continue;

		lxc_list_del(it);
		free(elem->key);
		free(elem->value);
		free(elem);
		free(it);
	}

	return 0;
}

int lxc_clear_procs(struct lxc_conf *c, const char *key)
{
	struct lxc_list *it, *next;
	const char *k = NULL;
	bool all = false;

	if (strcmp(key, "lxc.proc") == 0)
		all = true;
	else if (strncmp(key, "lxc.proc.", STRLITERALLEN("lxc.proc.")) == 0)
		k = key + STRLITERALLEN("lxc.proc.");
	else
		return -1;

	lxc_list_for_each_safe (it, &c->procs, next) {
		struct lxc_proc *proc = it->elem;

		if (!all && strcmp(proc->filename, k) != 0)
			continue;

		lxc_list_del(it);
		free(proc->filename);
		free(proc->value);
		free(proc);
		free(it);
	}

	return 0;
}

int lxc_clear_groups(struct lxc_conf *c)
{
	struct lxc_list *it, *next;

	lxc_list_for_each_safe (it, &c->groups, next) {
		lxc_list_del(it);
		free(it->elem);
		free(it);
	}

	return 0;
}

int lxc_clear_environment(struct lxc_conf *c)
{
	struct lxc_list *it, *next;

	lxc_list_for_each_safe (it, &c->environment, next) {
		lxc_list_del(it);
		free(it->elem);
		free(it);
	}

	return 0;
}

int lxc_clear_mount_entries(struct lxc_conf *c)
{
	struct lxc_list *it, *next;

	lxc_list_for_each_safe (it, &c->mount_list, next) {
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
	int i;
	struct lxc_list *it, *next;
	const char *k = NULL;
	bool all = false, done = false;

	if (strcmp(key, "lxc.hook") == 0)
		all = true;
	else if (strncmp(key, "lxc.hook.", STRLITERALLEN("lxc.hook.")) == 0)
		k = key + STRLITERALLEN("lxc.hook.");
	else
		return -1;

	for (i = 0; i < NUM_LXC_HOOKS; i++) {
		if (all || strcmp(k, lxchook_names[i]) == 0) {
			lxc_list_for_each_safe (it, &c->hooks[i], next) {
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

static inline void lxc_clear_aliens(struct lxc_conf *conf)
{
	struct lxc_list *it, *next;

	lxc_list_for_each_safe (it, &conf->aliens, next) {
		lxc_list_del(it);
		free(it->elem);
		free(it);
	}
}

void lxc_clear_includes(struct lxc_conf *conf)
{
	struct lxc_list *it, *next;

	lxc_list_for_each_safe (it, &conf->includes, next) {
		lxc_list_del(it);
		free(it->elem);
		free(it);
	}
}

int lxc_clear_apparmor_raw(struct lxc_conf *c)
{
	struct lxc_list *it, *next;

	lxc_list_for_each_safe (it, &c->lsm_aa_raw, next) {
		lxc_list_del(it);
		free(it->elem);
		free(it);
	}

	return 0;
}

void lxc_conf_free(struct lxc_conf *conf)
{
	if (!conf)
		return;

	if (current_config == conf)
		current_config = NULL;
	lxc_terminal_conf_free(&conf->console);
	free(conf->rootfs.mount);
	free(conf->rootfs.bdev_type);
	free(conf->rootfs.options);
	free(conf->rootfs.path);
	free(conf->logfile);
	if (conf->logfd != -1)
		close(conf->logfd);
	free(conf->utsname);
	free(conf->ttys.dir);
	free(conf->ttys.tty_names);
	free(conf->fstab);
	free(conf->rcfile);
	free(conf->execute_cmd);
	free(conf->init_cmd);
	free(conf->init_cwd);
	free(conf->unexpanded_config);
	free(conf->syslog);
	lxc_free_networks(&conf->network);
	free(conf->lsm_aa_profile);
	free(conf->lsm_aa_profile_computed);
	free(conf->lsm_se_context);
	lxc_seccomp_free(conf);
	lxc_clear_config_caps(conf);
	lxc_clear_config_keepcaps(conf);
	lxc_clear_cgroups(conf, "lxc.cgroup", CGROUP_SUPER_MAGIC);
	lxc_clear_cgroups(conf, "lxc.cgroup2", CGROUP2_SUPER_MAGIC);
	lxc_clear_hooks(conf, "lxc.hook");
	lxc_clear_mount_entries(conf);
	lxc_clear_idmaps(conf);
	lxc_clear_groups(conf);
	lxc_clear_includes(conf);
	lxc_clear_aliens(conf);
	lxc_clear_environment(conf);
	lxc_clear_limits(conf, "lxc.prlimit");
	lxc_clear_sysctls(conf, "lxc.sysctl");
	lxc_clear_procs(conf, "lxc.proc");
	lxc_clear_apparmor_raw(conf);
	free(conf->cgroup_meta.dir);
	free(conf->cgroup_meta.controllers);
	free(conf->shmount.path_host);
	free(conf->shmount.path_cont);
	free(conf);
}

struct userns_fn_data {
	int (*fn)(void *);
	const char *fn_name;
	void *arg;
	int p[2];
};

static int run_userns_fn(void *data)
{
	int ret;
	char c;
	struct userns_fn_data *d = data;

	/* Close write end of the pipe. */
	close(d->p[1]);

	/* Wait for parent to finish establishing a new mapping in the user
	 * namespace we are executing in.
	 */
	ret = lxc_read_nointr(d->p[0], &c, 1);
	/* Close read end of the pipe. */
	close(d->p[0]);
	if (ret != 1)
		return -1;

	if (d->fn_name)
		TRACE("Calling function \"%s\"", d->fn_name);

	/* Call function to run. */
	return d->fn(d->arg);
}

static struct id_map *mapped_nsid_add(struct lxc_conf *conf, unsigned id,
				      enum idtype idtype)
{
	const struct id_map *map;
	struct id_map *retmap;

	map = find_mapped_nsid_entry(conf, id, idtype);
	if (!map)
		return NULL;

	retmap = malloc(sizeof(*retmap));
	if (!retmap)
		return NULL;

	memcpy(retmap, map, sizeof(*retmap));
	return retmap;
}

static struct id_map *find_mapped_hostid_entry(struct lxc_conf *conf,
					       unsigned id, enum idtype idtype)
{
	struct id_map *map;
	struct lxc_list *it;
	struct id_map *retmap = NULL;

	lxc_list_for_each (it, &conf->id_map) {
		map = it->elem;
		if (map->idtype != idtype)
			continue;

		if (id >= map->hostid && id < map->hostid + map->range) {
			retmap = map;
			break;
		}
	}

	return retmap;
}

/* Allocate a new {g,u}id mapping for the given {g,u}id. Re-use an already
 * existing one or establish a new one.
 */
static struct id_map *mapped_hostid_add(struct lxc_conf *conf, uid_t id,
					enum idtype type)
{
	int hostid_mapped;
	struct id_map *entry = NULL, *tmp = NULL;

	entry = malloc(sizeof(*entry));
	if (!entry)
		return NULL;

	/* Reuse existing mapping. */
	tmp = find_mapped_hostid_entry(conf, id, type);
	if (tmp)
		return memcpy(entry, tmp, sizeof(*entry));

	/* Find new mapping. */
	hostid_mapped = find_unmapped_nsid(conf, type);
	if (hostid_mapped < 0) {
		DEBUG("Failed to find free mapping for id %d", id);
		free(entry);
		return NULL;
	}

	entry->idtype = type;
	entry->nsid = hostid_mapped;
	entry->hostid = (unsigned long)id;
	entry->range = 1;

	return entry;
}

struct lxc_list *get_minimal_idmap(struct lxc_conf *conf)
{
	uid_t euid, egid;
	uid_t nsuid = (conf->root_nsuid_map != NULL) ? 0 : conf->init_uid;
	gid_t nsgid = (conf->root_nsgid_map != NULL) ? 0 : conf->init_gid;
	struct lxc_list *idmap = NULL, *tmplist = NULL;
	struct id_map *container_root_uid = NULL, *container_root_gid = NULL,
		      *host_uid_map = NULL, *host_gid_map = NULL;

	/* Find container root mappings. */
	container_root_uid = mapped_nsid_add(conf, nsuid, ID_TYPE_UID);
	if (!container_root_uid) {
		DEBUG("Failed to find mapping for namespace uid %d", 0);
		goto on_error;
	}
	euid = geteuid();
	if (euid >= container_root_uid->hostid &&
	    euid < (container_root_uid->hostid + container_root_uid->range))
		host_uid_map = container_root_uid;

	container_root_gid = mapped_nsid_add(conf, nsgid, ID_TYPE_GID);
	if (!container_root_gid) {
		DEBUG("Failed to find mapping for namespace gid %d", 0);
		goto on_error;
	}
	egid = getegid();
	if (egid >= container_root_gid->hostid &&
	    egid < (container_root_gid->hostid + container_root_gid->range))
		host_gid_map = container_root_gid;

	/* Check whether the {g,u}id of the user has a mapping. */
	if (!host_uid_map)
		host_uid_map = mapped_hostid_add(conf, euid, ID_TYPE_UID);
	if (!host_uid_map) {
		DEBUG("Failed to find mapping for uid %d", euid);
		goto on_error;
	}

	if (!host_gid_map)
		host_gid_map = mapped_hostid_add(conf, egid, ID_TYPE_GID);
	if (!host_gid_map) {
		DEBUG("Failed to find mapping for gid %d", egid);
		goto on_error;
	}

	/* Allocate new {g,u}id map list. */
	idmap = malloc(sizeof(*idmap));
	if (!idmap)
		goto on_error;
	lxc_list_init(idmap);

	/* Add container root to the map. */
	tmplist = malloc(sizeof(*tmplist));
	if (!tmplist)
		goto on_error;
	lxc_list_add_elem(tmplist, container_root_uid);
	lxc_list_add_tail(idmap, tmplist);

	if (host_uid_map && (host_uid_map != container_root_uid)) {
		/* idmap will now keep track of that memory. */
		container_root_uid = NULL;

		/* Add container root to the map. */
		tmplist = malloc(sizeof(*tmplist));
		if (!tmplist)
			goto on_error;
		lxc_list_add_elem(tmplist, host_uid_map);
		lxc_list_add_tail(idmap, tmplist);
	}
	/* idmap will now keep track of that memory. */
	container_root_uid = NULL;
	/* idmap will now keep track of that memory. */
	host_uid_map = NULL;

	tmplist = malloc(sizeof(*tmplist));
	if (!tmplist)
		goto on_error;
	lxc_list_add_elem(tmplist, container_root_gid);
	lxc_list_add_tail(idmap, tmplist);

	if (host_gid_map && (host_gid_map != container_root_gid)) {
		/* idmap will now keep track of that memory. */
		container_root_gid = NULL;

		tmplist = malloc(sizeof(*tmplist));
		if (!tmplist)
			goto on_error;
		lxc_list_add_elem(tmplist, host_gid_map);
		lxc_list_add_tail(idmap, tmplist);
	}
	/* idmap will now keep track of that memory. */
	container_root_gid = NULL;
	/* idmap will now keep track of that memory. */
	host_gid_map = NULL;

	TRACE("Allocated minimal idmapping");
	return idmap;

on_error:
	if (idmap) {
		lxc_free_idmap(idmap);
		free(idmap);
	}
	if (container_root_uid)
		free(container_root_uid);
	if (container_root_gid)
		free(container_root_gid);
	if (host_uid_map && (host_uid_map != container_root_uid))
		free(host_uid_map);
	if (host_gid_map && (host_gid_map != container_root_gid))
		free(host_gid_map);

	return NULL;
}

/* Run a function in a new user namespace.
 * The caller's euid/egid will be mapped if it is not already.
 * Afaict, userns_exec_1() is only used to operate based on privileges for the
 * user's own {g,u}id on the host and for the container root's unmapped {g,u}id.
 * This means we require only to establish a mapping from:
 * - the container root {g,u}id as seen from the host > user's host {g,u}id
 * - the container root -> some sub{g,u}id
 * The former we add, if the user did not specify a mapping. The latter we
 * retrieve from the container's configured {g,u}id mappings as it must have been
 * there to start the container in the first place.
 */
int userns_exec_1(struct lxc_conf *conf, int (*fn)(void *), void *data,
		  const char *fn_name)
{
	pid_t pid;
	int p[2];
	struct userns_fn_data d;
	struct lxc_list *idmap;
	int ret = -1, status = -1;
	char c = '1';

	if (!conf)
		return -EINVAL;

	idmap = get_minimal_idmap(conf);
	if (!idmap)
		return -1;

	ret = pipe2(p, O_CLOEXEC);
	if (ret < 0) {
		SYSERROR("Failed to create pipe");
		return -1;
	}
	d.fn = fn;
	d.fn_name = fn_name;
	d.arg = data;
	d.p[0] = p[0];
	d.p[1] = p[1];

	/* Clone child in new user namespace. */
	pid = lxc_raw_clone_cb(run_userns_fn, &d, CLONE_NEWUSER);
	if (pid < 0) {
		ERROR("Failed to clone process in new user namespace");
		goto on_error;
	}

	close(p[0]);
	p[0] = -1;

	if (lxc_log_get_level() == LXC_LOG_LEVEL_TRACE ||
	    conf->loglevel == LXC_LOG_LEVEL_TRACE) {
		struct id_map *map;
		struct lxc_list *it;

		lxc_list_for_each (it, idmap) {
			map = it->elem;
			TRACE("Establishing %cid mapping for \"%d\" in new "
			      "user namespace: nsuid %lu - hostid %lu - range "
			      "%lu",
			      (map->idtype == ID_TYPE_UID) ? 'u' : 'g', pid,
			      map->nsid, map->hostid, map->range);
		}
	}

	/* Set up {g,u}id mapping for user namespace of child process. */
	ret = lxc_map_ids(idmap, pid);
	if (ret < 0) {
		ERROR("Error setting up {g,u}id mappings for child process \"%d\"", pid);
		goto on_error;
	}

	/* Tell child to proceed. */
	if (lxc_write_nointr(p[1], &c, 1) != 1) {
		SYSERROR("Failed telling child process \"%d\" to proceed", pid);
		goto on_error;
	}

on_error:
	if (p[0] != -1)
		close(p[0]);
	close(p[1]);

	/* Wait for child to finish. */
	if (pid > 0)
		status = wait_for_pid(pid);

	if (status < 0)
		ret = -1;

	return ret;
}

int userns_exec_full(struct lxc_conf *conf, int (*fn)(void *), void *data,
		     const char *fn_name)
{
	pid_t pid;
	uid_t euid, egid;
	int p[2];
	struct id_map *map;
	struct lxc_list *cur;
	struct userns_fn_data d;
	int ret = -1;
	char c = '1';
	struct lxc_list *idmap = NULL, *tmplist = NULL;
	struct id_map *container_root_uid = NULL, *container_root_gid = NULL,
		      *host_uid_map = NULL, *host_gid_map = NULL;

	if (!conf)
		return -EINVAL;

	ret = pipe2(p, O_CLOEXEC);
	if (ret < 0) {
		SYSERROR("opening pipe");
		return -1;
	}
	d.fn = fn;
	d.fn_name = fn_name;
	d.arg = data;
	d.p[0] = p[0];
	d.p[1] = p[1];

	/* Clone child in new user namespace. */
	pid = lxc_clone(run_userns_fn, &d, CLONE_NEWUSER);
	if (pid < 0) {
		ERROR("Failed to clone process in new user namespace");
		goto on_error;
	}

	close(p[0]);
	p[0] = -1;

	euid = geteuid();
	egid = getegid();

	/* Allocate new {g,u}id map list. */
	idmap = malloc(sizeof(*idmap));
	if (!idmap)
		goto on_error;
	lxc_list_init(idmap);

	/* Find container root. */
	lxc_list_for_each (cur, &conf->id_map) {
		struct id_map *tmpmap;

		tmplist = malloc(sizeof(*tmplist));
		if (!tmplist)
			goto on_error;

		tmpmap = malloc(sizeof(*tmpmap));
		if (!tmpmap) {
			free(tmplist);
			goto on_error;
		}

		memset(tmpmap, 0, sizeof(*tmpmap));
		memcpy(tmpmap, cur->elem, sizeof(*tmpmap));
		tmplist->elem = tmpmap;

		lxc_list_add_tail(idmap, tmplist);

		map = cur->elem;

		if (map->idtype == ID_TYPE_UID)
			if (euid >= map->hostid && euid < map->hostid + map->range)
				host_uid_map = map;

		if (map->idtype == ID_TYPE_GID)
			if (egid >= map->hostid && egid < map->hostid + map->range)
				host_gid_map = map;

		if (map->nsid != 0)
			continue;

		if (map->idtype == ID_TYPE_UID)
			if (container_root_uid == NULL)
				container_root_uid = map;

		if (map->idtype == ID_TYPE_GID)
			if (container_root_gid == NULL)
				container_root_gid = map;
	}

	if (!container_root_uid || !container_root_gid) {
		ERROR("No mapping for container root found");
		goto on_error;
	}

	/* Check whether the {g,u}id of the user has a mapping. */
	if (!host_uid_map)
		host_uid_map = mapped_hostid_add(conf, euid, ID_TYPE_UID);
	else
		host_uid_map = container_root_uid;

	if (!host_gid_map)
		host_gid_map = mapped_hostid_add(conf, egid, ID_TYPE_GID);
	else
		host_gid_map = container_root_gid;

	if (!host_uid_map) {
		DEBUG("Failed to find mapping for uid %d", euid);
		goto on_error;
	}

	if (!host_gid_map) {
		DEBUG("Failed to find mapping for gid %d", egid);
		goto on_error;
	}

	if (host_uid_map && (host_uid_map != container_root_uid)) {
		/* Add container root to the map. */
		tmplist = malloc(sizeof(*tmplist));
		if (!tmplist)
			goto on_error;
		lxc_list_add_elem(tmplist, host_uid_map);
		lxc_list_add_tail(idmap, tmplist);
	}
	/* idmap will now keep track of that memory. */
	host_uid_map = NULL;

	if (host_gid_map && (host_gid_map != container_root_gid)) {
		tmplist = malloc(sizeof(*tmplist));
		if (!tmplist)
			goto on_error;
		lxc_list_add_elem(tmplist, host_gid_map);
		lxc_list_add_tail(idmap, tmplist);
	}
	/* idmap will now keep track of that memory. */
	host_gid_map = NULL;

	if (lxc_log_get_level() == LXC_LOG_LEVEL_TRACE ||
	    conf->loglevel == LXC_LOG_LEVEL_TRACE) {
		lxc_list_for_each (cur, idmap) {
			map = cur->elem;
			TRACE("establishing %cid mapping for \"%d\" in new "
			      "user namespace: nsuid %lu - hostid %lu - range "
			      "%lu",
			      (map->idtype == ID_TYPE_UID) ? 'u' : 'g', pid,
			      map->nsid, map->hostid, map->range);
		}
	}

	/* Set up {g,u}id mapping for user namespace of child process. */
	ret = lxc_map_ids(idmap, pid);
	if (ret < 0) {
		ERROR("error setting up {g,u}id mappings for child process \"%d\"", pid);
		goto on_error;
	}

	/* Tell child to proceed. */
	if (lxc_write_nointr(p[1], &c, 1) != 1) {
		SYSERROR("Failed telling child process \"%d\" to proceed", pid);
		goto on_error;
	}

on_error:
	if (p[0] != -1)
		close(p[0]);
	close(p[1]);

	/* Wait for child to finish. */
	if (pid > 0)
		ret = wait_for_pid(pid);

	if (idmap) {
		lxc_free_idmap(idmap);
		free(idmap);
	}

	if (host_uid_map && (host_uid_map != container_root_uid))
		free(host_uid_map);
	if (host_gid_map && (host_gid_map != container_root_gid))
		free(host_gid_map);

	return ret;
}

/* not thread-safe, do not use from api without first forking */
static char *getuname(void)
{
	struct passwd pwent;
	struct passwd *pwentp = NULL;
	char *buf;
	char *username;
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

		ERROR("Failed to get password record - %u", geteuid());
		free(buf);
		return NULL;
	}

	username = strdup(pwent.pw_name);
	free(buf);

	return username;
}

/* not thread-safe, do not use from api without first forking */
static char *getgname(void)
{
	struct group grent;
	struct group *grentp = NULL;
	char *buf;
	char *grname;
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

		ERROR("Failed to get group record - %u", getegid());
		free(buf);
		return NULL;
	}

	grname = strdup(grent.gr_name);
	free(buf);

	return grname;
}

/* not thread-safe, do not use from api without first forking */
void suggest_default_idmap(void)
{
	char *uname, *gname;
	FILE *f;
	unsigned int uid = 0, urange = 0, gid = 0, grange = 0;
	size_t len = 0;
	char *line = NULL;

	uname = getuname();
	if (!uname)
		return;

	gname = getgname();
	if (!gname) {
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
		char *p, *p2;
		size_t no_newline = 0;

		p = strchr(line, ':');
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
		no_newline = strcspn(p2, "\n");
		p2[no_newline] = '\0';

		if (lxc_safe_uint(p, &uid) < 0)
			WARN("Could not parse UID");
		if (lxc_safe_uint(p2, &urange) < 0)
			WARN("Could not parse UID range");
	}
	fclose(f);

	f = fopen(subgidfile, "r");
	if (!f) {
		ERROR("Your system is not configured with subgids");
		free(gname);
		free(uname);
		return;
	}

	while (getline(&line, &len, f) != -1) {
		char *p, *p2;
		size_t no_newline = 0;

		p = strchr(line, ':');
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
		no_newline = strcspn(p2, "\n");
		p2[no_newline] = '\0';

		if (lxc_safe_uint(p, &gid) < 0)
			WARN("Could not parse GID");
		if (lxc_safe_uint(p2, &grange) < 0)
			WARN("Could not parse GID range");
	}
	fclose(f);

	free(line);

	if (!urange || !grange) {
		ERROR("You do not have subuids or subgids allocated");
		ERROR("Unprivileged containers require subuids and subgids");
		free(uname);
		free(gname);
		return;
	}

	ERROR("You must either run as root, or define uid mappings");
	ERROR("To pass uid mappings to lxc-create, you could create");
	ERROR("~/.config/lxc/default.conf:");
	ERROR("lxc.include = %s", LXC_DEFAULT_CONFIG);
	ERROR("lxc.idmap = u 0 %u %u", uid, urange);
	ERROR("lxc.idmap = g 0 %u %u", gid, grange);

	free(gname);
	free(uname);
}

static void free_cgroup_settings(struct lxc_list *result)
{
	struct lxc_list *iterator, *next;

	lxc_list_for_each_safe (iterator, result, next) {
		lxc_list_del(iterator);
		free(iterator);
	}
	free(result);
}

/* Return the list of cgroup_settings sorted according to the following rules
 * 1. Put memory.limit_in_bytes before memory.memsw.limit_in_bytes
 */
struct lxc_list *sort_cgroup_settings(struct lxc_list *cgroup_settings)
{
	struct lxc_list *result;
	struct lxc_cgroup *cg = NULL;
	struct lxc_list *it = NULL, *item = NULL, *memsw_limit = NULL;

	result = malloc(sizeof(*result));
	if (!result)
		return NULL;
	lxc_list_init(result);

	/* Iterate over the cgroup settings and copy them to the output list. */
	lxc_list_for_each (it, cgroup_settings) {
		item = malloc(sizeof(*item));
		if (!item) {
			free_cgroup_settings(result);
			return NULL;
		}

		item->elem = it->elem;
		cg = it->elem;
		if (strcmp(cg->subsystem, "memory.memsw.limit_in_bytes") == 0) {
			/* Store the memsw_limit location */
			memsw_limit = item;
		} else if (strcmp(cg->subsystem, "memory.limit_in_bytes") == 0 &&
			   memsw_limit != NULL) {
			/* lxc.cgroup.memory.memsw.limit_in_bytes is found
			 * before lxc.cgroup.memory.limit_in_bytes, swap these
			 * two items */
			item->elem = memsw_limit->elem;
			memsw_limit->elem = it->elem;
		}
		lxc_list_add_tail(result, item);
	}

	return result;
}

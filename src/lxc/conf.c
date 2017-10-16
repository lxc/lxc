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

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <libgen.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/loop.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>

/* makedev() */
#ifdef MAJOR_IN_MKDEV
#    include <sys/mkdev.h>
#endif

#ifdef HAVE_STATVFS
#include <sys/statvfs.h>
#endif

#if HAVE_PTY_H
#include <pty.h>
#else
#include <../include/openpty.h>
#endif

#ifdef HAVE_LINUX_MEMFD_H
#include <linux/memfd.h>
#endif

#include "af_unix.h"
#include "caps.h"       /* for lxc_caps_last_cap() */
#include "cgroup.h"
#include "conf.h"
#include "confile_utils.h"
#include "error.h"
#include "log.h"
#include "lxclock.h"
#include "lxcseccomp.h"
#include "namespace.h"
#include "network.h"
#include "parse.h"
#include "storage.h"
#include "storage/aufs.h"
#include "storage/overlay.h"
#include "utils.h"
#include "lsm/lsm.h"

#if HAVE_LIBCAP
#include <sys/capability.h>
#endif

#if HAVE_SYS_PERSONALITY_H
#include <sys/personality.h>
#endif

#if IS_BIONIC
#include <../include/lxcmntent.h>
#ifndef HAVE_PRLIMIT
#include <../include/prlimit.h>
#endif
#else
#include <mntent.h>
#endif

lxc_log_define(lxc_conf, lxc);

#if HAVE_LIBCAP
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

#ifndef CAP_SETUID
#define CAP_SETUID 7
#endif

#ifndef CAP_SETGID
#define CAP_SETGID 6
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

#ifndef MS_PRIVATE
#define MS_PRIVATE (1<<18)
#endif

#ifndef MS_LAZYTIME
#define MS_LAZYTIME (1<<25)
#endif

/* memfd_create() */
#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

#ifndef MFD_ALLOW_SEALING
#define MFD_ALLOW_SEALING 0x0002U
#endif

#ifndef HAVE_MEMFD_CREATE
static int memfd_create(const char *name, unsigned int flags) {
	#ifndef __NR_memfd_create
		#if defined __i386__
			#define __NR_memfd_create 356
		#elif defined __x86_64__
			#define __NR_memfd_create 319
		#elif defined __arm__
			#define __NR_memfd_create 385
		#elif defined __aarch64__
			#define __NR_memfd_create 279
		#elif defined __s390__
			#define __NR_memfd_create 350
		#elif defined __powerpc__
			#define __NR_memfd_create 360
		#elif defined __sparc__
			#define __NR_memfd_create 348
		#elif defined __blackfin__
			#define __NR_memfd_create 390
		#elif defined __ia64__
			#define __NR_memfd_create 1340
		#elif defined _MIPS_SIM
			#if _MIPS_SIM == _MIPS_SIM_ABI32
				#define __NR_memfd_create 4354
			#endif
			#if _MIPS_SIM == _MIPS_SIM_NABI32
				#define __NR_memfd_create 6318
			#endif
			#if _MIPS_SIM == _MIPS_SIM_ABI64
				#define __NR_memfd_create 5314
			#endif
		#endif
	#endif
	#ifdef __NR_memfd_create
	return syscall(__NR_memfd_create, name, flags);
	#else
	errno = ENOSYS;
	return -1;
	#endif
}
#else
extern int memfd_create(const char *name, unsigned int flags);
#endif

char *lxchook_names[NUM_LXC_HOOKS] = {"pre-start", "pre-mount", "mount",
				      "autodev",   "start",     "stop",
				      "post-stop", "clone",     "destroy"};

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

#if HAVE_LIBCAP
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
	struct lxc_popen_FILE *f;
	char *output;
	int ret;

	f = lxc_popen(buffer);
	if (!f) {
		SYSERROR("Failed to popen() %s.", buffer);
		return -1;
	}

	output = malloc(LXC_LOG_BUFFER_SIZE);
	if (!output) {
		ERROR("Failed to allocate memory for %s.", buffer);
		lxc_pclose(f);
		return -1;
	}

	while (fgets(output, LXC_LOG_BUFFER_SIZE, f->f))
		DEBUG("Script %s with output: %s.", buffer, output);

	free(output);

	ret = lxc_pclose(f);
	if (ret == -1) {
		SYSERROR("Script exited with error.");
		return -1;
	} else if (WIFEXITED(ret) && WEXITSTATUS(ret) != 0) {
		ERROR("Script exited with status %d.", WEXITSTATUS(ret));
		return -1;
	} else if (WIFSIGNALED(ret)) {
		ERROR("Script terminated by signal %d.", WTERMSIG(ret));
		return -1;
	}

	return 0;
}

static int run_script_argv(const char *name, const char *section,
			   const char *script, const char *hook,
			   const char *lxcpath, char **argsin)
{
	int ret, i;
	char *buffer;
	size_t size = 0;

	INFO("Executing script \"%s\" for container \"%s\", config section \"%s\".",
	     script, name, section);

	for (i = 0; argsin && argsin[i]; i++)
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
		ERROR("Failed to allocate memory.");
		return -1;
	}

	ret =
	    snprintf(buffer, size, "%s %s %s %s", script, name, section, hook);
	if (ret < 0 || (size_t)ret >= size) {
		ERROR("Script name too long.");
		return -1;
	}

	for (i = 0; argsin && argsin[i]; i++) {
		int len = size - ret;
		int rc;
		rc = snprintf(buffer + ret, len, " %s", argsin[i]);
		if (rc < 0 || rc >= len) {
			ERROR("Script args too long.");
			return -1;
		}
		ret += rc;
	}

	return run_buffer(buffer);
}

int run_script(const char *name, const char *section, const char *script, ...)
{
	int ret;
	char *buffer, *p;
	size_t size = 0;
	va_list ap;

	INFO("Executing script \"%s\" for container \"%s\", config section \"%s\".",
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
		ERROR("Failed to allocate memory.");
		return -1;
	}

	ret = snprintf(buffer, size, "%s %s %s", script, name, section);
	if (ret < 0 || ret >= size) {
		ERROR("Script name too long.");
		return -1;
	}

	va_start(ap, script);
	while ((p = va_arg(ap, char *))) {
		int len = size - ret;
		int rc;
		rc = snprintf(buffer + ret, len, " %s", p);
		if (rc < 0 || rc >= len) {
			ERROR("Script args too long.");
			return -1;
		}
		ret += rc;
	}
	va_end(ap);

	return run_buffer(buffer);
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
unsigned long add_required_remount_flags(const char *s, const char *d,
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

			if (!lxc_list_empty(&conf->keepcaps))
				has_sys_admin = in_caplist(CAP_SYS_ADMIN, &conf->keepcaps);
			else
				has_sys_admin = !in_caplist(CAP_SYS_ADMIN, &conf->caps);

			if (cg_flags == LXC_AUTO_CGROUP_NOSPEC)
				cg_flags = has_sys_admin ? LXC_AUTO_CGROUP_RW : LXC_AUTO_CGROUP_MIXED;
			else
				cg_flags = has_sys_admin ? LXC_AUTO_CGROUP_FULL_RW : LXC_AUTO_CGROUP_FULL_MIXED;
		}

		if (!cgroup_mount(conf->rootfs.path ? conf->rootfs.mount : "", handler, cg_flags)) {
			SYSERROR("error mounting /sys/fs/cgroup");
			return -1;
		}
	}

	return 0;
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

static int lxc_setup_dev_symlinks(const struct lxc_rootfs *rootfs)
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

/* Build a space-separate list of ptys to pass to systemd. */
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

static int lxc_setup_ttys(struct lxc_conf *conf)
{
	int i, ret;
	const struct lxc_tty_info *tty_info = &conf->tty_info;
	char *ttydir = conf->ttydir;
	char path[MAXPATHLEN], lxcpath[MAXPATHLEN];

	if (!conf->rootfs.path)
		return 0;

	for (i = 0; i < tty_info->nbtty; i++) {
		struct lxc_pty_info *pty_info = &tty_info->pty_info[i];

		ret = snprintf(path, sizeof(path), "/dev/tty%d", i + 1);
		if (ret < 0 || (size_t)ret >= sizeof(path))
			return -1;

		if (ttydir) {
			/* create dev/lxc/tty%d" */
			ret = snprintf(lxcpath, sizeof(lxcpath),
				       "/dev/%s/tty%d", ttydir, i + 1);
			if (ret < 0 || (size_t)ret >= sizeof(lxcpath))
				return -1;

			ret = creat(lxcpath, 0660);
			if (ret < 0 && errno != EEXIST) {
				SYSERROR("Failed to create \"%s\"", lxcpath);
				return -1;
			}
			if (ret >= 0)
				close(ret);

			ret = unlink(path);
			if (ret < 0 && errno != ENOENT) {
				SYSERROR("Failed to unlink \"%s\"", path);
				return -1;
			}

			ret = mount(pty_info->name, lxcpath, "none", MS_BIND, 0);
			if (ret < 0) {
				WARN("Failed to bind mount \"%s\" onto \"%s\"",
				     pty_info->name, path);
				continue;
			}
			DEBUG("bind mounted \"%s\" onto \"%s\"", pty_info->name,
			      path);

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
			ret = access(path, F_OK);
			if (ret < 0) {
				ret = creat(path, 0660);
				if (ret < 0) {
					SYSERROR("Failed to create \"%s\"", path);
					/* this isn't fatal, continue */
				} else {
					close(ret);
				}
			}

			ret = mount(pty_info->name, path, "none", MS_BIND, 0);
			if (ret < 0) {
				SYSERROR("Failed to mount '%s'->'%s'", pty_info->name, path);
				continue;
			}

			DEBUG("Bind mounted \"%s\" onto \"%s\"", pty_info->name,
			      path);
		}

		if (!append_ptyname(&conf->pty_names, pty_info->name)) {
			ERROR("Error setting up container_ttys string");
			return -1;
		}
	}

	INFO("Finished setting up %d /dev/tty<N> device(s)", tty_info->nbtty);
	return 0;
}

int lxc_allocate_ttys(const char *name, struct lxc_conf *conf)
{
	struct lxc_tty_info *tty_info = &conf->tty_info;
	int i, ret;

	/* no tty in the configuration */
	if (!conf->tty)
		return 0;

	tty_info->pty_info = malloc(sizeof(*tty_info->pty_info) * conf->tty);
	if (!tty_info->pty_info) {
		SYSERROR("failed to allocate struct *pty_info");
		return -ENOMEM;
	}

	for (i = 0; i < conf->tty; i++) {
		struct lxc_pty_info *pty_info = &tty_info->pty_info[i];

		process_lock();
		ret = openpty(&pty_info->master, &pty_info->slave,
			      pty_info->name, NULL, NULL);
		process_unlock();
		if (ret) {
			SYSERROR("failed to create pty device number %d", i);
			tty_info->nbtty = i;
			lxc_delete_tty(tty_info);
			return -ENOTTY;
		}

		DEBUG("allocated pty \"%s\" with master fd %d and slave fd %d",
		      pty_info->name, pty_info->master, pty_info->slave);

		/* Prevent leaking the file descriptors to the container */
		ret = fcntl(pty_info->master, F_SETFD, FD_CLOEXEC);
		if (ret < 0)
			WARN("failed to set FD_CLOEXEC flag on master fd %d of "
			     "pty device \"%s\": %s",
			     pty_info->master, pty_info->name, strerror(errno));

		ret = fcntl(pty_info->slave, F_SETFD, FD_CLOEXEC);
		if (ret < 0)
			WARN("failed to set FD_CLOEXEC flag on slave fd %d of "
			     "pty device \"%s\": %s",
			     pty_info->slave, pty_info->name, strerror(errno));

		pty_info->busy = 0;
	}

	tty_info->nbtty = conf->tty;

	INFO("finished allocating %d pts devices", conf->tty);
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
	tty_info->pty_info = NULL;
	tty_info->nbtty = 0;
}

static int lxc_send_ttys_to_parent(struct lxc_handler *handler)
{
	int i;
	struct lxc_conf *conf = handler->conf;
	struct lxc_tty_info *tty_info = &conf->tty_info;
	int sock = handler->data_sock[0];
	int ret = -1;

	if (!conf->tty)
		return 0;

	for (i = 0; i < conf->tty; i++) {
		int ttyfds[2];
		struct lxc_pty_info *pty_info = &tty_info->pty_info[i];

		ttyfds[0] = pty_info->master;
		ttyfds[1] = pty_info->slave;

		ret = lxc_abstract_unix_send_fds(sock, ttyfds, 2, NULL, 0);
		if (ret < 0)
			break;

		TRACE("Send pty \"%s\" with master fd %d and slave fd %d to "
		      "parent", pty_info->name, pty_info->master, pty_info->slave);
	}

	if (ret < 0)
		ERROR("Failed to send %d ttys to parent: %s", conf->tty,
		      strerror(errno));
	else
		TRACE("Sent %d ttys to parent", conf->tty);

	return ret;
}

static int lxc_create_ttys(struct lxc_handler *handler)
{
	int ret = -1;
	struct lxc_conf *conf = handler->conf;

	ret = lxc_allocate_ttys(handler->name, conf);
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

	if (conf->pty_names) {
		ret = setenv("container_ttys", conf->pty_names, 1);
		if (ret < 0)
			SYSERROR("Failed to set \"container_ttys=%s\"", conf->pty_names);
	}

	ret = 0;

on_error:
	lxc_delete_tty(&conf->tty_info);

	return ret;
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

/* Just create a path for /dev under $lxcpath/$name and in rootfs If we hit an
 * error, log it but don't fail yet.
 */
static int mount_autodev(const char *name, const struct lxc_rootfs *rootfs,
			 const char *lxcpath)
{
	int ret;
	size_t clen;
	char *path;

	INFO("Preparing \"/dev\"");

	/* $(rootfs->mount) + "/dev/pts" + '\0' */
	clen = (rootfs->path ? strlen(rootfs->mount) : 0) + 9;
	path = alloca(clen);

	ret = snprintf(path, clen, "%s/dev", rootfs->path ? rootfs->mount : "");
	if (ret < 0 || (size_t)ret >= clen)
		return -1;

	if (!dir_exists(path)) {
		WARN("\"/dev\" directory does not exist. Proceeding without "
		     "autodev being set up");
		return 0;
	}

	ret = safe_mount("none", path, "tmpfs", 0, "size=500000,mode=755",
			 rootfs->path ? rootfs->mount : NULL);
	if (ret < 0) {
		SYSERROR("Failed to mount tmpfs on \"%s\"", path);
		return -1;
	}
	INFO("Mounted tmpfs on \"%s\"", path);

	ret = snprintf(path, clen, "%s/dev/pts", rootfs->path ? rootfs->mount : "");
	if (ret < 0 || (size_t)ret >= clen)
		return -1;

	/* If we are running on a devtmpfs mapping, dev/pts may already exist.
	 * If not, then create it and exit if that fails...
	 */
	if (!dir_exists(path)) {
		ret = mkdir(path, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
		if (ret < 0) {
			SYSERROR("Failed to create directory \"%s\"", path);
			return -1;
		}
	}

	INFO("Prepared \"/dev\"");
	return 0;
}

struct lxc_devs {
	const char *name;
	mode_t mode;
	int maj;
	int min;
};

static const struct lxc_devs lxc_devs[] = {
	{ "null",    S_IFCHR | S_IRWXU | S_IRWXG | S_IRWXO, 1, 3 },
	{ "zero",    S_IFCHR | S_IRWXU | S_IRWXG | S_IRWXO, 1, 5 },
	{ "full",    S_IFCHR | S_IRWXU | S_IRWXG | S_IRWXO, 1, 7 },
	{ "urandom", S_IFCHR | S_IRWXU | S_IRWXG | S_IRWXO, 1, 9 },
	{ "random",  S_IFCHR | S_IRWXU | S_IRWXG | S_IRWXO, 1, 8 },
	{ "tty",     S_IFCHR | S_IRWXU | S_IRWXG | S_IRWXO, 5, 0 },
};

static int lxc_fill_autodev(const struct lxc_rootfs *rootfs)
{
	int ret;
	char path[MAXPATHLEN];
	int i;
	mode_t cmask;

	ret = snprintf(path, MAXPATHLEN, "%s/dev",
		       rootfs->path ? rootfs->mount : "");
	if (ret < 0 || ret >= MAXPATHLEN)
		return -1;

	/* ignore, just don't try to fill in */
	if (!dir_exists(path))
		return 0;

	INFO("Populating \"/dev\"");

	cmask = umask(S_IXUSR | S_IXGRP | S_IXOTH);
	for (i = 0; i < sizeof(lxc_devs) / sizeof(lxc_devs[0]); i++) {
		const struct lxc_devs *d = &lxc_devs[i];

		ret = snprintf(path, MAXPATHLEN, "%s/dev/%s",
			       rootfs->path ? rootfs->mount : "", d->name);
		if (ret < 0 || ret >= MAXPATHLEN)
			return -1;

		ret = mknod(path, d->mode, makedev(d->maj, d->min));
		if (ret < 0) {
			FILE *pathfile;
			char hostpath[MAXPATHLEN];

			if (errno == EEXIST) {
				DEBUG("\"%s\" device already existed", path);
				continue;
			}

			/* Unprivileged containers cannot create devices, so
			 * bind mount the device from the host.
			 */
			ret = snprintf(hostpath, MAXPATHLEN, "/dev/%s", d->name);
			if (ret < 0 || ret >= MAXPATHLEN)
				return -1;

			pathfile = fopen(path, "wb");
			if (!pathfile) {
				SYSERROR("Failed to create file \"%s\"", path);
				return -1;
			}
			fclose(pathfile);

			ret = safe_mount(hostpath, path, 0, MS_BIND, NULL,
					 rootfs->path ? rootfs->mount : NULL);
			if (ret < 0) {
				SYSERROR("Failed to bind mount \"%s\" from "
					 "host into container",
					 d->name);
				return -1;
			}
			DEBUG("Bind mounted \"%s\" onto \"%s\"", hostpath,
			      path);
		} else {
			DEBUG("Created device node \"%s\"", path);
		}
	}
	umask(cmask);

	INFO("Populated \"/dev\"");
	return 0;
}

static int lxc_setup_rootfs(struct lxc_conf *conf)
{
	int ret;
	struct lxc_storage *bdev;
	const struct lxc_rootfs *rootfs;

	rootfs = &conf->rootfs;
	if (!rootfs->path) {
		if (mount("", "/", NULL, MS_SLAVE | MS_REC, 0)) {
			SYSERROR("Failed to make / rslave.");
			return -1;
		}
		return 0;
	}

	if (access(rootfs->mount, F_OK)) {
		SYSERROR("Failed to access to \"%s\". Check it is present.",
			 rootfs->mount);
		return -1;
	}

	bdev = storage_init(conf, rootfs->path, rootfs->mount, rootfs->options);
	if (!bdev) {
		ERROR("Failed to mount rootfs \"%s\" onto \"%s\" with options \"%s\".",
		      rootfs->path, rootfs->mount,
		      rootfs->options ? rootfs->options : "(null)");
		return -1;
	}

	ret = bdev->ops->mount(bdev);
	storage_put(bdev);
	if (ret < 0) {
		ERROR("Failed to mount rootfs \"%s\" onto \"%s\" with options \"%s\".",
		      rootfs->path, rootfs->mount,
		      rootfs->options ? rootfs->options : "(null)");
		return -1;
	}

	DEBUG("Mounted rootfs \"%s\" onto \"%s\" with options \"%s\".",
	      rootfs->path, rootfs->mount,
	      rootfs->options ? rootfs->options : "(null)");

	return 0;
}

int prepare_ramfs_root(char *root)
{
	char buf[LXC_LINELEN], *p;
	char nroot[PATH_MAX];
	FILE *f;
	int i;
	char *p2;

	if (realpath(root, nroot) == NULL)
		return -errno;

	if (chdir("/") == -1)
		return -errno;

	/*
	 * We could use here MS_MOVE, but in userns this mount is
	 * locked and can't be moved.
	 */
	if (mount(root, "/", NULL, MS_REC | MS_BIND, NULL) < 0) {
		SYSERROR("Failed to move %s into /", root);
		return -errno;
	}

	if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0) {
		SYSERROR("Failed to make . rprivate");
		return -errno;
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
	if (!rootfs->path) {
		DEBUG("container does not have a rootfs, so not doing pivot root");
		return 0;
	}

	if (detect_ramfs_rootfs()) {
		DEBUG("detected that container is on ramfs");
		if (prepare_ramfs_root(rootfs->mount)) {
			ERROR("failed to prepare minimal ramfs root");
			return -1;
		}

		DEBUG("prepared ramfs root for container");
		return 0;
	}

	if (setup_rootfs_pivot_root(rootfs->mount) < 0) {
		ERROR("failed to pivot root");
		return -1;
	}

	DEBUG("finished pivot root");
	return 0;
}

static int lxc_setup_devpts(int num_pts)
{
	int ret;
	const char *default_devpts_mntopts = "newinstance,ptmxmode=0666,mode=0620,gid=5";
	char devpts_mntopts[256];

	if (!num_pts) {
		DEBUG("no new devpts instance will be mounted since no pts "
		      "devices are requested");
		return 0;
	}

	ret = snprintf(devpts_mntopts, sizeof(devpts_mntopts), "%s,max=%d",
		       default_devpts_mntopts, num_pts);
	if (ret < 0 || (size_t)ret >= sizeof(devpts_mntopts))
		return -1;

	/* Unmount old devpts instance. */
	ret = access("/dev/pts/ptmx", F_OK);
	if (!ret) {
		ret = umount("/dev/pts");
		if (ret < 0) {
			SYSERROR("failed to unmount old devpts instance");
			return -1;
		}
		DEBUG("unmounted old /dev/pts instance");
	}

	/* Create mountpoint for devpts instance. */
	ret = mkdir("/dev/pts", 0755);
	if (ret < 0 && errno != EEXIST) {
		SYSERROR("failed to create the \"/dev/pts\" directory");
		return -1;
	}

	/* Mount new devpts instance. */
	ret = mount("devpts", "/dev/pts", "devpts", MS_MGC_VAL, devpts_mntopts);
	if (ret < 0) {
		SYSERROR("failed to mount new devpts instance");
		return -1;
	}
	DEBUG("mount new devpts instance with options \"%s\"", devpts_mntopts);

	/* Remove any pre-existing /dev/ptmx file. */
	ret = access("/dev/ptmx", F_OK);
	if (!ret) {
		ret = remove("/dev/ptmx");
		if (ret < 0) {
			SYSERROR("failed to remove existing \"/dev/ptmx\"");
			return -1;
		}
		DEBUG("removed existing \"/dev/ptmx\"");
	}

	/* Create dummy /dev/ptmx file as bind mountpoint for /dev/pts/ptmx. */
	ret = open("/dev/ptmx", O_CREAT, 0666);
	if (ret < 0) {
		SYSERROR("failed to create dummy \"/dev/ptmx\" file as bind mount target");
		return -1;
	}
	close(ret);
	DEBUG("created dummy \"/dev/ptmx\" file as bind mount target");

	/* Fallback option: create symlink /dev/ptmx -> /dev/pts/ptmx  */
	ret = mount("/dev/pts/ptmx", "/dev/ptmx", NULL, MS_BIND, NULL);
	if (!ret) {
		DEBUG("bind mounted \"/dev/pts/ptmx\" to \"/dev/ptmx\"");
		return 0;
	} else {
		/* Fallthrough and try to create a symlink. */
		ERROR("failed to bind mount \"/dev/pts/ptmx\" to \"/dev/ptmx\"");
	}

	/* Remove the dummy /dev/ptmx file we created above. */
	ret = remove("/dev/ptmx");
	if (ret < 0) {
		SYSERROR("failed to remove existing \"/dev/ptmx\"");
		return -1;
	}

	/* Fallback option: Create symlink /dev/ptmx -> /dev/pts/ptmx. */
	ret = symlink("/dev/pts/ptmx", "/dev/ptmx");
	if (ret < 0) {
		SYSERROR("failed to create symlink \"/dev/ptmx\" -> \"/dev/pts/ptmx\"");
		return -1;
	}
	DEBUG("created symlink \"/dev/ptmx\" -> \"/dev/pts/ptmx\"");

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

static int lxc_setup_dev_console(const struct lxc_rootfs *rootfs,
				 const struct lxc_console *console)
{
	char path[MAXPATHLEN];
	int ret, fd;

	if (console->path && !strcmp(console->path, "none"))
		return 0;

	ret = snprintf(path, sizeof(path), "%s/dev/console", rootfs->mount);
	if (ret < 0 || (size_t)ret >= sizeof(path))
		return -1;

	/* When we are asked to setup a console we remove any previous
	 * /dev/console bind-mounts.
	 */
	if (file_exists(path)) {
		ret = lxc_unstack_mountpoint(path, false);
		if (ret < 0) {
			ERROR("failed to unmount \"%s\": %s", path, strerror(errno));
			return -ret;
		} else {
			DEBUG("cleared all (%d) mounts from \"%s\"", ret, path);
		}

		ret = unlink(path);
		if (ret < 0) {
			SYSERROR("error unlinking %s", path);
			return -errno;
		}
	}

	/* For unprivileged containers autodev or automounts will already have
	 * taken care of creating /dev/console.
	 */
	fd = open(path, O_CREAT | O_EXCL, S_IXUSR | S_IXGRP | S_IXOTH);
	if (fd < 0) {
		if (errno != EEXIST) {
			SYSERROR("failed to create console");
			return -errno;
		}
	} else {
		close(fd);
	}

	if (chmod(console->name, S_IXUSR | S_IXGRP | S_IXOTH)) {
		SYSERROR("failed to set mode '0%o' to '%s'", S_IXUSR | S_IXGRP | S_IXOTH, console->name);
		return -errno;
	}

	if (safe_mount(console->name, path, "none", MS_BIND, 0, rootfs->mount) < 0) {
		ERROR("failed to mount '%s' on '%s'", console->name, path);
		return -1;
	}

	DEBUG("mounted pts device \"%s\" onto \"%s\"", console->name, path);
	return 0;
}

static int lxc_setup_ttydir_console(const struct lxc_rootfs *rootfs,
				    const struct lxc_console *console,
				    char *ttydir)
{
	int ret;
	char path[MAXPATHLEN], lxcpath[MAXPATHLEN];

	/* create rootfs/dev/<ttydir> directory */
	ret = snprintf(path, sizeof(path), "%s/dev/%s", rootfs->mount, ttydir);
	if (ret < 0 || (size_t)ret >= sizeof(path))
		return -1;

	ret = mkdir(path, 0755);
	if (ret && errno != EEXIST) {
		SYSERROR("failed with errno %d to create %s", errno, path);
		return -errno;
	}
 	DEBUG("Created directory for console and tty devices at \"%s\"", path);

	ret = snprintf(lxcpath, sizeof(lxcpath), "%s/dev/%s/console", rootfs->mount, ttydir);
	if (ret < 0 || (size_t)ret >= sizeof(lxcpath))
		return -1;

	ret = creat(lxcpath, 0660);
	if (ret == -1 && errno != EEXIST) {
		SYSERROR("error %d creating %s", errno, lxcpath);
		return -errno;
	}
	if (ret >= 0)
		close(ret);

	ret = snprintf(path, sizeof(path), "%s/dev/console", rootfs->mount);
	if (ret < 0 || (size_t)ret >= sizeof(lxcpath))
		return -1;

	/* When we are asked to setup a console we remove any previous
	 * /dev/console bind-mounts.
	 */
	if (console->path && !strcmp(console->path, "none")) {
		struct stat st;
		ret = stat(path, &st);
		if (ret < 0) {
			if (errno == ENOENT)
				return 0;
			SYSERROR("failed stat() \"%s\"", path);
			return -errno;
		}

		/* /dev/console must be character device with major number 5 and
		 * minor number 1. If not, give benefit of the doubt and assume
		 * the user has mounted something else right there on purpose.
		 */
		if (((st.st_mode & S_IFMT) != S_IFCHR) || major(st.st_rdev) != 5 || minor(st.st_rdev) != 1)
			return 0;

		/* In case the user requested a bind-mount for /dev/console and
		 * requests a ttydir we move the mount to the
		 * /dev/<ttydir/console.
		 * Note, we only move the uppermost mount and clear all other
		 * mounts underneath for safety.
		 * If it is a character device created via mknod() we simply
		 * rename it.
		 */
		ret = safe_mount(path, lxcpath, "none", MS_MOVE, NULL, rootfs->mount);
		if (ret < 0) {
			if (errno != EINVAL) {
				ERROR("failed to MS_MOVE \"%s\" to \"%s\": %s", path, lxcpath, strerror(errno));
				return -errno;
			}
			/* path was not a mountpoint */
			ret = rename(path, lxcpath);
			if (ret < 0) {
				ERROR("failed to rename \"%s\" to \"%s\": %s", path, lxcpath, strerror(errno));
				return -errno;
			}
			DEBUG("renamed \"%s\" to \"%s\"", path, lxcpath);
		} else {
			DEBUG("moved mount \"%s\" to \"%s\"", path, lxcpath);
		}

		/* Clear all remaining bind-mounts. */
		ret = lxc_unstack_mountpoint(path, false);
		if (ret < 0) {
			ERROR("failed to unmount \"%s\": %s", path, strerror(errno));
			return -ret;
		} else {
			DEBUG("cleared all (%d) mounts from \"%s\"", ret, path);
		}
	} else {
		if (file_exists(path)) {
			ret = lxc_unstack_mountpoint(path, false);
			if (ret < 0) {
				ERROR("failed to unmount \"%s\": %s", path, strerror(errno));
				return -ret;
			} else {
				DEBUG("cleared all (%d) mounts from \"%s\"", ret, path);
			}
		}

		if (safe_mount(console->name, lxcpath, "none", MS_BIND, 0, rootfs->mount) < 0) {
			ERROR("failed to mount '%s' on '%s'", console->name, lxcpath);
			return -1;
		}
		DEBUG("mounted \"%s\" onto \"%s\"", console->name, lxcpath);
	}

	/* create symlink from rootfs /dev/console to '<ttydir>/console' */
	ret = snprintf(lxcpath, sizeof(lxcpath), "%s/console", ttydir);
	if (ret < 0 || (size_t)ret >= sizeof(lxcpath))
		return -1;

	ret = unlink(path);
	if (ret && errno != ENOENT) {
		SYSERROR("error unlinking %s", path);
		return -errno;
	}

	ret = symlink(lxcpath, path);
	if (ret < 0) {
		SYSERROR("failed to create symlink for console from \"%s\" to \"%s\"", lxcpath, path);
		return -1;
	}

	DEBUG("console has been setup under \"%s\" and symlinked to \"%s\"", lxcpath, path);
	return 0;
}

static int lxc_setup_console(const struct lxc_rootfs *rootfs,
			     const struct lxc_console *console, char *ttydir)
{
	/* We don't have a rootfs, /dev/console will be shared. */
	if (!rootfs->path) {
		DEBUG("/dev/console will be shared with the host");
		return 0;
	}

	if (!ttydir)
		return lxc_setup_dev_console(rootfs, console);

	return lxc_setup_ttydir_console(rootfs, console, ttydir);
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
		       const char *data, int optional, int dev,
		       const char *rootfs)
{
	int ret;
#ifdef HAVE_STATVFS
	struct statvfs sb;
#endif

	ret = safe_mount(fsname, target, fstype, mountflags & ~MS_REMOUNT, data,
			 rootfs);
	if (ret < 0) {
		if (optional) {
			INFO("Failed to mount \"%s\" on \"%s\" (optional): %s",
			     fsname, target, strerror(errno));
			return 0;
		}

		SYSERROR("Failed to mount \"%s\" on \"%s\"", fsname, target);
		return -1;
	}

	if ((mountflags & MS_REMOUNT) || (mountflags & MS_BIND)) {
		unsigned long rqd_flags = 0;

		DEBUG("Remounting \"%s\" on \"%s\" to respect bind or remount "
		      "options",
		      fsname ? fsname : "(none)", target ? target : "(none)");

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

			DEBUG("Flags for \"%s\" were %lu, required extra flags "
			      "are %lu", fsname, sb.f_flag, required_flags);

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

		ret = mount(fsname, target, fstype, mountflags | MS_REMOUNT, data);
		if (ret < 0) {
			if (optional) {
				INFO("Failed to mount \"%s\" on \"%s\" "
				     "(optional): %s", fsname, target,
				     strerror(errno));
				return 0;
			}

			SYSERROR("Failed to mount \"%s\" on \"%s\"", fsname, target);
			return -1;
		}
	}

#ifdef HAVE_STATVFS
skipremount:
#endif
	DEBUG("Mounted \"%s\" on \"%s\" with filesystem type \"%s\"", fsname,
	      target, fstype);

	return 0;
}

/* Remove "optional", "create=dir", and "create=file" from mntopt */
static void cull_mntent_opt(struct mntent *mntent)
{
	int i;
	char *list[] = {"create=dir", "create=file", "optional", NULL};

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
				       const char *lxc_name,
				       const char *lxc_path)
{
	int ret = 0;

	if (!strncmp(mntent->mnt_type, "overlay", 7))
		ret = ovl_mkdir(mntent, rootfs, lxc_name, lxc_path);
	else if (!strncmp(mntent->mnt_type, "aufs", 4))
		ret = aufs_mkdir(mntent, rootfs, lxc_name, lxc_path);
	if (ret < 0)
		return -1;

	if (hasmntopt(mntent, "create=dir")) {
		ret = mkdir_p(path, 0755);
		if (ret < 0 && errno != EEXIST) {
			SYSERROR("Failed to create directory \"%s\"", path);
			return -1;
		}
	}

	if (hasmntopt(mntent, "create=file") && access(path, F_OK)) {
		int fd;
		char *p1, *p2;

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

		fd = open(path, O_CREAT, 0644);
		if (fd < 0)
			return -1;
		close(fd);
	}

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
	bool dev, optional;
	char *rootfs_path = NULL;

	optional = hasmntopt(mntent, "optional") != NULL;
	dev = hasmntopt(mntent, "dev") != NULL;

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

	ret = parse_mntopts(mntent->mnt_opts, &mntflags, &mntdata);
	if (ret < 0)
		return -1;

	ret = mount_entry(mntent->mnt_fsname, path, mntent->mnt_type, mntflags,
			  mntdata, optional, dev, rootfs_path);

	free(mntdata);
	return ret;
}

static inline int mount_entry_on_systemfs(struct mntent *mntent)
{
	int ret;
	char path[MAXPATHLEN];

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
	char path[MAXPATHLEN];
	int ret = 0;

	lxcpath = lxc_global_config_value("lxc.lxcpath");
	if (!lxcpath)
		return -1;

	/* If rootfs->path is a blockdev path, allow container fstab to use
	 * <lxcpath>/<name>/rootfs" as the target prefix.
	 */
	ret = snprintf(path, MAXPATHLEN, "%s/%s/rootfs", lxcpath, lxc_name);
	if (ret < 0 || ret >= MAXPATHLEN)
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
	ret = snprintf(path, MAXPATHLEN, "%s/%s", rootfs->mount, aux + offset);
	if (ret < 0 || ret >= MAXPATHLEN)
		return -1;

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

/* This logs a NOTICE() when a user specifies mounts that would conflict with
 * devices liblxc sets up automatically.
 */
static void log_notice_on_conflict(const struct lxc_conf *conf, const char *src,
				   const char *dest)
{
	char *clean_mnt_fsname, *clean_mnt_dir, *tmp;
	bool needs_warning = false;

	clean_mnt_fsname = lxc_deslashify(src);
	if (!clean_mnt_fsname)
		return;

	clean_mnt_dir = lxc_deslashify(dest);
	if (!clean_mnt_dir) {
		free(clean_mnt_fsname);
		return;
	}

	tmp = clean_mnt_dir;
	if (*tmp == '/')
		tmp++;

	if (strncmp(src, "/dev", 4) || strncmp(tmp, "dev", 3)) {
		free(clean_mnt_dir);
		free(clean_mnt_fsname);
		return;
	}

	if (!conf->autodev && !conf->pts && !conf->tty &&
	    (!conf->console.path || !strcmp(conf->console.path, "none"))) {
		free(clean_mnt_dir);
		free(clean_mnt_fsname);
		return;
	}

	if (!strcmp(tmp, "dev") && conf->autodev > 0)
		needs_warning = true;
	else if (!strcmp(tmp, "dev/pts") && (conf->autodev > 0 || conf->pts > 0))
		needs_warning = true;
	else if (!strcmp(tmp, "dev/ptmx") && (conf->autodev > 0 || conf->pts > 0))
		needs_warning = true;
	else if (!strcmp(tmp, "dev/pts/ptmx") && (conf->autodev > 0 || conf->pts > 0))
		needs_warning = true;
	else if (!strcmp(tmp, "dev/null") && conf->autodev > 0)
		needs_warning = true;
	else if (!strcmp(tmp, "dev/zero") && conf->autodev > 0)
		needs_warning = true;
	else if (!strcmp(tmp, "dev/full") && conf->autodev > 0)
		needs_warning = true;
	else if (!strcmp(tmp, "dev/urandom") && conf->autodev > 0)
		needs_warning = true;
	else if (!strcmp(tmp, "dev/random") && conf->autodev > 0)
		needs_warning = true;
	else if (!strcmp(tmp, "dev/tty") && conf->autodev > 0)
		needs_warning = true;
	else if (!strncmp(tmp, "dev/tty", 7) && (conf->autodev > 0 || conf->tty > 0))
		needs_warning = true;

	if (needs_warning)
		NOTICE("Requesting to mount \"%s\" on \"%s\" while requesting "
		       "automatic device setup under \"/dev\"",
		       clean_mnt_fsname, clean_mnt_dir);

	free(clean_mnt_dir);
	free(clean_mnt_fsname);
}

static int mount_file_entries(const struct lxc_conf *conf,
			      const struct lxc_rootfs *rootfs, FILE *file,
			      const char *lxc_name, const char *lxc_path)
{
	struct mntent mntent;
	char buf[4096];
	int ret = -1;

	while (getmntent_r(file, &mntent, buf, sizeof(buf))) {
		log_notice_on_conflict(conf, mntent.mnt_fsname, mntent.mnt_dir);

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

	INFO("Set up mount entries");
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

FILE *make_anonymous_mount_file(struct lxc_list *mount)
{
	int ret;
	char *mount_entry;
	struct lxc_list *iterator;
	FILE *f;
	int fd = -1;

	fd = memfd_create("lxc_mount_file", MFD_CLOEXEC);
	if (fd < 0) {
		if (errno != ENOSYS)
			return NULL;
		f = tmpfile();
		TRACE("Created temporary mount file");
	} else {
		f = fdopen(fd, "r+");
		TRACE("Created anonymous mount file");
	}

	if (!f) {
		SYSERROR("Could not create mount file");
		if (fd != -1)
			close(fd);
		return NULL;
	}

	lxc_list_for_each(iterator, mount) {
		mount_entry = iterator->elem;
		ret = fprintf(f, "%s\n", mount_entry);
		if (ret < strlen(mount_entry))
			WARN("Could not write mount entry to mount file");
	}

	ret = fseek(f, 0, SEEK_SET);
	if (ret < 0) {
		SYSERROR("Failed to seek mount file");
		fclose(f);
		return NULL;
	}

	return f;
}

static int setup_mount_entries(const struct lxc_conf *conf,
			       const struct lxc_rootfs *rootfs,
			       struct lxc_list *mount, const char *lxc_name,
			       const char *lxc_path)
{
	FILE *f;
	int ret;

	f = make_anonymous_mount_file(mount);
	if (!f)
		return -1;

	ret = mount_file_entries(conf, rootfs, f, lxc_name, lxc_path);

	fclose(f);
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

	/* caplist[i] is 1 if we keep capability i */
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

static int parse_resource(const char *res) {
	size_t i;
	int resid = -1;

	for (i = 0; i < sizeof(limit_opt)/sizeof(limit_opt[0]); ++i) {
		if (strcmp(res, limit_opt[i].name) == 0)
			return limit_opt[i].value;
	}

	/* try to see if it's numeric, so the user may specify
	 * resources that the running kernel knows about but
	 * we don't */
	if (lxc_safe_int(res, &resid) == 0)
		return resid;
	return -1;
}

int setup_resource_limits(struct lxc_list *limits, pid_t pid) {
	struct lxc_list *it;
	struct lxc_limit *lim;
	int resid;

	lxc_list_for_each(it, limits) {
		lim = it->elem;

		resid = parse_resource(lim->resource);
		if (resid < 0) {
			ERROR("unknown resource %s", lim->resource);
			return -1;
		}

		if (prlimit(pid, resid, &lim->limit, NULL) != 0) {
			ERROR("failed to set limit %s: %s", lim->resource, strerror(errno));
			return -1;
		}
	}
	return 0;
}

static char *default_rootfs_mount = LXCROOTFSMOUNT;

struct lxc_conf *lxc_conf_init(void)
{
	struct lxc_conf *new;
	int i;

	new = malloc(sizeof(*new));
	if (!new) {
		ERROR("lxc_conf_init : %s", strerror(errno));
		return NULL;
	}
	memset(new, 0, sizeof(*new));

	new->loglevel = LXC_LOG_LEVEL_NOTSET;
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
		ERROR("lxc_conf_init : %s", strerror(errno));
		free(new);
		return NULL;
	}
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
	lxc_list_init(&new->limits);
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
	memset(&new->cgroup_meta, 0, sizeof(struct lxc_cgroup));

	return new;
}

static int write_id_mapping(enum idtype idtype, pid_t pid, const char *buf,
			    size_t buf_size)
{
	char path[MAXPATHLEN];
	int fd, ret;

	ret = snprintf(path, MAXPATHLEN, "/proc/%d/%cid_map", pid,
		       idtype == ID_TYPE_UID ? 'u' : 'g');
	if (ret < 0 || ret >= MAXPATHLEN) {
		ERROR("failed to create path \"%s\"", path);
		return -E2BIG;
	}

	fd = open(path, O_WRONLY);
	if (fd < 0) {
		SYSERROR("failed to open \"%s\"", path);
		return -1;
	}

	errno = 0;
	ret = lxc_write_nointr(fd, buf, buf_size);
	if (ret != buf_size) {
		SYSERROR("failed to write %cid mapping to \"%s\"",
			 idtype == ID_TYPE_UID ? 'u' : 'g', path);
		close(fd);
		return -1;
	}
	close(fd);

	return 0;
}

/* Check whether a binary exist and has either CAP_SETUID, CAP_SETGID or both.
 *
 * @return  1      if functional binary was found
 * @return  0      if binary exists but is lacking privilege
 * @return -ENOENT if binary does not exist
 * @return -EINVAL if cap to check is neither CAP_SETUID nor CAP_SETGID
 *
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
		DEBUG("The binary \"%s\" does have the setuid bit set.", path);
		fret = 1;
		goto cleanup;
	}

	#if HAVE_LIBCAP && LIBCAP_SUPPORTS_FILE_CAPABILITIES
	/* Check if it has the CAP_SETUID capability. */
	if ((cap & CAP_SETUID) &&
	    lxc_file_cap_is_set(path, CAP_SETUID, CAP_EFFECTIVE) &&
	    lxc_file_cap_is_set(path, CAP_SETUID, CAP_PERMITTED)) {
		DEBUG("The binary \"%s\" has CAP_SETUID in its CAP_EFFECTIVE "
		      "and CAP_PERMITTED sets.", path);
		fret = 1;
		goto cleanup;
	}

	/* Check if it has the CAP_SETGID capability. */
	if ((cap & CAP_SETGID) &&
	    lxc_file_cap_is_set(path, CAP_SETGID, CAP_EFFECTIVE) &&
	    lxc_file_cap_is_set(path, CAP_SETGID, CAP_PERMITTED)) {
		DEBUG("The binary \"%s\" has CAP_SETGID in its CAP_EFFECTIVE "
		      "and CAP_PERMITTED sets.", path);
		fret = 1;
		goto cleanup;
	}
	#else
	/* If we cannot check for file capabilities we need to give the benefit
	 * of the doubt. Otherwise we might fail even though all the necessary
	 * file capabilities are set.
	 */
	DEBUG("Cannot check for file capabilites as full capability support is "
	      "missing. Manual intervention needed.");
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
	struct id_map *map;
	struct lxc_list *iterator;
	enum idtype type;
	char u_or_g;
	char *pos;
	int fill, left;
	char cmd_output[MAXPATHLEN];
	/* strlen("new@idmap") = 9
	 * +
	 * strlen(" ") = 1
	 * +
	 * LXC_NUMSTRLEN64
	 * +
	 * strlen(" ") = 1
	 *
	 * We add some additional space to make sure that we really have
	 * LXC_IDMAPLEN bytes available for our the {g,u]id mapping.
	 */
	char mapbuf[9 + 1 + LXC_NUMSTRLEN64 + 1 + LXC_IDMAPLEN] = {0};
	int ret = 0, uidmap = 0, gidmap = 0;
	bool use_shadow = false, had_entry = false;

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
		DEBUG("Functional newuidmap and newgidmap binary found.");
		use_shadow = true;
	} else {
		/* In case unprivileged users run application containers via
		 * execute() or a start*() there are valid cases where they may
		 * only want to map their own {g,u}id. Let's not block them from
		 * doing so by requiring geteuid() == 0.
		 */
		DEBUG("No newuidmap and newgidmap binary found. Trying to "
		      "write directly with euid %d.", geteuid());
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

		/* Try to catch the ouput of new{g,u}idmap to make debugging
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

int find_unmapped_nsid(struct lxc_conf *conf, enum idtype idtype)
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

int chown_mapped_root_exec_wrapper(void *args)
{
	execvp("lxc-usernsexec", args);
	return -1;
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
	uid_t rootuid, rootgid;
	unsigned long val;
	int hostuid, hostgid, ret;
	struct stat sb;
	char map1[100], map2[100], map3[100], map4[100], map5[100];
	char ugid[100];
	char *args1[] = {"lxc-usernsexec",
			 "-m", map1,
			 "-m", map2,
			 "-m", map3,
			 "-m", map5,
			 "--", "chown", ugid, path,
			 NULL};
	char *args2[] = {"lxc-usernsexec",
			 "-m", map1,
			 "-m", map2,
			 "-m", map3,
			 "-m", map4,
			 "-m", map5,
			 "--", "chown", ugid, path,
			 NULL};
	char cmd_output[MAXPATHLEN];

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

int lxc_ttys_shift_ids(struct lxc_conf *c)
{
	if (lxc_list_empty(&c->id_map))
		return 0;

	if (!strcmp(c->console.name, ""))
		return 0;

	if (chown_mapped_root(c->console.name, c) < 0) {
		ERROR("failed to chown console \"%s\"", c->console.name);
		return -1;
	}

	TRACE("chowned console \"%s\"", c->console.name);

	return 0;
}

/* NOTE: Must not be called from inside the container namespace! */
int lxc_create_tmp_proc_mount(struct lxc_conf *conf)
{
	int mounted;

	mounted = lxc_mount_proc_if_needed(conf->rootfs.path ? conf->rootfs.mount : "");
	if (mounted == -1) {
		SYSERROR("failed to mount /proc in the container");
		/* continue only if there is no rootfs */
		if (conf->rootfs.path)
			return -1;
	} else if (mounted == 1) {
		conf->tmp_umount_proc = 1;
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

	if (lxc_setup_rootfs(conf)) {
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

int lxc_setup(struct lxc_handler *handler)
{
	int ret;
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

	if (lxc_setup_network_in_child_namespaces(lxc_conf, &lxc_conf->network)) {
		ERROR("failed to setup the network for '%s'", name);
		return -1;
	}

	if (lxc_network_send_name_and_ifindex_to_parent(handler) < 0) {
		ERROR("Failed to network device names and ifindices to parent");
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

	if (setup_mount(lxc_conf, &lxc_conf->rootfs, lxc_conf->fstab, name, lxcpath)) {
		ERROR("failed to setup the mounts for '%s'", name);
		return -1;
	}

	if (!lxc_list_empty(&lxc_conf->mount_list) && setup_mount_entries(lxc_conf, &lxc_conf->rootfs, &lxc_conf->mount_list, name, lxcpath)) {
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
		if (run_lxc_hooks(name, "autodev", lxc_conf, lxcpath, NULL)) {
			ERROR("failed to run autodev hooks for container '%s'.", name);
			return -1;
		}

		if (lxc_fill_autodev(&lxc_conf->rootfs)) {
			ERROR("failed to populate /dev in the container");
			return -1;
		}
	}

	ret = lxc_setup_console(&lxc_conf->rootfs, &lxc_conf->console,
				lxc_conf->ttydir);
	if (ret < 0) {
		ERROR("Failed to setup console");
		return -1;
	}

	ret = lxc_setup_dev_symlinks(&lxc_conf->rootfs);
	if (ret < 0) {
		ERROR("Failed to setup /dev symlinks");
		return -1;
	}

	/* mount /proc if it's not already there */
	if (lxc_create_tmp_proc_mount(lxc_conf) < 0) {
		ERROR("failed to LSM mount proc for '%s'", name);
		return -1;
	}

	if (setup_pivot_root(&lxc_conf->rootfs)) {
		ERROR("failed to set rootfs for '%s'", name);
		return -1;
	}

	if (lxc_setup_devpts(lxc_conf->pts)) {
		ERROR("failed to setup the new pts instance");
		return -1;
	}

	ret = lxc_create_ttys(handler);
	if (ret < 0)
		return -1;

	if (setup_personality(lxc_conf->personality)) {
		ERROR("failed to setup personality");
		return -1;
	}

	if (!lxc_list_empty(&lxc_conf->keepcaps)) {
		if (!lxc_list_empty(&lxc_conf->caps)) {
			ERROR("Container requests lxc.cap.drop and lxc.cap.keep: either use lxc.cap.drop or lxc.cap.keep, not both.");
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

	NOTICE("Container \"%s\" is set up", name);

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

int lxc_clear_config_caps(struct lxc_conf *c)
{
	struct lxc_list *it, *next;

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
	const char *k = NULL;

	if (strcmp(key, "lxc.cgroup") == 0)
		all = true;
	else if (strncmp(key, "lxc.cgroup.", sizeof("lxc.cgroup.")-1) == 0)
		k = key + sizeof("lxc.cgroup.")-1;
	else
		return -1;

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

int lxc_clear_limits(struct lxc_conf *c, const char *key)
{
	struct lxc_list *it, *next;
	bool all = false;
	const char *k = NULL;

	if (strcmp(key, "lxc.limit") == 0
	    || strcmp(key, "lxc.prlimit"))
		all = true;
	else if (strncmp(key, "lxc.limit.", sizeof("lxc.limit.")-1) == 0)
		k = key + sizeof("lxc.limit.")-1;
	else if (strncmp(key, "lxc.prlimit.", sizeof("lxc.prlimit.")-1) == 0)
		k = key + sizeof("lxc.prlimit.")-1;
	else
		return -1;

	lxc_list_for_each_safe(it, &c->limits, next) {
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
	const char *k = NULL;
	int i;

	if (strcmp(key, "lxc.hook") == 0)
		all = true;
	else if (strncmp(key, "lxc.hook.", sizeof("lxc.hook.")-1) == 0)
		k = key + sizeof("lxc.hook.")-1;
	else
		return -1;

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

static inline void lxc_clear_aliens(struct lxc_conf *conf)
{
	struct lxc_list *it,*next;

	lxc_list_for_each_safe(it, &conf->aliens, next) {
		lxc_list_del(it);
		free(it->elem);
		free(it);
	}
}

void lxc_clear_includes(struct lxc_conf *conf)
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
	free(conf->syslog);
	lxc_free_networks(&conf->network);
	free(conf->lsm_aa_profile);
	free(conf->lsm_se_context);
	lxc_seccomp_free(conf);
	lxc_clear_config_caps(conf);
	lxc_clear_config_keepcaps(conf);
	lxc_clear_cgroups(conf, "lxc.cgroup");
	lxc_clear_hooks(conf, "lxc.hook");
	lxc_clear_mount_entries(conf);
	lxc_clear_idmaps(conf);
	lxc_clear_groups(conf);
	lxc_clear_includes(conf);
	lxc_clear_aliens(conf);
	lxc_clear_environment(conf);
	lxc_clear_limits(conf, "lxc.prlimit");
	free(conf->cgroup_meta.dir);
	free(conf->cgroup_meta.controllers);
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
	struct userns_fn_data *d = data;
	char c;

	/* Close write end of the pipe. */
	close(d->p[1]);

	/* Wait for parent to finish establishing a new mapping in the user
	 * namespace we are executing in.
	 */
	if (read(d->p[0], &c, 1) != 1)
		return -1;

	/* Close read end of the pipe. */
	close(d->p[0]);

	if (d->fn_name)
		TRACE("calling function \"%s\"", d->fn_name);
	/* Call function to run. */
	return d->fn(d->arg);
}

static struct id_map *mapped_hostid_entry(struct lxc_conf *conf, unsigned id,
					  enum idtype idtype)
{
	struct lxc_list *it;
	struct id_map *map;
	struct id_map *retmap = NULL;

	lxc_list_for_each(it, &conf->id_map) {
		map = it->elem;
		if (map->idtype != idtype)
			continue;

		if (id >= map->hostid && id < map->hostid + map->range) {
			retmap = map;
			break;
		}
	}

	if (!retmap)
		return NULL;

	retmap = malloc(sizeof(*retmap));
	if (!retmap)
		return NULL;

	memcpy(retmap, map, sizeof(*retmap));
	return retmap;
}

/*
 * Allocate a new {g,u}id mapping for the given {g,u}id. Re-use an already
 * existing one or establish a new one.
 */
static struct id_map *idmap_add(struct lxc_conf *conf, uid_t id, enum idtype type)
{
	int hostid_mapped;
	struct id_map *entry = NULL;

	/* Reuse existing mapping. */
	entry = mapped_hostid_entry(conf, id, type);
	if (entry)
		return entry;

	/* Find new mapping. */
	hostid_mapped = find_unmapped_nsid(conf, type);
	if (hostid_mapped < 0) {
		DEBUG("failed to find free mapping for id %d", id);
		return NULL;
	}

	entry = malloc(sizeof(*entry));
	if (!entry)
		return NULL;

	entry->idtype = type;
	entry->nsid = hostid_mapped;
	entry->hostid = (unsigned long)id;
	entry->range = 1;

	return entry;
}

/* Run a function in a new user namespace.
 * The caller's euid/egid will be mapped if it is not already.
 * Afaict, userns_exec_1() is only used to operate based on privileges for the
 * user's own {g,u}id on the host and for the container root's unmapped {g,u}id.
 * This means we require only to establish a mapping from:
 * - the container root {g,u}id as seen from the host > user's host {g,u}id
 * - the container root -> some sub{g,u}id
 * The former we add, if the user did not specifiy a mapping. The latter we
 * retrieve from the ontainer's configured {g,u}id mappings as it must have been
 * there to start the container in the first place.
 */
int userns_exec_1(struct lxc_conf *conf, int (*fn)(void *), void *data,
		  const char *fn_name)
{
	pid_t pid;
	uid_t euid, egid;
	struct userns_fn_data d;
	int p[2];
	struct lxc_list *it;
	struct id_map *map;
	char c = '1';
	int ret = -1;
	struct lxc_list *idmap = NULL, *tmplist = NULL;
	struct id_map *container_root_uid = NULL, *container_root_gid = NULL,
		      *host_uid_map = NULL, *host_gid_map = NULL;

	ret = pipe(p);
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
		ERROR("failed to clone child process in new user namespace");
		goto on_error;
	}

	close(p[0]);
	p[0] = -1;

	euid = geteuid();
	egid = getegid();

	/* Find container root. */
	lxc_list_for_each(it, &conf->id_map) {
		map = it->elem;

		if (map->nsid != 0)
			continue;

		if (map->idtype == ID_TYPE_UID && container_root_uid == NULL) {
			container_root_uid = malloc(sizeof(*container_root_uid));
			if (!container_root_uid)
				goto on_error;
			container_root_uid->idtype = map->idtype;
			container_root_uid->hostid = map->hostid;
			container_root_uid->nsid = 0;
			container_root_uid->range = map->range;

			/* Check if container root mapping contains a mapping
			 * for user's uid.
			 */
			if (euid >= map->hostid && euid < map->hostid + map->range)
				host_uid_map = container_root_uid;
		} else if (map->idtype == ID_TYPE_GID && container_root_gid == NULL) {
			container_root_gid = malloc(sizeof(*container_root_gid));
			if (!container_root_gid)
				goto on_error;
			container_root_gid->idtype = map->idtype;
			container_root_gid->hostid = map->hostid;
			container_root_gid->nsid = 0;
			container_root_gid->range = map->range;

			/* Check if container root mapping contains a mapping
			 * for user's gid.
			 */
			if (egid >= map->hostid && egid < map->hostid + map->range)
				host_gid_map = container_root_gid;
		}

		/* Found container root. */
		if (container_root_uid && container_root_gid)
			break;
	}

	/* This is actually checked earlier but it can't hurt. */
	if (!container_root_uid || !container_root_gid) {
		ERROR("no mapping for container root found");
		goto on_error;
	}

	/* Check whether the {g,u}id of the user has a mapping. */
	if (!host_uid_map)
		host_uid_map = idmap_add(conf, euid, ID_TYPE_UID);

	if (!host_gid_map)
		host_gid_map = idmap_add(conf, egid, ID_TYPE_GID);

	if (!host_uid_map) {
		DEBUG("failed to find mapping for uid %d", euid);
		goto on_error;
	}

	if (!host_gid_map) {
		DEBUG("failed to find mapping for gid %d", egid);
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

	if (lxc_log_get_level() == LXC_LOG_LEVEL_TRACE ||
	    conf->loglevel == LXC_LOG_LEVEL_TRACE) {
		lxc_list_for_each(it, idmap) {
			map = it->elem;
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
		ERROR("error setting up {g,u}id mappings for child process "
		      "\"%d\"", pid);
		goto on_error;
	}

	/* Tell child to proceed. */
	if (write(p[1], &c, 1) != 1) {
		SYSERROR("failed telling child process \"%d\" to proceed", pid);
		goto on_error;
	}

	/* Wait for child to finish. */
	ret = wait_for_pid(pid);

on_error:
	if (idmap)
		lxc_free_idmap(idmap);
	if (container_root_uid)
		free(container_root_uid);
	if (container_root_gid)
		free(container_root_gid);
	if (host_uid_map && (host_uid_map != container_root_uid))
		free(host_uid_map);
	if (host_gid_map && (host_gid_map != container_root_gid))
		free(host_gid_map);

	if (p[0] != -1)
		close(p[0]);
	close(p[1]);

	return ret;
}

int userns_exec_full(struct lxc_conf *conf, int (*fn)(void *), void *data,
		     const char *fn_name)
{
	pid_t pid;
	uid_t euid, egid;
	struct userns_fn_data d;
	int p[2];
	struct id_map *map;
	struct lxc_list *cur;
	char c = '1';
	int ret = -1;
	struct lxc_list *idmap = NULL, *tmplist = NULL;
	struct id_map *container_root_uid = NULL, *container_root_gid = NULL,
		      *host_uid_map = NULL, *host_gid_map = NULL;

	ret = pipe(p);
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
		ERROR("failed to clone child process in new user namespace");
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
	lxc_list_for_each(cur, &conf->id_map) {
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
		host_uid_map = idmap_add(conf, euid, ID_TYPE_UID);
	else
		host_uid_map = container_root_uid;

	if (!host_gid_map)
		host_gid_map = idmap_add(conf, egid, ID_TYPE_GID);
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
		lxc_list_for_each(cur, idmap) {
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
		ERROR("error setting up {g,u}id mappings for child process "
		      "\"%d\"", pid);
		goto on_error;
	}

	/* Tell child to proceed. */
	if (write(p[1], &c, 1) != 1) {
		SYSERROR("failed telling child process \"%d\" to proceed", pid);
		goto on_error;
	}

	/* Wait for child to finish. */
	ret = wait_for_pid(pid);

on_error:
	if (idmap)
		lxc_free_idmap(idmap);
	if (host_uid_map && (host_uid_map != container_root_uid))
		free(host_uid_map);
	if (host_gid_map && (host_gid_map != container_root_gid))
		free(host_gid_map);

	if (p[0] != -1)
		close(p[0]);
	close(p[1]);

	return ret;
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
		size_t no_newline = 0;
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
		no_newline = strcspn(p2, "\n");
		p2[no_newline] = '\0';

		if (lxc_safe_uint(p, &uid) < 0)
			WARN("Could not parse UID.");
		if (lxc_safe_uint(p2, &urange) < 0)
			WARN("Could not parse UID range.");
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
		size_t no_newline = 0;
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
		no_newline = strcspn(p2, "\n");
		p2[no_newline] = '\0';

		if (lxc_safe_uint(p, &gid) < 0)
			WARN("Could not parse GID.");
		if (lxc_safe_uint(p2, &grange) < 0)
			WARN("Could not parse GID range.");
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
	ERROR("lxc.idmap = u 0 %u %u", uid, urange);
	ERROR("lxc.idmap = g 0 %u %u", gid, grange);

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

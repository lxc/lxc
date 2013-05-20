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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */
#define _GNU_SOURCE
#include <stdio.h>
#undef _GNU_SOURCE
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/syscall.h>

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
#include "parse.h"
#include "config.h"
#include "utils.h"
#include "conf.h"
#include "log.h"
#include "lxc.h"	/* for lxc_cgroup_set() */
#include "caps.h"       /* for lxc_caps_last_cap() */
#include "bdev.h"

#if HAVE_APPARMOR
#include <apparmor.h>
#endif

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

#define MAXHWLEN    18
#define MAXINDEXLEN 20
#define MAXMTULEN   16
#define MAXLINELEN  128

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

char *lxchook_names[NUM_LXC_HOOKS] = {
	"pre-start", "pre-mount", "mount", "autodev", "start", "post-stop", "clone" };

typedef int (*instanciate_cb)(struct lxc_handler *, struct lxc_netdev *);

struct mount_opt {
	char *name;
	int clear;
	int flag;
};

struct caps_opt {
	char *name;
	int value;
};

static int instanciate_veth(struct lxc_handler *, struct lxc_netdev *);
static int instanciate_macvlan(struct lxc_handler *, struct lxc_netdev *);
static int instanciate_vlan(struct lxc_handler *, struct lxc_netdev *);
static int instanciate_phys(struct lxc_handler *, struct lxc_netdev *);
static int instanciate_empty(struct lxc_handler *, struct lxc_netdev *);

static  instanciate_cb netdev_conf[LXC_NET_MAXCONFTYPE + 1] = {
	[LXC_NET_VETH]    = instanciate_veth,
	[LXC_NET_MACVLAN] = instanciate_macvlan,
	[LXC_NET_VLAN]    = instanciate_vlan,
	[LXC_NET_PHYS]    = instanciate_phys,
	[LXC_NET_EMPTY]   = instanciate_empty,
};

static int shutdown_veth(struct lxc_handler *, struct lxc_netdev *);
static int shutdown_macvlan(struct lxc_handler *, struct lxc_netdev *);
static int shutdown_vlan(struct lxc_handler *, struct lxc_netdev *);
static int shutdown_phys(struct lxc_handler *, struct lxc_netdev *);
static int shutdown_empty(struct lxc_handler *, struct lxc_netdev *);

static  instanciate_cb netdev_deconf[LXC_NET_MAXCONFTYPE + 1] = {
	[LXC_NET_VETH]    = shutdown_veth,
	[LXC_NET_MACVLAN] = shutdown_macvlan,
	[LXC_NET_VLAN]    = shutdown_vlan,
	[LXC_NET_PHYS]    = shutdown_phys,
	[LXC_NET_EMPTY]   = shutdown_empty,
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
};
#else
static struct caps_opt caps_opt[] = {};
#endif

static int run_buffer(char *buffer)
{
	FILE *f;
	char *output;
	int ret;

	f = popen(buffer, "r");
	if (!f) {
		SYSERROR("popen failed");
		return -1;
	}

	output = malloc(LXC_LOG_BUFFER_SIZE);
	if (!output) {
		ERROR("failed to allocate memory for script output");
		pclose(f);
		return -1;
	}

	while(fgets(output, LXC_LOG_BUFFER_SIZE, f))
		DEBUG("script output: %s", output);

	free(output);

	ret = pclose(f);
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
		      const char *script, const char *hook, char **argsin)
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

static int find_fstype_cb(char* buffer, void *data)
{
	struct cbarg {
		const char *rootfs;
		const char *target;
		int mntopt;
	} *cbarg = data;

	char *fstype;

	/* we don't try 'nodev' entries */
	if (strstr(buffer, "nodev"))
		return 0;

	fstype = buffer;
	fstype += lxc_char_left_gc(fstype, strlen(fstype));
	fstype[lxc_char_right_gc(fstype, strlen(fstype))] = '\0';

	DEBUG("trying to mount '%s'->'%s' with fstype '%s'",
	      cbarg->rootfs, cbarg->target, fstype);

	if (mount(cbarg->rootfs, cbarg->target, fstype, cbarg->mntopt, NULL)) {
		DEBUG("mount failed with error: %s", strerror(errno));
		return 0;
	}

	INFO("mounted '%s' on '%s', with fstype '%s'",
	     cbarg->rootfs, cbarg->target, fstype);

	return 1;
}

static int mount_unknow_fs(const char *rootfs, const char *target, int mntopt)
{
	int i;

	struct cbarg {
		const char *rootfs;
		const char *target;
		int mntopt;
	} cbarg = {
		.rootfs = rootfs,
		.target = target,
		.mntopt = mntopt,
	};

	/*
	 * find the filesystem type with brute force:
	 * first we check with /etc/filesystems, in case the modules
	 * are auto-loaded and fall back to the supported kernel fs
	 */
	char *fsfile[] = {
		"/etc/filesystems",
		"/proc/filesystems",
	};

	for (i = 0; i < sizeof(fsfile)/sizeof(fsfile[0]); i++) {

		int ret;

		if (access(fsfile[i], F_OK))
			continue;

		ret = lxc_file_for_each_line(fsfile[i], find_fstype_cb, &cbarg);
		if (ret < 0) {
			ERROR("failed to parse '%s'", fsfile[i]);
			return -1;
		}

		if (ret)
			return 0;
	}

	ERROR("failed to determine fs type for '%s'", rootfs);
	return -1;
}

static int mount_rootfs_dir(const char *rootfs, const char *target)
{
	return mount(rootfs, target, "none", MS_BIND | MS_REC, NULL);
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

static int mount_rootfs_file(const char *rootfs, const char *target)
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
			ret = mount_unknow_fs(path, target, 0);
		close(fd);

		break;
	}

	if (closedir(dir))
		WARN("failed to close directory");

	return ret;
}

static int mount_rootfs_block(const char *rootfs, const char *target)
{
	return mount_unknow_fs(rootfs, target, 0);
}

/*
 * pin_rootfs
 * if rootfs is a directory, then open ${rootfs}.hold for writing for the
 * duration of the container run, to prevent the container from marking the
 * underlying fs readonly on shutdown.
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

	if (!realpath(rootfs, absrootfs)) {
		INFO("failed to get real path for '%s', not pinning", rootfs);
		return -2;
	}

	if (access(absrootfs, F_OK)) {
		SYSERROR("'%s' is not accessible", absrootfs);
		return -1;
	}

	if (stat(absrootfs, &s)) {
		SYSERROR("failed to stat '%s'", absrootfs);
		return -1;
	}

	if (!S_ISDIR(s.st_mode))
		return -2;

	ret = snprintf(absrootfspin, MAXPATHLEN, "%s%s", absrootfs, ".hold");
	if (ret >= MAXPATHLEN) {
		SYSERROR("pathname too long for rootfs hold file");
		return -1;
	}

	fd = open(absrootfspin, O_CREAT | O_RDWR, S_IWUSR|S_IRUSR);
	INFO("opened %s as fd %d\n", absrootfspin, fd);
	return fd;
}

static int mount_rootfs(const char *rootfs, const char *target)
{
	char absrootfs[MAXPATHLEN];
	struct stat s;
	int i;

	typedef int (*rootfs_cb)(const char *, const char *);

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

		return rtfs_type[i].cb(absrootfs, target);
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

static int setup_tty(const struct lxc_rootfs *rootfs,
		     const struct lxc_tty_info *tty_info, char *ttydir)
{
	char path[MAXPATHLEN], lxcpath[MAXPATHLEN];
	int i, ret;

	if (!rootfs->path)
		return 0;

	for (i = 0; i < tty_info->nbtty; i++) {

		struct lxc_pty_info *pty_info = &tty_info->pty_info[i];

		ret = snprintf(path, sizeof(path), "%s/dev/tty%d",
			 rootfs->mount, i + 1);
		if (ret >= sizeof(path)) {
			ERROR("pathname too long for ttys");
			return -1;
		}
		if (ttydir) {
			/* create dev/lxc/tty%d" */
			ret = snprintf(lxcpath, sizeof(lxcpath), "%s/dev/%s/tty%d",
				 rootfs->mount, ttydir, i + 1);
			if (ret >= sizeof(lxcpath)) {
				ERROR("pathname too long for ttys");
				return -1;
			}
			ret = creat(lxcpath, 0660);
			if (ret==-1 && errno != EEXIST) {
				SYSERROR("error creating %s\n", lxcpath);
				return -1;
			}
			if (ret >= 0)
				close(ret);
			ret = unlink(path);
			if (ret && errno != ENOENT) {
				SYSERROR("error unlinking %s\n", path);
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
				SYSERROR("failed to create symlink for tty %d\n", i+1);
				return -1;
			}
		} else {
			/* If we populated /dev, then we need to create /dev/ttyN */
			if (access(path, F_OK)) {
				ret = creat(path, 0660);
				if (ret==-1) {
					SYSERROR("error creating %s\n", path);
					/* this isn't fatal, continue */
				} else
					close(ret);
			}
			if (mount(pty_info->name, path, "none", MS_BIND, 0)) {
				WARN("failed to mount '%s'->'%s'",
						pty_info->name, path);
				continue;
			}
		}
	}

	INFO("%d tty(s) has been setup", tty_info->nbtty);

	return 0;
}

static int setup_rootfs_pivot_root_cb(char *buffer, void *data)
{
	struct lxc_list	*mountlist, *listentry, *iterator;
	char *pivotdir, *mountpoint, *mountentry, *saveptr = NULL;
	int found;
	void **cbparm;

	mountentry = buffer;
	cbparm = (void **)data;

	mountlist = cbparm[0];
	pivotdir  = cbparm[1];

	/* parse entry, first field is mountname, ignore */
	mountpoint = strtok_r(mountentry, " ", &saveptr);
	if (!mountpoint)
		return -1;

	/* second field is mountpoint */
	mountpoint = strtok_r(NULL, " ", &saveptr);
	if (!mountpoint)
		return -1;

	/* only consider mountpoints below old root fs */
	if (strncmp(mountpoint, pivotdir, strlen(pivotdir)))
		return 0;

	/* filter duplicate mountpoints */
	found = 0;
	lxc_list_for_each(iterator, mountlist) {
		if (!strcmp(iterator->elem, mountpoint)) {
			found = 1;
			break;
		}
	}
	if (found)
		return 0;

	/* add entry to list */
	listentry = malloc(sizeof(*listentry));
	if (!listentry) {
		SYSERROR("malloc for mountpoint listentry failed");
		return -1;
	}

	listentry->elem = strdup(mountpoint);
	if (!listentry->elem) {
		SYSERROR("strdup failed");
		free(listentry);
		return -1;
	}
	lxc_list_add_tail(mountlist, listentry);

	return 0;
}

static int umount_oldrootfs(const char *oldrootfs)
{
	char path[MAXPATHLEN];
	void *cbparm[2];
	struct lxc_list mountlist, *iterator, *next;
	int ok, still_mounted, last_still_mounted;
	int rc;

	/* read and parse /proc/mounts in old root fs */
	lxc_list_init(&mountlist);

	/* oldrootfs is on the top tree directory now */
	rc = snprintf(path, sizeof(path), "/%s", oldrootfs);
	if (rc >= sizeof(path)) {
		ERROR("rootfs name too long");
		return -1;
	}
	cbparm[0] = &mountlist;

	cbparm[1] = strdup(path);
	if (!cbparm[1]) {
		SYSERROR("strdup failed");
		return -1;
	}

	rc = snprintf(path, sizeof(path), "%s/proc/mounts", oldrootfs);
	if (rc >= sizeof(path)) {
		ERROR("container proc/mounts name too long");
		return -1;
	}

	ok = lxc_file_for_each_line(path,
				    setup_rootfs_pivot_root_cb, &cbparm);
	if (ok < 0) {
		SYSERROR("failed to read or parse mount list '%s'", path);
		return -1;
	}

	/* umount filesystems until none left or list no longer shrinks */
	still_mounted = 0;
	do {
		last_still_mounted = still_mounted;
		still_mounted = 0;

		lxc_list_for_each_safe(iterator, &mountlist, next) {

			/* umount normally */
			if (!umount(iterator->elem)) {
				DEBUG("umounted '%s'", (char *)iterator->elem);
				lxc_list_del(iterator);
				continue;
			}

			still_mounted++;
		}

	} while (still_mounted > 0 && still_mounted != last_still_mounted);


	lxc_list_for_each(iterator, &mountlist) {

		/* let's try a lazy umount */
		if (!umount2(iterator->elem, MNT_DETACH)) {
			INFO("lazy unmount of '%s'", (char *)iterator->elem);
			continue;
		}

		/* be more brutal (nfs) */
		if (!umount2(iterator->elem, MNT_FORCE)) {
			INFO("forced unmount of '%s'", (char *)iterator->elem);
			continue;
		}

		WARN("failed to unmount '%s'", (char *)iterator->elem);
	}

	return 0;
}

static int setup_rootfs_pivot_root(const char *rootfs, const char *pivotdir)
{
	char path[MAXPATHLEN];
	int remove_pivotdir = 0;
	int rc;

	/* change into new root fs */
	if (chdir(rootfs)) {
		SYSERROR("can't chdir to new rootfs '%s'", rootfs);
		return -1;
	}

	if (!pivotdir)
		pivotdir = "lxc_putold";

	/* compute the full path to pivotdir under rootfs */
	rc = snprintf(path, sizeof(path), "%s/%s", rootfs, pivotdir);
	if (rc >= sizeof(path)) {
		ERROR("pivot dir name too long");
		return -1;
	}

	if (access(path, F_OK)) {

		if (mkdir_p(path, 0755)) {
			SYSERROR("failed to create pivotdir '%s'", path);
			return -1;
		}

		remove_pivotdir = 1;
		DEBUG("created '%s' directory", path);
	}

	DEBUG("mountpoint for old rootfs is '%s'", path);

	/* pivot_root into our new root fs */
	if (pivot_root(".", path)) {
		SYSERROR("pivot_root syscall failed");
		return -1;
	}

	if (chdir("/")) {
		SYSERROR("can't chdir to / after pivot_root");
		return -1;
	}

	DEBUG("pivot_root syscall to '%s' successful", rootfs);

	/* we switch from absolute path to relative path */
	if (umount_oldrootfs(pivotdir))
		return -1;

	/* remove temporary mount point, we don't consider the removing
	 * as fatal */
	if (remove_pivotdir && rmdir(pivotdir))
		WARN("can't remove mountpoint '%s': %m", pivotdir);

	return 0;
}

/*
 * Do we want to add options for max size of /dev and a file to
 * specify which devices to create?
 */
static int mount_autodev(char *root)
{
	int ret;
	char path[MAXPATHLEN];

	INFO("Mounting /dev under %s\n", root);
	ret = snprintf(path, MAXPATHLEN, "%s/dev", root);
	if (ret < 0 || ret > MAXPATHLEN)
		return -1;
	ret = mount("none", path, "tmpfs", 0, "size=100000");
	if (ret) {
		SYSERROR("Failed to mount /dev at %s\n", root);
		return -1;
	}
	ret = snprintf(path, MAXPATHLEN, "%s/dev/pts", root);
	if (ret < 0 || ret >= MAXPATHLEN)
		return -1;
	ret = mkdir(path, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
	if (ret) {
		SYSERROR("Failed to create /dev/pts in container");
		return -1;
	}

	INFO("Mounted /dev under %s\n", root);
	return 0;
}

struct lxc_devs {
	char *name;
	mode_t mode;
	int maj;
	int min;
};

struct lxc_devs lxc_devs[] = {
	{ "null",	S_IFCHR | S_IRWXU | S_IRWXG | S_IRWXO, 1, 3	},
	{ "zero",	S_IFCHR | S_IRWXU | S_IRWXG | S_IRWXO, 1, 5	},
	{ "full",	S_IFCHR | S_IRWXU | S_IRWXG | S_IRWXO, 1, 7	},
	{ "urandom",	S_IFCHR | S_IRWXU | S_IRWXG | S_IRWXO, 1, 9	},
	{ "random",	S_IFCHR | S_IRWXU | S_IRWXG | S_IRWXO, 1, 8	},
	{ "tty",	S_IFCHR | S_IRWXU | S_IRWXG | S_IRWXO, 5, 0	},
	{ "console",	S_IFCHR | S_IRUSR | S_IWUSR,	       5, 1	},
};

static int setup_autodev(char *root)
{
	int ret;
	struct lxc_devs *d;
	char path[MAXPATHLEN];
	int i;
	mode_t cmask;

	INFO("Creating initial consoles under %s/dev\n", root);

	ret = snprintf(path, MAXPATHLEN, "%s/dev", root);
	if (ret < 0 || ret >= MAXPATHLEN) {
		ERROR("Error calculating container /dev location");
		return -1;
	}

	INFO("Populating /dev under %s\n", root);
	cmask = umask(S_IXUSR | S_IXGRP | S_IXOTH);
	for (i = 0; i < sizeof(lxc_devs) / sizeof(lxc_devs[0]); i++) {
		d = &lxc_devs[i];
		ret = snprintf(path, MAXPATHLEN, "%s/dev/%s", root, d->name);
		if (ret < 0 || ret >= MAXPATHLEN)
			return -1;
		ret = mknod(path, d->mode, makedev(d->maj, d->min));
		if (ret && errno != EEXIST) {
			SYSERROR("Error creating %s\n", d->name);
			return -1;
		}
	}
	umask(cmask);

	INFO("Populated /dev under %s\n", root);
	return 0;
}

/*
 * Detect whether / is mounted MS_SHARED.  The only way I know of to
 * check that is through /proc/self/mountinfo.
 * I'm only checking for /.  If the container rootfs or mount location
 * is MS_SHARED, but not '/', then you're out of luck - figuring that
 * out would be too much work to be worth it.
 */
#define LINELEN 4096
int detect_shared_rootfs(void)
{
	char buf[LINELEN], *p;
	FILE *f;
	int i;
	char *p2;

	f = fopen("/proc/self/mountinfo", "r");
	if (!f)
		return 0;
	while ((p = fgets(buf, LINELEN, f))) {
		INFO("looking at .%s.", p);
		for (p = buf, i=0; p && i < 4; i++)
			p = index(p+1, ' ');
		if (!p)
			continue;
		p2 = index(p+1, ' ');
		if (!p2)
			continue;
		*p2 = '\0';
		INFO("now p is .%s.", p);
		if (strcmp(p+1, "/") == 0) {
			// this is '/'.  is it shared?
			p = index(p2+1, ' ');
			if (p && strstr(p, "shared:")) {
				fclose(f);
				return 1;
			}
		}
	}
	fclose(f);
	return 0;
}

/*
 * I'll forgive you for asking whether all of this is needed :)  The
 * answer is yes.
 * pivot_root will fail if the new root, the put_old dir, or the parent
 * of current->fs->root are MS_SHARED.  (parent of current->fs_root may
 * or may not be current->fs_root - if we assumed it always was, we could
 * just mount --make-rslave /).  So,
 *    1. mount a tiny tmpfs to be parent of current->fs->root.
 *    2. make that MS_SLAVE
 *    3. make a 'root' directory under that
 *    4. mount --rbind / under the $tinyroot/root.
 *    5. make that rslave
 *    6. chdir and chroot into $tinyroot/root
 *    7. $tinyroot will be unmounted by our parent in start.c
 */
static int chroot_into_slave(struct lxc_conf *conf)
{
	char path[MAXPATHLEN];
	const char *destpath = conf->rootfs.mount;
	int ret;

	if (mount(destpath, destpath, NULL, MS_BIND, 0)) {
		SYSERROR("failed to mount %s bind", destpath);
		return -1;
	}
	if (mount("", destpath, NULL, MS_SLAVE, 0)) {
		SYSERROR("failed to make %s slave", destpath);
		return -1;
	}
	if (mount("none", destpath, "tmpfs", 0, "size=10000")) {
		SYSERROR("Failed to mount tmpfs / at %s", destpath);
		return -1;
	}
	ret = snprintf(path, MAXPATHLEN, "%s/root", destpath);
	if (ret < 0 || ret >= MAXPATHLEN) {
		ERROR("out of memory making root path");
		return -1;
	}
	if (mkdir(path, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)) {
		SYSERROR("Failed to create /dev/pts in container");
		return -1;
	}
	if (mount("/", path, NULL, MS_BIND|MS_REC, 0)) {
		SYSERROR("Failed to rbind mount / to %s", path);
		return -1;
	}
	if (mount("", destpath, NULL, MS_SLAVE|MS_REC, 0)) {
		SYSERROR("Failed to make tmp-/ at %s rslave", path);
		return -1;
	}
	if (chdir(path)) {
		SYSERROR("Failed to chdir into tmp-/");
		return -1;
	}
	if (chroot(path)) {
		SYSERROR("Failed to chroot into tmp-/");
		return -1;
	}
	INFO("Chrooted into tmp-/ at %s\n", path);
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

	if (detect_shared_rootfs()) {
		if (chroot_into_slave(conf)) {
			ERROR("Failed to chroot into slave /");
			return -1;
		}
	}

	// First try mounting rootfs using a bdev
	struct bdev *bdev = bdev_init(rootfs->path, rootfs->mount, NULL);
	if (bdev && bdev->ops->mount(bdev) == 0) {
		DEBUG("mounted '%s' on '%s'", rootfs->path, rootfs->mount);
		return 0;
	}
	if (mount_rootfs(rootfs->path, rootfs->mount)) {
		ERROR("failed to mount rootfs");
		return -1;
	}

	DEBUG("mounted '%s' on '%s'", rootfs->path, rootfs->mount);

	return 0;
}

int setup_pivot_root(const struct lxc_rootfs *rootfs)
{
	if (!rootfs->path)
		return 0;

	if (setup_rootfs_pivot_root(rootfs->mount, rootfs->pivot)) {
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

	if (mount("devpts", "/dev/pts", "devpts", MS_MGC_VAL,
		  "newinstance,ptmxmode=0666")) {
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
	struct stat s;
	int ret;

	ret = snprintf(path, sizeof(path), "%s/dev/console", rootfs->mount);
	if (ret >= sizeof(path)) {
		ERROR("console path too long\n");
		return -1;
	}

	if (access(path, F_OK)) {
		WARN("rootfs specified but no console found at '%s'", path);
		return 0;
	}

	if (console->peer == -1) {
		INFO("no console output required");
		return 0;
	}

	if (stat(path, &s)) {
		SYSERROR("failed to stat '%s'", path);
		return -1;
	}

	if (chmod(console->name, s.st_mode)) {
		SYSERROR("failed to set mode '0%o' to '%s'",
			 s.st_mode, console->name);
		return -1;
	}

	if (mount(console->name, path, "none", MS_BIND, 0)) {
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
		SYSERROR("failed with errno %d to create %s\n", errno, path);
		return -1;
	}
	INFO("created %s\n", path);

	ret = snprintf(lxcpath, sizeof(lxcpath), "%s/dev/%s/console",
		       rootfs->mount, ttydir);
	if (ret >= sizeof(lxcpath)) {
		ERROR("console path too long\n");
		return -1;
	}

	snprintf(path, sizeof(path), "%s/dev/console", rootfs->mount);
	ret = unlink(path);
	if (ret && errno != ENOENT) {
		SYSERROR("error unlinking %s\n", path);
		return -1;
	}

	ret = creat(lxcpath, 0660);
	if (ret==-1 && errno != EEXIST) {
		SYSERROR("error %d creating %s\n", errno, lxcpath);
		return -1;
	}
	if (ret >= 0)
		close(ret);

	if (console->peer == -1) {
		INFO("no console output required");
		return 0;
	}

	if (mount(console->name, lxcpath, "none", MS_BIND, 0)) {
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
		SYSERROR("error unlinking %s\n", kpath);
		return -1;
	}

	ret = symlink("console", kpath);
	if (ret) {
		SYSERROR("failed to create symlink for kmsg");
		return -1;
	}

	return 0;
}

static int _setup_cgroup(const char *cgpath, struct lxc_list *cgroups,
			  int devices)
{
	struct lxc_list *iterator;
	struct lxc_cgroup *cg;
	int ret = -1;

	if (lxc_list_empty(cgroups))
		return 0;

	lxc_list_for_each(iterator, cgroups) {
		cg = iterator->elem;

		if (devices == !strncmp("devices", cg->subsystem, 7)) {
			if (lxc_cgroup_set_bypath(cgpath, cg->subsystem,
			    cg->value)) {
				ERROR("Error setting %s to %s for %s\n",
				      cg->subsystem, cg->value, cgpath);
				goto out;
			}
		}

		DEBUG("cgroup '%s' set to '%s'", cg->subsystem, cg->value);
	}

	ret = 0;
	INFO("cgroup has been setup");
out:
	return ret;
}

int setup_cgroup_devices(const char *cgpath, struct lxc_list *cgroups)
{
	return _setup_cgroup(cgpath, cgroups, 1);
}

int setup_cgroup(const char *cgpath, struct lxc_list *cgroups)
{
	return _setup_cgroup(cgpath, cgroups, 0);
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

static int parse_mntopts(const char *mntopts, unsigned long *mntflags,
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

static int mount_entry(const char *fsname, const char *target,
		       const char *fstype, unsigned long mountflags,
		       const char *data)
{
	if (mount(fsname, target, fstype, mountflags & ~MS_REMOUNT, data)) {
		SYSERROR("failed to mount '%s' on '%s'", fsname, target);
		return -1;
	}

	if ((mountflags & MS_REMOUNT) || (mountflags & MS_BIND)) {

		DEBUG("remounting %s on %s to respect bind or remount options",
		      fsname, target);

		if (mount(fsname, target, fstype,
			  mountflags | MS_REMOUNT, data)) {
			SYSERROR("failed to mount '%s' on '%s'",
				 fsname, target);
			return -1;
		}
	}

	DEBUG("mounted '%s' on '%s', type '%s'", fsname, target, fstype);

	return 0;
}

static inline int mount_entry_on_systemfs(struct mntent *mntent)
{
	unsigned long mntflags;
	char *mntdata;
	int ret;

	if (parse_mntopts(mntent->mnt_opts, &mntflags, &mntdata) < 0) {
		ERROR("failed to parse mount option '%s'", mntent->mnt_opts);
		return -1;
	}

	ret = mount_entry(mntent->mnt_fsname, mntent->mnt_dir,
			  mntent->mnt_type, mntflags, mntdata);

	if (hasmntopt(mntent, "optional") != NULL)
		ret = 0;

	free(mntdata);

	return ret;
}

static int mount_entry_on_absolute_rootfs(struct mntent *mntent,
					  const struct lxc_rootfs *rootfs,
					  const char *lxc_name)
{
	char *aux;
	char path[MAXPATHLEN];
	unsigned long mntflags;
	char *mntdata;
	int r, ret = 0, offset;
	const char *lxcpath;

	if (parse_mntopts(mntent->mnt_opts, &mntflags, &mntdata) < 0) {
		ERROR("failed to parse mount option '%s'", mntent->mnt_opts);
		return -1;
	}

	lxcpath = default_lxc_path();
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
		goto out;
	}
	offset = strlen(rootfs->path);

skipabs:

	r = snprintf(path, MAXPATHLEN, "%s/%s", rootfs->mount,
		 aux + offset);
	if (r < 0 || r >= MAXPATHLEN) {
		WARN("pathnme too long for '%s'", mntent->mnt_dir);
		ret = -1;
		goto out;
	}


	ret = mount_entry(mntent->mnt_fsname, path, mntent->mnt_type,
			  mntflags, mntdata);

	if (hasmntopt(mntent, "optional") != NULL)
		ret = 0;

out:
	free(mntdata);
	return ret;
}

static int mount_entry_on_relative_rootfs(struct mntent *mntent,
					  const char *rootfs)
{
	char path[MAXPATHLEN];
	unsigned long mntflags;
	char *mntdata;
	int ret;

	if (parse_mntopts(mntent->mnt_opts, &mntflags, &mntdata) < 0) {
		ERROR("failed to parse mount option '%s'", mntent->mnt_opts);
		return -1;
	}

        /* relative to root mount point */
	ret = snprintf(path, sizeof(path), "%s/%s", rootfs, mntent->mnt_dir);
	if (ret >= sizeof(path)) {
		ERROR("path name too long");
		return -1;
	}

	ret = mount_entry(mntent->mnt_fsname, path, mntent->mnt_type,
			  mntflags, mntdata);

	if (hasmntopt(mntent, "optional") != NULL)
		ret = 0;

	free(mntdata);

	return ret;
}

static int mount_file_entries(const struct lxc_rootfs *rootfs, FILE *file,
	const char *lxc_name)
{
	struct mntent *mntent;
	int ret = -1;

	while ((mntent = getmntent(file))) {

		if (!rootfs->path) {
			if (mount_entry_on_systemfs(mntent))
				goto out;
			continue;
		}

		/* We have a separate root, mounts are relative to it */
		if (mntent->mnt_dir[0] != '/') {
			if (mount_entry_on_relative_rootfs(mntent,
							   rootfs->mount))
				goto out;
			continue;
		}

		if (mount_entry_on_absolute_rootfs(mntent, rootfs, lxc_name))
			goto out;
	}

	ret = 0;

	INFO("mount points have been setup");
out:
	return ret;
}

static int setup_mount(const struct lxc_rootfs *rootfs, const char *fstab,
	const char *lxc_name)
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

	ret = mount_file_entries(rootfs, file, lxc_name);

	endmntent(file);
	return ret;
}

static int setup_mount_entries(const struct lxc_rootfs *rootfs, struct lxc_list *mount,
	const char *lxc_name)
{
	FILE *file;
	struct lxc_list *iterator;
	char *mount_entry;
	int ret;

	file = tmpfile();
	if (!file) {
		ERROR("tmpfile error: %m");
		return -1;
	}

	lxc_list_for_each(iterator, mount) {
		mount_entry = iterator->elem;
		fprintf(file, "%s\n", mount_entry);
	}

	rewind(file);

	ret = mount_file_entries(rootfs, file, lxc_name);

	fclose(file);
	return ret;
}

static int setup_caps(struct lxc_list *caps)
{
	struct lxc_list *iterator;
	char *drop_entry;
	char *ptr;
	int i, capid;

	lxc_list_for_each(iterator, caps) {

		drop_entry = iterator->elem;

		capid = -1;

		for (i = 0; i < sizeof(caps_opt)/sizeof(caps_opt[0]); i++) {

			if (strcmp(drop_entry, caps_opt[i].name))
				continue;

			capid = caps_opt[i].value;
			break;
		}

		if (capid < 0) {
			/* try to see if it's numeric, so the user may specify
			* capabilities  that the running kernel knows about but
			* we don't */
			capid = strtol(drop_entry, &ptr, 10);
			if (!ptr || *ptr != '\0' ||
			capid == LONG_MIN || capid == LONG_MAX)
				/* not a valid number */
				capid = -1;
			else if (capid > lxc_caps_last_cap())
				/* we have a number but it's not a valid
				* capability */
				capid = -1;
		}

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

	DEBUG("capabilities has been setup");

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

	DEBUG("mac address '%s' on '%s' has been setup", hwaddr, ifname);

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
		return 0;
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
	err = lxc_netdev_rename_by_name(ifname, netdev->name);
	if (err) {
		ERROR("failed to rename %s->%s : %s", ifname, netdev->name,
		      strerror(-err));
		return -1;
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

void lxc_rename_phys_nics_on_shutdown(struct lxc_conf *conf)
{
	int i;

	INFO("running to reset %d nic names", conf->num_savednics);
	for (i=0; i<conf->num_savednics; i++) {
		struct saved_nic *s = &conf->saved_nics[i];
		INFO("resetting nic %d to %s\n", s->ifindex, s->orig_name);
		lxc_netdev_rename_by_index(s->ifindex, s->orig_name);
		free(s->orig_name);
	}
	conf->num_savednics = 0;
	free(conf->saved_nics);
}

static int setup_private_host_hw_addr(char *veth1)
{
	struct ifreq ifr;
	int err;
	int sockfd;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0)
		return -errno;

	snprintf((char *)ifr.ifr_name, IFNAMSIZ, "%s", veth1);
	err = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
	if (err < 0) {
		close(sockfd);
		return -errno;
	}

	ifr.ifr_hwaddr.sa_data[0] = 0xfe;
	err = ioctl(sockfd, SIOCSIFHWADDR, &ifr);
	close(sockfd);
	if (err < 0)
		return -errno;

	DEBUG("mac address of host interface '%s' changed to private "
	      "%02x:%02x:%02x:%02x:%02x:%02x", veth1,
	      ifr.ifr_hwaddr.sa_data[0] & 0xff,
	      ifr.ifr_hwaddr.sa_data[1] & 0xff,
	      ifr.ifr_hwaddr.sa_data[2] & 0xff,
	      ifr.ifr_hwaddr.sa_data[3] & 0xff,
	      ifr.ifr_hwaddr.sa_data[4] & 0xff,
	      ifr.ifr_hwaddr.sa_data[5] & 0xff);

	return 0;
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

	new->personality = -1;
	new->console.log_path = NULL;
	new->console.log_fd = -1;
	new->console.path = NULL;
	new->console.peer = -1;
	new->console.master = -1;
	new->console.slave = -1;
	new->console.name[0] = '\0';
	new->maincmd_fd = -1;
	new->rootfs.mount = default_rootfs_mount;
	new->kmsg = 1;
	lxc_list_init(&new->cgroup);
	lxc_list_init(&new->network);
	lxc_list_init(&new->mount_list);
	lxc_list_init(&new->caps);
	lxc_list_init(&new->id_map);
	for (i=0; i<NUM_LXC_HOOKS; i++)
		lxc_list_init(&new->hooks[i]);
#if HAVE_APPARMOR
	new->aa_profile = NULL;
#endif
#if HAVE_APPARMOR /* || HAVE_SMACK || HAVE_SELINUX */
	new->lsm_umount_proc = 0;
#endif

	return new;
}

static int instanciate_veth(struct lxc_handler *handler, struct lxc_netdev *netdev)
{
	char veth1buf[IFNAMSIZ], *veth1;
	char veth2buf[IFNAMSIZ], *veth2;
	int err;

	if (netdev->priv.veth_attr.pair)
		veth1 = netdev->priv.veth_attr.pair;
	else {
		err = snprintf(veth1buf, sizeof(veth1buf), "vethXXXXXX");
		if (err >= sizeof(veth1buf)) { /* can't *really* happen, but... */
			ERROR("veth1 name too long");
			return -1;
		}
		veth1 = mktemp(veth1buf);
		/* store away for deconf */
		memcpy(netdev->priv.veth_attr.veth1, veth1, IFNAMSIZ);
	}

	snprintf(veth2buf, sizeof(veth2buf), "vethXXXXXX");
	veth2 = mktemp(veth2buf);

	if (!strlen(veth1) || !strlen(veth2)) {
		ERROR("failed to allocate a temporary name");
		return -1;
	}

	err = lxc_veth_create(veth1, veth2);
	if (err) {
		ERROR("failed to create %s-%s : %s", veth1, veth2,
		      strerror(-err));
		return -1;
	}

	/* changing the high byte of the mac address to 0xfe, the bridge interface
	 * will always keep the host's mac address and not take the mac address
	 * of a container */
	err = setup_private_host_hw_addr(veth1);
	if (err) {
		ERROR("failed to change mac address of host interface '%s' : %s",
			veth1, strerror(-err));
		goto out_delete;
	}

	if (netdev->mtu) {
		err = lxc_netdev_set_mtu(veth1, atoi(netdev->mtu));
		if (!err)
			err = lxc_netdev_set_mtu(veth2, atoi(netdev->mtu));
		if (err) {
			ERROR("failed to set mtu '%s' for %s-%s : %s",
			      netdev->mtu, veth1, veth2, strerror(-err));
			goto out_delete;
		}
	}

	if (netdev->link) {
		err = lxc_bridge_attach(netdev->link, veth1);
		if (err) {
			ERROR("failed to attach '%s' to the bridge '%s' : %s",
				      veth1, netdev->link, strerror(-err));
			goto out_delete;
		}
	}

	netdev->ifindex = if_nametoindex(veth2);
	if (!netdev->ifindex) {
		ERROR("failed to retrieve the index for %s", veth2);
		goto out_delete;
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

	DEBUG("instanciated veth '%s/%s', index is '%d'",
	      veth1, veth2, netdev->ifindex);

	return 0;

out_delete:
	lxc_netdev_delete_by_name(veth1);
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

static int instanciate_macvlan(struct lxc_handler *handler, struct lxc_netdev *netdev)
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

	peer = mktemp(peerbuf);
	if (!strlen(peer)) {
		ERROR("failed to make a temporary name");
		return -1;
	}

	err = lxc_macvlan_create(netdev->link, peer,
				 netdev->priv.macvlan_attr.mode);
	if (err) {
		ERROR("failed to create macvlan interface '%s' on '%s' : %s",
		      peer, netdev->link, strerror(-err));
		return -1;
	}

	netdev->ifindex = if_nametoindex(peer);
	if (!netdev->ifindex) {
		ERROR("failed to retrieve the index for %s", peer);
		lxc_netdev_delete_by_name(peer);
		return -1;
	}

	if (netdev->upscript) {
		err = run_script(handler->name, "net", netdev->upscript, "up",
				 "macvlan", netdev->link, (char*) NULL);
		if (err)
			return -1;
	}

	DEBUG("instanciated macvlan '%s', index is '%d' and mode '%d'",
	      peer, netdev->ifindex, netdev->priv.macvlan_attr.mode);

	return 0;
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

/* XXX: merge with instanciate_macvlan */
static int instanciate_vlan(struct lxc_handler *handler, struct lxc_netdev *netdev)
{
	char peer[IFNAMSIZ];
	int err;

	if (!netdev->link) {
		ERROR("no link specified for vlan netdev");
		return -1;
	}

	err = snprintf(peer, sizeof(peer), "vlan%d", netdev->priv.vlan_attr.vid);
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

	DEBUG("instanciated vlan '%s', ifindex is '%d'", " vlan1000",
	      netdev->ifindex);

	return 0;
}

static int shutdown_vlan(struct lxc_handler *handler, struct lxc_netdev *netdev)
{
	return 0;
}

static int instanciate_phys(struct lxc_handler *handler, struct lxc_netdev *netdev)
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

static int instanciate_empty(struct lxc_handler *handler, struct lxc_netdev *netdev)
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

int lxc_create_network(struct lxc_handler *handler)
{
	struct lxc_list *network = &handler->conf->network;
	struct lxc_list *iterator;
	struct lxc_netdev *netdev;

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
			WARN("failed to remove interface '%s'", netdev->name);
	}
}

int lxc_assign_network(struct lxc_list *network, pid_t pid)
{
	struct lxc_list *iterator;
	struct lxc_netdev *netdev;
	int err;

	lxc_list_for_each(iterator, network) {

		netdev = iterator->elem;

		/* empty network namespace, nothing to move */
		if (!netdev->ifindex)
			continue;

		err = lxc_netdev_move_by_index(netdev->ifindex, pid);
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
		fprintf(stderr, "%s: path name too long", __func__);
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
	int ret = 0;
	enum idtype type;
	char *buf = NULL, *pos;

	for(type = ID_TYPE_UID; type <= ID_TYPE_GID; type++) {
		int left, fill;

		pos = buf;
		lxc_list_for_each(iterator, idmap) {
			/* The kernel only takes <= 4k for writes to /proc/<nr>/[ug]id_map */
			if (!buf)
				buf = pos = malloc(4096);
			if (!buf)
				return -ENOMEM;

			map = iterator->elem;
			if (map->idtype == type) {
				left = 4096 - (pos - buf);
				fill = snprintf(pos, left, "%lu %lu %lu\n",
					map->nsid, map->hostid, map->range);
				if (fill <= 0 || fill >= left)
					SYSERROR("snprintf failed, too many mappings");
				pos += fill;
			}
		}
		if (pos == buf) // no mappings were found
			continue;
		ret = write_id_mapping(type, pid, buf, pos-buf);
		if (ret)
			break;
	}

	if (buf)
		free(buf);
	return ret;
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
	int i;

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

		if (openpty(&pty_info->master, &pty_info->slave,
			    pty_info->name, NULL, NULL)) {
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
 * given a host uid, return the ns uid if it is mapped.
 * if it is not mapped, return the original host id.
 */
static int shiftid(struct lxc_conf *c, int uid, enum idtype w)
{
	struct lxc_list *iterator;
	struct id_map *map;
	int low, high;

	lxc_list_for_each(iterator, &c->id_map) {
		map = iterator->elem;
		if (map->idtype != w)
			continue;

		low = map->nsid;
		high = map->nsid + map->range;
		if (uid < low || uid >= high)
			continue;

		return uid - low + map->hostid;
	}

	return uid;
}

/*
 * Take a pathname for a file created on the host, and map the uid and gid
 * into the container if needed.  (Used for ttys)
 */
static int uid_shift_file(char *path, struct lxc_conf *c)
{
	struct stat statbuf;
	int newuid, newgid;

	if (stat(path, &statbuf)) {
		SYSERROR("stat(%s)", path);
		return -1;
	}

	newuid = shiftid(c, statbuf.st_uid, ID_TYPE_UID);
	newgid = shiftid(c, statbuf.st_gid, ID_TYPE_GID);
	if (newuid != statbuf.st_uid || newgid != statbuf.st_gid) {
		DEBUG("chowning %s from %d:%d to %d:%d\n", path, (int)statbuf.st_uid, (int)statbuf.st_gid, newuid, newgid);
		if (chown(path, newuid, newgid)) {
			SYSERROR("chown(%s)", path);
			return -1;
		}
	}
	return 0;
}

int uid_shift_ttys(int pid, struct lxc_conf *conf)
{
	int i, ret;
	struct lxc_tty_info *tty_info = &conf->tty_info;
	char path[MAXPATHLEN];
	char *ttydir = conf->ttydir;

	if (!conf->rootfs.path)
		return 0;
	/* first the console */
	ret = snprintf(path, sizeof(path), "/proc/%d/root/dev/%s/console", pid, ttydir ? ttydir : "");
	if (ret < 0 || ret >= sizeof(path)) {
		ERROR("console path too long\n");
		return -1;
	}
	if (uid_shift_file(path, conf)) {
		DEBUG("Failed to chown the console %s.\n", path);
		return -1;
	}
	for (i=0; i< tty_info->nbtty; i++) {
		ret = snprintf(path, sizeof(path), "/proc/%d/root/dev/%s/tty%d",
			pid, ttydir ? ttydir : "", i + 1);
		if (ret < 0 || ret >= sizeof(path)) {
			ERROR("pathname too long for ttys");
			return -1;
		}
		if (uid_shift_file(path, conf)) {
			DEBUG("Failed to chown pty %s.\n", path);
			return -1;
		}
	}

	return 0;
}

int lxc_setup(const char *name, struct lxc_conf *lxc_conf)
{
#if HAVE_APPARMOR /* || HAVE_SMACK || HAVE_SELINUX */
	int mounted;
#endif

	if (setup_utsname(lxc_conf->utsname)) {
		ERROR("failed to setup the utsname for '%s'", name);
		return -1;
	}

	if (setup_network(&lxc_conf->network)) {
		ERROR("failed to setup the network for '%s'", name);
		return -1;
	}

	if (run_lxc_hooks(name, "pre-mount", lxc_conf, NULL)) {
		ERROR("failed to run pre-mount hooks for container '%s'.", name);
		return -1;
	}

	if (setup_rootfs(lxc_conf)) {
		ERROR("failed to setup rootfs for '%s'", name);
		return -1;
	}

	if (lxc_conf->autodev) {
		if (mount_autodev(lxc_conf->rootfs.mount)) {
			ERROR("failed to mount /dev in the container");
			return -1;
		}
	}

	if (setup_mount(&lxc_conf->rootfs, lxc_conf->fstab, name)) {
		ERROR("failed to setup the mounts for '%s'", name);
		return -1;
	}

	if (!lxc_list_empty(&lxc_conf->mount_list) && setup_mount_entries(&lxc_conf->rootfs, &lxc_conf->mount_list, name)) {
		ERROR("failed to setup the mount entries for '%s'", name);
		return -1;
	}

	if (run_lxc_hooks(name, "mount", lxc_conf, NULL)) {
		ERROR("failed to run mount hooks for container '%s'.", name);
		return -1;
	}

	if (lxc_conf->autodev) {
		if (run_lxc_hooks(name, "autodev", lxc_conf, NULL)) {
			ERROR("failed to run autodev hooks for container '%s'.", name);
			return -1;
		}
		if (setup_autodev(lxc_conf->rootfs.mount)) {
			ERROR("failed to populate /dev in the container");
			return -1;
		}
	}

	if (setup_console(&lxc_conf->rootfs, &lxc_conf->console, lxc_conf->ttydir)) {
		ERROR("failed to setup the console for '%s'", name);
		return -1;
	}

	if (lxc_conf->kmsg) {
		if (setup_kmsg(&lxc_conf->rootfs, &lxc_conf->console))  // don't fail
			ERROR("failed to setup kmsg for '%s'", name);
	}

	if (setup_tty(&lxc_conf->rootfs, &lxc_conf->tty_info, lxc_conf->ttydir)) {
		ERROR("failed to setup the ttys for '%s'", name);
		return -1;
	}

#if HAVE_APPARMOR /* || HAVE_SMACK || HAVE_SELINUX */
	INFO("rootfs path is .%s., mount is .%s.", lxc_conf->rootfs.path,
		lxc_conf->rootfs.mount);
	if (lxc_conf->rootfs.path == NULL || strlen(lxc_conf->rootfs.path) == 0)
		mounted = 0;
	else
		mounted = lsm_mount_proc_if_needed(lxc_conf->rootfs.path, lxc_conf->rootfs.mount);
	if (mounted == -1) {
		SYSERROR("failed to mount /proc in the container.");
		return -1;
	} else if (mounted == 1) {
		lxc_conf->lsm_umount_proc = 1;
	}
#endif

	if (setup_pivot_root(&lxc_conf->rootfs)) {
		ERROR("failed to set rootfs for '%s'", name);
		return -1;
	}

	if (setup_pts(lxc_conf->pts)) {
		ERROR("failed to setup the new pts instance");
		return -1;
	}

	if (setup_personality(lxc_conf->personality)) {
		ERROR("failed to setup personality");
		return -1;
	}

	if (lxc_list_empty(&lxc_conf->id_map)) {
		if (setup_caps(&lxc_conf->caps)) {
			ERROR("failed to drop capabilities");
			return -1;
		}
	}

	NOTICE("'%s' is setup.", name);

	return 0;
}

int run_lxc_hooks(const char *name, char *hook, struct lxc_conf *conf, char *argv[])
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
	else if (strcmp(hook, "post-stop") == 0)
		which = LXCHOOK_POSTSTOP;
	else if (strcmp(hook, "clone") == 0)
		which = LXCHOOK_CLONE;
	else
		return -1;
	lxc_list_for_each(it, &conf->hooks[which]) {
		int ret;
		char *hookname = it->elem;
		ret = run_script_argv(name, "lxc", hookname, hook, argv);
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

	if (netdev->link)
		free(netdev->link);
	if (netdev->name)
		free(netdev->name);
	if (netdev->upscript)
		free(netdev->upscript);
	if (netdev->hwaddr)
		free(netdev->hwaddr);
	if (netdev->mtu)
		free(netdev->mtu);
	if (netdev->ipv4_gateway)
		free(netdev->ipv4_gateway);
	if (netdev->ipv6_gateway)
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

	p1 = index(key, '.');
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
	} else if (strcmp(p1, "ipv4") == 0) {
		struct lxc_list *it2,*next;
		lxc_list_for_each_safe(it2, &netdev->ipv4, next) {
			lxc_list_del(it2);
			free(it2->elem);
			free(it2);
		}
	} else if (strcmp(p1, "ipv6") == 0) {
		struct lxc_list *it2,*next;
		lxc_list_for_each_safe(it2, &netdev->ipv6, next) {
			lxc_list_del(it2);
			free(it2->elem);
			free(it2);
		}
	} else if (strcmp(p1, "link") == 0) {
		if (netdev->link) {
			free(netdev->link);
			netdev->link = NULL;
		}
	} else if (strcmp(p1, "name") == 0) {
		if (netdev->name) {
			free(netdev->name);
			netdev->name = NULL;
		}
	} else if (strcmp(p1, "script.up") == 0) {
		if (netdev->upscript) {
			free(netdev->upscript);
			netdev->upscript = NULL;
		}
	} else if (strcmp(p1, "hwaddr") == 0) {
		if (netdev->hwaddr) {
			free(netdev->hwaddr);
			netdev->hwaddr = NULL;
		}
	} else if (strcmp(p1, "mtu") == 0) {
		if (netdev->mtu) {
			free(netdev->mtu);
			netdev->mtu = NULL;
		}
	} else if (strcmp(p1, "ipv4_gateway") == 0) {
		if (netdev->ipv4_gateway) {
			free(netdev->ipv4_gateway);
			netdev->ipv4_gateway = NULL;
		}
	} else if (strcmp(p1, "ipv6_gateway") == 0) {
		if (netdev->ipv6_gateway) {
			free(netdev->ipv6_gateway);
			netdev->ipv6_gateway = NULL;
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

void lxc_clear_saved_nics(struct lxc_conf *conf)
{
	int i;

	if (!conf->num_savednics)
		return;
	for (i=0; i < conf->num_savednics; i++)
		free(conf->saved_nics[i].orig_name);
	conf->saved_nics = 0;
	free(conf->saved_nics);
}

void lxc_conf_free(struct lxc_conf *conf)
{
	if (!conf)
		return;
	if (conf->console.path)
		free(conf->console.path);
	if (conf->rootfs.mount != default_rootfs_mount)
		free(conf->rootfs.mount);
	if (conf->rootfs.path)
		free(conf->rootfs.path);
	if (conf->utsname)
		free(conf->utsname);
	if (conf->ttydir)
		free(conf->ttydir);
	if (conf->fstab)
		free(conf->fstab);
	if (conf->rcfile)
		free(conf->rcfile);
	lxc_clear_config_network(conf);
#if HAVE_APPARMOR
	if (conf->aa_profile)
		free(conf->aa_profile);
#endif
	lxc_seccomp_free(conf);
	lxc_clear_config_caps(conf);
	lxc_clear_cgroups(conf, "lxc.cgroup");
	lxc_clear_hooks(conf, "lxc.hook");
	lxc_clear_mount_entries(conf);
	lxc_clear_saved_nics(conf);
	free(conf);
}

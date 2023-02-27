/* SPDX-License-Identifier: LGPL-2.1+ */

#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <unistd.h>

#include "caps.h"
#include "cgroups/cgroup_utils.h"
#include "conf.h"
#include "initutils.h"
#include "file_utils.h"
#include "log.h"
#include "lsm.h"
#include "open_utils.h"
#include "parse.h"
#include "process_utils.h"
#include "utils.h"

lxc_log_define(apparmor, lsm);

#define AA_DEF_PROFILE "lxc-container-default"
#define AA_DEF_PROFILE_CGNS "lxc-container-default-cgns"
#define AA_MOUNT_RESTR "/sys/kernel/security/apparmor/features/mount/mask"
#define AA_ENABLED_FILE "/sys/module/apparmor/parameters/enabled"
#define AA_UNCHANGED "unchanged"
#define AA_GENERATED "generated"

#define AA_CMD_LOAD   'r'
#define AA_CMD_UNLOAD 'R'
#define AA_CMD_PARSE  'Q'

static const char AA_PROFILE_BASE[] =
"  ### Base profile\n"
"  capability,\n"
"  dbus,\n"
"  file,\n"
"  network,\n"
"  umount,\n"
"\n"
"  # Allow us to receive signals from anywhere.\n"
"  signal (receive),\n"
"\n"
"  # Allow us to send signals to ourselves\n"
"  signal peer=@{profile_name},\n"
"\n"
"  # Allow other processes to read our /proc entries, futexes, perf tracing and\n"
"  # kcmp for now (they will need 'read' in the first place). Administrators can\n"
"  # override with:\n"
"  #   deny ptrace (readby) ...\n"
"  ptrace (readby),\n"
"\n"
"  # Allow other processes to trace us by default (they will need 'trace' in\n"
"  # the first place). Administrators can override with:\n"
"  #   deny ptrace (tracedby) ...\n"
"  ptrace (tracedby),\n"
"\n"
"  # Allow us to ptrace ourselves\n"
"  ptrace peer=@{profile_name},\n"
"\n"
"  # ignore DENIED message on / remount\n"
"  deny mount options=(ro, remount) -> /,\n"
"  deny mount options=(ro, remount, silent) -> /,\n"
"\n"
"  # allow tmpfs mounts everywhere\n"
"  mount fstype=tmpfs,\n"
"\n"
"  # allow hugetlbfs mounts everywhere\n"
"  mount fstype=hugetlbfs,\n"
"\n"
"  # allow mqueue mounts everywhere\n"
"  mount fstype=mqueue,\n"
"\n"
"  # allow fuse mounts everywhere\n"
"  mount fstype=fuse,\n"
"  mount fstype=fuse.*,\n"
"\n"
"  # deny access under /proc/bus to avoid e.g. messing with pci devices directly\n"
"  deny @{PROC}/bus/** wklx,\n"
"\n"
"  # deny writes in /proc/sys/fs but allow binfmt_misc to be mounted\n"
"  mount fstype=binfmt_misc -> /proc/sys/fs/binfmt_misc/,\n"
"  deny @{PROC}/sys/fs/** wklx,\n"
"\n"
"  # allow efivars to be mounted, writing to it will be blocked though\n"
"  mount fstype=efivarfs -> /sys/firmware/efi/efivars/,\n"
"\n"
"  # block some other dangerous paths\n"
"  deny @{PROC}/kcore rwklx,\n"
"  deny @{PROC}/sysrq-trigger rwklx,\n"
"  deny @{PROC}/acpi/** rwklx,\n"
"\n"
"  # deny writes in /sys except for /sys/fs/cgroup, also allow\n"
"  # fusectl, securityfs and debugfs to be mounted there (read-only)\n"
"  mount fstype=fusectl -> /sys/fs/fuse/connections/,\n"
"  mount fstype=securityfs -> /sys/kernel/security/,\n"
"  mount fstype=debugfs -> /sys/kernel/debug/,\n"
"  deny mount fstype=debugfs -> /var/lib/ureadahead/debugfs/,\n"
"  mount fstype=proc -> /proc/,\n"
"  mount fstype=sysfs -> /sys/,\n"
"  mount options=(rw, nosuid, nodev, noexec, remount) -> /sys/,\n"
"  deny /sys/firmware/efi/efivars/** rwklx,\n"
"  # note, /sys/kernel/security/** handled below\n"
"  mount options=(ro, nosuid, nodev, noexec, remount, strictatime) -> /sys/fs/cgroup/,\n"
"\n"
"  # deny reads from debugfs\n"
"  deny /sys/kernel/debug/{,**} rwklx,\n"
"\n"
"  # allow paths to be made dependent, shared, private or unbindable\n"
"  # TODO: This currently doesn't work due to the apparmor parser treating those as allowing all mounts.\n"
"#  mount options=(rw,make-slave) -> **,\n"
"#  mount options=(rw,make-rslave) -> **,\n"
"#  mount options=(rw,make-shared) -> **,\n"
"#  mount options=(rw,make-rshared) -> **,\n"
"#  mount options=(rw,make-private) -> **,\n"
"#  mount options=(rw,make-rprivate) -> **,\n"
"#  mount options=(rw,make-unbindable) -> **,\n"
"#  mount options=(rw,make-runbindable) -> **,\n"
"\n"
"# Allow limited modification of mount propagation\n"
"  mount options=(rw,make-slave) -> /,\n"
"  mount options=(rw,make-rslave) -> /,\n"
"  mount options=(rw,make-shared) -> /,\n"
"  mount options=(rw,make-rshared) -> /,\n"
"  mount options=(rw,make-private) -> /,\n"
"  mount options=(rw,make-rprivate) -> /,\n"
"  mount options=(rw,make-unbindable) -> /,\n"
"  mount options=(rw,make-runbindable) -> /,\n"
"\n"
"  # allow bind-mounts of anything except /proc, /sys and /dev\n"
"  mount options=(rw,bind) /[^spd]*{,/**},\n"
"  mount options=(rw,bind) /d[^e]*{,/**},\n"
"  mount options=(rw,bind) /de[^v]*{,/**},\n"
"  mount options=(rw,bind) /dev/.[^l]*{,/**},\n"
"  mount options=(rw,bind) /dev/.l[^x]*{,/**},\n"
"  mount options=(rw,bind) /dev/.lx[^c]*{,/**},\n"
"  mount options=(rw,bind) /dev/.lxc?*{,/**},\n"
"  mount options=(rw,bind) /dev/[^.]*{,/**},\n"
"  mount options=(rw,bind) /dev?*{,/**},\n"
"  mount options=(rw,bind) /p[^r]*{,/**},\n"
"  mount options=(rw,bind) /pr[^o]*{,/**},\n"
"  mount options=(rw,bind) /pro[^c]*{,/**},\n"
"  mount options=(rw,bind) /proc?*{,/**},\n"
"  mount options=(rw,bind) /s[^y]*{,/**},\n"
"  mount options=(rw,bind) /sy[^s]*{,/**},\n"
"  mount options=(rw,bind) /sys?*{,/**},\n"
"\n"
"  # Allow rbind-mounts of anything except /, /dev, /proc and /sys\n"
"  mount options=(rw,rbind) /[^spd]*{,/**},\n"
"  mount options=(rw,rbind) /d[^e]*{,/**},\n"
"  mount options=(rw,rbind) /de[^v]*{,/**},\n"
"  mount options=(rw,rbind) /dev?*{,/**},\n"
"  mount options=(rw,rbind) /p[^r]*{,/**},\n"
"  mount options=(rw,rbind) /pr[^o]*{,/**},\n"
"  mount options=(rw,rbind) /pro[^c]*{,/**},\n"
"  mount options=(rw,rbind) /proc?*{,/**},\n"
"  mount options=(rw,rbind) /s[^y]*{,/**},\n"
"  mount options=(rw,rbind) /sy[^s]*{,/**},\n"
"  mount options=(rw,rbind) /sys?*{,/**},\n"
"\n"
"  # allow moving mounts except for /proc, /sys and /dev\n"
"  mount options=(rw,move) /[^spd]*{,/**},\n"
"  mount options=(rw,move) /d[^e]*{,/**},\n"
"  mount options=(rw,move) /de[^v]*{,/**},\n"
"  mount options=(rw,move) /dev/.[^l]*{,/**},\n"
"  mount options=(rw,move) /dev/.l[^x]*{,/**},\n"
"  mount options=(rw,move) /dev/.lx[^c]*{,/**},\n"
"  mount options=(rw,move) /dev/.lxc?*{,/**},\n"
"  mount options=(rw,move) /dev/[^.]*{,/**},\n"
"  mount options=(rw,move) /dev?*{,/**},\n"
"  mount options=(rw,move) /p[^r]*{,/**},\n"
"  mount options=(rw,move) /pr[^o]*{,/**},\n"
"  mount options=(rw,move) /pro[^c]*{,/**},\n"
"  mount options=(rw,move) /proc?*{,/**},\n"
"  mount options=(rw,move) /s[^y]*{,/**},\n"
"  mount options=(rw,move) /sy[^s]*{,/**},\n"
"  mount options=(rw,move) /sys?*{,/**},\n"
"\n"
"  # generated by: lxc-generate-aa-rules.py container-rules.base\n"
"  deny /proc/sys/[^kn]*{,/**} wklx,\n"
"  deny /proc/sys/k[^e]*{,/**} wklx,\n"
"  deny /proc/sys/ke[^r]*{,/**} wklx,\n"
"  deny /proc/sys/ker[^n]*{,/**} wklx,\n"
"  deny /proc/sys/kern[^e]*{,/**} wklx,\n"
"  deny /proc/sys/kerne[^l]*{,/**} wklx,\n"
"  deny /proc/sys/kernel/[^smhd]*{,/**} wklx,\n"
"  deny /proc/sys/kernel/d[^o]*{,/**} wklx,\n"
"  deny /proc/sys/kernel/do[^m]*{,/**} wklx,\n"
"  deny /proc/sys/kernel/dom[^a]*{,/**} wklx,\n"
"  deny /proc/sys/kernel/doma[^i]*{,/**} wklx,\n"
"  deny /proc/sys/kernel/domai[^n]*{,/**} wklx,\n"
"  deny /proc/sys/kernel/domain[^n]*{,/**} wklx,\n"
"  deny /proc/sys/kernel/domainn[^a]*{,/**} wklx,\n"
"  deny /proc/sys/kernel/domainna[^m]*{,/**} wklx,\n"
"  deny /proc/sys/kernel/domainnam[^e]*{,/**} wklx,\n"
"  deny /proc/sys/kernel/domainname?*{,/**} wklx,\n"
"  deny /proc/sys/kernel/h[^o]*{,/**} wklx,\n"
"  deny /proc/sys/kernel/ho[^s]*{,/**} wklx,\n"
"  deny /proc/sys/kernel/hos[^t]*{,/**} wklx,\n"
"  deny /proc/sys/kernel/host[^n]*{,/**} wklx,\n"
"  deny /proc/sys/kernel/hostn[^a]*{,/**} wklx,\n"
"  deny /proc/sys/kernel/hostna[^m]*{,/**} wklx,\n"
"  deny /proc/sys/kernel/hostnam[^e]*{,/**} wklx,\n"
"  deny /proc/sys/kernel/hostname?*{,/**} wklx,\n"
"  deny /proc/sys/kernel/m[^s]*{,/**} wklx,\n"
"  deny /proc/sys/kernel/ms[^g]*{,/**} wklx,\n"
"  deny /proc/sys/kernel/msg*/** wklx,\n"
"  deny /proc/sys/kernel/s[^he]*{,/**} wklx,\n"
"  deny /proc/sys/kernel/se[^m]*{,/**} wklx,\n"
"  deny /proc/sys/kernel/sem*/** wklx,\n"
"  deny /proc/sys/kernel/sh[^m]*{,/**} wklx,\n"
"  deny /proc/sys/kernel/shm*/** wklx,\n"
"  deny /proc/sys/kernel?*{,/**} wklx,\n"
"  deny /proc/sys/n[^e]*{,/**} wklx,\n"
"  deny /proc/sys/ne[^t]*{,/**} wklx,\n"
"  deny /proc/sys/net?*{,/**} wklx,\n"
"  deny /sys/[^fdck]*{,/**} wklx,\n"
"  deny /sys/c[^l]*{,/**} wklx,\n"
"  deny /sys/cl[^a]*{,/**} wklx,\n"
"  deny /sys/cla[^s]*{,/**} wklx,\n"
"  deny /sys/clas[^s]*{,/**} wklx,\n"
"  deny /sys/class/[^n]*{,/**} wklx,\n"
"  deny /sys/class/n[^e]*{,/**} wklx,\n"
"  deny /sys/class/ne[^t]*{,/**} wklx,\n"
"  deny /sys/class/net?*{,/**} wklx,\n"
"  deny /sys/class?*{,/**} wklx,\n"
"  deny /sys/d[^e]*{,/**} wklx,\n"
"  deny /sys/de[^v]*{,/**} wklx,\n"
"  deny /sys/dev[^i]*{,/**} wklx,\n"
"  deny /sys/devi[^c]*{,/**} wklx,\n"
"  deny /sys/devic[^e]*{,/**} wklx,\n"
"  deny /sys/device[^s]*{,/**} wklx,\n"
"  deny /sys/devices/[^v]*{,/**} wklx,\n"
"  deny /sys/devices/v[^i]*{,/**} wklx,\n"
"  deny /sys/devices/vi[^r]*{,/**} wklx,\n"
"  deny /sys/devices/vir[^t]*{,/**} wklx,\n"
"  deny /sys/devices/virt[^u]*{,/**} wklx,\n"
"  deny /sys/devices/virtu[^a]*{,/**} wklx,\n"
"  deny /sys/devices/virtua[^l]*{,/**} wklx,\n"
"  deny /sys/devices/virtual/[^n]*{,/**} wklx,\n"
"  deny /sys/devices/virtual/n[^e]*{,/**} wklx,\n"
"  deny /sys/devices/virtual/ne[^t]*{,/**} wklx,\n"
"  deny /sys/devices/virtual/net?*{,/**} wklx,\n"
"  deny /sys/devices/virtual?*{,/**} wklx,\n"
"  deny /sys/devices?*{,/**} wklx,\n"
"  deny /sys/f[^s]*{,/**} wklx,\n"
"  deny /sys/fs/[^c]*{,/**} wklx,\n"
"  deny /sys/fs/c[^g]*{,/**} wklx,\n"
"  deny /sys/fs/cg[^r]*{,/**} wklx,\n"
"  deny /sys/fs/cgr[^o]*{,/**} wklx,\n"
"  deny /sys/fs/cgro[^u]*{,/**} wklx,\n"
"  deny /sys/fs/cgrou[^p]*{,/**} wklx,\n"
"  deny /sys/fs/cgroup?*{,/**} wklx,\n"
"  deny /sys/fs?*{,/**} wklx,\n"
;

static const char AA_PROFILE_UNIX_SOCKETS[] =
"\n"
"  ### Feature: unix\n"
"  # Allow receive via unix sockets from anywhere\n"
"  unix (receive),\n"
"\n"
"  # Allow all unix sockets in the container\n"
"  unix peer=(label=@{profile_name}),\n"
;

static const char AA_PROFILE_CGROUP_NAMESPACES[] =
"\n"
"  ### Feature: cgroup namespace\n"
"  mount fstype=cgroup -> /sys/fs/cgroup/**,\n"
"  mount fstype=cgroup2 -> /sys/fs/cgroup/**,\n"
;

/* '_BASE' because we still need to append generated change_profile rules */
static const char AA_PROFILE_STACKING_BASE[] =
"\n"
"  ### Feature: apparmor stacking\n"
"  ### Configuration: apparmor profile loading (in namespace)\n"
"  deny /sys/k[^e]*{,/**} wklx,\n"
"  deny /sys/ke[^r]*{,/**} wklx,\n"
"  deny /sys/ker[^n]*{,/**} wklx,\n"
"  deny /sys/kern[^e]*{,/**} wklx,\n"
"  deny /sys/kerne[^l]*{,/**} wklx,\n"
"  deny /sys/kernel/[^s]*{,/**} wklx,\n"
"  deny /sys/kernel/s[^e]*{,/**} wklx,\n"
"  deny /sys/kernel/se[^c]*{,/**} wklx,\n"
"  deny /sys/kernel/sec[^u]*{,/**} wklx,\n"
"  deny /sys/kernel/secu[^r]*{,/**} wklx,\n"
"  deny /sys/kernel/secur[^i]*{,/**} wklx,\n"
"  deny /sys/kernel/securi[^t]*{,/**} wklx,\n"
"  deny /sys/kernel/securit[^y]*{,/**} wklx,\n"
"  deny /sys/kernel/security/[^a]*{,/**} wklx,\n"
"  deny /sys/kernel/security/a[^p]*{,/**} wklx,\n"
"  deny /sys/kernel/security/ap[^p]*{,/**} wklx,\n"
"  deny /sys/kernel/security/app[^a]*{,/**} wklx,\n"
"  deny /sys/kernel/security/appa[^r]*{,/**} wklx,\n"
"  deny /sys/kernel/security/appar[^m]*{,/**} wklx,\n"
"  deny /sys/kernel/security/apparm[^o]*{,/**} wklx,\n"
"  deny /sys/kernel/security/apparmo[^r]*{,/**} wklx,\n"
"  deny /sys/kernel/security/apparmor?*{,/**} wklx,\n"
"  deny /sys/kernel/security?*{,/**} wklx,\n"
"  deny /sys/kernel?*{,/**} wklx,\n"
;

static const char AA_PROFILE_NO_STACKING[] =
"\n"
"  ### Feature: apparmor stacking (not present)\n"
"  deny /sys/k*{,/**} rwklx,\n"
;

/* '_BASE' because we need to append change_profile for stacking */
static const char AA_PROFILE_NESTING_BASE[] =
"\n"
"  ### Configuration: nesting\n"
"  pivot_root,\n"
"  ptrace,\n"
"  signal,\n"
"\n"
   /* NOTE: See conf.c's "nesting_helpers" for details. */
"  deny /dev/.lxc/proc/** rw,\n"
"  deny /dev/.lxc/sys/** rw,\n"
"\n"
"  mount fstype=proc -> /usr/lib/*/lxc/**,\n"
"  mount fstype=sysfs -> /usr/lib/*/lxc/**,\n"
"\n"
"  # Allow nested LXD\n"
"  mount none -> /var/lib/lxd/shmounts/,\n"
"  mount /var/lib/lxd/shmounts/ -> /var/lib/lxd/shmounts/,\n"
"  mount options=bind /var/lib/lxd/shmounts/** -> /var/lib/lxd/**,\n"
"\n"
"  # TODO: There doesn't seem to be a way to ask for:\n"
"  # mount options=(ro,nosuid,nodev,noexec,remount,bind),\n"
"  # as we always get mount to $cdir/proc/sys with those flags denied\n"
"  # So allow all mounts until that is straightened out:\n"
"  mount,\n"
;

static const char AA_PROFILE_UNPRIVILEGED[] =
"\n"
"  ### Configuration: unprivileged container\n"
"  pivot_root,\n"
"\n"
"  # Allow modifying mount propagation\n"
"  mount options=(rw,make-slave) -> **,\n"
"  mount options=(rw,make-rslave) -> **,\n"
"  mount options=(rw,make-shared) -> **,\n"
"  mount options=(rw,make-rshared) -> **,\n"
"  mount options=(rw,make-private) -> **,\n"
"  mount options=(rw,make-rprivate) -> **,\n"
"  mount options=(rw,make-unbindable) -> **,\n"
"  mount options=(rw,make-runbindable) -> **,\n"
"\n"
"  # Allow all bind-mounts\n"
"  mount options=(rw,bind),\n"
"  mount options=(rw,rbind),\n"
"\n"
"  # Allow remounting things read-only\n"
"  mount options=(ro,remount),\n"
;

static void load_mount_features_enabled(struct lsm_ops *ops)
{
	struct stat statbuf;
	int ret;

	ret = stat(AA_MOUNT_RESTR, &statbuf);
	if (ret == 0)
		ops->aa_mount_features_enabled = 1;
}

/* aa_getcon is not working right now.  Use our hand-rolled version below */
static int apparmor_enabled(struct lsm_ops *ops)
{
	__do_fclose FILE *fin = NULL;
	char e;
	int ret;

	fin = fopen_cloexec(AA_ENABLED_FILE, "r");
	if (!fin)
		return 0;

	ret = fscanf(fin, "%c", &e);
	if (ret == 1 && e == 'Y') {
		load_mount_features_enabled(ops);
		return 1;
	}

	return 0;
}

static int __apparmor_process_label_open(struct lsm_ops *ops, pid_t pid, int o_flags, bool on_exec)
{
	int ret = -1;
	int labelfd;
	char path[LXC_LSMATTRLEN];

	if (on_exec)
		TRACE("On-exec not supported with AppArmor");

	/* first try the apparmor subdir */
	ret = snprintf(path, LXC_LSMATTRLEN, "/proc/%d/attr/apparmor/current", pid);
	if (ret < 0 || (size_t)ret >= LXC_LSMATTRLEN)
		return -1;

	labelfd = open(path, o_flags);
	if (labelfd >= 0)
		return labelfd;
	else if (errno != ENOENT)
		goto error;

	/* fallback to legacy global attr directory */
	ret = snprintf(path, LXC_LSMATTRLEN, "/proc/%d/attr/current", pid);
	if (ret < 0 || (size_t)ret >= LXC_LSMATTRLEN)
		return -1;

	labelfd = open(path, o_flags);
	if (labelfd >= 0)
		return labelfd;

error:
	return log_error_errno(-errno, errno, "Unable to open AppArmor LSM label file descriptor");
}

static char *apparmor_process_label_get(struct lsm_ops *ops, pid_t pid)
{
	__do_close int fd_label = -EBADF;
	__do_free char *buf = NULL;
	__do_free char *label = NULL;
	int ret;
	size_t len;

	fd_label = __apparmor_process_label_open(ops, pid, O_RDONLY, false);
	if (fd_label < 0)
		return NULL;

	ret = fd_to_buf(fd_label, &buf, &len);
	if (ret < 0)
		return NULL;

	if (len == 0)
		return NULL;

	label = malloc(len + 1);
	if (!label)
		return NULL;
	memcpy(label, buf, len);
	label[len] = '\0';

	len = strcspn(label, "\n \t");
	if (len)
		label[len] = '\0';

	return move_ptr(label);
}

static char *apparmor_process_label_get_at(struct lsm_ops *ops, int fd_pid)
{
	__do_free char *label = NULL;
	size_t len;

	/* first try the apparmor subdir, then fall back to legacy interface */
	label = read_file_at(fd_pid, "attr/apparmor/current", PROTECT_OPEN, PROTECT_LOOKUP_BENEATH);
	if (!label && errno == ENOENT)
		label = read_file_at(fd_pid, "attr/current", PROTECT_OPEN, PROTECT_LOOKUP_BENEATH);
	if (!label)
		return log_error_errno(NULL, errno, "Failed to get AppArmor context");

	len = strcspn(label, "\n \t");
	if (len)
		label[len] = '\0';
	return move_ptr(label);
}

/*
 * Probably makes sense to reorganize these to only read
 * the label once
 */
static bool apparmor_am_unconfined(struct lsm_ops *ops)
{
	char *p = apparmor_process_label_get(ops, lxc_raw_getpid());
	bool ret = false;
	if (!p || strequal(p, "unconfined"))
		ret = true;
	free(p);
	return ret;
}

static bool aa_needs_transition(char *curlabel)
{
	if (!curlabel)
		return false;
	if (strequal(curlabel, "unconfined"))
		return false;
	if (strequal(curlabel, "/usr/bin/lxc-start"))
		return false;
	return true;
}

static inline void uint64hex(char *buf, uint64_t num)
{
	size_t i;

	buf[16] = 0;
	for (i = 16; i--;) {
		char c = (char)(num & 0xf);
		buf[i] = c + (c < 0xa ? '0' : 'a' - 0xa);
		num >>= 4;
	}
}

static inline char *shorten_apparmor_name(char *name)
{
	size_t len = strlen(name);
	if (len + 7 > 253) {
		uint64_t hash;
		hash = fnv_64a_buf(name, len, FNV1A_64_INIT);
		name = must_realloc(name, 16 + 1);
		uint64hex(name, hash);
	}

	return name;
}

/* Replace slashes with hyphens */
static inline void sanitize_path(char *path)
{
	size_t i;

	for (i = 0; path[i]; i++)
		if (path[i] == '/')
			path[i] = '-';
}

static inline char *apparmor_dir(const char *ctname, const char *lxcpath)
{
	return must_make_path(lxcpath, ctname, "apparmor", NULL);
}


static inline char *apparmor_profile_full(const char *ctname, const char *lxcpath)
{
	return shorten_apparmor_name(must_concat(NULL, "lxc-", ctname, "_<", lxcpath, ">", NULL));
}

/* Like apparmor_profile_full() but with slashes replaced by hyphens */
static inline char *apparmor_namespace(const char *ctname, const char *lxcpath)
{
	char *full;

	full = apparmor_profile_full(ctname, lxcpath);
	sanitize_path(full);

	return full;
}

static bool check_apparmor_parser_version(struct lsm_ops *ops)
{
	int major = 0, minor = 0, micro = 0, ret = 0;
	struct lxc_popen_FILE *parserpipe;
	int rc;

	switch (ops->aa_parser_available) {
	case 0:
		return false;
	case 1:
		return true;
	}

	parserpipe = lxc_popen("apparmor_parser --version");
	if (!parserpipe) {
		fprintf(stderr, "Failed to run check for apparmor_parser\n");
		goto out;
	}

	rc = fscanf(parserpipe->f, "AppArmor parser version %d.%d.%d", &major, &minor, &micro);
	if (rc < 1) {
		lxc_pclose(parserpipe);
		/* We stay silent for now as this most likely means the shell
		 * lxc_popen executed failed to find the apparmor_parser binary.
		 * See the TODO comment above for details.
		 */
		goto out;
	}

	rc = lxc_pclose(parserpipe);
	if (rc < 0) {
		fprintf(stderr, "Error waiting for child process\n");
		goto out;
	}
	if (rc != 0) {
		fprintf(stderr, "'apparmor_parser --version' executed with an error status\n");
		goto out;
	}

	if ((major > 2) || (major == 2 && minor > 10) || (major == 2 && minor == 10 && micro >= 95))
		ops->aa_supports_unix = 1;

	ret = 1;

out:
	ops->aa_parser_available = ret;
	return ret == 1;
}

static bool file_is_yes(const char *path)
{
	__do_close int fd = -EBADF;
	ssize_t rd;
	char buf[8]; /* we actually just expect "yes" or "no" */

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return false;

	rd = lxc_read_nointr(fd, buf, sizeof(buf));

	return rd >= 4 && strnequal(buf, "yes\n", 4);
}

static bool apparmor_can_stack(void)
{
	int major, minor, scanned;
	FILE *f;

	if (!file_is_yes("/sys/kernel/security/apparmor/features/domain/stack"))
		return false;

	f = fopen_cloexec("/sys/kernel/security/apparmor/features/domain/version", "r");
	if (!f)
		return false;

	scanned = fscanf(f, "%d.%d", &major, &minor);
	fclose(f);
	if (scanned != 2)
		return false;

	return major > 1 || (major == 1 && minor >= 2);
}

static void must_append_sized_full(char **buf, size_t *bufsz, const char *data,
				   size_t size, bool append_newline)
{
	size_t newsize = *bufsz + size;

	if (append_newline)
		++newsize;

	*buf = must_realloc(*buf, newsize);
	memcpy(*buf + *bufsz, data, size);

	if (append_newline)
		(*buf)[newsize - 1] = '\n';

	*bufsz = newsize;
}

static void must_append_sized(char **buf, size_t *bufsz, const char *data, size_t size)
{
	return must_append_sized_full(buf, bufsz, data, size, false);
}

static bool is_privileged(struct lxc_conf *conf)
{
	return list_empty(&conf->id_map);
}

static const char* AA_ALL_DEST_PATH_LIST[] = {
	" -> /[^spd]*{,/**},\n",
	" -> /d[^e]*{,/**},\n",
	" -> /de[^v]*{,/**},\n",
	" -> /dev/.[^l]*{,/**},\n",
	" -> /dev/.l[^x]*{,/**},\n",
	" -> /dev/.lx[^c]*{,/**},\n",
	" -> /dev/.lxc?*{,/**},\n",
	" -> /dev/[^.]*{,/**},\n",
	" -> /dev?*{,/**},\n",
	" -> /p[^r]*{,/**},\n",
	" -> /pr[^o]*{,/**},\n",
	" -> /pro[^c]*{,/**},\n",
	" -> /proc?*{,/**},\n",
	" -> /s[^y]*{,/**},\n",
	" -> /sy[^s]*{,/**},\n",
	" -> /sys?*{,/**},\n",
	NULL,
};

static const struct mntopt_t {
	const char *opt;
	size_t len;
} REMOUNT_OPTIONS[] = {
	{ ",nodev", sizeof(",nodev")-1 },
	{ ",nosuid", sizeof(",nosuid")-1 },
	{ ",noexec", sizeof(",noexec")-1 },
};

static void append_remount_rule(char **profile, size_t *size, const char *rule)
{
	size_t rule_len = strlen(rule);

	for (const char **dest = AA_ALL_DEST_PATH_LIST; *dest; ++dest) {
		must_append_sized(profile, size, rule, rule_len);
		must_append_sized(profile, size, *dest, strlen(*dest));
	}
}

static void append_all_remount_rules(char **profile, size_t *size)
{
	/*
	 * That's 30, and we add at most:
	 * ",nodev,nosuid,noexec,strictatime -> /dev/.lx[^c]*{,/ **},\ n",
	 * which is anouther ~58, this s hould be enough:
	 */
	char buf[128] = "  mount options=(ro,remount,bind";
	const size_t buf_append_pos = strlen(buf);

	const size_t opt_count = ARRAY_SIZE(REMOUNT_OPTIONS);

	must_append_sized(profile, size,
			  "# allow various ro-bind-*re*mounts\n",
			  sizeof("# allow various ro-bind-*re*mounts\n")-1);

	for (size_t opt_bits = 0; opt_bits != (size_t)1 << opt_count; ++opt_bits) {
		size_t at = buf_append_pos;
		unsigned bit = 1;
		size_t o;

		for (o = 0; o != opt_count; ++o, bit <<= 1) {
			if (opt_bits & bit) {
				const struct mntopt_t *opt = &REMOUNT_OPTIONS[o];
				memcpy(&buf[at], opt->opt, opt->len);
				at += opt->len;
			}
		}

		memcpy(&buf[at], ")", sizeof(")"));
		append_remount_rule(profile, size, buf);

		/* noatime and strictatime don't go together */
		memcpy(&buf[at], ",noatime)", sizeof(",noatime)"));
		append_remount_rule(profile, size, buf);
		memcpy(&buf[at], ",strictatime)", sizeof(",strictatime)"));
		append_remount_rule(profile, size, buf);
	}
}

static char *get_apparmor_profile_content(struct lsm_ops *ops, struct lxc_conf *conf, const char *lxcpath)
{
	char *profile, *profile_name_full;
	size_t size;
	struct string_entry *rule;

	profile_name_full = apparmor_profile_full(conf->name, lxcpath);

	profile = must_concat(NULL,
"#include <tunables/global>\n"
"profile \"", profile_name_full, "\" flags=(attach_disconnected,mediate_deleted) {\n",
	                      NULL);
	size = strlen(profile);

	must_append_sized(&profile, &size, AA_PROFILE_BASE,
	                  STRARRAYLEN(AA_PROFILE_BASE));

	append_all_remount_rules(&profile, &size);

	if (ops->aa_supports_unix)
		must_append_sized(&profile, &size, AA_PROFILE_UNIX_SOCKETS,
		                  STRARRAYLEN(AA_PROFILE_UNIX_SOCKETS));

	if (file_exists("/proc/self/ns/cgroup"))
		must_append_sized(&profile, &size, AA_PROFILE_CGROUP_NAMESPACES,
		                  STRARRAYLEN(AA_PROFILE_CGROUP_NAMESPACES));

	if (ops->aa_can_stack && !ops->aa_is_stacked) {
		char *namespace, *temp;

		must_append_sized(&profile, &size, AA_PROFILE_STACKING_BASE,
		                  STRARRAYLEN(AA_PROFILE_STACKING_BASE));

		namespace = apparmor_namespace(conf->name, lxcpath);
		temp = must_concat(NULL, "  change_profile -> \":", namespace, ":*\",\n"
		                   "  change_profile -> \":", namespace, "://*\",\n",
		                   NULL);
		free(namespace);

		must_append_sized(&profile, &size, temp, strlen(temp));
		free(temp);
	} else {
		must_append_sized(&profile, &size, AA_PROFILE_NO_STACKING,
		                  STRARRAYLEN(AA_PROFILE_NO_STACKING));
	}

	if (conf->lsm_aa_allow_nesting) {
		must_append_sized(&profile, &size, AA_PROFILE_NESTING_BASE,
		                  STRARRAYLEN(AA_PROFILE_NESTING_BASE));

		if (!ops->aa_can_stack || ops->aa_is_stacked) {
			char *temp;

			temp = must_concat(NULL, "  change_profile -> \"",
			                   profile_name_full, "\",\n", NULL);
			must_append_sized(&profile, &size, temp, strlen(temp));
			free(temp);
		}
	}

	if (!is_privileged(conf) || am_host_unpriv())
		must_append_sized(&profile, &size, AA_PROFILE_UNPRIVILEGED,
		                  STRARRAYLEN(AA_PROFILE_UNPRIVILEGED));

	list_for_each_entry(rule, &conf->lsm_aa_raw, head) {
		const char *line = rule->val;

		must_append_sized_full(&profile, &size, line, strlen(line), true);
	}

	/* include terminating \0 byte */
	must_append_sized(&profile, &size, "}\n", 3);

	free(profile_name_full);

	return profile;
}

/*
 * apparmor_parser creates a cache file using the parsed file's name as a name.
 * This means there may be multiple containers with the same name but different
 * lxcpaths. Therefore we need a sanitized version of the complete profile name
 * as profile file-name.
 * We already get this exactly from apparmor_namespace().
 */
static char *make_apparmor_profile_path(const char *ctname, const char *lxcpath)
{
	char *ret, *filename;

	filename = apparmor_namespace(ctname, lxcpath);
	ret = must_make_path(lxcpath, ctname, "apparmor", filename, NULL);
	free(filename);

	return ret;
}

static char *make_apparmor_namespace_path(const char *ctname, const char *lxcpath)
{
	char *ret, *namespace;

	namespace = apparmor_namespace(ctname, lxcpath);
	ret = must_make_path("/sys/kernel/security/apparmor/policy/namespaces", namespace, NULL);
	free(namespace);

	return ret;
}

static bool make_apparmor_namespace(struct lsm_ops *ops, struct lxc_conf *conf, const char *lxcpath)
{
	char *path;

	if (!ops->aa_can_stack || ops->aa_is_stacked)
		return true;

	path = make_apparmor_namespace_path(conf->name, lxcpath);
	errno = 0;
	if (mkdir(path, 0755) < 0 && errno != EEXIST) {
		SYSERROR("Error creating AppArmor namespace: %s", path);
		free(path);
		return false;
	}
	free(path);

	return true;
}

static void remove_apparmor_namespace(struct lxc_conf *conf, const char *lxcpath)
{
	char *path;

	path = make_apparmor_namespace_path(conf->name, lxcpath);
	if (rmdir(path) != 0)
		SYSERROR("Error removing AppArmor namespace");
	free(path);
}

struct apparmor_parser_args {
	char cmd;
	char *file;
};

static int apparmor_parser_exec(void *data)
{
	struct apparmor_parser_args *args = data;
	char cmdbuf[] = { '-', args->cmd, 'W', 'L', 0 };

	execlp("apparmor_parser", "apparmor_parser", cmdbuf, APPARMOR_CACHE_DIR, args->file, NULL);

	return -1;
}

static int run_apparmor_parser(char command,
                               struct lxc_conf *conf,
                               const char *lxcpath)
{
	char output[PATH_MAX];
	int ret;
	struct apparmor_parser_args args = {
		.cmd = command,
		.file = make_apparmor_profile_path(conf->name, lxcpath),
	};

	ret = run_command(output, sizeof(output), apparmor_parser_exec, (void*)&args);
	if (ret < 0) {
		ERROR("Failed to run apparmor_parser on \"%s\": %s", args.file, output);
		ret = -1;
	}


	free(args.file);
	return ret;
}

static void remove_apparmor_profile(struct lxc_conf *conf, const char *lxcpath)
{
	char *path;

	/* It's ok if these deletes fail: if the container was never started,
	 * we'll have never written a profile or cached it.
	 */

	path = make_apparmor_profile_path(conf->name, lxcpath);
	(void)unlink(path);
	free(path);

	/* Also remove the apparmor/ subdirectory */
	path = apparmor_dir(conf->name, lxcpath);
	(void)rmdir(path);
	free(path);
}

static int load_apparmor_profile(struct lsm_ops *ops, struct lxc_conf *conf, const char *lxcpath)
{
	struct stat profile_sb;
	size_t content_len;
	int ret = -1;
	size_t old_len = 0;
	char *profile_path = NULL, *old_content = NULL, *new_content = NULL;
	int profile_fd = -1;

	if (!make_apparmor_namespace(ops, conf, lxcpath))
		return -1;

	/* In order to avoid forcing a profile parse (potentially slow) on
	 * every container start, let's use apparmor's binary policy cache,
	 * which checks mtime of the files to figure out if the policy needs to
	 * be regenerated.
	 *
	 * Since it uses mtimes, we shouldn't just always write out our local
	 * apparmor template; instead we should check to see whether the
	 * template is the same as ours. If it isn't we should write our
	 * version out so that the new changes are reflected and we definitely
	 * force a recompile.
	 */

	profile_path = make_apparmor_profile_path(conf->name, lxcpath);
	profile_fd = open(profile_path, O_RDONLY | O_CLOEXEC);
	if (profile_fd >= 0) {
		if (fstat(profile_fd, &profile_sb) < 0) {
			SYSERROR("Error accessing old profile from %s",
			         profile_path);
			goto out;
		}
		old_len = profile_sb.st_size;
		if (old_len) {
			old_content = lxc_strmmap(NULL, old_len, PROT_READ,
						  MAP_PRIVATE, profile_fd, 0);
			if (old_content == MAP_FAILED) {
				SYSERROR("Failed to mmap old profile from %s",
					 profile_path);
				goto out;
			}
		}
	} else if (errno != ENOENT) {
		SYSERROR("Error reading old profile from %s", profile_path);
		goto out;
	}

	new_content = get_apparmor_profile_content(ops, conf, lxcpath);
	if (!new_content)
		goto out;

	content_len = strlen(new_content);

	if (!old_content || old_len != content_len || memcmp(old_content, new_content, content_len) != 0) {
		char *path;

		ret = mkdir_p(APPARMOR_CACHE_DIR, 0755);
		if (ret < 0) {
			SYSERROR("Error creating AppArmor profile cache directory " APPARMOR_CACHE_DIR);
			goto out;
		}

		path = apparmor_dir(conf->name, lxcpath);
		ret = mkdir_p(path, 0755);
		if (ret < 0) {
			SYSERROR("Error creating AppArmor profile directory: %s", path);
			free(path);
			goto out;
		}
		free(path);

		ret = lxc_write_to_file(profile_path, new_content, content_len, false, 0600);
		if (ret < 0) {
			SYSERROR("Error writing profile to %s", profile_path);
			goto out;
		}
	}

	ret = run_apparmor_parser(AA_CMD_LOAD, conf, lxcpath);
	if (ret != 0)
		goto out_remove_profile;

	conf->lsm_aa_profile_created = true;

	goto out_ok;

out_remove_profile:
	remove_apparmor_profile(conf, lxcpath);
out:
	remove_apparmor_namespace(conf, lxcpath);
out_ok:
	if (profile_fd >= 0) {
		if (old_content)
			lxc_strmunmap(old_content, old_len);
		close(profile_fd);
	}
	free(profile_path);
	free(new_content);
	return ret;
}

/*
 * Ensure that the container's policy namespace is unloaded to free kernel
 * memory. This does not delete the policy from disk or cache.
 */
static void apparmor_cleanup(struct lsm_ops *ops, struct lxc_conf *conf, const char *lxcpath)
{
	if (!ops->aa_admin)
		return;

	if (!conf->lsm_aa_profile_created)
		return;

	remove_apparmor_namespace(conf, lxcpath);
	(void)run_apparmor_parser(AA_CMD_UNLOAD, conf, lxcpath);

	remove_apparmor_profile(conf, lxcpath);
}

static int apparmor_prepare(struct lsm_ops *ops, struct lxc_conf *conf, const char *lxcpath)
{
	int ret = -1;
	const char *label;
	char *curlabel = NULL, *genlabel = NULL;

	if (!ops->aa_enabled)
		return log_error(-1, "AppArmor not enabled");

	label = conf->lsm_aa_profile;

	/* user may request that we just ignore apparmor */
	if (label && strequal(label, AA_UNCHANGED)) {
		INFO("AppArmor profile unchanged per user request");
		conf->lsm_aa_profile_computed = must_copy_string(label);
		return 0;
	}

	if (label && strequal(label, AA_GENERATED)) {
		if (!check_apparmor_parser_version(ops)) {
			ERROR("Cannot use generated profile: apparmor_parser not available");
			goto out;
		}

		/* auto-generate profile based on available/requested security features */
		if (load_apparmor_profile(ops, conf, lxcpath) != 0) {
			ERROR("Failed to load generated AppArmor profile");
			goto out;
		}

		genlabel = apparmor_profile_full(conf->name, lxcpath);
		if (!genlabel) {
			ERROR("Failed to build AppArmor profile name");
			goto out;
		}

		if (ops->aa_can_stack && !ops->aa_is_stacked) {
			char *namespace = apparmor_namespace(conf->name, lxcpath);
			size_t llen = strlen(genlabel);
			must_append_sized(&genlabel, &llen, "//&:", STRARRAYLEN("//&:"));
			must_append_sized(&genlabel, &llen, namespace, strlen(namespace));
			must_append_sized(&genlabel, &llen, ":", STRARRAYLEN(":") + 1); /* with the nul byte */
			free(namespace);
		}

		label = genlabel;
	}

	curlabel = apparmor_process_label_get(ops, lxc_raw_getpid());

	if (!ops->aa_can_stack && aa_needs_transition(curlabel)) {
		/* we're already confined, and stacking isn't supported */

		if (!label || strequal(curlabel, label)) {
			/* no change requested */
			ret = 0;
			goto out;
		}

		ERROR("Already AppArmor confined, but new label requested.");
		goto out;
	}

	if (!label) {
		if (cgns_supported())
			label = AA_DEF_PROFILE_CGNS;
		else
			label = AA_DEF_PROFILE;
	}

	if (!ops->aa_mount_features_enabled && !strequal(label, "unconfined")) {
		WARN("Incomplete AppArmor support in your kernel");
		if (!conf->lsm_aa_allow_incomplete) {
			ERROR("If you really want to start this container, set");
			ERROR("lxc.apparmor.allow_incomplete = 1");
			ERROR("in your container configuration file");
			goto out;
		}
	}

	conf->lsm_aa_profile_computed = must_copy_string(label);
	ret = 0;

out:
	if (genlabel) {
		free(genlabel);
		if (ret != 0)
			apparmor_cleanup(ops, conf, lxcpath);
	}
	free(curlabel);
	return ret;
}

static int apparmor_keyring_label_set(struct lsm_ops *ops, const char *label)
{
	return 0;
}

static int apparmor_process_label_fd_get(struct lsm_ops *ops, pid_t pid, bool on_exec)
{
	return __apparmor_process_label_open(ops, pid, O_RDWR, on_exec);
}

static int apparmor_process_label_set_at(struct lsm_ops *ops, int label_fd,
					 const char *label, bool on_exec)
{
	__do_free char *command = NULL;
	int ret = -1;
	size_t len;

	if (on_exec)
		TRACE("Changing AppArmor profile on exec not supported");

	len = strlen(label) + strlen("changeprofile ") + 1;
	command = zalloc(len);
	if (!command)
		return ret_errno(ENOMEM);

	ret = snprintf(command, len, "changeprofile %s", label);
	if (ret < 0 || (size_t)ret >= len)
		return -EFBIG;

	ret = lxc_write_nointr(label_fd, command, len - 1);
	if (ret < 0)
		return syserror("Failed to write AppArmor profile \"%s\" to %d",
				label, label_fd);

	INFO("Set AppArmor label to \"%s\"", label);
	return 0;
}

/*
 * apparmor_process_label_set: Set AppArmor process profile
 *
 * @label   : the profile to set
 * @conf    : the container configuration to use if @label is NULL
 * @default : use the default profile if @label is NULL
 * @on_exec : this is ignored.  Apparmor profile will be changed immediately
 *
 * Returns 0 on success, < 0 on failure
 *
 * Notes: This relies on /proc being available.
 */
static int apparmor_process_label_set(struct lsm_ops *ops, const char *inlabel,
				      struct lxc_conf *conf, bool on_exec)
{
	__do_close int label_fd = -EBADF;
	int ret;
	const char *label;

	if (!ops->aa_enabled)
		return log_error_errno(-EOPNOTSUPP, EOPNOTSUPP, "AppArmor not enabled");

	label = inlabel ? inlabel : conf->lsm_aa_profile_computed;
	if (!label)
		return log_error_errno(-EINVAL, EINVAL, "LSM wasn't prepared");

	/* user may request that we just ignore apparmor */
	if (strequal(label, AA_UNCHANGED))
		return log_info(0, "AppArmor profile unchanged per user request");

	if (strequal(label, "unconfined") && apparmor_am_unconfined(ops))
		return log_info(0, "AppArmor profile unchanged");

	label_fd = apparmor_process_label_fd_get(ops, lxc_raw_gettid(), on_exec);
	if (label_fd < 0)
		return log_error_errno(-EINVAL, EINVAL, "Failed to change AppArmor profile to %s", label);

	ret = apparmor_process_label_set_at(ops, label_fd, label, on_exec);
	if (ret < 0)
		return log_error_errno(-EINVAL, EINVAL, "Failed to change AppArmor profile to %s", label);

	return log_info(0, "Changed AppArmor profile to %s", label);
}

static struct lsm_ops apparmor_ops = {
	.name				= "AppArmor",
	.aa_admin			= -1,
	.aa_can_stack			= -1,
	.aa_enabled			= -1,
	.aa_is_stacked			= -1,
	.aa_mount_features_enabled	= -1,
	.aa_parser_available		= -1,
	.aa_supports_unix		= -1,
	.cleanup			= apparmor_cleanup,
	.enabled			= apparmor_enabled,
	.keyring_label_set		= apparmor_keyring_label_set,
	.prepare           		= apparmor_prepare,
	.process_label_fd_get		= apparmor_process_label_fd_get,
	.process_label_get 		= apparmor_process_label_get,
	.process_label_set 		= apparmor_process_label_set,
	.process_label_get_at 		= apparmor_process_label_get_at,
	.process_label_set_at		= apparmor_process_label_set_at,
};

struct lsm_ops *lsm_apparmor_ops_init(void)
{
	apparmor_ops.aa_admin = 0;
	apparmor_ops.aa_can_stack = 0;
	apparmor_ops.aa_enabled = 0;
	apparmor_ops.aa_is_stacked = 0;
	apparmor_ops.aa_mount_features_enabled = 0;
	apparmor_ops.aa_parser_available = -1;
	apparmor_ops.aa_supports_unix = 0;

	if (!apparmor_enabled(&apparmor_ops))
		return NULL;

	apparmor_ops.aa_can_stack = apparmor_can_stack();
	if (apparmor_ops.aa_can_stack)
		apparmor_ops.aa_is_stacked = file_is_yes("/sys/kernel/security/apparmor/.ns_stacked");

	#if HAVE_LIBCAP
	apparmor_ops.aa_admin = lxc_proc_cap_is_set(CAP_SETGID, CAP_EFFECTIVE);
	#endif
	if (!apparmor_ops.aa_admin)
		WARN("Per-container AppArmor profiles are disabled because the mac_admin capability is missing");
	else if (am_host_unpriv() && !apparmor_ops.aa_is_stacked)
		WARN("Per-container AppArmor profiles are disabled because LXC is running in an unprivileged container without stacking");

	apparmor_ops.aa_enabled = 1;
	return &apparmor_ops;
}

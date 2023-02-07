/* SPDX-License-Identifier: LGPL-2.1+ */

#include "config.h"

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
#include <stdbool.h>
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

#include "conf.h"
#include "af_unix.h"
#include "caps.h"
#include "cgroups/cgroup.h"
#include "compiler.h"
#include "confile.h"
#include "confile_utils.h"
#include "error.h"
#include "log.h"
#include "lsm/lsm.h"
#include "lxclock.h"
#include "lxcseccomp.h"
#include "macro.h"
#include "memory_utils.h"
#include "mount_utils.h"
#include "namespace.h"
#include "network.h"
#include "open_utils.h"
#include "parse.h"
#include "process_utils.h"
#include "ringbuf.h"
#include "start.h"
#include "storage/storage.h"
#include "storage/overlay.h"
#include "sync.h"
#include "syscall_wrappers.h"
#include "terminal.h"
#include "utils.h"
#include "uuid.h"

#ifdef MAJOR_IN_MKDEV
#include <sys/mkdev.h>
#endif

#ifdef HAVE_STATVFS
#include <sys/statvfs.h>
#endif

#if HAVE_OPENPTY
#include <pty.h>
#else
#include "openpty.h"
#endif

#if HAVE_LIBCAP
#include <sys/capability.h>
#endif

#if !HAVE_STRLCAT
#include "strlcat.h"
#endif

#if IS_BIONIC
#include "lxcmntent.h"
#else
#include <mntent.h>
#endif

#if !HAVE_PRLIMIT && HAVE_PRLIMIT64
#include "prlimit.h"
#endif

#if !HAVE_STRLCPY
#include "strlcpy.h"
#endif

#if !HAVE_STRCHRNUL
#include "strchrnul.h"
#endif

lxc_log_define(conf, lxc);

/*
 * The lxc_conf of the container currently being worked on in an API call.
 * This is used in the error calls.
 */
thread_local struct lxc_conf *current_config;

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
	bool recursive;
	__u64 flag;
	int legacy_flag;
};

struct caps_opt {
	char *name;
	__u32 value;
};

struct limit_opt {
	char *name;
	int value;
};

static struct mount_opt mount_opt[] = {
	{ "atime",         1, false, MOUNT_ATTR_NOATIME,     MS_NOATIME       },
	{ "dev",           1, false, MOUNT_ATTR_NODEV,       MS_NODEV         },
	{ "diratime",      1, false, MOUNT_ATTR_NODIRATIME,  MS_NODIRATIME    },
	{ "exec",          1, false, MOUNT_ATTR_NOEXEC,      MS_NOEXEC        },
	{ "noatime",       0, false, MOUNT_ATTR_NOATIME,     MS_NOATIME       },
	{ "nodev",         0, false, MOUNT_ATTR_NODEV,       MS_NODEV         },
	{ "nodiratime",    0, false, MOUNT_ATTR_NODIRATIME,  MS_NODIRATIME    },
	{ "noexec",        0, false, MOUNT_ATTR_NOEXEC,      MS_NOEXEC        },
	{ "norelatime",    1, false, MOUNT_ATTR_RELATIME,    MS_RELATIME      },
	{ "nostrictatime", 1, false, MOUNT_ATTR_STRICTATIME, MS_STRICTATIME   },
	{ "nosuid",        0, false, MOUNT_ATTR_NOSUID,      MS_NOSUID        },
	{ "relatime",      0, false, MOUNT_ATTR_RELATIME,    MS_RELATIME      },
	{ "ro",            0, false, MOUNT_ATTR_RDONLY,      MS_RDONLY        },
	{ "rw",            1, false, MOUNT_ATTR_RDONLY,      MS_RDONLY        },
	{ "strictatime",   0, false, MOUNT_ATTR_STRICTATIME, MS_STRICTATIME   },
	{ "suid",          1, false, MOUNT_ATTR_NOSUID,      MS_NOSUID        },

	{ "bind",          0, false,  0,                     MS_BIND          },
	{ "defaults",      0, false,  0,                     0                },
	{ "rbind",         0, true,   0,                     MS_BIND | MS_REC },

	{ "sync",          0, false, ~0,                     MS_SYNCHRONOUS   },
	{ "async",         1, false, ~0,		     MS_SYNCHRONOUS   },
	{ "dirsync",       0, false, ~0,                     MS_DIRSYNC       },
	{ "lazytime",      0, false, ~0,                     MS_LAZYTIME      },
	{ "mand",          0, false, ~0,                     MS_MANDLOCK      },
	{ "nomand",        1, false, ~0,                     MS_MANDLOCK      },
	{ "remount",       0, false, ~0,                     MS_REMOUNT       },

	{ NULL,            0, false, ~0,                     ~0               },
};

static struct mount_opt propagation_opt[] = {
	{ "private",     0, false, MS_PRIVATE,    MS_PRIVATE             },
	{ "shared",      0, false, MS_SHARED,     MS_SHARED              },
	{ "slave",       0, false, MS_SLAVE,      MS_SLAVE               },
	{ "unbindable",  0, false, MS_UNBINDABLE, MS_UNBINDABLE          },
	{ "rprivate",    0, true,  MS_PRIVATE,    MS_PRIVATE | MS_REC    },
	{ "rshared",     0, true,  MS_SHARED,     MS_SHARED | MS_REC     },
	{ "rslave",      0, true,  MS_SLAVE,      MS_SLAVE | MS_REC      },
	{ "runbindable", 0, true,  MS_UNBINDABLE, MS_UNBINDABLE | MS_REC },
	{ NULL,          0, false, 0,             0                     },
};

static struct caps_opt caps_opt[] = {
#if HAVE_LIBCAP
	{ "chown",              CAP_CHOWN              },
	{ "dac_override",       CAP_DAC_OVERRIDE       },
	{ "dac_read_search",    CAP_DAC_READ_SEARCH    },
	{ "fowner",             CAP_FOWNER             },
	{ "fsetid",             CAP_FSETID             },
	{ "kill",               CAP_KILL               },
	{ "setgid",             CAP_SETGID             },
	{ "setuid",             CAP_SETUID             },
	{ "setpcap",            CAP_SETPCAP            },
	{ "linux_immutable",    CAP_LINUX_IMMUTABLE    },
	{ "net_bind_service",   CAP_NET_BIND_SERVICE   },
	{ "net_broadcast",      CAP_NET_BROADCAST      },
	{ "net_admin",          CAP_NET_ADMIN          },
	{ "net_raw",            CAP_NET_RAW            },
	{ "ipc_lock",           CAP_IPC_LOCK           },
	{ "ipc_owner",          CAP_IPC_OWNER          },
	{ "sys_module",         CAP_SYS_MODULE         },
	{ "sys_rawio",          CAP_SYS_RAWIO          },
	{ "sys_chroot",         CAP_SYS_CHROOT         },
	{ "sys_ptrace",         CAP_SYS_PTRACE         },
	{ "sys_pacct",          CAP_SYS_PACCT          },
	{ "sys_admin",          CAP_SYS_ADMIN          },
	{ "sys_boot",           CAP_SYS_BOOT           },
	{ "sys_nice",           CAP_SYS_NICE           },
	{ "sys_resource",       CAP_SYS_RESOURCE       },
	{ "sys_time",           CAP_SYS_TIME           },
	{ "sys_tty_config",     CAP_SYS_TTY_CONFIG     },
	{ "mknod",              CAP_MKNOD              },
	{ "lease",              CAP_LEASE              },
	{ "audit_write",        CAP_AUDIT_WRITE        },
	{ "audit_control",      CAP_AUDIT_CONTROL      },
	{ "setfcap",            CAP_SETFCAP            },
	{ "mac_override",       CAP_MAC_OVERRIDE       },
	{ "mac_admin",          CAP_MAC_ADMIN          },
	{ "syslog",             CAP_SYSLOG             },
	{ "wake_alarm",         CAP_WAKE_ALARM         },
	{ "block_suspend",      CAP_BLOCK_SUSPEND      },
	{ "audit_read",         CAP_AUDIT_READ         },
	{ "perfmon",            CAP_PERFMON            },
	{ "bpf",                CAP_BPF                },
	{ "checkpoint_restore", CAP_CHECKPOINT_RESTORE },
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
	__do_free char *output = NULL;
	__do_lxc_pclose struct lxc_popen_FILE *f = NULL;
	int fd, ret;

	f = lxc_popen(buffer);
	if (!f)
		return log_error_errno(-1, errno, "Failed to popen() %s", buffer);

	output = zalloc(LXC_LOG_BUFFER_SIZE);
	if (!output)
		return log_error_errno(-1, ENOMEM, "Failed to allocate memory for %s", buffer);

	fd = fileno(f->f);
	if (fd < 0)
		return log_error_errno(-1, errno, "Failed to retrieve underlying file descriptor");

	for (int i = 0; i < 10; i++) {
		ssize_t bytes_read;

		bytes_read = lxc_read_nointr(fd, output, LXC_LOG_BUFFER_SIZE - 1);
		if (bytes_read > 0) {
			output[bytes_read] = '\0';
			DEBUG("Script %s produced output: %s", buffer, output);
			continue;
		}

		break;
	}

	ret = lxc_pclose(move_ptr(f));
	if (ret == -1)
		return log_error_errno(-1, errno, "Script exited with error");
	else if (WIFEXITED(ret) && WEXITSTATUS(ret) != 0)
		return log_error(-1, "Script exited with status %d", WEXITSTATUS(ret));
	else if (WIFSIGNALED(ret))
		return log_error(-1, "Script terminated by signal %d", WTERMSIG(ret));

	return 0;
}

int run_script_argv(const char *name, unsigned int hook_version,
		    const char *section, const char *script,
		    const char *hookname, char **argv)
{
	__do_free char *buffer = NULL;
	int buf_pos, i, ret;
	size_t size = 0;

	if (hook_version == 0)
		INFO("Executing script \"%s\" for container \"%s\", config section \"%s\"",
		     script, name, section);
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

	buffer = zalloc(size);
	if (!buffer)
		return -ENOMEM;

	if (hook_version == 0)
		buf_pos = strnprintf(buffer, size, "exec %s %s %s %s", script, name, section, hookname);
	else
		buf_pos = strnprintf(buffer, size, "exec %s", script);
	if (buf_pos < 0)
		return log_error_errno(-1, errno, "Failed to create command line for script \"%s\"", script);

	if (hook_version == 1) {
		ret = setenv("LXC_HOOK_TYPE", hookname, 1);
		if (ret < 0) {
			return log_error_errno(-1, errno, "Failed to set environment variable: LXC_HOOK_TYPE=%s", hookname);
		}
		TRACE("Set environment variable: LXC_HOOK_TYPE=%s", hookname);

		ret = setenv("LXC_HOOK_SECTION", section, 1);
		if (ret < 0)
			return log_error_errno(-1, errno, "Failed to set environment variable: LXC_HOOK_SECTION=%s", section);
		TRACE("Set environment variable: LXC_HOOK_SECTION=%s", section);

		if (strequal(section, "net")) {
			char *parent;

			if (!argv || !argv[0])
				return -1;

			ret = setenv("LXC_NET_TYPE", argv[0], 1);
			if (ret < 0)
				return log_error_errno(-1, errno, "Failed to set environment variable: LXC_NET_TYPE=%s", argv[0]);
			TRACE("Set environment variable: LXC_NET_TYPE=%s", argv[0]);

			parent = argv[1] ? argv[1] : "";

			if (strequal(argv[0], "macvlan")) {
				ret = setenv("LXC_NET_PARENT", parent, 1);
				if (ret < 0)
					return log_error_errno(-1, errno, "Failed to set environment variable: LXC_NET_PARENT=%s", parent);
				TRACE("Set environment variable: LXC_NET_PARENT=%s", parent);
			} else if (strequal(argv[0], "phys")) {
				ret = setenv("LXC_NET_PARENT", parent, 1);
				if (ret < 0)
					return log_error_errno(-1, errno, "Failed to set environment variable: LXC_NET_PARENT=%s", parent);
				TRACE("Set environment variable: LXC_NET_PARENT=%s", parent);
			} else if (strequal(argv[0], "veth")) {
				char *peer = argv[2] ? argv[2] : "";

				ret = setenv("LXC_NET_PEER", peer, 1);
				if (ret < 0)
					return log_error_errno(-1, errno, "Failed to set environment variable: LXC_NET_PEER=%s", peer);
				TRACE("Set environment variable: LXC_NET_PEER=%s", peer);

				ret = setenv("LXC_NET_PARENT", parent, 1);
				if (ret < 0)
					return log_error_errno(-1, errno, "Failed to set environment variable: LXC_NET_PARENT=%s", parent);
				TRACE("Set environment variable: LXC_NET_PARENT=%s", parent);
			}
		}
	}

	for (i = 0; argv && argv[i]; i++) {
		size_t len = size - buf_pos;

		ret = strnprintf(buffer + buf_pos, len, " %s", argv[i]);
		if (ret < 0)
			return log_error_errno(-1, errno, "Failed to create command line for script \"%s\"", script);
		buf_pos += ret;
	}

	return run_buffer(buffer);
}

int run_script(const char *name, const char *section, const char *script, ...)
{
	__do_free char *buffer = NULL;
	int ret;
	char *p;
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

	buffer = must_realloc(NULL, size);
	ret = strnprintf(buffer, size, "exec %s %s %s", script, name, section);
	if (ret < 0)
		return -1;

	va_start(ap, script);
	while ((p = va_arg(ap, char *))) {
		int len = size - ret;
		int rc;
		rc = strnprintf(buffer + ret, len, " %s", p);
		if (rc < 0) {
			va_end(ap);
			return -1;
		}
		ret += rc;
	}
	va_end(ap);

	return run_buffer(buffer);
}

int lxc_storage_prepare(struct lxc_conf *conf)
{
	int ret;
	struct lxc_rootfs *rootfs = &conf->rootfs;

	if (!rootfs->path) {
		ret = mount("", "/", NULL, MS_SLAVE | MS_REC, 0);
		if (ret < 0)
			return log_error_errno(-1, errno, "Failed to recursively turn root mount tree into dependent mount");

		rootfs->dfd_mnt = open_at(-EBADF, "/", PROTECT_OPATH_DIRECTORY, PROTECT_LOOKUP_ABSOLUTE, 0);
		if (rootfs->dfd_mnt < 0)
			return -errno;

		return 0;
	}

	ret = access(rootfs->mount, F_OK);
	if (ret != 0)
		return log_error_errno(-1, errno, "Failed to access to \"%s\". Check it is present",
				       rootfs->mount);

	rootfs->storage = storage_init(conf);
	if (!rootfs->storage)
		return log_error(-1, "Failed to mount rootfs \"%s\" onto \"%s\" with options \"%s\"",
				 rootfs->path, rootfs->mount,
				 rootfs->mnt_opts.raw_options ? rootfs->mnt_opts.raw_options : "(null)");

	return 0;
}

void lxc_storage_put(struct lxc_conf *conf)
{
	storage_put(conf->rootfs.storage);
	conf->rootfs.storage = NULL;
}

/* lxc_rootfs_prepare
 * if rootfs is a directory, then open ${rootfs}/.lxc-keep for writing for
 * the duration of the container run, to prevent the container from marking
 * the underlying fs readonly on shutdown. unlink the file immediately so
 * no name pollution is happens.
 * don't unlink on NFS to avoid random named stale handles.
 */
int lxc_rootfs_init(struct lxc_conf *conf, bool userns)
{
	__do_close int dfd_path = -EBADF, fd_pin = -EBADF;
	int ret;
	struct stat st;
	struct statfs stfs;
	struct lxc_rootfs *rootfs = &conf->rootfs;

	ret = lxc_storage_prepare(conf);
	if (ret)
		return syserror_set(-EINVAL, "Failed to prepare rootfs storage");

	if (!is_empty_string(rootfs->mnt_opts.userns_path)) {
		if (!rootfs->path)
			return syserror_set(-EINVAL, "Idmapped rootfs currently only supported with separate rootfs for container");

		if (rootfs->bdev_type && !strequal(rootfs->bdev_type, "dir"))
			return syserror_set(-EINVAL, "Idmapped rootfs currently only supports the \"dir\" storage driver");
	}

	if (!rootfs->path)
		return log_trace(0, "Not pinning because container does not have a rootfs");

	if (userns)
		return log_trace(0, "Not pinning because container runs in user namespace");

	if (rootfs->bdev_type) {
		if (strequal(rootfs->bdev_type, "overlay") ||
		    strequal(rootfs->bdev_type, "overlayfs"))
			return log_trace_errno(0, EINVAL, "Not pinning on stacking filesystem");

		if (strequal(rootfs->bdev_type, "zfs"))
			return log_trace_errno(0, EINVAL, "Not pinning on ZFS filesystem");
	}

	dfd_path = open_at(-EBADF, rootfs->path, PROTECT_OPATH_FILE, 0, 0);
	if (dfd_path < 0)
		return syserror("Failed to open \"%s\"", rootfs->path);

	ret = fstat(dfd_path, &st);
	if (ret < 0)
		return log_trace_errno(-errno, errno, "Failed to retrieve file status");

	if (!S_ISDIR(st.st_mode))
		return log_trace_errno(0, ENOTDIR, "Not pinning because file descriptor is not a directory");

	fd_pin = open_at(dfd_path, ".lxc_keep",
			 PROTECT_OPEN | O_CREAT,
			 PROTECT_LOOKUP_BENEATH,
			 S_IWUSR | S_IRUSR);
	if (fd_pin < 0) {
		if (errno == EROFS)
			return log_trace_errno(0, EROFS, "Not pinning on read-only filesystem");
		return syserror("Failed to pin rootfs");
	}

	TRACE("Pinned rootfs %d(.lxc_keep)", fd_pin);

	ret = fstatfs(fd_pin, &stfs);
	if (ret < 0) {
		SYSWARN("Failed to retrieve filesystem status");
		goto out;
	}

	if (stfs.f_type == NFS_SUPER_MAGIC) {
		DEBUG("Not unlinking pinned file on NFS");
		goto out;
	}

	if (unlinkat(dfd_path, ".lxc_keep", 0))
		SYSTRACE("Failed to unlink rootfs pinning file %d(.lxc_keep)", dfd_path);
	else
		TRACE("Unlinked pinned file %d(.lxc_keep)", dfd_path);

out:
	rootfs->fd_path_pin = move_fd(fd_pin);
	return 0;
}

int lxc_rootfs_prepare_parent(struct lxc_handler *handler)
{
	__do_close int dfd_idmapped = -EBADF, fd_userns = -EBADF;
	struct lxc_rootfs *rootfs = &handler->conf->rootfs;
	struct lxc_storage *storage = rootfs->storage;
	const struct lxc_mount_options *mnt_opts = &rootfs->mnt_opts;
	int ret;
	const char *path_source;

	if (list_empty(&handler->conf->id_map))
		return 0;

	if (is_empty_string(rootfs->mnt_opts.userns_path))
		return 0;

	if (handler->conf->rootfs_setup)
		return 0;

	if (rootfs_is_blockdev(handler->conf))
		return syserror_set(-EOPNOTSUPP, "Idmapped mounts on block-backed storage not yet supported");

	if (!can_use_bind_mounts())
		return syserror_set(-EOPNOTSUPP, "Kernel does not support the new mount api");

	if (strequal(rootfs->mnt_opts.userns_path, "container"))
		fd_userns = dup_cloexec(handler->nsfd[LXC_NS_USER]);
	else
		fd_userns = open_at(-EBADF, rootfs->mnt_opts.userns_path,
				    PROTECT_OPEN_WITH_TRAILING_SYMLINKS, 0, 0);
	if (fd_userns < 0)
		return syserror("Failed to open user namespace");

	path_source = lxc_storage_get_path(storage->src, storage->type);

	dfd_idmapped = create_detached_idmapped_mount(path_source, fd_userns, true,
						      mnt_opts->attr.attr_set,
						      mnt_opts->attr.attr_clr);
	if (dfd_idmapped < 0)
		return syserror("Failed to create detached idmapped mount");

	ret = lxc_abstract_unix_send_fds(handler->data_sock[0], &dfd_idmapped, 1, NULL, 0);
	if (ret < 0)
		return syserror("Failed to send detached idmapped mount fd");

	TRACE("Created detached idmapped mount %d", dfd_idmapped);
	return 0;
}

static int add_shmount_to_list(struct lxc_conf *conf)
{
	char new_mount[PATH_MAX];
	/* Offset for the leading '/' since the path_cont
	 * is absolute inside the container.
	 */
	int offset = 1, ret = -1;

	ret = strnprintf(new_mount, sizeof(new_mount),
		       "%s %s none bind,create=dir 0 0", conf->shmount.path_host,
		       conf->shmount.path_cont + offset);
	if (ret < 0)
		return -1;

	return add_elem_to_mount_list(new_mount, conf);
}

static int lxc_mount_auto_mounts(struct lxc_handler *handler, int flags)
{
	int i, ret;
	static struct {
		int match_mask;
		int match_flag;
		const char *source;
		const char *destination;
		const char *fstype;
		unsigned long flags;
		const char *options;
		bool requires_cap_net_admin;
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
		{ LXC_AUTO_PROC_MASK, LXC_AUTO_PROC_MIXED, "proc",                                           "%r/proc",                    "proc",  MS_NODEV|MS_NOEXEC|MS_NOSUID,                    NULL, false },
		/* proc/tty is used as a temporary placeholder for proc/sys/net which we'll move back in a few steps */
		{ LXC_AUTO_PROC_MASK, LXC_AUTO_PROC_MIXED, "%r/proc/sys/net",                                "%r/proc/tty",                NULL,    MS_BIND,                                         NULL, true, },
		{ LXC_AUTO_PROC_MASK, LXC_AUTO_PROC_MIXED, "%r/proc/sys",                                    "%r/proc/sys",                NULL,    MS_BIND,                                         NULL, false },
		{ LXC_AUTO_PROC_MASK, LXC_AUTO_PROC_MIXED, NULL,                                             "%r/proc/sys",                NULL,    MS_REMOUNT|MS_BIND|MS_RDONLY,                    NULL, false },
		{ LXC_AUTO_PROC_MASK, LXC_AUTO_PROC_MIXED, "%r/proc/tty",                                    "%r/proc/sys/net",            NULL,    MS_MOVE,                                         NULL, true  },
		{ LXC_AUTO_PROC_MASK, LXC_AUTO_PROC_MIXED, "%r/proc/sysrq-trigger",                          "%r/proc/sysrq-trigger",      NULL,    MS_BIND,                                         NULL, false },
		{ LXC_AUTO_PROC_MASK, LXC_AUTO_PROC_MIXED, NULL,                                             "%r/proc/sysrq-trigger",      NULL,    MS_REMOUNT|MS_BIND|MS_RDONLY,                    NULL, false },
		{ LXC_AUTO_PROC_MASK, LXC_AUTO_PROC_RW,    "proc",                                           "%r/proc",                    "proc",  MS_NODEV|MS_NOEXEC|MS_NOSUID,                    NULL, false },
		{ LXC_AUTO_SYS_MASK,  LXC_AUTO_SYS_RW,     "sysfs",                                          "%r/sys",                     "sysfs", 0,                                               NULL, false },
		{ LXC_AUTO_SYS_MASK,  LXC_AUTO_SYS_RO,     "sysfs",                                          "%r/sys",                     "sysfs", MS_RDONLY,                                       NULL, false },
		/* /proc/sys is used as a temporary staging directory for the read-write sysfs mount and unmounted after binding net */
		{ LXC_AUTO_SYS_MASK,  LXC_AUTO_SYS_MIXED,  "sysfs",                                          "%r/proc/sys",                "sysfs", MS_NOSUID|MS_NODEV|MS_NOEXEC,                    NULL, false },
		{ LXC_AUTO_SYS_MASK,  LXC_AUTO_SYS_MIXED,  "sysfs",                                          "%r/sys",                     "sysfs", MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC,          NULL, false },
		{ LXC_AUTO_SYS_MASK,  LXC_AUTO_SYS_MIXED,  "%r/proc/sys/devices/virtual/net",                "%r/sys/devices/virtual/net", NULL,    MS_BIND,                                         NULL, false },
		{ LXC_AUTO_SYS_MASK,  LXC_AUTO_SYS_MIXED,  "%r/proc/sys",                                    NULL,                         NULL,    0,                                               NULL, false },
		{ 0,                  0,                   NULL,                                             NULL,                         NULL,    0,                                               NULL, false }
	};
	struct lxc_conf *conf = handler->conf;
        struct lxc_rootfs *rootfs = &conf->rootfs;
        bool has_cap_net_admin;

        if (flags & LXC_AUTO_PROC_MASK) {
		if (rootfs->path) {
			/*
			 * Only unmount procfs if we have a separate rootfs so
			 * we can still access it in safe_mount() below.
			 */
			ret = strnprintf(rootfs->buf, sizeof(rootfs->buf), "%s/proc",
					rootfs->path ? rootfs->mount : "");
			if (ret < 0)
				return ret_errno(EIO);

			ret = umount2(rootfs->buf, MNT_DETACH);
			if (ret)
				SYSDEBUG("Tried to ensure procfs is unmounted");
		}

		ret = mkdirat(rootfs->dfd_mnt, "proc" , S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
		if (ret < 0 && errno != EEXIST)
			return syserror("Failed to create procfs mountpoint under %d", rootfs->dfd_mnt);

		TRACE("Created procfs mountpoint under %d", rootfs->dfd_mnt);
	}

	if (flags & LXC_AUTO_SYS_MASK) {
		if (rootfs->path) {
			/*
			 * Only unmount sysfs if we have a separate rootfs so
			 * we can still access it in safe_mount() below.
			 */
			ret = strnprintf(rootfs->buf, sizeof(rootfs->buf), "%s/sys",
					rootfs->path ? rootfs->mount : "");
			if (ret < 0)
				return ret_errno(EIO);

			ret = umount2(rootfs->buf, MNT_DETACH);
			if (ret)
				SYSDEBUG("Tried to ensure sysfs is unmounted");
		}

		ret = mkdirat(rootfs->dfd_mnt, "sys" , S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
		if (ret < 0 && errno != EEXIST)
			return syserror("Failed to create sysfs mountpoint under %d", rootfs->dfd_mnt);

		TRACE("Created sysfs mountpoint under %d", rootfs->dfd_mnt);
	}

        has_cap_net_admin = lxc_wants_cap(CAP_NET_ADMIN, conf);
        for (i = 0; default_mounts[i].match_mask; i++) {
		__do_free char *destination = NULL, *source = NULL;
		unsigned long mflags = default_mounts[i].flags;

		if ((flags & default_mounts[i].match_mask) != default_mounts[i].match_flag)
			continue;

		if (default_mounts[i].source) {
			/* will act like strdup if %r is not present */
			source = lxc_string_replace("%r", rootfs->path ? rootfs->mount : "", default_mounts[i].source);
			if (!source)
				return syserror_set(-ENOMEM, "Failed to create source path");
		}

		if (!has_cap_net_admin && default_mounts[i].requires_cap_net_admin) {
			TRACE("Container does not have CAP_NET_ADMIN. Skipping \"%s\" mount", default_mounts[i].source ?: "(null)");
			continue;
		}

		if (!default_mounts[i].destination) {
			ret = umount2(source, MNT_DETACH);
			if (ret < 0)
				return log_error_errno(-1, errno,
						       "Failed to unmount \"%s\"",
						       source);
			TRACE("Unmounted automount \"%s\"", source);
			continue;
		}

		/* will act like strdup if %r is not present */
		destination = lxc_string_replace("%r", rootfs->path ? rootfs->mount : "", default_mounts[i].destination);
		if (!destination)
			return syserror_set(-ENOMEM, "Failed to create target path");

		ret = safe_mount(source, destination,
				 default_mounts[i].fstype,
				 mflags,
				 default_mounts[i].options,
				 rootfs->path ? rootfs->mount : NULL);
		if (ret < 0) {
			if (errno != ENOENT)
				return syserror("Failed to mount \"%s\" on \"%s\" with flags %lu", source, destination, mflags);

			INFO("Mount source or target for \"%s\" on \"%s\" does not exist. Skipping", source, destination);
			continue;
		}

		if (mflags & MS_REMOUNT)
			TRACE("Remounted automount \"%s\" on \"%s\" %s with flags %lu", source, destination, (mflags & MS_RDONLY) ? "read-only" : "read-write", mflags);
		else
			TRACE("Mounted automount \"%s\" on \"%s\" %s with flags %lu", source, destination, (mflags & MS_RDONLY) ? "read-only" : "read-write", mflags);
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
		if ((cg_flags == LXC_AUTO_CGROUP_NOSPEC) || (cg_flags == LXC_AUTO_CGROUP_FULL_NOSPEC)) {
			if (cg_flags == LXC_AUTO_CGROUP_NOSPEC)
				cg_flags = has_cap(CAP_SYS_ADMIN, conf)
					       ? LXC_AUTO_CGROUP_RW
					       : LXC_AUTO_CGROUP_MIXED;
			else
				cg_flags = has_cap(CAP_SYS_ADMIN, conf)
					       ? LXC_AUTO_CGROUP_FULL_RW
					       : LXC_AUTO_CGROUP_FULL_MIXED;
		}

		if (flags & LXC_AUTO_CGROUP_FORCE)
			cg_flags |= LXC_AUTO_CGROUP_FORCE;

		if (!handler->cgroup_ops->mount(handler->cgroup_ops, handler, cg_flags))
			return log_error_errno(-1, errno, "Failed to mount \"/sys/fs/cgroup\"");
	}

	if (flags & LXC_AUTO_SHMOUNTS_MASK) {
		ret = add_shmount_to_list(conf);
		if (ret < 0)
			return log_error(-1, "Failed to add shmount entry to container config");
	}

	return 0;
}

static int setup_utsname(struct utsname *utsname)
{
	int ret;

	if (!utsname)
		return 0;

	ret = sethostname(utsname->nodename, strlen(utsname->nodename));
	if (ret < 0)
		return log_error_errno(-1, errno, "Failed to set the hostname to \"%s\"",
				       utsname->nodename);

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
	for (size_t i = 0; i < sizeof(dev_symlinks) / sizeof(dev_symlinks[0]); i++) {
		int ret;
		struct stat s;
		const struct dev_symlinks *d = &dev_symlinks[i];

		/*
		 * Stat the path first. If we don't get an error accept it as
		 * is and don't try to create it
		 */
		ret = fstatat(rootfs->dfd_dev, d->name, &s, 0);
		if (ret == 0)
			continue;

		ret = symlinkat(d->oldpath, rootfs->dfd_dev, d->name);
		if (ret) {
			switch (errno) {
			case EROFS:
				WARN("Failed to create \"%s\" on read-only filesystem", d->name);
				__fallthrough;
			case EEXIST:
				break;
			default:
				return log_error_errno(-errno, errno, "Failed to create \"%s\"", d->name);
			}
		}
	}

	return 0;
}

/* Build a space-separate list of ptys to pass to systemd. */
static bool append_ttyname(struct lxc_tty_info *ttys, char *tty_name)
{
	char *tty_names, *buf;
	size_t size;

	if (!tty_name)
		return false;

	size = strlen(tty_name) + 1;
	if (ttys->tty_names)
		size += strlen(ttys->tty_names) + 1;

	buf = realloc(ttys->tty_names, size);
	if (!buf)
		return false;
	tty_names = buf;

	if (ttys->tty_names)
		(void)strlcat(buf, " ", size);
	else
		buf[0] = '\0';
	(void)strlcat(buf, tty_name, size);
	ttys->tty_names = tty_names;
	return true;
}

static int open_ttymnt_at(int dfd, const char *path)
{
	int fd;

	fd = open_at(dfd, path,
		     PROTECT_OPEN | O_CREAT | O_EXCL,
		     PROTECT_LOOKUP_BENEATH,
		     0);
	if (fd < 0) {
		if (errno != ENXIO && errno != EEXIST)
			return syserror("Failed to create \"%d/\%s\"", dfd, path);

		SYSINFO("Failed to create \"%d/\%s\"", dfd, path);
		fd = open_at(dfd, path,
			     PROTECT_OPATH_FILE,
			     PROTECT_LOOKUP_BENEATH,
			     0);
	}

	return fd;
}

static int lxc_setup_ttys(struct lxc_conf *conf)
{
	int ret;
	struct lxc_rootfs *rootfs = &conf->rootfs;
	const struct lxc_tty_info *ttys = &conf->ttys;
	char *ttydir = ttys->dir;

	if (!conf->rootfs.path)
		return 0;

	for (size_t i = 0; i < ttys->max; i++) {
		__do_close int fd_to = -EBADF;
		struct lxc_terminal_info *tty = &ttys->tty[i];

		if (ttydir) {
			char *tty_name, *tty_path;

			ret = strnprintf(rootfs->buf, sizeof(rootfs->buf),
				       "/dev/%s/tty%zu", ttydir, i + 1);
			if (ret < 0)
				return ret_errno(-EIO);

			tty_path = &rootfs->buf[STRLITERALLEN("/dev/")];
			tty_name = tty_path + strlen(ttydir) + 1;

			/* create bind-mount target */
			fd_to = open_ttymnt_at(rootfs->dfd_dev, tty_path);
			if (fd_to < 0)
				return log_error_errno(-errno, errno,
						       "Failed to create tty mount target %d(%s)",
						       rootfs->dfd_dev, tty_path);

			ret = unlinkat(rootfs->dfd_dev, tty_name, 0);
			if (ret < 0 && errno != ENOENT)
				return log_error_errno(-errno, errno,
						       "Failed to unlink %d(%s)",
						       rootfs->dfd_dev, tty_name);

			if (can_use_mount_api())
				ret = fd_bind_mount(tty->pty, "",
						    PROTECT_OPATH_FILE,
						    PROTECT_LOOKUP_BENEATH_XDEV,
						    fd_to, "",
						    PROTECT_OPATH_FILE,
						    PROTECT_LOOKUP_BENEATH_XDEV,
						    0,
						    0,
						    0,
						    false);
			else
				ret = mount_fd(tty->pty, fd_to, "none", MS_BIND, 0);
			if (ret < 0)
				return log_error_errno(-errno, errno,
						       "Failed to bind mount \"%s\" onto \"%s\"",
						       tty->name, rootfs->buf);
			DEBUG("Bind mounted \"%s\" onto \"%s\"", tty->name, rootfs->buf);

			ret = symlinkat(tty_path, rootfs->dfd_dev, tty_name);
			if (ret < 0)
				return log_error_errno(-errno, errno,
						       "Failed to create symlink \"%d(%s)\" -> \"%d(%s)\"",
						       rootfs->dfd_dev, tty_name,
						       rootfs->dfd_dev, tty_path);
		} else {
			ret = strnprintf(rootfs->buf, sizeof(rootfs->buf), "tty%zu", i + 1);
			if (ret < 0)
				return ret_errno(-EIO);

			/* If we populated /dev, then we need to create /dev/tty<idx>. */
			fd_to = open_ttymnt_at(rootfs->dfd_dev, rootfs->buf);
			if (fd_to < 0)
				return log_error_errno(-errno, errno,
						       "Failed to create tty mount target %d(%s)",
						       rootfs->dfd_dev, rootfs->buf);

			if (can_use_mount_api())
				ret = fd_bind_mount(tty->pty, "",
						    PROTECT_OPATH_FILE,
						    PROTECT_LOOKUP_BENEATH_XDEV,
						    fd_to, "",
						    PROTECT_OPATH_FILE,
						    PROTECT_LOOKUP_BENEATH,
						    0,
						    0,
						    0,
						    false);
			else
				ret = mount_fd(tty->pty, fd_to, "none", MS_BIND, 0);
			if (ret < 0)
				return log_error_errno(-errno, errno,
						       "Failed to bind mount \"%s\" onto \"%s\"",
						       tty->name, rootfs->buf);
			DEBUG("Bind mounted \"%s\" onto \"%s\"", tty->name, rootfs->buf);
		}

		if (!append_ttyname(&conf->ttys, tty->name))
			return log_error(-1, "Error setting up container_ttys string");
	}

	INFO("Finished setting up %zu /dev/tty<N> device(s)", ttys->max);
	return 0;
}

define_cleanup_function(struct lxc_tty_info *, lxc_delete_tty);

static int lxc_allocate_ttys(struct lxc_conf *conf)
{
	call_cleaner(lxc_delete_tty) struct lxc_tty_info *ttys = &conf->ttys;
	int ret;

	/* no tty in the configuration */
	if (ttys->max == 0)
		return 0;

	ttys->tty = zalloc(sizeof(struct lxc_terminal_info) * ttys->max);
	if (!ttys->tty)
		return -ENOMEM;

	for (size_t i = 0; i < conf->ttys.max; i++) {
		struct lxc_terminal_info *tty = &ttys->tty[i];

		ret = lxc_devpts_terminal(conf->devpts_fd, &tty->ptx,
					  &tty->pty, &tty->pty_nr, false);
		if (ret < 0) {
			conf->ttys.max = i;
			return syserror_set(-ENOTTY, "Failed to create tty %zu", i);
		}
		ret = strnprintf(tty->name, sizeof(tty->name), "pts/%d", tty->pty_nr);
		if (ret < 0)
			return syserror("Failed to create tty %zu", i);

		DEBUG("Created tty with ptx fd %d and pty fd %d and index %d",
		      tty->ptx, tty->pty, tty->pty_nr);
		tty->busy = -1;
	}

	INFO("Finished creating %zu tty devices", ttys->max);
	move_ptr(ttys);
	return 0;
}

void lxc_delete_tty(struct lxc_tty_info *ttys)
{
	if (!ttys || !ttys->tty)
		return;

	for (size_t i = 0; i < ttys->max; i++) {
		struct lxc_terminal_info *tty = &ttys->tty[i];
		close_prot_errno_disarm(tty->ptx);
		close_prot_errno_disarm(tty->pty);
	}

	free_disarm(ttys->tty);
}

static int __lxc_send_ttys_to_parent(struct lxc_handler *handler)
{
	int ret = -1;
	struct lxc_conf *conf = handler->conf;
	struct lxc_tty_info *ttys = &conf->ttys;
	int sock = handler->data_sock[0];

	if (ttys->max == 0)
		return 0;

	for (size_t i = 0; i < ttys->max; i++) {
		int ttyfds[2];
		struct lxc_terminal_info *tty = &ttys->tty[i];

		ttyfds[0] = tty->ptx;
		ttyfds[1] = tty->pty;

		ret = lxc_abstract_unix_send_fds(sock, ttyfds, 2, NULL, 0);
		if (ret < 0)
			break;

		TRACE("Sent tty \"%s\" with ptx fd %d and pty fd %d to parent",
		      tty->name, tty->ptx, tty->pty);
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

	if (!conf->is_execute) {
		ret = lxc_setup_ttys(conf);
		if (ret < 0) {
			ERROR("Failed to setup ttys");
			goto on_error;
		}
	}

	if (conf->ttys.tty_names) {
		ret = setenv("container_ttys", conf->ttys.tty_names, 1);
		if (ret < 0) {
			SYSERROR("Failed to set \"container_ttys=%s\"", conf->ttys.tty_names);
			goto on_error;
		}
		TRACE("Set \"container_ttys=%s\"", conf->ttys.tty_names);
	}

	return 0;

on_error:
	lxc_delete_tty(&conf->ttys);

	return -1;
}

static int lxc_send_ttys_to_parent(struct lxc_handler *handler)
{
	int ret = -1;

	ret = __lxc_send_ttys_to_parent(handler);
	lxc_delete_tty(&handler->conf->ttys);
	return ret;
}

/* Just create a path for /dev under $lxcpath/$name and in rootfs If we hit an
 * error, log it but don't fail yet.
 */
static int mount_autodev(const char *name, const struct lxc_rootfs *rootfs,
			 int autodevtmpfssize, const char *lxcpath)
{
	__do_close int fd_fs = -EBADF;
	const char *path = rootfs->path ? rootfs->mount : NULL;
	size_t tmpfs_size = (autodevtmpfssize != 0) ? autodevtmpfssize : 500000;
	int ret;
	mode_t cur_mask;
        char mount_options[128];

	INFO("Preparing \"/dev\"");

	cur_mask = umask(S_IXUSR | S_IXGRP | S_IXOTH);
	ret = mkdirat(rootfs->dfd_mnt, "dev" , S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
	if (ret < 0 && errno != EEXIST) {
		SYSERROR("Failed to create \"/dev\" directory");
		ret = -errno;
		goto reset_umask;
	}

	if (can_use_mount_api()) {
		fd_fs = fs_prepare("tmpfs", -EBADF, "", 0, 0);
		if (fd_fs < 0)
			return log_error_errno(-errno, errno, "Failed to prepare filesystem context for tmpfs");

		sprintf(mount_options, "%zu", tmpfs_size);

		ret = fs_set_property(fd_fs, "mode", "0755");
		if (ret < 0)
			return log_error_errno(-errno, errno, "Failed to mount tmpfs onto %d(dev)", fd_fs);

		ret = fs_set_property(fd_fs, "size", mount_options);
		if (ret < 0)
			return log_error_errno(-errno, errno, "Failed to mount tmpfs onto %d(dev)", fd_fs);

		ret = fs_attach(fd_fs, rootfs->dfd_mnt, "dev",
				PROTECT_OPATH_DIRECTORY,
				PROTECT_LOOKUP_BENEATH_XDEV, 0);
	} else {
		__do_free char *fallback_path = NULL;

		sprintf(mount_options, "size=%zu,mode=755", tmpfs_size);
		DEBUG("Using mount options: %s", mount_options);

		if (path) {
			fallback_path = must_make_path(path, "/dev", NULL);
			ret = safe_mount("none", fallback_path, "tmpfs", 0, mount_options, path);
		} else {
			ret = safe_mount("none", "dev", "tmpfs", 0, mount_options, NULL);
		}
	}
	if (ret < 0) {
		SYSERROR("Failed to mount tmpfs on \"%s\"", path);
		goto reset_umask;
	}

	/* If we are running on a devtmpfs mapping, dev/pts may already exist.
	 * If not, then create it and exit if that fails...
	 */
	ret = mkdirat(rootfs->dfd_mnt, "dev/pts", S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
	if (ret < 0 && errno != EEXIST) {
		SYSERROR("Failed to create directory \"dev/pts\"");
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

static int lxc_fill_autodev(struct lxc_rootfs *rootfs)
{
	int ret;
	mode_t cmask;
	int use_mknod = LXC_DEVNODE_MKNOD;

	if (rootfs->dfd_dev < 0)
		return log_info(0, "No /dev directory found, skipping setup");

	INFO("Populating \"/dev\"");

	cmask = umask(S_IXUSR | S_IXGRP | S_IXOTH);
	for (size_t i = 0; i < sizeof(lxc_devices) / sizeof(lxc_devices[0]); i++) {
		const struct lxc_device_node *device = &lxc_devices[i];

		if (use_mknod >= LXC_DEVNODE_MKNOD) {
			ret = mknodat(rootfs->dfd_dev, device->name, device->mode, makedev(device->maj, device->min));
			if (ret == 0 || (ret < 0 && errno == EEXIST)) {
				DEBUG("Created device node \"%s\"", device->name);
			} else if (ret < 0) {
				if (errno != EPERM)
					return log_error_errno(-1, errno, "Failed to create device node \"%s\"", device->name);

				use_mknod = LXC_DEVNODE_BIND;
			}

			/* Device nodes are fully useable. */
			if (use_mknod == LXC_DEVNODE_OPEN)
				continue;

			if (use_mknod == LXC_DEVNODE_MKNOD) {
				__do_close int fd = -EBADF;
				/* See
				 * - https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=55956b59df336f6738da916dbb520b6e37df9fbd
				 * - https://lists.linuxfoundation.org/pipermail/containers/2018-June/039176.html
				 */
				fd = open_at(rootfs->dfd_dev, device->name, PROTECT_OPEN, PROTECT_LOOKUP_BENEATH, 0);
				if (fd >= 0) {
					/* Device nodes are fully useable. */
					use_mknod = LXC_DEVNODE_OPEN;
					continue;
				}

				SYSTRACE("Failed to open \"%s\" device", device->name);
				/* Device nodes are only partially useable. */
				use_mknod = LXC_DEVNODE_PARTIAL;
			}
		}

		if (use_mknod != LXC_DEVNODE_PARTIAL) {
			/* If we are dealing with partially functional device
			 * nodes the prio mknod() call will have created the
			 * device node so we can use it as a bind-mount target.
			 */
			ret = mknodat(rootfs->dfd_dev, device->name, S_IFREG | 0000, 0);
			if (ret < 0 && errno != EEXIST)
				return log_error_errno(-1, errno, "Failed to create file \"%s\"", device->name);
		}

		/* Fallback to bind-mounting the device from the host. */
		ret = strnprintf(rootfs->buf, sizeof(rootfs->buf), "dev/%s", device->name);
		if (ret < 0)
			return ret_errno(EIO);

		if (can_use_mount_api()) {
			ret = fd_bind_mount(rootfs->dfd_host, rootfs->buf,
					    PROTECT_OPATH_FILE,
					    PROTECT_LOOKUP_BENEATH_XDEV,
					    rootfs->dfd_dev, device->name,
					    PROTECT_OPATH_FILE,
					    PROTECT_LOOKUP_BENEATH,
					    0,
					    0,
					    0,
					    false);
		} else {
			char path[PATH_MAX];

			ret = strnprintf(rootfs->buf, sizeof(rootfs->buf), "/dev/%s", device->name);
			if (ret < 0)
				return ret_errno(EIO);

			ret = strnprintf(path, sizeof(path), "%s/dev/%s", get_rootfs_mnt(rootfs), device->name);
			if (ret < 0)
				return log_error(-1, "Failed to create device path for %s", device->name);

			ret = safe_mount(rootfs->buf, path, 0, MS_BIND, NULL, get_rootfs_mnt(rootfs));
			if (ret < 0)
				return log_error_errno(-1, errno, "Failed to bind mount host device node \"%s\" to \"%s\"", rootfs->buf, path);

			DEBUG("Bind mounted host device node \"%s\" to \"%s\"", rootfs->buf, path);
			continue;
		}
		DEBUG("Bind mounted host device %d(%s) to %d(%s)", rootfs->dfd_host, rootfs->buf, rootfs->dfd_dev, device->name);
	}
	(void)umask(cmask);

	INFO("Populated \"/dev\"");
	return 0;
}

static int lxc_mount_rootfs(struct lxc_rootfs *rootfs)
{
	int ret;

	if (!rootfs->path) {
		ret = mount("", "/", NULL, MS_SLAVE | MS_REC, 0);
		if (ret < 0)
			return log_error_errno(-1, errno, "Failed to recursively turn root mount tree into dependent mount");

		rootfs->dfd_mnt = open_at(-EBADF, "/", PROTECT_OPATH_DIRECTORY, PROTECT_LOOKUP_ABSOLUTE, 0);
		if (rootfs->dfd_mnt < 0)
			return -errno;

		return log_trace(0, "Container doesn't use separate rootfs. Opened host's rootfs");
	}

	ret = access(rootfs->mount, F_OK);
	if (ret != 0)
		return log_error_errno(-1, errno, "Failed to access to \"%s\". Check it is present",
				       rootfs->mount);

	ret = rootfs->storage->ops->mount(rootfs->storage);
	if (ret < 0)
		return log_error(-1, "Failed to mount rootfs \"%s\" onto \"%s\" with options \"%s\"",
				 rootfs->path, rootfs->mount,
				 rootfs->mnt_opts.raw_options ? rootfs->mnt_opts.raw_options : "(null)");

	DEBUG("Mounted rootfs \"%s\" onto \"%s\" with options \"%s\"",
	      rootfs->path, rootfs->mount,
	      rootfs->mnt_opts.raw_options ? rootfs->mnt_opts.raw_options : "(null)");

	rootfs->dfd_mnt = open_at(-EBADF, rootfs->mount, PROTECT_OPATH_DIRECTORY, PROTECT_LOOKUP_ABSOLUTE_XDEV, 0);
	if (rootfs->dfd_mnt < 0)
		return -errno;

	return log_trace(0, "Container uses separate rootfs. Opened container's rootfs");
}

static bool lxc_rootfs_overmounted(struct lxc_rootfs *rootfs)
{
	__do_close int fd_rootfs = -EBADF;

	if (!rootfs->path)
		fd_rootfs = open_at(-EBADF, "/", PROTECT_OPATH_DIRECTORY, PROTECT_LOOKUP_ABSOLUTE, 0);
	else
		fd_rootfs = open_at(-EBADF, rootfs->mount, PROTECT_OPATH_DIRECTORY, PROTECT_LOOKUP_ABSOLUTE_XDEV, 0);
	if (fd_rootfs < 0)
		return true;

	if (!same_file_lax(rootfs->dfd_mnt, fd_rootfs))
		return syswarn_ret(true, "Rootfs seems to have changed after setting up mounts");

	return false;
}

static int lxc_chroot(const struct lxc_rootfs *rootfs)
{
	__do_free char *nroot = NULL;
	int i, ret;
	char *root = rootfs->mount;

	nroot = realpath(root, NULL);
	if (!nroot)
		return log_error_errno(-1, errno, "Failed to resolve \"%s\"", root);

	ret = chdir("/");
	if (ret < 0)
		return -1;

	/* We could use here MS_MOVE, but in userns this mount is locked and
	 * can't be moved.
	 */
	ret = mount(nroot, "/", NULL, MS_REC | MS_BIND, NULL);
	if (ret < 0)
		return log_error_errno(-1, errno, "Failed to mount \"%s\" onto \"/\" as MS_REC | MS_BIND", nroot);

	ret = mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);
	if (ret < 0)
		return log_error_errno(-1, errno, "Failed to remount \"/\"");

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
		__do_fclose FILE *f = NULL;
		__do_free char *line = NULL;
		char *slider1, *slider2;
		int progress = 0;
		size_t len = 0;

		f = fopen("./proc/self/mountinfo", "re");
		if (!f)
			return log_error_errno(-1, errno, "Failed to open \"/proc/self/mountinfo\"");

		while (getline(&line, &len, f) > 0) {
			for (slider1 = line, i = 0; slider1 && i < 4; i++)
				slider1 = strchr(slider1 + 1, ' ');

			if (!slider1)
				continue;

			slider2 = strchr(slider1 + 1, ' ');
			if (!slider2)
				continue;

			*slider2 = '\0';
			*slider1 = '.';

			if (strequal(slider1 + 1, "/"))
				continue;

			if (strequal(slider1 + 1, "/proc"))
				continue;

			ret = umount2(slider1, MNT_DETACH);
			if (ret == 0)
				progress++;
		}

		if (!progress)
			break;
	}

	/* This also can be skipped if a container uses userns. */
	(void)umount2("./proc", MNT_DETACH);

	/* It is weird, but chdir("..") moves us in a new root */
	ret = chdir("..");
	if (ret < 0)
		return log_error_errno(-1, errno, "Failed to chdir(\"..\")");

	ret = chroot(".");
	if (ret < 0)
		return log_error_errno(-1, errno, "Failed to chroot(\".\")");

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
static int lxc_pivot_root(const struct lxc_rootfs *rootfs)
{
	__do_close int fd_oldroot = -EBADF;
	int ret;

	fd_oldroot = open_at(-EBADF, "/", PROTECT_OPATH_DIRECTORY, PROTECT_LOOKUP_ABSOLUTE, 0);
	if (fd_oldroot < 0)
		return log_error_errno(-1, errno, "Failed to open old root directory");

	/* change into new root fs */
	ret = fchdir(rootfs->dfd_mnt);
	if (ret < 0)
		return log_error_errno(-errno, errno, "Failed to change into new root directory \"%s\"", rootfs->mount);

	/* pivot_root into our new root fs */
	ret = pivot_root(".", ".");
	if (ret < 0)
		return log_error_errno(-errno, errno, "Failed to pivot into new root directory \"%s\"", rootfs->mount);

	/* At this point the old-root is mounted on top of our new-root. To
	 * unmounted it we must not be chdir'd into it, so escape back to
	 * old-root.
	 */
	ret = fchdir(fd_oldroot);
	if (ret < 0)
		return log_error_errno(-errno, errno, "Failed to enter old root directory");

	/*
	 * Unprivileged containers will have had all their mounts turned into
	 * dependent mounts when the container was created. But for privileged
	 * containers we need to turn the old root mount tree into a dependent
	 * mount tree to prevent propagating mounts and umounts into the host
	 * mount namespace.
	 */
	ret = mount("", ".", "", MS_SLAVE | MS_REC, NULL);
	if (ret < 0)
		return log_error_errno(-errno, errno, "Failed to recursively turn old root mount tree into dependent mount");

	ret = umount2(".", MNT_DETACH);
	if (ret < 0)
		return log_error_errno(-errno, errno, "Failed to detach old root directory");

	ret = fchdir(rootfs->dfd_mnt);
	if (ret < 0)
		return log_error_errno(-errno, errno, "Failed to re-enter new root directory \"%s\"", rootfs->mount);

	/*
	 * Finally, we turn the rootfs into a shared mount. Note, that this
	 * doesn't reestablish mount propagation with the hosts mount
	 * namespace. Instead we'll create a new peer group.
	 *
	 * We're doing this because most workloads do rely on the rootfs being
	 * a shared mount. For example, systemd daemon like sytemd-udevd run in
	 * their own mount namespace. Their mount namespace has been made a
	 * dependent mount (MS_SLAVE) with the host rootfs as it's dominating
	 * mount. This means new mounts on the host propagate into the
	 * respective services.
	 *
	 * This is broken if we leave the container's rootfs a dependent mount.
	 * In which case both the container's rootfs and the service's rootfs
	 * will be dependent mounts with the host's rootfs as their dominating
	 * mount. So if you were to mount over the rootfs from the host it
	 * would not just propagate into the container's mount namespace it
	 * would also propagate into the service. That's nonsense semantics for
	 * nearly all relevant use-cases. Instead, establish the container's
	 * rootfs as a separate peer group mirroring the behavior on the host.
	 */
	ret = mount("", ".", "", MS_SHARED | MS_REC, NULL);
	if (ret < 0)
		return log_error_errno(-errno, errno, "Failed to turn new root mount tree into shared mount tree");

	TRACE("Changed into new rootfs \"%s\"", rootfs->mount);
	return 0;
}

static int lxc_setup_rootfs_switch_root(const struct lxc_rootfs *rootfs)
{
	if (!rootfs->path)
		return log_debug(0, "Container does not have a rootfs");

	if (detect_ramfs_rootfs())
		return lxc_chroot(rootfs);

	return lxc_pivot_root(rootfs);
}

static const struct id_map *find_mapped_nsid_entry(const struct lxc_conf *conf,
						   unsigned id,
						   enum idtype idtype)
{
	struct id_map *map;
	struct id_map *retmap = NULL;

	/* Shortcut for container's root mappings. */
	if (id == 0) {
		if (idtype == ID_TYPE_UID)
			return conf->root_nsuid_map;

		if (idtype == ID_TYPE_GID)
			return conf->root_nsgid_map;
	}

	list_for_each_entry(map, &conf->id_map, head) {
		if (map->idtype != idtype)
			continue;

		if (id >= map->nsid && id < map->nsid + map->range) {
			retmap = map;
			break;
		}
	}

	return retmap;
}

static int lxc_recv_devpts_from_child(struct lxc_handler *handler)
{
	int ret;

	if (handler->conf->pty_max <= 0)
		return 0;

	ret = lxc_abstract_unix_recv_one_fd(handler->data_sock[1],
					    &handler->conf->devpts_fd,
					    &handler->conf->devpts_fd,
					    sizeof(handler->conf->devpts_fd));
	if (ret < 0)
		return log_error_errno(-1, errno, "Failed to receive devpts fd from child");

	TRACE("Received devpts file descriptor %d from child", handler->conf->devpts_fd);
	return 0;
}

static int lxc_setup_devpts_child(struct lxc_handler *handler)
{
	__do_close int devpts_fd = -EBADF, fd_fs = -EBADF;
	struct lxc_conf *conf = handler->conf;
	struct lxc_rootfs *rootfs = &conf->rootfs;
	size_t pty_max = conf->pty_max;
	int ret;

	pty_max += conf->ttys.max;
	if (pty_max <= 0)
		return log_debug(0, "No new devpts instance will be mounted since no pts devices are required");

	ret = strnprintf(rootfs->buf, sizeof(rootfs->buf),
			 "/proc/self/fd/%d/pts", rootfs->dfd_dev);
	if (ret < 0)
		return syserror("Failed to create path");

	(void)umount2(rootfs->buf, MNT_DETACH);

	/* Create mountpoint for devpts instance. */
	ret = mkdirat(rootfs->dfd_dev, "pts", 0755);
	if (ret < 0 && errno != EEXIST)
		return log_error_errno(-1, errno, "Failed to create \"/dev/pts\" directory");

	if (can_use_mount_api()) {
		fd_fs = fs_prepare("devpts", -EBADF, "", 0, 0);
		if (fd_fs < 0)
			return syserror("Failed to prepare filesystem context for devpts");

		ret = fs_set_property(fd_fs, "source", "devpts");
		if (ret < 0)
			SYSTRACE("Failed to set \"source=devpts\" on devpts filesystem context %d", fd_fs);

		ret = fs_set_property(fd_fs, "gid", "5");
		if (ret < 0)
			SYSTRACE("Failed to set \"gid=5\" on devpts filesystem context %d", fd_fs);

		ret = fs_set_flag(fd_fs, "newinstance");
		if (ret < 0)
			return syserror("Failed to set \"newinstance\" property on devpts filesystem context %d", fd_fs);

		ret = fs_set_property(fd_fs, "ptmxmode", "0666");
		if (ret < 0)
			return syserror("Failed to set \"ptmxmode=0666\" property on devpts filesystem context %d", fd_fs);

		ret = fs_set_property(fd_fs, "mode", "0620");
		if (ret < 0)
			return syserror("Failed to set \"mode=0620\" property on devpts filesystem context %d", fd_fs);

		ret = fs_set_property(fd_fs, "max", fdstr(pty_max));
		if (ret < 0)
			return syserror("Failed to set \"max=%zu\" property on devpts filesystem context %d", conf->pty_max, fd_fs);

		ret = fsconfig(fd_fs, FSCONFIG_CMD_CREATE, NULL, NULL, 0);
		if (ret < 0)
			return syserror("Failed to finalize filesystem context %d", fd_fs);

		devpts_fd = fsmount(fd_fs, FSMOUNT_CLOEXEC, MOUNT_ATTR_NOSUID | MOUNT_ATTR_NOEXEC);
		if (devpts_fd < 0)
			return syserror("Failed to create new mount for filesystem context %d", fd_fs);
		TRACE("Created detached devpts mount %d", devpts_fd);

		ret = move_mount(devpts_fd, "", rootfs->dfd_dev, "pts", MOVE_MOUNT_F_EMPTY_PATH);
		if (ret)
			return syserror("Failed to attach devpts mount %d to %d/pts", conf->devpts_fd, rootfs->dfd_dev);

		DEBUG("Attached detached devpts mount %d to %d/pts", devpts_fd, rootfs->dfd_dev);
	} else {
		char **opts;
		char devpts_mntopts[256];
		char *mntopt_sets[5];
		char default_devpts_mntopts[256] = "gid=5,newinstance,ptmxmode=0666,mode=0620";

		/*
		 * Fallback codepath in case the new mount API can't be used to
		 * create detached mounts.
		 */

		ret = strnprintf(devpts_mntopts, sizeof(devpts_mntopts), "%s,max=%zu",
				default_devpts_mntopts, pty_max);
		if (ret < 0)
			return -1;

		/* Create mountpoint for devpts instance. */
		ret = mkdirat(rootfs->dfd_dev, "pts", 0755);
		if (ret < 0 && errno != EEXIST)
			return log_error_errno(-1, errno, "Failed to create \"/dev/pts\" directory");

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
			ret = mount_at(rootfs->dfd_dev, "", 0,
				       rootfs->dfd_dev, "pts", PROTECT_LOOKUP_BENEATH,
				       "devpts", MS_NOSUID | MS_NOEXEC, *opts);
			if (ret == 0)
				break;
		}
		if (ret < 0)
			return log_error_errno(-1, errno, "Failed to mount new devpts instance");

		devpts_fd = open_at(rootfs->dfd_dev, "pts", PROTECT_OPATH_DIRECTORY, PROTECT_LOOKUP_BENEATH_XDEV, 0);
		if (devpts_fd < 0) {
			devpts_fd = -EBADF;
			TRACE("Failed to create detached devpts mount");
		}

		DEBUG("Mounted new devpts instance with options \"%s\"", *opts);
	}

	handler->conf->devpts_fd = move_fd(devpts_fd);

	/*
	 * In order to allocate terminal devices the devpts filesystem will
	 * have to be attached to the filesystem at least ones in the new mount
	 * api. The reason is lengthy but the gist is that until the new mount
	 * has been attached to the filesystem it is a detached mount with an
	 * anonymous mount mamespace attached to it for which the kernel
	 * refuses certain operations.
	 * We end up here if the user has requested to allocate tty devices
	 * while not requestig pty devices be made available to the container.
	 * We only need the devpts_fd to allocate tty devices.
	 */
	if (conf->pty_max <= 0)
		return 0;

	/* Remove any pre-existing /dev/ptmx file. */
	ret = unlinkat(rootfs->dfd_dev, "ptmx", 0);
	if (ret < 0) {
		if (errno != ENOENT)
			return log_error_errno(-1, errno, "Failed to remove existing \"/dev/ptmx\" file");
	} else {
		DEBUG("Removed existing \"/dev/ptmx\" file");
	}

	/* Create placeholder /dev/ptmx file as bind mountpoint for /dev/pts/ptmx. */
	ret = mknodat(rootfs->dfd_dev, "ptmx", S_IFREG | 0000, 0);
	if (ret < 0 && errno != EEXIST)
		return log_error_errno(-1, errno, "Failed to create \"/dev/ptmx\" file as bind mount target");
	DEBUG("Created \"/dev/ptmx\" file as bind mount target");

	/* Main option: use a bind-mount to please AppArmor  */
	ret = mount_at(rootfs->dfd_dev, "pts/ptmx", (PROTECT_LOOKUP_BENEATH_WITH_SYMLINKS & ~RESOLVE_NO_XDEV),
		       rootfs->dfd_dev, "ptmx", (PROTECT_LOOKUP_BENEATH_WITH_SYMLINKS & ~RESOLVE_NO_XDEV),
		       NULL, MS_BIND, NULL);
	if (!ret)
		return log_debug(0, "Bind mounted \"/dev/pts/ptmx\" to \"/dev/ptmx\"");
	else
		/* Fallthrough and try to create a symlink. */
		ERROR("Failed to bind mount \"/dev/pts/ptmx\" to \"/dev/ptmx\"");

	/* Remove the placeholder /dev/ptmx file we created above. */
	ret = unlinkat(rootfs->dfd_dev, "ptmx", 0);
	if (ret < 0)
		return log_error_errno(-1, errno, "Failed to remove existing \"/dev/ptmx\"");

	/* Fallback option: Create symlink /dev/ptmx -> /dev/pts/ptmx. */
	ret = symlinkat("/dev/pts/ptmx", rootfs->dfd_dev, "dev/ptmx");
	if (ret < 0)
		return log_error_errno(-1, errno, "Failed to create symlink from \"/dev/ptmx\" to \"/dev/pts/ptmx\"");

	DEBUG("Created symlink from \"/dev/ptmx\" to \"/dev/pts/ptmx\"");
	return 0;
}

static int lxc_finish_devpts_child(struct lxc_handler *handler)
{
	struct lxc_conf *conf = handler->conf;
	struct lxc_rootfs *rootfs = &conf->rootfs;
	int ret;

	if (conf->pty_max > 0)
		return 0;

	/*
	 * We end up here if the user has requested to allocate tty devices
	 * while not requestig pty devices be made available to the container.
	 * This means we can unmount the devpts instance. We only need the
	 * devpts_fd to allocate tty devices.
	 */
	ret = strnprintf(rootfs->buf, sizeof(rootfs->buf),
			 "/proc/self/fd/%d/pts", rootfs->dfd_dev);
	if (ret < 0)
		return syserror("Failed to create path");

	close_prot_errno_disarm(conf->devpts_fd);
	(void)umount2(rootfs->buf, MNT_DETACH);
	return 0;
}

static int lxc_send_devpts_to_parent(struct lxc_handler *handler)
{
	int ret;

	if (handler->conf->pty_max <= 0)
		return log_debug(0, "No devpts file descriptor will be sent since no pts devices are requested");

	ret = lxc_abstract_unix_send_fds(handler->data_sock[0], &handler->conf->devpts_fd, 1, NULL, 0);
	if (ret < 0)
		SYSERROR("Failed to send devpts file descriptor %d to parent", handler->conf->devpts_fd);
	else
		TRACE("Sent devpts file descriptor %d to parent", handler->conf->devpts_fd);

	close_prot_errno_disarm(handler->conf->devpts_fd);

	return 0;
}

static int setup_personality(personality_t persona)
{
	int ret;

	if (persona == LXC_ARCH_UNCHANGED)
		return log_debug(0, "Retaining original personality");

	ret = lxc_personality(persona);
	if (ret < 0)
		return syserror("Failed to set personality to \"0lx%lx\"", persona);

	INFO("Set personality to \"0lx%lx\"", persona);
	return 0;
}

static int bind_mount_console(int fd_devpts, struct lxc_rootfs *rootfs,
			      struct lxc_terminal *console, int fd_to)
{
	__do_close int fd_pty = -EBADF;

	if (is_empty_string(console->name))
		return ret_errno(EINVAL);

	/*
	 * When the pty fd stashed in console->pty has been retrieved via the
	 * TIOCGPTPEER ioctl() to avoid dangerous path-based lookups when
	 * allocating new pty devices we can't reopen it through openat2() or
	 * created a detached mount through open_tree() from it. This means we
	 * would need to mount using the path stased in console->name which is
	 * unsafe. We could be mounting a device that isn't identical to the
	 * one we've already safely opened and stashed in console->pty.
	 * So, what we do is we open an O_PATH file descriptor for
	 * console->name and verify that the opened fd and the fd we stashed in
	 * console->pty refer to the same device. If they do we can go on and
	 * created a detached mount based on the newly opened O_PATH file
	 * descriptor and then safely mount.
	 */
	fd_pty = open_at_same(console->pty, fd_devpts, fdstr(console->pty_nr),
			      PROTECT_OPATH_FILE, PROTECT_LOOKUP_ABSOLUTE_XDEV, 0);
	if (fd_pty < 0)
		return syserror("Failed to open \"%s\"", console->name);

	/*
	 * Note, there are intentionally no open or lookup restrictions since
	 * we're operating directly on the fd.
	 */
	if (can_use_mount_api())
		return fd_bind_mount(fd_pty, "", 0, 0, fd_to, "", 0, 0, 0, 0, 0, false);

	return mount_fd(fd_pty, fd_to, "none", MS_BIND, 0);
}

static int lxc_setup_dev_console(int fd_devpts, struct lxc_rootfs *rootfs,
				 struct lxc_terminal *console)
{
	__do_close int fd_console = -EBADF;
	int ret;

	/*
	 * When we are asked to setup a console we remove any previous
	 * /dev/console bind-mounts.
	 */
	if (exists_file_at(rootfs->dfd_dev, "console")) {
		char *rootfs_path = rootfs->path ? rootfs->mount : "";

		ret = strnprintf(rootfs->buf, sizeof(rootfs->buf), "%s/dev/console", rootfs_path);
		if (ret < 0)
			return -1;

		ret = lxc_unstack_mountpoint(rootfs->buf, false);
		if (ret < 0)
			return log_error_errno(-ret, errno, "Failed to unmount \"%s\"", rootfs->buf);
		else
			DEBUG("Cleared all (%d) mounts from \"%s\"", ret, rootfs->buf);
	}

	/*
	 * For unprivileged containers autodev or automounts will already have
	 * taken care of creating /dev/console.
	 */
	fd_console = open_at(rootfs->dfd_dev,
			     "console",
			     PROTECT_OPEN | O_CREAT,
			     PROTECT_LOOKUP_BENEATH,
			     0000);
	if (fd_console < 0)
		return syserror("Failed to create \"%d/console\"", rootfs->dfd_dev);

	ret = fchmod(console->pty, 0620);
	if (ret < 0)
		return syserror("Failed to change console mode");

	ret = bind_mount_console(fd_devpts, rootfs, console, fd_console);
	if (ret < 0)
		return syserror("Failed to mount \"%d(%s)\" on \"%d\"",
				console->pty, console->name, fd_console);

	TRACE("Setup console \"%s\"", console->name);
	return 0;
}

static int lxc_setup_ttydir_console(int fd_devpts, struct lxc_rootfs *rootfs,
				    struct lxc_terminal *console,
				    char *ttydir)
{
	__do_close int fd_ttydir = -EBADF, fd_dev_console = -EBADF,
		       fd_reg_console = -EBADF, fd_reg_ttydir_console = -EBADF;
	int ret;

	/* create dev/<ttydir> */
	ret = mkdirat(rootfs->dfd_dev, ttydir, 0755);
	if (ret < 0 && errno != EEXIST)
		return syserror("Failed to create \"%d/%s\"", rootfs->dfd_dev, ttydir);

	fd_ttydir = open_at(rootfs->dfd_dev,
			    ttydir,
			    PROTECT_OPATH_DIRECTORY,
			    PROTECT_LOOKUP_BENEATH,
			    0);
	if (fd_ttydir < 0)
		return syserror("Failed to open \"%d/%s\"", rootfs->dfd_dev, ttydir);

	ret = strnprintf(rootfs->buf, sizeof(rootfs->buf), "%s/console", ttydir);
	if (ret < 0)
		return -1;

	/* create dev/<ttydir>/console */
	fd_reg_ttydir_console = open_at(fd_ttydir,
					"console",
					PROTECT_OPEN | O_CREAT,
					PROTECT_LOOKUP_BENEATH,
					0000);
	if (fd_reg_ttydir_console < 0)
		return syserror("Failed to create \"%d/console\"", fd_ttydir);

	if (file_exists(rootfs->buf)) {
		char *rootfs_path = rootfs->path ? rootfs->mount : "";

		ret = strnprintf(rootfs->buf, sizeof(rootfs->buf), "%s/dev/console", rootfs_path);
		if (ret < 0)
			return -1;

		ret = lxc_unstack_mountpoint(rootfs->buf, false);
		if (ret < 0)
			return log_error_errno(-ret, errno, "Failed to unmount \"%s\"", rootfs->buf);
		else
			DEBUG("Cleared all (%d) mounts from \"%s\"", ret, rootfs->buf);
	}

	/* create dev/console */
	fd_reg_console = open_at(rootfs->dfd_dev,
				"console",
				 PROTECT_OPEN | O_CREAT,
				 PROTECT_LOOKUP_BENEATH,
				 0000);
	if (fd_reg_console < 0)
		return syserror("Failed to create \"%d/console\"", rootfs->dfd_dev);

	ret = fchmod(console->pty, 0620);
	if (ret < 0)
		return syserror("Failed to change console mode");

	/* bind mount console to '/dev/<ttydir>/console' */
	ret = bind_mount_console(fd_devpts, rootfs, console, fd_reg_ttydir_console);
	if (ret < 0)
		return syserror("Failed to mount \"%d(%s)\" on \"%d\"",
				console->pty, console->name, fd_reg_ttydir_console);

	fd_dev_console = open_at_same(console->pty,
				      fd_ttydir,
				      "console",
				      PROTECT_OPATH_FILE,
				      PROTECT_LOOKUP_BENEATH_XDEV,
				      0);
	if (fd_dev_console < 0)
		return syserror("Failed to open \"%d/console\"", fd_ttydir);

	/* bind mount '/dev/<ttydir>/console' to '/dev/console' */
	if (can_use_mount_api())
		ret = fd_bind_mount(fd_dev_console,
				    "",
				    PROTECT_OPATH_FILE,
				    PROTECT_LOOKUP_BENEATH_XDEV,
				    fd_reg_console,
				    "",
				    PROTECT_OPATH_FILE,
				    PROTECT_LOOKUP_BENEATH,
				    0,
				    0,
				    0,
				    false);
	else
		ret = mount_fd(fd_dev_console, fd_reg_console, "none", MS_BIND, 0);
	if (ret < 0)
		return syserror("Failed to mount \"%d\" on \"%d\"",
				fd_dev_console, fd_reg_console);

	TRACE("Setup console \"%s\"", console->name);
	return 0;
}

static int lxc_setup_console(const struct lxc_handler *handler,
			     struct lxc_rootfs *rootfs,
			     struct lxc_terminal *console, char *ttydir)
{
	__do_close int fd_devpts_host = -EBADF;
	int fd_devpts = handler->conf->devpts_fd;
	int ret = -1;

	if (!wants_console(console))
		return log_trace(0, "Skipping console setup");

	if (console->pty < 0)  {
		/*
		 * Allocate a console from the container's devpts instance. We
		 * have checked on the host that we have enough pty devices
		 * available.
		 */
		ret = lxc_devpts_terminal(handler->conf->devpts_fd, &console->ptx,
					  &console->pty, &console->pty_nr, false);
		if (ret < 0)
			return syserror("Failed to allocate console from container's devpts instance");

		ret = strnprintf(console->name, sizeof(console->name),
				"/dev/pts/%d", console->pty_nr);
		if (ret < 0)
			return syserror("Failed to create console path");
	} else {
		/*
		 * We're using a console from the host's devpts instance. Open
		 * it again so we can later verify that the console we're
		 * supposed to use is still the same as the one we opened on
		 * the host.
		 */
		fd_devpts_host = open_at(rootfs->dfd_host,
					 "dev/pts",
					 PROTECT_OPATH_DIRECTORY,
					 PROTECT_LOOKUP_BENEATH_XDEV,
					 0);
		if (fd_devpts_host < 0)
			return syserror("Failed to open host devpts");

		fd_devpts = fd_devpts_host;
	}

	if (ttydir)
		ret = lxc_setup_ttydir_console(fd_devpts, rootfs, console, ttydir);
	else
		ret = lxc_setup_dev_console(fd_devpts, rootfs, console);
	if (ret < 0)
		return syserror("Failed to setup console");

	/*
	 * Some init's such as busybox will set sane tty settings on stdin,
	 * stdout, stderr which it thinks is the console. We already set them
	 * the way we wanted on the real terminal, and we want init to do its
	 * setup on its console ie. the pty allocated in lxc_terminal_setup() so
	 * make sure that that pty is stdin,stdout,stderr.
	 */
	if (console->pty >= 0) {
		if (handler->daemonize || !handler->conf->is_execute)
			ret = set_stdfds(console->pty);
		else
			ret = lxc_terminal_set_stdfds(console->pty);
		if (ret < 0)
			return syserror("Failed to redirect std{in,out,err} to pty file descriptor %d", console->pty);

		/*
		 * If the console has been allocated from the host's devpts
		 * we're done and we don't need to send fds to the parent.
		 */
		if (fd_devpts_host >= 0)
			lxc_terminal_delete(console);
	}

	return ret;
}

static int parse_mntopt(char *opt, unsigned long *flags, char **data, size_t size)
{
	size_t ret;

	/* If '=' is contained in opt, the option must go into data. */
	if (!strchr(opt, '=')) {
		/*
		 * If opt is found in mount_opt, set or clear flags.
		 * Otherwise append it to data.
		 */
		size_t opt_len = strlen(opt);
		for (struct mount_opt *mo = &mount_opt[0]; mo->name != NULL; mo++) {
			size_t mo_name_len = strlen(mo->name);

			if (opt_len == mo_name_len && strnequal(opt, mo->name, mo_name_len)) {
				if (mo->clear)
					*flags &= ~mo->legacy_flag;
				else
					*flags |= mo->legacy_flag;
				return 0;
			}
		}
	}

	if (strlen(*data)) {
		ret = strlcat(*data, ",", size);
		if (ret >= size)
			return log_error_errno(ret, errno, "Failed to append \",\" to %s", *data);
	}

	ret = strlcat(*data, opt, size);
	if (ret >= size)
		return log_error_errno(ret, errno, "Failed to append \"%s\" to %s", opt, *data);

	return 0;
}

int parse_mntopts_legacy(const char *mntopts, unsigned long *mntflags, char **mntdata)
{
	__do_free char *mntopts_new = NULL, *mntopts_dup = NULL;
	char *mntopt_cur = NULL;
	size_t size;

	if (*mntdata || *mntflags)
		return ret_errno(EINVAL);

	if (!mntopts)
		return 0;

	mntopts_dup = strdup(mntopts);
	if (!mntopts_dup)
		return ret_errno(ENOMEM);

	size = strlen(mntopts_dup) + 1;
	mntopts_new = zalloc(size);
	if (!mntopts_new)
		return ret_errno(ENOMEM);

	lxc_iterate_parts(mntopt_cur, mntopts_dup, ",")
		if (parse_mntopt(mntopt_cur, mntflags, &mntopts_new, size) < 0)
			return ret_errno(EINVAL);

	if (*mntopts_new)
		*mntdata = move_ptr(mntopts_new);

	return 0;
}

static int parse_vfs_attr(struct lxc_mount_options *opts, char *opt, size_t size)
{
	/*
	 * If opt is found in mount_opt, set or clear flags.
	 * Otherwise append it to data.
	 */
	for (struct mount_opt *mo = &mount_opt[0]; mo->name != NULL; mo++) {
		if (!strnequal(opt, mo->name, strlen(mo->name)))
			continue;

		/* This is a recursive bind-mount. */
		if (strequal(mo->name, "rbind")) {
			opts->bind_recursively = 1;
			opts->bind = 1;
			opts->mnt_flags |= mo->legacy_flag; /* MS_BIND | MS_REC */
			return 0;
		}

		/* This is a bind-mount. */
		if (strequal(mo->name, "bind")) {
			opts->bind = 1;
			opts->mnt_flags |= mo->legacy_flag; /* MS_BIND */
			return 0;
		}

		if (mo->flag == (__u64)~0)
			return log_info(0, "Ignoring %s mount option", mo->name);

		if (mo->clear) {
			opts->attr.attr_clr |= mo->flag;
			opts->mnt_flags &= ~mo->legacy_flag;
			TRACE("Lowering %s", mo->name);
		} else {
			opts->attr.attr_set |= mo->flag;
			opts->mnt_flags |= mo->legacy_flag;
			TRACE("Raising %s", mo->name);
		}

		return 0;
	}

	for (struct mount_opt *mo = &propagation_opt[0]; mo->name != NULL; mo++) {
		if (!strnequal(opt, mo->name, strlen(mo->name)))
			continue;

		if (strequal(mo->name, "rslave") ||
		    strequal(mo->name, "rshared") ||
		    strequal(mo->name, "runbindable") ||
		    strequal(mo->name, "rprivate"))
			opts->propagate_recursively = 1;

		opts->attr.propagation = mo->flag;
		opts->prop_flags |= mo->legacy_flag;
		return 0;
	}

	return 0;
}

int parse_mount_attrs(struct lxc_mount_options *opts, const char *mntopts)
{
	__do_free char *mntopts_new = NULL, *mntopts_dup = NULL;
	char *end = NULL, *mntopt_cur = NULL;
	int ret;
	size_t size;

	if (!opts)
		return ret_errno(EINVAL);

	if (!mntopts)
		return 0;

	mntopts_dup = strdup(mntopts);
	if (!mntopts_dup)
		return ret_errno(ENOMEM);

	size = strlen(mntopts_dup) + 1;
	mntopts_new = zalloc(size);
	if (!mntopts_new)
		return ret_errno(ENOMEM);

	lxc_iterate_parts(mntopt_cur, mntopts_dup, ",") {
		/* This is a filesystem specific option. */
		if (strchr(mntopt_cur, '=')) {
			if (!end) {
				end = stpcpy(mntopts_new, mntopt_cur);
			} else {
				end = stpcpy(end, ",");
				end = stpcpy(end, mntopt_cur);
			}

			continue;
		}

		/* This is a generic vfs option. */
		ret = parse_vfs_attr(opts, mntopt_cur, size);
		if (ret < 0)
			return syserror("Failed to parse mount attributes: \"%s\"", mntopt_cur);
	}

	if (*mntopts_new)
		opts->data = move_ptr(mntopts_new);

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
		ret = strnprintf(srcbuf, sizeof(srcbuf), "%s/%s", rootfs ? rootfs : "/", fsname ? fsname : "");
		if (ret < 0)
			return log_error_errno(-1, errno, "source path is too long");
		srcpath = srcbuf;
	}

	ret = safe_mount(srcpath, target, fstype, mountflags & ~MS_REMOUNT, data,
			 rootfs);
	if (ret < 0) {
		if (optional)
			return log_info_errno(0, errno, "Failed to mount \"%s\" on \"%s\" (optional)",
					      srcpath ? srcpath : "(null)", target);

		return log_error_errno(-1, errno, "Failed to mount \"%s\" on \"%s\"",
				       srcpath ? srcpath : "(null)", target);
	}

	if ((mountflags & MS_REMOUNT) || (mountflags & MS_BIND)) {

		DEBUG("Remounting \"%s\" on \"%s\" to respect bind or remount options",
		      srcpath ? srcpath : "(none)", target ? target : "(none)");

#ifdef HAVE_STATVFS
		if (srcpath && statvfs(srcpath, &sb) == 0) {
			unsigned long required_flags = 0;

			if (sb.f_flag & MS_NOSUID)
				required_flags |= MS_NOSUID;

			if (sb.f_flag & MS_NODEV && !dev)
				required_flags |= MS_NODEV;

			if (sb.f_flag & MS_RDONLY)
				required_flags |= MS_RDONLY;

			if (sb.f_flag & MS_NOEXEC)
				required_flags |= MS_NOEXEC;

			DEBUG("Flags for \"%s\" were %lu, required extra flags are %lu",
			      srcpath, sb.f_flag, required_flags);

			/* If this was a bind mount request, and required_flags
			 * does not have any flags which are not already in
			 * mountflags, then skip the remount.
			 */
			if (!(mountflags & MS_REMOUNT) &&
			    (!(required_flags & ~mountflags) && !(mountflags & MS_RDONLY))) {
				DEBUG("Mountflags already were %lu, skipping remount", mountflags);
				goto skipremount;
			}

			mountflags |= required_flags;
		}
#endif

		ret = mount(srcpath, target, fstype, mountflags | MS_REMOUNT, data);
		if (ret < 0) {
			if (optional)
				return log_info_errno(0, errno, "Failed to mount \"%s\" on \"%s\" (optional)",
						      srcpath ? srcpath : "(null)",
						      target);

			return log_error_errno(-1, errno, "Failed to mount \"%s\" on \"%s\"",
					       srcpath ? srcpath : "(null)",
					       target);
		}
	}

#ifdef HAVE_STATVFS
skipremount:
#endif
	if (pflags) {
		ret = mount(NULL, target, NULL, pflags, NULL);
		if (ret < 0) {
			if (optional)
				return log_info_errno(0, errno, "Failed to change mount propagation for \"%s\" (optional)", target);
			else
				return log_error_errno(-1, errno, "Failed to change mount propagation for \"%s\" (optional)", target);
		}
		DEBUG("Changed mount propagation for \"%s\"", target);
	}

	DEBUG("Mounted \"%s\" on \"%s\" with filesystem type \"%s\"",
	      srcpath ? srcpath : "(null)", target, fstype);

	return 0;
}

const char *lxc_mount_options_info[LXC_MOUNT_MAX] = {
	"create=dir",
	"create=file",
	"optional",
	"relative",
	"idmap=",
};

/* Remove "optional", "create=dir", and "create=file" from mntopt */
int parse_lxc_mount_attrs(struct lxc_mount_options *opts, char *mnt_opts)
{
	for (size_t i = LXC_MOUNT_CREATE_DIR; i < LXC_MOUNT_MAX; i++) {
		__do_close int fd_userns = -EBADF;
		const char *opt_name = lxc_mount_options_info[i];
		size_t len;
		char *idmap_path, *opt, *opt_next;

		opt = strstr(mnt_opts, opt_name);
		if (!opt)
			continue;

		switch (i) {
		case LXC_MOUNT_CREATE_DIR:
			opts->create_dir = 1;
			break;
		case LXC_MOUNT_CREATE_FILE:
			opts->create_file = 1;
			break;
		case LXC_MOUNT_OPTIONAL:
			opts->optional = 1;
			break;
		case LXC_MOUNT_RELATIVE:
			opts->relative = 1;
			break;
		case LXC_MOUNT_IDMAP:
			opt_next = opt;
			opt_next += STRLITERALLEN("idmap=");
			idmap_path = strchrnul(opt_next, ',');
			len = idmap_path - opt_next + 1;

			if (len >= sizeof(opts->userns_path))
				return syserror_set(-EIO, "Excessive idmap path length for \"idmap=<path>\" LXC specific mount option");

			strlcpy(opts->userns_path, opt_next, len);

			if (is_empty_string(opts->userns_path))
				return syserror_set(-EINVAL, "Missing idmap path for \"idmap=<path>\" LXC specific mount option");

			if (!strequal(opts->userns_path, "container")) {
				fd_userns = open(opts->userns_path, O_RDONLY | O_NOCTTY | O_CLOEXEC);
				if (fd_userns < 0)
					return syserror("Failed to open user namespace %s", opts->userns_path);
			}

			TRACE("Parse LXC specific mount option %d->\"idmap=%s\"", fd_userns, opts->userns_path);
			break;
		default:
			return syserror_set(-EINVAL, "Unknown LXC specific mount option");
		}

		opt_next = strchr(opt, ',');
		if (!opt_next)
			*opt = '\0'; /* no more mntopts, so just chop it here */
		else
			memmove(opt, opt_next + 1, strlen(opt_next + 1) + 1);
	}

	return 0;
}

static int mount_entry_create_dir_file(const struct mntent *mntent,
				       const char *path,
				       const struct lxc_rootfs *rootfs,
				       const char *lxc_name, const char *lxc_path)
{
	__do_free char *p1 = NULL;
	int ret;
	char *p2;

	if (strnequal(mntent->mnt_type, "overlay", 7)) {
		ret = ovl_mkdir(mntent, rootfs, lxc_name, lxc_path);
		if (ret < 0)
			return -1;
	}

	if (hasmntopt(mntent, "create=dir")) {
		ret = mkdir_p(path, 0755);
		if (ret < 0 && errno != EEXIST)
			return log_error_errno(-1, errno, "Failed to create directory \"%s\"", path);
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
	if (ret < 0 && errno != EEXIST)
		return log_error_errno(-1, errno, "Failed to create directory \"%s\"", path);

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
	__do_free char *mntdata = NULL;
	char *rootfs_path = NULL;
	int ret;
	bool dev, optional, relative;
	struct lxc_mount_options opts = {};

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

	ret = parse_lxc_mount_attrs(&opts, mntent->mnt_opts);
	if (ret < 0)
		return ret;

	/*
	 * Idmapped mount entries will be setup by the parent for us. Note that
	 * we rely on mount_entry_create_dir_file() above to have already
	 * created the target path for us. So the parent can just open the
	 * target and send us the target fd.
	 */
	errno = EOPNOTSUPP;
	if (!is_empty_string(opts.userns_path))
		return systrace_ret(0, "Skipping idmapped mount entry");

	ret = parse_mount_attrs(&opts, mntent->mnt_opts);
	if (ret < 0)
		return -1;

	ret = mount_entry(mntent->mnt_fsname,
			  path,
			  mntent->mnt_type,
			  opts.mnt_flags,
			  opts.prop_flags,
			  opts.data,
			  optional,
			  dev,
			  relative,
			  rootfs_path);

	return ret;
}

static inline int mount_entry_on_systemfs(struct lxc_rootfs *rootfs,
					  struct mntent *mntent)
{
	int ret;

	/* For containers created without a rootfs all mounts are treated as
	 * absolute paths starting at / on the host.
	 */
	if (mntent->mnt_dir[0] != '/')
		ret = strnprintf(rootfs->buf, sizeof(rootfs->buf), "/%s", mntent->mnt_dir);
	else
		ret = strnprintf(rootfs->buf, sizeof(rootfs->buf), "%s", mntent->mnt_dir);
	if (ret < 0)
		return -1;

	return mount_entry_on_generic(mntent, rootfs->buf, NULL, NULL, NULL);
}

static int mount_entry_on_absolute_rootfs(struct mntent *mntent,
					  struct lxc_rootfs *rootfs,
					  const char *lxc_name,
					  const char *lxc_path)
{
	int offset;
	char *aux;
	const char *lxcpath;
	int ret = 0;

	lxcpath = lxc_global_config_value("lxc.lxcpath");
	if (!lxcpath)
		return -1;

	/* If rootfs->path is a blockdev path, allow container fstab to use
	 * <lxcpath>/<name>/rootfs" as the target prefix.
	 */
	ret = strnprintf(rootfs->buf, sizeof(rootfs->buf), "%s/%s/rootfs", lxcpath, lxc_name);
	if (ret < 0)
		goto skipvarlib;

	aux = strstr(mntent->mnt_dir, rootfs->buf);
	if (aux) {
		offset = strlen(rootfs->buf);
		goto skipabs;
	}

skipvarlib:
	aux = strstr(mntent->mnt_dir, rootfs->path);
	if (!aux)
		return log_warn(ret, "Ignoring mount point \"%s\"", mntent->mnt_dir);
	offset = strlen(rootfs->path);

skipabs:
	ret = strnprintf(rootfs->buf, sizeof(rootfs->buf), "%s/%s", rootfs->mount, aux + offset);
	if (ret < 0)
		return -1;

	return mount_entry_on_generic(mntent, rootfs->buf, rootfs, lxc_name, lxc_path);
}

static int mount_entry_on_relative_rootfs(struct mntent *mntent,
					  struct lxc_rootfs *rootfs,
					  const char *lxc_name,
					  const char *lxc_path)
{
	int ret;

	/* relative to root mount point */
	ret = strnprintf(rootfs->buf, sizeof(rootfs->buf), "%s/%s", rootfs->mount, mntent->mnt_dir);
	if (ret < 0)
		return -1;

	return mount_entry_on_generic(mntent, rootfs->buf, rootfs, lxc_name, lxc_path);
}

static int mount_file_entries(struct lxc_rootfs *rootfs, FILE *file,
			      const char *lxc_name, const char *lxc_path)
{
	char buf[PATH_MAX];
	struct mntent mntent;

	while (getmntent_r(file, &mntent, buf, sizeof(buf))) {
		int ret;

		if (!rootfs->path)
			ret = mount_entry_on_systemfs(rootfs, &mntent);
		else if (mntent.mnt_dir[0] != '/')
			ret = mount_entry_on_relative_rootfs(&mntent, rootfs,
							     lxc_name, lxc_path);
		else
			ret = mount_entry_on_absolute_rootfs(&mntent, rootfs,
							     lxc_name, lxc_path);
		if (ret < 0)
			return -1;
	}

	if (!feof(file) || ferror(file))
		return log_error(-1, "Failed to parse mount entries");

	return 0;
}

static inline void __auto_endmntent__(FILE **f)
{
	if (*f)
		endmntent(*f);
}

#define __do_endmntent __attribute__((__cleanup__(__auto_endmntent__)))

static int setup_mount_fstab(struct lxc_rootfs *rootfs, const char *fstab,
			     const char *lxc_name, const char *lxc_path)
{
	__do_endmntent FILE *f = NULL;
	int ret;

	if (!fstab)
		return 0;

	f = setmntent(fstab, "re");
	if (!f)
		return log_error_errno(-1, errno, "Failed to open \"%s\"", fstab);

	ret = mount_file_entries(rootfs, f, lxc_name, lxc_path);
	if (ret < 0)
		ERROR("Failed to set up mount entries");

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
"proc dev/.lxc/proc proc create=dir,optional 0 0\n"
"sys dev/.lxc/sys sysfs create=dir,optional 0 0\n";

FILE *make_anonymous_mount_file(const struct list_head *mount_entries,
				bool include_nesting_helpers)
{
	__do_close int fd = -EBADF;
	FILE *f;
	int ret;
	struct string_entry *entry;

	fd = memfd_create(".lxc_mount_file", MFD_CLOEXEC);
	if (fd < 0) {
		char template[] = P_tmpdir "/.lxc_mount_file_XXXXXX";

		if (errno != ENOSYS)
			return NULL;

		fd = lxc_make_tmpfile(template, true);
		if (fd < 0)
			return log_error_errno(NULL, errno, "Could not create temporary mount file");

		TRACE("Created temporary mount file");
	}

	list_for_each_entry(entry, mount_entries, head) {
		size_t len;

		len = strlen(entry->val);

		ret = lxc_write_nointr(fd, entry->val, len);
		if (ret < 0 || (size_t)ret != len)
			return NULL;

		ret = lxc_write_nointr(fd, "\n", 1);
		if (ret != 1)
			return NULL;
	}

	if (include_nesting_helpers) {
		ret = lxc_write_nointr(fd, nesting_helpers,
				       STRARRAYLEN(nesting_helpers));
		if (ret != STRARRAYLEN(nesting_helpers))
			return NULL;
	}

	ret = lseek(fd, 0, SEEK_SET);
	if (ret < 0)
		return NULL;

	f = fdopen(fd, "re+");
	if (f)
		move_fd(fd); /* Transfer ownership of fd. */
	return f;
}

static int setup_mount_entries(const struct lxc_conf *conf,
			       struct lxc_rootfs *rootfs,
			       const char *lxc_name, const char *lxc_path)
{
	__do_fclose FILE *f = NULL;

	f = make_anonymous_mount_file(&conf->mount_entries, conf->lsm_aa_allow_nesting);
	if (!f)
		return -1;

	return mount_file_entries(rootfs, f, lxc_name, lxc_path);
}

static int __lxc_idmapped_mounts_child(struct lxc_handler *handler, FILE *f)
{
	struct lxc_conf *conf = handler->conf;
	struct lxc_rootfs *rootfs = &conf->rootfs;
	int mnt_seq = 0;
	int ret;
	char buf[PATH_MAX];
	struct mntent mntent;

	while (getmntent_r(f, &mntent, buf, sizeof(buf))) {
		__do_close int fd_from = -EBADF, fd_to = -EBADF,
			       fd_userns = -EBADF;
		__do_free char *__data = NULL;
		int cur_mnt_seq = -1;
		struct lxc_mount_options opts = {};
		int dfd_from;
		const char *source_relative, *target_relative;
		struct mount_attr attr = {};

		ret = parse_lxc_mount_attrs(&opts, mntent.mnt_opts);
		if (ret < 0)
			return syserror("Failed to parse LXC specific mount options");
		__data = opts.data;

		ret = parse_mount_attrs(&opts, mntent.mnt_opts);
		if (ret < 0)
			return syserror("Failed to parse mount options");

		/* No idmapped mount entry so skip it. */
		if (is_empty_string(opts.userns_path))
			continue;

		if (!can_use_bind_mounts())
			return syserror_set(-EINVAL, "Kernel does not support idmapped mounts");

		if (!opts.bind)
			return syserror_set(-EINVAL, "Only bind mounts can currently be idmapped");

		/* We don't support new filesystem mounts yet. */
		if (!is_empty_string(mntent.mnt_type) &&
		    !strequal(mntent.mnt_type, "none"))
			return syserror_set(-EINVAL, "Only bind mounts can currently be idmapped");

		/* Someone specified additional mount options for a bind-mount. */
		if (!is_empty_string(opts.data))
			return syserror_set(-EINVAL, "Bind mounts don't support non-generic mount options");

		/*
		 * The source path is supposed to be taken relative to the
		 * container's rootfs mount or - if the container does not have
		 * a separate rootfs - to the host's /.
		 */
		source_relative = deabs(mntent.mnt_fsname);
		if (opts.relative || !rootfs->path)
			dfd_from = rootfs->dfd_mnt;
		else
			dfd_from = rootfs->dfd_host;
		fd_from = open_tree(dfd_from, source_relative,
				    OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC |
				    (opts.bind_recursively ? AT_RECURSIVE : 0));
		if (fd_from < 0)
			return syserror("Failed to create detached %smount of %d/%s",
					opts.bind_recursively ? "recursive " : "",
					dfd_from, source_relative);

		if (strequal(opts.userns_path, "container"))
			fd_userns = openat(dfd_from, "proc/self/ns/user", O_RDONLY | O_CLOEXEC);
		else
			fd_userns = open_at(-EBADF, opts.userns_path,
					    PROTECT_OPEN_WITH_TRAILING_SYMLINKS, 0, 0);
		if (fd_userns < 0) {
			if (opts.optional) {
				TRACE("Skipping optional idmapped mount");
				continue;
			}

			return syserror("Failed to open user namespace \"%s\" for detached %smount of %d/%s",
					opts.userns_path, opts.bind_recursively ? "recursive " : "",
					dfd_from, source_relative);
		}

		ret = __lxc_abstract_unix_send_two_fds(handler->data_sock[0],
						       fd_from, fd_userns,
						       &opts, sizeof(opts));
		if (ret <= 0) {
			if (opts.optional) {
				TRACE("Skipping optional idmapped mount");
				continue;
			}

			return syserror("Failed to send file descriptor %d for detached %smount of %d/%s and file descriptor %d of user namespace \"%s\" to parent",
					fd_from, opts.bind_recursively ? "recursive " : "",
					dfd_from, source_relative, fd_userns,
					opts.userns_path);
		}

		ret = lxc_abstract_unix_rcv_credential(handler->data_sock[0],
						       &cur_mnt_seq,
						       sizeof(cur_mnt_seq));
		if (ret <= 0) {
			if (opts.optional) {
				TRACE("Skipping optional idmapped mount");
				continue;
			}

			return syserror("Failed to receive notification that parent idmapped detached %smount %d/%s to user namespace %d",
					opts.bind_recursively ? "recursive " : "",
					dfd_from, source_relative, fd_userns);
		}

		if (mnt_seq != cur_mnt_seq)
			return syserror("Expected mount sequence number and mount sequence number from parent mismatch: %d != %d",
					mnt_seq, cur_mnt_seq);
		mnt_seq++;

		/* Set regular mount options. */
		attr = opts.attr;
		attr.propagation = 0;
		ret = mount_setattr(fd_from,
				    "",
				    AT_EMPTY_PATH |
				    (opts.bind_recursively ? AT_RECURSIVE : 0),
				    &attr,
				    sizeof(attr));
		if (ret < 0) {
			if (opts.optional) {
				TRACE("Skipping optional idmapped mount");
				continue;
			}

			return syserror("Failed to set %smount options on detached %d/%s",
					opts.bind_recursively ? "recursive " : "",
					dfd_from, source_relative);
		}

		/* Set propagation mount options. */
		if (opts.attr.propagation) {
			attr = (struct mount_attr) {
				.propagation = opts.attr.propagation,
			};

			ret = mount_setattr(fd_from,
					"",
					AT_EMPTY_PATH |
					(opts.propagate_recursively ? AT_RECURSIVE : 0),
					&attr,
					sizeof(attr));
			if (ret < 0) {
				if (opts.optional) {
					TRACE("Skipping optional idmapped mount");
					continue;
				}

				return syserror("Failed to set %spropagation mount options on detached %d/%s",
						opts.bind_recursively ? "recursive " : "",
						dfd_from, source_relative);
			}
		}


		/*
		 * In contrast to the legacy mount codepath we will simplify
		 * our lifes and just always treat the target mountpoint to be
		 * relative to the container's rootfs mountpoint or - if the
		 * container does not have a separate rootfs - to the host's /.
		 */

		target_relative = deabs(mntent.mnt_dir);
		if (rootfs->path)
			dfd_from = rootfs->dfd_mnt;
		else
			dfd_from = rootfs->dfd_host;
		fd_to = open_at(dfd_from, target_relative, PROTECT_OPATH_FILE, PROTECT_LOOKUP_BENEATH_XDEV, 0);
		if (fd_to < 0) {
			if (opts.optional) {
				TRACE("Skipping optional idmapped mount");
				continue;
			}

			return syserror("Failed to open target mountpoint %d/%s for detached idmapped %smount %d:%d/%s",
					dfd_from, target_relative,
					opts.bind_recursively ? "recursive " : "",
					fd_userns, dfd_from, source_relative);
		}

		ret = move_detached_mount(fd_from, fd_to, "", 0, 0);
		if (ret) {
			if (opts.optional) {
				TRACE("Skipping optional idmapped mount");
				continue;
			}

			return syserror("Failed to attach detached idmapped %smount %d:%d/%s to target mountpoint %d/%s",
					opts.bind_recursively ? "recursive " : "",
					fd_userns, dfd_from, source_relative, dfd_from, target_relative);
		}

		TRACE("Attached detached idmapped %smount %d:%d/%s to target mountpoint %d/%s",
		      opts.bind_recursively ? "recursive " : "", fd_userns, dfd_from,
		      source_relative, dfd_from, target_relative);
	}

	if (!feof(f) || ferror(f))
		return syserror_set(-EINVAL, "Failed to parse mount entries");

	return 0;
}

static int lxc_idmapped_mounts_child(struct lxc_handler *handler)
{
	__do_fclose FILE *f_entries = NULL;
	int fret = -1;
	struct lxc_conf *conf = handler->conf;
	const char *fstab = conf->fstab;
	int ret;

	f_entries = make_anonymous_mount_file(&conf->mount_entries,
					      conf->lsm_aa_allow_nesting);
	if (!f_entries) {
		SYSERROR("Failed to create anonymous mount file");
		goto out;
	}

	ret = __lxc_idmapped_mounts_child(handler, f_entries);
	if (ret) {
		SYSERROR("Failed to setup idmapped mount entries");
		goto out;
	}

	TRACE("Finished setting up idmapped mounts");

	if (fstab) {
		__do_endmntent FILE *f_fstab = NULL;

		f_fstab = setmntent(fstab, "re");
		if (!f_fstab) {
			SYSERROR("Failed to open fstab format file \"%s\"", fstab);
			goto out;
		}

		ret = __lxc_idmapped_mounts_child(handler, f_fstab);
		if (ret) {
			SYSERROR("Failed to setup idmapped mount entries specified in fstab");
			goto out;
		}

		TRACE("Finished setting up idmapped mounts specified in fstab");
	}

	fret = 0;

out:
	ret = lxc_abstract_unix_send_credential(handler->data_sock[0], NULL, 0);
	if (ret < 0)
		return syserror("Failed to inform parent that we are done setting up mounts");

	return fret;
}

int parse_cap(const char *cap_name, __u32 *cap)
{
	size_t end = sizeof(caps_opt) / sizeof(caps_opt[0]);
	int ret;
	unsigned int res;
	__u32 last_cap;

	if (strequal(cap_name, "none"))
		return -2;

	for (size_t i = 0; i < end; i++) {
		if (!strequal(cap_name, caps_opt[i].name))
			continue;

		*cap = caps_opt[i].value;
		return 0;
	}

	/*
	 * Try to see if it's numeric, so the user may specify
	 * capabilities that the running kernel knows about but we
	 * don't.
	 */
	ret = lxc_safe_uint(cap_name, &res);
	if (ret < 0)
		return -1;

	ret = lxc_caps_last_cap(&last_cap);
	if (ret)
		return -1;

	if ((__u32)res > last_cap)
		return -1;

	*cap = (__u32)res;
	return 0;
}

bool has_cap(__u32 cap, struct lxc_conf *conf)
{
	bool cap_in_list = false;
	struct cap_entry *cap_entry;

	list_for_each_entry(cap_entry, &conf->caps.list, head) {
		if (cap_entry->cap != cap)
			continue;

		cap_in_list = true;
	}

	/* The capability is kept. */
	if (conf->caps.keep)
		return cap_in_list;

	/* The capability is not dropped. */
	return !cap_in_list;
}

static int capabilities_deny(struct lxc_conf *conf)
{
	struct cap_entry *cap;

	list_for_each_entry(cap, &conf->caps.list, head) {
		int ret;

		ret = prctl(PR_CAPBSET_DROP, prctl_arg(cap->cap), prctl_arg(0),
			    prctl_arg(0), prctl_arg(0));
		if (ret < 0)
			return syserror("Failed to remove %s capability", cap->cap_name);

		DEBUG("Dropped %s (%d) capability", cap->cap_name, cap->cap);
	}

	DEBUG("Capabilities have been setup");
	return 0;
}

static int capabilities_allow(struct lxc_conf *conf)
{
	__do_free __u32 *keep_bits = NULL;
	int ret;
	struct cap_entry *cap;
	__u32 last_cap, nr_u32;

	ret = lxc_caps_last_cap(&last_cap);
	if (ret || last_cap > 200)
		return ret_errno(EINVAL);

	TRACE("Found %d capabilities", last_cap);

	nr_u32 = BITS_TO_LONGS(last_cap);
	keep_bits = zalloc(nr_u32 * sizeof(__u32));
	if (!keep_bits)
		return ret_errno(ENOMEM);

	list_for_each_entry(cap, &conf->caps.list, head) {
		if (cap->cap > last_cap)
			continue;

		set_bit(cap->cap, keep_bits);
		DEBUG("Keeping %s (%d) capability", cap->cap_name, cap->cap);
	}

	for (__u32 cap_bit = 0; cap_bit <= last_cap; cap_bit++) {
		if (is_set(cap_bit, keep_bits))
			continue;

		ret = prctl(PR_CAPBSET_DROP, prctl_arg(cap_bit), prctl_arg(0),
			    prctl_arg(0), prctl_arg(0));
		if (ret < 0)
			return syserror("Failed to remove capability %d", cap_bit);

		TRACE("Dropped capability %d", cap_bit);
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
		if (strequal(res, limit_opt[i].name))
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

int setup_resource_limits(struct lxc_conf *conf, pid_t pid)
{
	int resid;
	struct lxc_limit *lim;

	if (list_empty(&conf->limits))
		return 0;

	list_for_each_entry(lim, &conf->limits, head) {
		resid = parse_resource(lim->resource);
		if (resid < 0)
			return log_error(-1, "Unknown resource %s", lim->resource);

#if HAVE_PRLIMIT || HAVE_PRLIMIT64
		if (prlimit(pid, resid, &lim->limit, NULL) != 0)
			return log_error_errno(-1, errno, "Failed to set limit %s", lim->resource);

		TRACE("Setup \"%s\" limit", lim->resource);
#else
		return log_error(-1, "Cannot set limit \"%s\" as prlimit is missing", lim->resource);
#endif
	}

	TRACE("Setup resource limits");
	return 0;
}

int setup_sysctl_parameters(struct lxc_conf *conf)
{
	__do_free char *tmp = NULL;
	int ret = 0;
	char filename[PATH_MAX] = {0};
	struct lxc_sysctl *sysctl, *nsysctl;

	if (list_empty(&conf->sysctls))
		return 0;

	list_for_each_entry_safe(sysctl, nsysctl, &conf->sysctls, head) {
		tmp = lxc_string_replace(".", "/", sysctl->key);
		if (!tmp)
			return log_error(-1, "Failed to replace key %s", sysctl->key);

		ret = strnprintf(filename, sizeof(filename), "/proc/sys/%s", tmp);
		if (ret < 0)
			return log_error(-1, "Error setting up sysctl parameters path");

		ret = lxc_write_to_file(filename, sysctl->value,
					strlen(sysctl->value), false, 0666);
		if (ret < 0)
			return log_error_errno(-1, errno, "Failed to setup sysctl parameters %s to %s",
					       sysctl->key, sysctl->value);

		TRACE("Setting %s to %s", filename, sysctl->value);
	}

	TRACE("Setup /proc/sys settings");
	return 0;
}

int setup_proc_filesystem(struct lxc_conf *conf, pid_t pid)
{
	__do_free char *tmp = NULL;
	int ret = 0;
	char filename[PATH_MAX] = {0};
	struct lxc_proc *proc;

	if (list_empty(&conf->procs))
		return 0;

	list_for_each_entry(proc, &conf->procs, head) {
		tmp = lxc_string_replace(".", "/", proc->filename);
		if (!tmp)
			return log_error(-1, "Failed to replace key %s", proc->filename);

		ret = strnprintf(filename, sizeof(filename), "/proc/%d/%s", pid, tmp);
		if (ret < 0)
			return log_error(-1, "Error setting up proc filesystem path");

		ret = lxc_write_to_file(filename, proc->value,
					strlen(proc->value), false, 0666);
		if (ret < 0)
			return log_error_errno(-1, errno, "Failed to setup proc filesystem %s to %s",
					       proc->filename, proc->value);

		TRACE("Setting %s to %s", filename, proc->value);
	}

	TRACE("Setup /proc/%d settings", pid);
	return 0;
}

static char *default_rootfs_mount = LXCROOTFSMOUNT;

struct lxc_conf *lxc_conf_init(void)
{
	int i;
	struct lxc_conf *new;

	new = zalloc(sizeof(*new));
	if (!new)
		return NULL;

	new->loglevel = LXC_LOG_LEVEL_NOTSET;
	new->personality = LXC_ARCH_UNCHANGED;
	new->autodev = 1;
	new->console.buffer_size = 0;
	new->console.log_path = NULL;
	new->console.log_fd = -1;
	new->console.log_size = 0;
	new->console.path = NULL;
	new->console.peer = -1;
	new->console.proxy.busy = -1;
	new->console.proxy.ptx = -1;
	new->console.proxy.pty = -1;
	new->console.ptx = -EBADF;
	new->console.pty = -EBADF;
	new->console.pty_nr = -1;
	new->console.name[0] = '\0';
	new->devpts_fd = -EBADF;
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
	new->rootfs.dfd_mnt = -EBADF;
	new->rootfs.dfd_dev = -EBADF;
	new->rootfs.dfd_host = -EBADF;
	new->rootfs.fd_path_pin = -EBADF;
	new->rootfs.dfd_idmapped = -EBADF;
	new->logfd = -1;
	INIT_LIST_HEAD(&new->cgroup);
	INIT_LIST_HEAD(&new->cgroup2);
	/* Block ("allowlist") all devices by default. */
	new->bpf_devices.list_type = LXC_BPF_DEVICE_CGROUP_ALLOWLIST;
	INIT_LIST_HEAD(&(new->bpf_devices).devices);
	INIT_LIST_HEAD(&new->mount_entries);
	INIT_LIST_HEAD(&new->caps.list);
	INIT_LIST_HEAD(&new->id_map);
	new->root_nsuid_map = NULL;
	new->root_nsgid_map = NULL;
	INIT_LIST_HEAD(&new->environment);
	INIT_LIST_HEAD(&new->limits);
	INIT_LIST_HEAD(&new->sysctls);
	INIT_LIST_HEAD(&new->procs);
	new->hooks_version = 0;
	for (i = 0; i < NUM_LXC_HOOKS; i++)
		INIT_LIST_HEAD(&new->hooks[i]);
	INIT_LIST_HEAD(&new->groups);
	INIT_LIST_HEAD(&new->state_clients);
	new->lsm_aa_profile = NULL;
	INIT_LIST_HEAD(&new->lsm_aa_raw);
	new->lsm_se_context = NULL;
	new->lsm_se_keyring_context = NULL;
	new->keyring_disable_session = false;
	new->transient_procfs_mnt = false;
	new->shmount.path_host = NULL;
	new->shmount.path_cont = NULL;
	new->sched_core = false;
	new->sched_core_cookie = INVALID_SCHED_CORE_COOKIE;

	/* if running in a new user namespace, init and COMMAND
	 * default to running as UID/GID 0 when using lxc-execute */
	new->init_uid = 0;
	new->init_gid = 0;
	memset(&new->init_groups, 0, sizeof(lxc_groups_t));
	memset(&new->cgroup_meta, 0, sizeof(struct lxc_cgroup));
	memset(&new->ns_share, 0, sizeof(char *) * LXC_NS_MAX);
	memset(&new->timens, 0, sizeof(struct timens_offsets));
	seccomp_conf_init(new);

	INIT_LIST_HEAD(&new->netdevs);

	return new;
}

int write_id_mapping(enum idtype idtype, pid_t pid, const char *buf,
		     size_t buf_size)
{
	__do_close int fd = -EBADF;
	int ret;
	char path[PATH_MAX];

	if (geteuid() != 0 && idtype == ID_TYPE_GID) {
		__do_close int setgroups_fd = -EBADF;

		ret = strnprintf(path, sizeof(path), "/proc/%d/setgroups", pid);
		if (ret < 0)
			return -E2BIG;

		setgroups_fd = open(path, O_WRONLY);
		if (setgroups_fd < 0 && errno != ENOENT)
			return log_error_errno(-1, errno, "Failed to open \"%s\"", path);

		if (setgroups_fd >= 0) {
			ret = lxc_write_nointr(setgroups_fd, "deny\n",
					       STRLITERALLEN("deny\n"));
			if (ret != STRLITERALLEN("deny\n"))
				return log_error_errno(-1, errno, "Failed to write \"deny\" to \"/proc/%d/setgroups\"", pid);
			TRACE("Wrote \"deny\" to \"/proc/%d/setgroups\"", pid);
		}
	}

	ret = strnprintf(path, sizeof(path), "/proc/%d/%cid_map", pid,
		       idtype == ID_TYPE_UID ? 'u' : 'g');
	if (ret < 0)
		return -E2BIG;

	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return log_error_errno(-1, errno, "Failed to open \"%s\"", path);

	ret = lxc_write_nointr(fd, buf, buf_size);
	if (ret < 0 || (size_t)ret != buf_size)
		return log_error_errno(-1, errno, "Failed to write %cid mapping to \"%s\"",
				       idtype == ID_TYPE_UID ? 'u' : 'g', path);

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
	__do_free char *path = NULL;
	int ret;
	struct stat st;

	if (cap != CAP_SETUID && cap != CAP_SETGID)
		return ret_errno(EINVAL);

	path = on_path(binary, NULL);
	if (!path)
		return ret_errno(ENOENT);

	ret = stat(path, &st);
	if (ret < 0)
		return -errno;

	/* Check if the binary is setuid. */
	if (st.st_mode & S_ISUID)
		return log_debug(1, "The binary \"%s\" does have the setuid bit set", path);

#if HAVE_LIBCAP && LIBCAP_SUPPORTS_FILE_CAPABILITIES
	/* Check if it has the CAP_SETUID capability. */
	if ((cap & CAP_SETUID) &&
	    lxc_file_cap_is_set(path, CAP_SETUID, CAP_EFFECTIVE) &&
	    lxc_file_cap_is_set(path, CAP_SETUID, CAP_PERMITTED))
		return log_debug(1, "The binary \"%s\" has CAP_SETUID in its CAP_EFFECTIVE and CAP_PERMITTED sets", path);

	/* Check if it has the CAP_SETGID capability. */
	if ((cap & CAP_SETGID) &&
	    lxc_file_cap_is_set(path, CAP_SETGID, CAP_EFFECTIVE) &&
	    lxc_file_cap_is_set(path, CAP_SETGID, CAP_PERMITTED))
		return log_debug(1, "The binary \"%s\" has CAP_SETGID in its CAP_EFFECTIVE and CAP_PERMITTED sets", path);

	return 0;
#else
	/*
	 * If we cannot check for file capabilities we need to give the benefit
	 * of the doubt. Otherwise we might fail even though all the necessary
	 * file capabilities are set.
	 */
	DEBUG("Cannot check for file capabilities as full capability support is missing. Manual intervention needed");
	return 1;
#endif
}

static int lxc_map_ids_exec_wrapper(void *args)
{
	execl("/bin/sh", "sh", "-c", (char *)args, (char *)NULL);
	return -1;
}

static struct id_map *find_mapped_hostid_entry(const struct list_head *idmap,
					       unsigned id, enum idtype idtype);

int lxc_map_ids(struct list_head *idmap, pid_t pid)
{
	int fill, left;
	uid_t hostuid;
	gid_t hostgid;
	char u_or_g;
	char *pos;
	char cmd_output[PATH_MAX];
	struct id_map *map;
	enum idtype type;
	int ret = 0, gidmap = 0, uidmap = 0;
	char mapbuf[STRLITERALLEN("new@idmap") + STRLITERALLEN(" ") +
		    INTTYPE_TO_STRLEN(pid_t) + STRLITERALLEN(" ") +
		    LXC_IDMAPLEN] = {0};
	bool had_entry = false, maps_host_root = false, use_shadow = false;

	hostuid = geteuid();
	hostgid = getegid();

	/*
	 * Check whether caller wants to map host root.
	 * Due to a security fix newer kernels require CAP_SETFCAP when mapping
	 * host root into the child userns as you would be able to write fscaps
	 * that would be valid in the ancestor userns. Mapping host root should
	 * rarely be the case but LXC is being clever in a bunch of cases.
	 */
	if (find_mapped_hostid_entry(idmap, 0, ID_TYPE_UID))
		maps_host_root = true;

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

	if (maps_host_root) {
		INFO("Caller maps host root. Writing mapping directly");
	} else if (uidmap > 0 && gidmap > 0) {
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
	* If the user is only remapping their own {g,u}id, we don't need it.
	*/
	if (use_shadow && list_len(map, idmap, head) == 2) {
		use_shadow = false;
		list_for_each_entry(map, idmap, head) {
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

		list_for_each_entry(map, idmap, head) {
			if (map->idtype != type)
				continue;

			had_entry = true;

			left = LXC_IDMAPLEN - (pos - mapbuf);
			fill = strnprintf(pos, left, "%s%lu %lu %lu%s",
					use_shadow ? " " : "", map->nsid,
					map->hostid, map->range,
					use_shadow ? "" : "\n");
			/*
			 * The kernel only takes <= 4k for writes to
			 * /proc/<pid>/{g,u}id_map
			 */
			if (fill <= 0)
				return log_error_errno(-1, errno, "Too many %cid mappings defined", u_or_g);

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
			if (ret < 0)
				return log_error(-1, "new%cidmap failed to write mapping \"%s\": %s", u_or_g, cmd_output, mapbuf);
			TRACE("new%cidmap wrote mapping \"%s\"", u_or_g, mapbuf);
		} else {
			ret = write_id_mapping(type, pid, mapbuf, pos - mapbuf);
			if (ret < 0)
				return log_error(-1, "Failed to write mapping: %s", mapbuf);
			TRACE("Wrote mapping \"%s\"", mapbuf);
		}

		memset(mapbuf, 0, sizeof(mapbuf));
	}

	return 0;
}

/*
 * Return the host uid/gid to which the container root is mapped in val.
 * Return true if id was found, false otherwise.
 */
static id_t get_mapped_rootid(const struct lxc_conf *conf, enum idtype idtype)
{
	unsigned nsid;
	struct id_map *map;

	if (idtype == ID_TYPE_UID)
		nsid = (conf->root_nsuid_map != NULL) ? 0 : conf->init_uid;
	else
		nsid = (conf->root_nsgid_map != NULL) ? 0 : conf->init_gid;

	list_for_each_entry (map, &conf->id_map, head) {
		if (map->idtype != idtype)
			continue;
		if (map->nsid != nsid)
			continue;
		return map->hostid;
	}

	if (idtype == ID_TYPE_UID)
		return LXC_INVALID_UID;

	return LXC_INVALID_GID;
}

int mapped_hostid(unsigned id, const struct lxc_conf *conf, enum idtype idtype)
{
	struct id_map *map;

	list_for_each_entry(map, &conf->id_map, head) {
		if (map->idtype != idtype)
			continue;

		if (id >= map->hostid && id < map->hostid + map->range)
			return (id - map->hostid) + map->nsid;
	}

	return -1;
}

int find_unmapped_nsid(const struct lxc_conf *conf, enum idtype idtype)
{
	struct id_map *map;
	unsigned int freeid = 0;

again:
	list_for_each_entry(map, &conf->id_map, head) {
		if (map->idtype != idtype)
			continue;

		if (freeid >= map->nsid && freeid < map->nsid + map->range) {
			freeid = map->nsid + map->range;
			goto again;
		}
	}

	return freeid;
}

/*
 * Mount a proc under @rootfs if proc self points to a pid other than
 * my own.  This is needed to have a known-good proc mount for setting
 * up LSMs both at container startup and attach.
 *
 * NOTE: not to be called from inside the container namespace!
 */
static int lxc_transient_proc(struct lxc_rootfs *rootfs)
{
	__do_close int fd_proc = -EBADF;
	int link_to_pid, link_len, pid_self, ret;
	char link[INTTYPE_TO_STRLEN(pid_t) + 1];

	link_len = readlinkat(rootfs->dfd_mnt, "proc/self", link, sizeof(link));
	if (link_len < 0) {
		ret = mkdirat(rootfs->dfd_mnt, "proc", 0000);
		if (ret < 0 && errno != EEXIST)
			return log_error_errno(-errno, errno, "Failed to create %d(proc)", rootfs->dfd_mnt);

		goto domount;
	} else if ((size_t)link_len >= sizeof(link)) {
		return log_error_errno(-EIO, EIO, "Truncated link target");
	}
	link[link_len] = '\0';

	pid_self = lxc_raw_getpid();
	INFO("Caller's PID is %d; /proc/self points to %s", pid_self, link);

	ret = lxc_safe_int(link, &link_to_pid);
	if (ret)
		return log_error_errno(-ret, ret, "Failed to parse %s", link);

	/* Correct procfs is already mounted. */
	if (link_to_pid == pid_self)
		return log_trace(0, "Correct procfs instance mounted");

	fd_proc = open_at(rootfs->dfd_mnt, "proc", PROTECT_OPATH_DIRECTORY,
			  PROTECT_LOOKUP_BENEATH_XDEV, 0);
	if (fd_proc < 0)
		return log_error_errno(-errno, errno, "Failed to open transient procfs mountpoint");

	ret = strnprintf(rootfs->buf, sizeof(rootfs->buf), "/proc/self/fd/%d", fd_proc);
	if (ret < 0)
		return ret_errno(EIO);

	ret = umount2(rootfs->buf, MNT_DETACH);
	if (ret < 0)
		SYSWARN("Failed to umount \"%s\" with MNT_DETACH", rootfs->buf);

domount:
	/* rootfs is NULL */
	if (!rootfs->path) {
		ret = mount("proc", rootfs->buf, "proc", 0, NULL);
	} else {
		ret = safe_mount_beneath_at(rootfs->dfd_mnt, "none", "proc", "proc", 0, NULL);
		if (ret < 0) {
			ret = strnprintf(rootfs->buf, sizeof(rootfs->buf), "%s/proc", rootfs->path ? rootfs->mount : "");
			if (ret < 0)
				return ret_errno(EIO);

			ret = safe_mount("proc", rootfs->buf, "proc", 0, NULL, rootfs->mount);
		}
	}
	if (ret < 0)
		return log_error_errno(-1, errno, "Failed to mount temporary procfs");

	INFO("Created transient procfs mount");
	return 1;
}

/* NOTE: Must not be called from inside the container namespace! */
static int lxc_create_tmp_proc_mount(struct lxc_conf *conf)
{
	int mounted;

	mounted = lxc_transient_proc(&conf->rootfs);
	if (mounted == -1) {
		/* continue only if there is no rootfs */
		if (conf->rootfs.path)
			return log_error_errno(-EPERM, EPERM, "Failed to create transient procfs mount");
	} else if (mounted == 1) {
		conf->transient_procfs_mnt = true;
	}

	return 0;
}

void tmp_proc_unmount(struct lxc_conf *lxc_conf)
{
	if (lxc_conf->transient_procfs_mnt) {
		(void)umount2("/proc", MNT_DETACH);
		lxc_conf->transient_procfs_mnt = false;
	}
}

/* Walk /proc/mounts and change any shared entries to dependent mounts. */
static void turn_into_dependent_mounts(const struct lxc_rootfs *rootfs)
{
	__do_free char *line = NULL;
	__do_fclose FILE *f = NULL;
	__do_close int memfd = -EBADF, mntinfo_fd = -EBADF;
	size_t len = 0;
	ssize_t copied;
	int ret;

	mntinfo_fd = open_at(rootfs->dfd_host, "proc/self/mountinfo", PROTECT_OPEN,
			     (PROTECT_LOOKUP_BENEATH_XDEV & ~RESOLVE_NO_SYMLINKS), 0);
	if (mntinfo_fd < 0) {
		SYSERROR("Failed to open %d/proc/self/mountinfo", rootfs->dfd_host);
		return;
	}

	memfd = memfd_create(".lxc_mountinfo", MFD_CLOEXEC);
	if (memfd < 0) {
		char template[] = P_tmpdir "/.lxc_mountinfo_XXXXXX";

		if (errno != ENOSYS) {
			SYSERROR("Failed to create temporary in-memory file");
			return;
		}

		memfd = lxc_make_tmpfile(template, true);
		if (memfd < 0) {
			WARN("Failed to create temporary file");
			return;
		}
	}

	copied = fd_to_fd(mntinfo_fd, memfd);
	if (copied < 0) {
		SYSERROR("Failed to copy \"/proc/self/mountinfo\"");
		return;
	}

	ret = lseek(memfd, 0, SEEK_SET);
	if (ret < 0) {
		SYSERROR("Failed to reset file descriptor offset");
		return;
	}

	f = fdopen(memfd, "re");
	if (!f) {
		SYSERROR("Failed to open copy of \"/proc/self/mountinfo\" to mark all shared. Continuing");
		return;
	}

	/*
	 * After a successful fdopen() memfd will be closed when calling
	 * fclose(f). Calling close(memfd) afterwards is undefined.
	 */
	move_fd(memfd);

	while (getline(&line, &len, f) != -1) {
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
			SYSERROR("Failed to recursively turn old root mount tree into dependent mount. Continuing...");
			continue;
		}
	}
	TRACE("Turned all mount table entries into dependent mount");
}

/* This does the work of remounting / if it is shared, calling the container
 * pre-mount hooks, and mounting the rootfs.
 */
int lxc_setup_rootfs_prepare_root(struct lxc_conf *conf, const char *name,
				  const char *lxcpath)
{
	int ret;

	conf->rootfs.dfd_host = open_at(-EBADF, "/", PROTECT_OPATH_DIRECTORY, PROTECT_LOOKUP_ABSOLUTE, 0);
	if (conf->rootfs.dfd_host < 0)
		return log_error_errno(-errno, errno, "Failed to open \"/\"");

	turn_into_dependent_mounts(&conf->rootfs);

	if (conf->rootfs_setup) {
		const char *path = conf->rootfs.mount;

		/*
		 * The rootfs was set up in another namespace. bind-mount it to
		 * give us a mount in our own ns so we can pivot_root to it
		 */
		ret = mount(path, path, "rootfs", MS_BIND, NULL);
		if (ret < 0)
			return log_error(-1, "Failed to bind mount container / onto itself");

		conf->rootfs.dfd_mnt = openat(-EBADF, path, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_PATH | O_NOCTTY);
		if (conf->rootfs.dfd_mnt < 0)
			return log_error_errno(-errno, errno, "Failed to open file descriptor for container rootfs");

		return log_trace(0, "Bind mounted container / onto itself");
	}

	ret = run_lxc_hooks(name, "pre-mount", conf, NULL);
	if (ret < 0)
		return log_error(-1, "Failed to run pre-mount hooks");

	ret = lxc_mount_rootfs(&conf->rootfs);
	if (ret < 0)
		return log_error(-1, "Failed to setup rootfs for");

	conf->rootfs_setup = true;
	return 0;
}

static bool verify_start_hooks(struct lxc_conf *conf)
{
	char path[PATH_MAX];
	struct string_entry *hook;

	list_for_each_entry(hook, &conf->hooks[LXCHOOK_START], head) {
		int ret;
		char *hookname = hook->val;

		ret = strnprintf(path, sizeof(path), "%s%s",
			       conf->rootfs.path ? conf->rootfs.mount : "",
			       hookname);
		if (ret < 0)
			return false;

		ret = access(path, X_OK);
		if (ret < 0)
			return log_error_errno(false, errno, "Start hook \"%s\" not found in container", hookname);

		return true;
	}

	return true;
}

static int lxc_setup_boot_id(void)
{
	int ret;
	const char *boot_id_path = "/proc/sys/kernel/random/boot_id";
	const char *mock_boot_id_path = "/dev/.lxc-boot-id";
	lxc_id128_t n;

	if (access(boot_id_path, F_OK))
		return 0;

	memset(&n, 0, sizeof(n));
	if (lxc_id128_randomize(&n)) {
		SYSERROR("Failed to generate random data for uuid");
		return -1;
	}

	ret = lxc_id128_write(mock_boot_id_path, n);
	if (ret < 0) {
		SYSERROR("Failed to write uuid to %s", mock_boot_id_path);
		return -1;
	}

	ret = chmod(mock_boot_id_path, 0444);
	if (ret < 0) {
		SYSERROR("Failed to chown %s", mock_boot_id_path);
		(void)unlink(mock_boot_id_path);
		return -1;
	}

	ret = mount(mock_boot_id_path, boot_id_path, NULL, MS_BIND, NULL);
	if (ret < 0) {
		SYSERROR("Failed to mount %s to %s", mock_boot_id_path,
			 boot_id_path);
		(void)unlink(mock_boot_id_path);
		return -1;
	}

	ret = mount(NULL, boot_id_path, NULL,
		    (MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NOEXEC |
		     MS_NODEV),
		    NULL);
	if (ret < 0) {
		SYSERROR("Failed to remount %s read-only", boot_id_path);
		(void)unlink(mock_boot_id_path);
		return -1;
	}

	return 0;
}

static int lxc_setup_keyring(struct lsm_ops *lsm_ops, const struct lxc_conf *conf)
{
	key_serial_t keyring;
	int ret = 0;

	if (conf->lsm_se_keyring_context)
		ret = lsm_ops->keyring_label_set(lsm_ops, conf->lsm_se_keyring_context);
	else if (conf->lsm_se_context)
		ret = lsm_ops->keyring_label_set(lsm_ops, conf->lsm_se_context);
	if (ret < 0)
		return syserror("Failed to set keyring context");

	/*
	 * Try to allocate a new session keyring for the container to prevent
	 * information leaks.
	 */
	keyring = keyctl(KEYCTL_JOIN_SESSION_KEYRING, prctl_arg(0),
			 prctl_arg(0), prctl_arg(0), prctl_arg(0));
	if (keyring < 0) {
		switch (errno) {
		case ENOSYS:
			DEBUG("The keyctl() syscall is not supported or blocked");
			break;
		case EACCES:
			__fallthrough;
		case EPERM:
			DEBUG("Failed to access kernel keyring. Continuing...");
			break;
		default:
			SYSWARN("Failed to create kernel keyring");
			break;
		}
	}

	return ret;
}

static int lxc_rootfs_prepare_child(struct lxc_handler *handler)
{
	struct lxc_rootfs *rootfs = &handler->conf->rootfs;
	int dfd_idmapped = -EBADF;
	int ret;

	if (list_empty(&handler->conf->id_map))
		return 0;

	if (is_empty_string(rootfs->mnt_opts.userns_path))
		return 0;

	if (handler->conf->rootfs_setup)
		return 0;

	ret = lxc_abstract_unix_recv_one_fd(handler->data_sock[1], &dfd_idmapped, NULL, 0);
	if (ret < 0)
		return syserror("Failed to receive idmapped mount fd");

	rootfs->dfd_idmapped = dfd_idmapped;
	TRACE("Received detached idmapped mount %d", rootfs->dfd_idmapped);
	return 0;
}

int lxc_idmapped_mounts_parent(struct lxc_handler *handler)
{
	int mnt_seq = 0;

	for (;;) {
		__do_close int fd_from = -EBADF, fd_userns = -EBADF;
		struct mount_attr attr = {};
		struct lxc_mount_options opts = {};
		ssize_t ret;

		ret = __lxc_abstract_unix_recv_two_fds(handler->data_sock[1],
						       &fd_from, &fd_userns,
						       &opts, sizeof(opts));
		if (ret < 0)
			return syserror("Failed to receive idmapped mount file descriptors from child");

		if (fd_from < 0 || fd_userns < 0)
			return log_trace(0, "Finished receiving idmapped mount file descriptors (%d | %d) from child", fd_from, fd_userns);

		attr.attr_set	= MOUNT_ATTR_IDMAP;
		attr.userns_fd	= fd_userns;
		ret = mount_setattr(fd_from, "",
				    AT_EMPTY_PATH |
				    (opts.bind_recursively ? AT_RECURSIVE : 0),
				    &attr, sizeof(attr));
		if (ret)
			return syserror("Failed to idmap detached %smount %d to %d",
					opts.bind_recursively ? "recursive " : "",
					fd_from, fd_userns);

		ret = lxc_abstract_unix_send_credential(handler->data_sock[1],
							&mnt_seq,
							sizeof(mnt_seq));
		if (ret < 0)
			return syserror("Parent failed to notify child that detached %smount %d was idmapped to user namespace %d",
					opts.bind_recursively ? "recursive " : "",
					fd_from, fd_userns);

		TRACE("Parent idmapped detached %smount %d to user namespace %d",
		      opts.bind_recursively ? "recursive " : "", fd_from, fd_userns);
		mnt_seq++;
	}
}

static int lxc_recv_ttys_from_child(struct lxc_handler *handler)
{
	call_cleaner(lxc_delete_tty) struct lxc_tty_info *info_new = &(struct lxc_tty_info){};
	int sock = handler->data_sock[1];
	struct lxc_conf *conf = handler->conf;
	struct lxc_tty_info *tty_info = &conf->ttys;
	size_t ttys_max = tty_info->max;
	struct lxc_terminal_info *terminal_info;
	int ret;

	if (!ttys_max)
		return 0;

	info_new->tty = malloc(sizeof(*(info_new->tty)) * ttys_max);
	if (!info_new->tty)
		return ret_errno(ENOMEM);

	for (size_t i = 0; i < ttys_max; i++) {
		terminal_info = &info_new->tty[i];
		terminal_info->busy = -1;
		terminal_info->pty_nr = -1;
		terminal_info->ptx = -EBADF;
		terminal_info->pty = -EBADF;
	}

	for (size_t i = 0; i < ttys_max; i++) {
		int ptx = -EBADF, pty = -EBADF;

		ret = lxc_abstract_unix_recv_two_fds(sock, &ptx, &pty);
		if (ret < 0)
			return syserror("Failed to receive %zu ttys from child", ttys_max);

		terminal_info = &info_new->tty[i];
		terminal_info->ptx = ptx;
		terminal_info->pty = pty;
		TRACE("Received pty with ptx fd %d and pty fd %d from child",
		      terminal_info->ptx, terminal_info->pty);
	}

	tty_info->tty = move_ptr(info_new->tty);
	TRACE("Received %zu ttys from child", ttys_max);
	return 0;
}

static int lxc_send_console_to_parent(struct lxc_handler *handler)
{
	struct lxc_terminal *console = &handler->conf->console;
	int ret;

	if (!wants_console(console))
		return 0;

	/* We've already allocated a console from the host's devpts instance. */
	if (console->pty < 0)
		return 0;

	ret = __lxc_abstract_unix_send_two_fds(handler->data_sock[0],
					       console->ptx, console->pty,
					       console,
					       sizeof(struct lxc_terminal));
	if (ret < 0)
		return syserror("Fail to send console to parent");

	TRACE("Sent console to parent");
	return 0;
}

static int lxc_recv_console_from_child(struct lxc_handler *handler)
{
	__do_close int fd_ptx = -EBADF, fd_pty = -EBADF;
	struct lxc_terminal *console = &handler->conf->console;
	int ret;

	if (!wants_console(console))
		return 0;

	/* We've already allocated a console from the host's devpts instance. */
	if (console->pty >= 0)
		return 0;

	ret = __lxc_abstract_unix_recv_two_fds(handler->data_sock[1],
					       &fd_ptx, &fd_pty,
					       console,
					       sizeof(struct lxc_terminal));
	if (ret < 0)
		return syserror("Fail to receive console from child");

	console->ptx = move_fd(fd_ptx);
	console->pty = move_fd(fd_pty);

	TRACE("Received console from child");
	return 0;
}

int lxc_sync_fds_parent(struct lxc_handler *handler)
{
	int ret;

	ret = lxc_seccomp_recv_notifier_fd(&handler->conf->seccomp, handler->data_sock[1]);
	if (ret < 0)
		return syserror_ret(ret, "Failed to receive seccomp notify fd from child");

	ret = lxc_recv_devpts_from_child(handler);
	if (ret < 0)
		return syserror_ret(ret, "Failed to receive devpts fd from child");

	/* Read tty fds allocated by child. */
	ret = lxc_recv_ttys_from_child(handler);
	if (ret < 0)
		return syserror_ret(ret, "Failed to receive tty info from child process");

	if (handler->ns_clone_flags & CLONE_NEWNET) {
		ret = lxc_network_recv_name_and_ifindex_from_child(handler);
		if (ret < 0)
			return syserror_ret(ret, "Failed to receive names and ifindices for network devices from child");
	}

	ret = lxc_recv_console_from_child(handler);
	if (ret < 0)
		return syserror_ret(ret, "Failed to receive console from child");

	TRACE("Finished syncing file descriptors with child");
	return 0;
}

int lxc_sync_fds_child(struct lxc_handler *handler)
{
	int ret;

	ret = lxc_seccomp_send_notifier_fd(&handler->conf->seccomp, handler->data_sock[0]);
	if (ret < 0)
		return syserror_ret(ret, "Failed to send seccomp notify fd to parent");

	ret = lxc_send_devpts_to_parent(handler);
	if (ret < 0)
		return syserror_ret(ret, "Failed to send seccomp devpts fd to parent");

	ret = lxc_send_ttys_to_parent(handler);
	if (ret < 0)
		return syserror_ret(ret, "Failed to send tty file descriptors to parent");

	if (handler->ns_clone_flags & CLONE_NEWNET) {
		ret = lxc_network_send_name_and_ifindex_to_parent(handler);
		if (ret < 0)
			return syserror_ret(ret, "Failed to send network device names and ifindices to parent");
	}

	ret = lxc_send_console_to_parent(handler);
	if (ret < 0)
		return syserror_ret(ret, "Failed to send console to parent");

	TRACE("Finished syncing file descriptors with parent");
	return 0;
}

static int setup_capabilities(struct lxc_conf *conf)
{
	int ret;

	if (conf->caps.keep)
		ret = capabilities_allow(conf);
	else
		ret = capabilities_deny(conf);
	if (ret < 0)
		return syserror_ret(ret, "Failed to %s capabilities", conf->caps.keep ? "allow" : "deny");

	return 0;
}

static int make_shmount_dependent_mount(const struct lxc_conf *conf)
{
	if (!(conf->auto_mounts & LXC_AUTO_SHMOUNTS_MASK))
		return 0;

	return mount(NULL, conf->shmount.path_cont, NULL, MS_REC | MS_SLAVE, 0);
}

int lxc_setup(struct lxc_handler *handler)
{
	int ret;
	const char *lxcpath = handler->lxcpath, *name = handler->name;
	struct lxc_conf *lxc_conf = handler->conf;

	ret = lxc_rootfs_prepare_child(handler);
	if (ret < 0)
		return syserror("Failed to prepare rootfs");

	ret = lxc_setup_rootfs_prepare_root(lxc_conf, name, lxcpath);
	if (ret < 0)
		return log_error(-1, "Failed to setup rootfs");

	if (handler->nsfd[LXC_NS_UTS] == -EBADF) {
		ret = setup_utsname(lxc_conf->utsname);
		if (ret < 0)
			return log_error(-1, "Failed to setup the utsname %s", name);
	}

	if (!lxc_conf->keyring_disable_session) {
		ret = lxc_setup_keyring(handler->lsm_ops, lxc_conf);
		if (ret < 0)
			return log_error(-1, "Failed to setup container keyring");
	}

	if (handler->ns_clone_flags & CLONE_NEWNET) {
		ret = lxc_network_recv_from_parent(handler);
		if (ret < 0)
			return log_error(-1, "Failed to receive veth names from parent");

		ret = lxc_setup_network_in_child_namespaces(lxc_conf);
		if (ret < 0)
			return log_error(-1, "Failed to setup network");
	}

	if (lxc_conf->autodev > 0) {
		ret = mount_autodev(name, &lxc_conf->rootfs, lxc_conf->autodevtmpfssize, lxcpath);
		if (ret < 0)
			return log_error(-1, "Failed to mount \"/dev\"");
	}

	/* Do automatic mounts (mainly /proc and /sys), but exclude those that
	 * need to wait until other stuff has finished.
	 */
	ret = lxc_mount_auto_mounts(handler, lxc_conf->auto_mounts & ~LXC_AUTO_CGROUP_MASK);
	if (ret < 0)
		return log_error(-1, "Failed to setup first automatic mounts");

	ret = setup_mount_fstab(&lxc_conf->rootfs, lxc_conf->fstab, name, lxcpath);
	if (ret < 0)
		return log_error(-1, "Failed to setup mounts");

	if (!list_empty(&lxc_conf->mount_entries)) {
		ret = setup_mount_entries(lxc_conf, &lxc_conf->rootfs, name, lxcpath);
		if (ret < 0)
			return log_error(-1, "Failed to setup mount entries");
	}

	if (!lxc_sync_wake_parent(handler, START_SYNC_IDMAPPED_MOUNTS))
		return -1;

	ret = lxc_idmapped_mounts_child(handler);
	if (ret)
		return syserror("Failed to attached detached idmapped mounts");

	lxc_conf->rootfs.dfd_dev = open_at(lxc_conf->rootfs.dfd_mnt, "dev",
					   PROTECT_OPATH_DIRECTORY, PROTECT_LOOKUP_BENEATH_XDEV, 0);
	if (lxc_conf->rootfs.dfd_dev < 0 && errno != ENOENT)
		return log_error_errno(-errno, errno, "Failed to open \"/dev\"");

	/* Now mount only cgroups, if wanted. Before, /sys could not have been
	 * mounted. It is guaranteed to be mounted now either through
	 * automatically or via fstab entries.
	 */
	ret = lxc_mount_auto_mounts(handler, lxc_conf->auto_mounts & LXC_AUTO_CGROUP_MASK);
	if (ret < 0)
		return log_error(-1, "Failed to setup remaining automatic mounts");

	ret = run_lxc_hooks(name, "mount", lxc_conf, NULL);
	if (ret < 0)
		return log_error(-1, "Failed to run mount hooks");

	if (lxc_rootfs_overmounted(&lxc_conf->rootfs))
		return log_error(-1, "Rootfs overmounted");

	if (lxc_conf->autodev > 0) {
		ret = run_lxc_hooks(name, "autodev", lxc_conf, NULL);
		if (ret < 0)
			return log_error(-1, "Failed to run autodev hooks");

		ret = lxc_fill_autodev(&lxc_conf->rootfs);
		if (ret < 0)
			return log_error(-1, "Failed to populate \"/dev\"");
	}

	/* Make sure any start hooks are in the container */
	if (!verify_start_hooks(lxc_conf))
		return log_error(-1, "Failed to verify start hooks");

	ret = lxc_create_tmp_proc_mount(lxc_conf);
	if (ret < 0)
		return log_error(-1, "Failed to mount transient procfs instance for LSMs");

	ret = lxc_setup_devpts_child(handler);
	if (ret < 0)
		return log_error(-1, "Failed to prepare new devpts instance");

	ret = lxc_finish_devpts_child(handler);
	if (ret < 0)
		return log_error(-1, "Failed to finish devpts setup");

	ret = lxc_setup_console(handler, &lxc_conf->rootfs, &lxc_conf->console,
				lxc_conf->ttys.dir);
	if (ret < 0)
		return log_error(-1, "Failed to setup console");

	ret = lxc_create_ttys(handler);
	if (ret < 0)
		return log_error(-1, "Failed to create ttys");

	ret = lxc_setup_dev_symlinks(&lxc_conf->rootfs);
	if (ret < 0)
		return log_error(-1, "Failed to setup \"/dev\" symlinks");

	ret = lxc_setup_rootfs_switch_root(&lxc_conf->rootfs);
	if (ret < 0)
		return log_error(-1, "Failed to pivot root into rootfs");

	ret = make_shmount_dependent_mount(lxc_conf);
	if (ret < 0)
		return log_error(-1, "Failed to turn mount tunnel \"%s\" into dependent mount",
				 lxc_conf->shmount.path_cont);

	/* Setting the boot-id is best-effort for now. */
	if (lxc_conf->autodev > 0)
		(void)lxc_setup_boot_id();

	ret = setup_personality(lxc_conf->personality);
	if (ret < 0)
		return syserror("Failed to set personality");

	/* Set sysctl value to a path under /proc/sys as determined from the
	 * key. For e.g. net.ipv4.ip_forward translated to
	 * /proc/sys/net/ipv4/ip_forward.
	 */
	ret = setup_sysctl_parameters(lxc_conf);
	if (ret < 0)
		return log_error(-1, "Failed to setup sysctl parameters");

	ret = setup_capabilities(lxc_conf);
	if (ret < 0)
		return log_error(-1, "Failed to setup capabilities");

	put_lxc_rootfs(&handler->conf->rootfs, true);
	NOTICE("The container \"%s\" is set up", name);

	return 0;
}

int run_lxc_hooks(const char *name, char *hookname, struct lxc_conf *conf,
		  char *argv[])
{
	int which;
	struct string_entry *entry;

	for (which = 0; which < NUM_LXC_HOOKS; which ++) {
		if (strequal(hookname, lxchook_names[which]))
			break;
	}

	if (which >= NUM_LXC_HOOKS)
		return -1;

	list_for_each_entry(entry, &conf->hooks[which], head) {
		int ret;
		char *hook = entry->val;

		ret = run_script_argv(name, conf->hooks_version, "lxc", hook,
				      hookname, argv);
		if (ret < 0)
			return -1;
	}

	return 0;
}

int lxc_clear_config_caps(struct lxc_conf *c)
{
	struct cap_entry *cap, *ncap;

	list_for_each_entry_safe(cap, ncap, &c->caps.list, head) {
		list_del(&cap->head);
		free(cap->cap_name);
		free(cap);
	}

	c->caps.keep = false;
	INIT_LIST_HEAD(&c->caps.list);
	return 0;
}

static int lxc_free_idmap(struct list_head *id_map)
{
	struct id_map *map, *nmap;

	list_for_each_entry_safe(map, nmap, id_map, head) {
		list_del(&map->head);
		free(map);
	}

	INIT_LIST_HEAD(id_map);
	return 0;
}

static int __lxc_free_idmap(struct list_head *id_map)
{
	lxc_free_idmap(id_map);
	return 0;
}
define_cleanup_function(struct list_head *, __lxc_free_idmap);

int lxc_clear_idmaps(struct lxc_conf *c)
{
	return lxc_free_idmap(&c->id_map);
}

int lxc_clear_namespace(struct lxc_conf *c)
{
	for (int i = 0; i < LXC_NS_MAX; i++)
		free_disarm(c->ns_share[i]);

	return 0;
}

int lxc_clear_cgroups(struct lxc_conf *c, const char *key, int version)
{
	const char *k = key;
	bool all = false;
	char *global_token, *namespaced_token;
	size_t namespaced_token_len;
	struct list_head *list;
	struct lxc_cgroup *cgroup, *ncgroup;

	if (version == CGROUP2_SUPER_MAGIC) {
		global_token		= "lxc.cgroup2";
		namespaced_token	= "lxc.cgroup2.";
		namespaced_token_len	= STRLITERALLEN("lxc.cgroup2.");
		list = &c->cgroup2;
	} else if (version == CGROUP_SUPER_MAGIC) {
		global_token		= "lxc.cgroup";
		namespaced_token	= "lxc.cgroup.";
		namespaced_token_len	= STRLITERALLEN("lxc.cgroup.");
		list = &c->cgroup;
	} else {
		return ret_errno(EINVAL);
	}

	if (strequal(key, global_token))
		all = true;
	else if (strnequal(key, namespaced_token, namespaced_token_len))
		k += namespaced_token_len;
	else
		return ret_errno(EINVAL);

	list_for_each_entry_safe(cgroup, ncgroup, list, head) {
		if (!all && !strequal(cgroup->subsystem, k))
			continue;

		list_del(&cgroup->head);
		free(cgroup->subsystem);
		free(cgroup->value);
		free(cgroup);
	}

	if (all)
		INIT_LIST_HEAD(list);

	return 0;
}

static inline void lxc_clear_cgroups_devices(struct lxc_conf *conf)
{
	lxc_clear_cgroup2_devices(&conf->bpf_devices);
}

int lxc_clear_limits(struct lxc_conf *c, const char *key)
{
	const char *k = NULL;
	bool all = false;
	struct lxc_limit *lim, *nlim;

	if (strequal(key, "lxc.limit") || strequal(key, "lxc.prlimit"))
		all = true;
	else if (strnequal(key, "lxc.limit.", STRLITERALLEN("lxc.limit.")))
		k = key + STRLITERALLEN("lxc.limit.");
	else if (strnequal(key, "lxc.prlimit.", STRLITERALLEN("lxc.prlimit.")))
		k = key + STRLITERALLEN("lxc.prlimit.");
	else
		return ret_errno(EINVAL);

	list_for_each_entry_safe(lim, nlim, &c->limits, head) {
		if (!all && !strequal(lim->resource, k))
			continue;

		list_del(&lim->head);
		free_disarm(lim->resource);
		free(lim);
	}

	if (all)
		INIT_LIST_HEAD(&c->limits);

	return 0;
}

int lxc_clear_sysctls(struct lxc_conf *c, const char *key)
{
	const char *k = NULL;
	bool all = false;
	struct lxc_sysctl *sysctl, *nsysctl;

	if (strequal(key, "lxc.sysctl"))
		all = true;
	else if (strnequal(key, "lxc.sysctl.", STRLITERALLEN("lxc.sysctl.")))
		k = key + STRLITERALLEN("lxc.sysctl.");
	else
		return -1;

	list_for_each_entry_safe(sysctl, nsysctl, &c->sysctls, head) {
		if (!all && !strequal(sysctl->key, k))
			continue;

		list_del(&sysctl->head);
		free(sysctl->key);
		free(sysctl->value);
		free(sysctl);
	}

	if (all)
		INIT_LIST_HEAD(&c->sysctls);

	return 0;
}

int lxc_clear_procs(struct lxc_conf *c, const char *key)
{
	const char *k = NULL;
	bool all = false;
	struct lxc_proc *proc, *nproc;

	if (strequal(key, "lxc.proc"))
		all = true;
	else if (strnequal(key, "lxc.proc.", STRLITERALLEN("lxc.proc.")))
		k = key + STRLITERALLEN("lxc.proc.");
	else
		return -1;

	list_for_each_entry_safe(proc, nproc, &c->procs, head) {
		if (!all && !strequal(proc->filename, k))
			continue;

		list_del(&proc->head);
		free(proc->filename);
		free(proc->value);
		free(proc);
	}

	if (all)
		INIT_LIST_HEAD(&c->procs);

	return 0;
}

int lxc_clear_groups(struct lxc_conf *c)
{
	struct string_entry *entry, *nentry;

	list_for_each_entry_safe(entry, nentry, &c->groups, head) {
		list_del(&entry->head);
		free(entry->val);
		free(entry);
	}

	INIT_LIST_HEAD(&c->groups);
	return 0;
}

int lxc_clear_environment(struct lxc_conf *c)
{
	struct environment_entry *env, *nenv;

	list_for_each_entry_safe(env, nenv, &c->environment, head) {
		list_del(&env->head);
		free(env->key);
		free(env->val);
		free(env);
	}

	INIT_LIST_HEAD(&c->environment);
	return 0;
}

int lxc_clear_mount_entries(struct lxc_conf *c)
{
	struct string_entry *entry, *nentry;

	list_for_each_entry_safe(entry, nentry, &c->mount_entries, head) {
		list_del(&entry->head);
		free(entry->val);
		free(entry);
	}

	INIT_LIST_HEAD(&c->mount_entries);
	return 0;
}

int lxc_clear_automounts(struct lxc_conf *c)
{
	c->auto_mounts = 0;
	return 0;
}

int lxc_clear_hooks(struct lxc_conf *c, const char *key)
{
	const char *k = NULL;
	bool all = false, done = false;
	struct string_entry *entry, *nentry;

	if (strequal(key, "lxc.hook"))
		all = true;
	else if (strnequal(key, "lxc.hook.", STRLITERALLEN("lxc.hook.")))
		k = key + STRLITERALLEN("lxc.hook.");
	else
		return -1;

	for (int i = 0; i < NUM_LXC_HOOKS; i++) {
		if (all || strequal(k, lxchook_names[i])) {
			list_for_each_entry_safe(entry, nentry, &c->hooks[i], head) {
				list_del(&entry->head);
				free(entry->val);
				free(entry);
			}
			INIT_LIST_HEAD(&c->hooks[i]);
			done = true;
		}
	}

	if (!done)
		return log_error(-1, "Invalid hook key: %s", key);

	return 0;
}

int lxc_clear_apparmor_raw(struct lxc_conf *c)
{
	struct string_entry *entry, *nentry;

	list_for_each_entry_safe(entry, nentry, &c->lsm_aa_raw, head) {
		list_del(&entry->head);
		free(entry->val);
		free(entry);
	}

	INIT_LIST_HEAD(&c->lsm_aa_raw);
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
	free(conf->rootfs.path);
	put_lxc_rootfs(&conf->rootfs, true);
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
	free(conf->init_groups.list);
	free(conf->init_cwd);
	free(conf->unexpanded_config);
	free(conf->syslog);
	lxc_free_networks(conf);
	free(conf->lsm_aa_profile);
	free(conf->lsm_aa_profile_computed);
	free(conf->lsm_se_context);
	free(conf->lsm_se_keyring_context);
	lxc_seccomp_free(&conf->seccomp);
	lxc_clear_config_caps(conf);
	lxc_clear_cgroups(conf, "lxc.cgroup", CGROUP_SUPER_MAGIC);
	lxc_clear_cgroups(conf, "lxc.cgroup2", CGROUP2_SUPER_MAGIC);
	lxc_clear_cgroups_devices(conf);
	lxc_clear_hooks(conf, "lxc.hook");
	lxc_clear_mount_entries(conf);
	lxc_clear_idmaps(conf);
	lxc_clear_groups(conf);
	lxc_clear_environment(conf);
	lxc_clear_limits(conf, "lxc.prlimit");
	lxc_clear_sysctls(conf, "lxc.sysctl");
	lxc_clear_procs(conf, "lxc.proc");
	lxc_clear_apparmor_raw(conf);
	lxc_clear_namespace(conf);
	free(conf->cgroup_meta.dir);
	free(conf->cgroup_meta.monitor_dir);
	free(conf->cgroup_meta.monitor_pivot_dir);
	free(conf->cgroup_meta.container_dir);
	free(conf->cgroup_meta.namespace_dir);
	free(conf->cgroup_meta.controllers);
	free(conf->cgroup_meta.systemd_scope);
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
	struct userns_fn_data *d = data;
	int ret;
	char c;

	close_prot_errno_disarm(d->p[1]);

	/*
	 * Wait for parent to finish establishing a new mapping in the user
	 * namespace we are executing in.
	 */
	ret = lxc_read_nointr(d->p[0], &c, 1);
	close_prot_errno_disarm(d->p[0]);
	if (ret != 1)
		return -1;

	if (d->fn_name)
		TRACE("Calling function \"%s\"", d->fn_name);

	/* Call function to run. */
	return d->fn(d->arg);
}

static struct id_map *mapped_nsid_add(const struct lxc_conf *conf, unsigned id,
				      enum idtype idtype)
{
	const struct id_map *map;
	struct id_map *retmap;

	map = find_mapped_nsid_entry(conf, id, idtype);
	if (!map)
		return NULL;

	retmap = zalloc(sizeof(*retmap));
	if (!retmap)
		return NULL;

	memcpy(retmap, map, sizeof(*retmap));
	return retmap;
}

static struct id_map *find_mapped_hostid_entry(const struct list_head *idmap,
					       unsigned id, enum idtype idtype)
{
	struct id_map *retmap = NULL;
	struct id_map *map;

	list_for_each_entry(map, idmap, head) {
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
static struct id_map *mapped_hostid_add(const struct lxc_conf *conf, uid_t id,
					enum idtype type)
{
	__do_free struct id_map *entry = NULL;
	int hostid_mapped;
	struct id_map *tmp = NULL;

	entry = zalloc(sizeof(*entry));
	if (!entry)
		return NULL;

	/* Reuse existing mapping. */
	tmp = find_mapped_hostid_entry(&conf->id_map, id, type);
	if (tmp) {
		memcpy(entry, tmp, sizeof(*entry));
	} else {
		/* Find new mapping. */
		hostid_mapped = find_unmapped_nsid(conf, type);
		if (hostid_mapped < 0)
			return log_debug(NULL, "Failed to find free mapping for id %d", id);

		entry->idtype = type;
		entry->nsid = hostid_mapped;
		entry->hostid = (unsigned long)id;
		entry->range = 1;
	}

	return move_ptr(entry);
}

static int get_minimal_idmap(const struct lxc_conf *conf, uid_t *resuid,
			     gid_t *resgid, struct list_head *head_ret)
{
	__do_free struct id_map *container_root_uid = NULL,
				*container_root_gid = NULL,
				*host_uid_map = NULL, *host_gid_map = NULL;
	uid_t euid, egid;
	uid_t nsuid = (conf->root_nsuid_map != NULL) ? 0 : conf->init_uid;
	gid_t nsgid = (conf->root_nsgid_map != NULL) ? 0 : conf->init_gid;

	/* Find container root mappings. */
	container_root_uid = mapped_nsid_add(conf, nsuid, ID_TYPE_UID);
	if (!container_root_uid)
		return sysdebug("Failed to find mapping for namespace uid %d", 0);
	euid = geteuid();
	if (euid >= container_root_uid->hostid &&
	    euid < (container_root_uid->hostid + container_root_uid->range))
		host_uid_map = move_ptr(container_root_uid);

	container_root_gid = mapped_nsid_add(conf, nsgid, ID_TYPE_GID);
	if (!container_root_gid)
		return sysdebug("Failed to find mapping for namespace gid %d", 0);
	egid = getegid();
	if (egid >= container_root_gid->hostid &&
	    egid < (container_root_gid->hostid + container_root_gid->range))
		host_gid_map = move_ptr(container_root_gid);

	/* Check whether the {g,u}id of the user has a mapping. */
	if (!host_uid_map)
		host_uid_map = mapped_hostid_add(conf, euid, ID_TYPE_UID);
	if (!host_uid_map)
		return sysdebug("Failed to find mapping for uid %d", euid);

	if (!host_gid_map)
		host_gid_map = mapped_hostid_add(conf, egid, ID_TYPE_GID);
	if (!host_gid_map)
		return sysdebug("Failed to find mapping for gid %d", egid);

	/* idmap will now keep track of that memory. */
	list_add_tail(&host_uid_map->head, head_ret);
	move_ptr(host_uid_map);

	if (container_root_uid) {
		/* idmap will now keep track of that memory. */
		list_add_tail(&container_root_uid->head, head_ret);
		move_ptr(container_root_uid);
	}

	/* idmap will now keep track of that memory. */
	list_add_tail(&host_gid_map->head, head_ret);
	move_ptr(host_gid_map);

	if (container_root_gid) {
		/* idmap will now keep track of that memory. */
		list_add_tail(&container_root_gid->head, head_ret);
		move_ptr(container_root_gid);
	}

	TRACE("Allocated minimal idmapping for ns uid %d and ns gid %d", nsuid, nsgid);

	if (resuid)
		*resuid = nsuid;
	if (resgid)
		*resgid = nsgid;

	return 0;
}

/*
 * Run a function in a new user namespace.
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
int userns_exec_1(const struct lxc_conf *conf, int (*fn)(void *), void *data,
		  const char *fn_name)
{
	LIST_HEAD(minimal_idmap);
	call_cleaner(__lxc_free_idmap) struct list_head *idmap = &minimal_idmap;
	int ret = -1, status = -1;
	char c = '1';
	struct userns_fn_data d = {
	    .arg	= data,
	    .fn		= fn,
	    .fn_name	= fn_name,
	};
	pid_t pid;
	int pipe_fds[2];

	if (!conf)
		return -EINVAL;

	ret = get_minimal_idmap(conf, NULL, NULL, idmap);
	if (ret)
		return ret_errno(ENOENT);

	ret = pipe2(pipe_fds, O_CLOEXEC);
	if (ret < 0)
		return -errno;

	d.p[0]		= pipe_fds[0];
	d.p[1]		= pipe_fds[1];

	/* Clone child in new user namespace. */
	pid = lxc_raw_clone_cb(run_userns_fn, &d, CLONE_NEWUSER, NULL);
	if (pid < 0) {
		ERROR("Failed to clone process in new user namespace");
		goto on_error;
	}

	close_prot_errno_disarm(pipe_fds[0]);

	if (lxc_log_trace()) {
		struct id_map *map;

		list_for_each_entry(map, idmap, head)
			TRACE("Establishing %cid mapping for \"%d\" in new user namespace: nsuid %lu - hostid %lu - range %lu",
			      (map->idtype == ID_TYPE_UID) ? 'u' : 'g', pid, map->nsid, map->hostid, map->range);
	}

	/* Set up {g,u}id mapping for user namespace of child process. */
	ret = lxc_map_ids(idmap, pid);
	if (ret < 0) {
		ERROR("Error setting up {g,u}id mappings for child process \"%d\"", pid);
		goto on_error;
	}

	/* Tell child to proceed. */
	if (lxc_write_nointr(pipe_fds[1], &c, 1) != 1) {
		SYSERROR("Failed telling child process \"%d\" to proceed", pid);
		goto on_error;
	}

on_error:
	close_prot_errno_disarm(pipe_fds[0]);
	close_prot_errno_disarm(pipe_fds[1]);

	/* Wait for child to finish. */
	if (pid > 0)
		status = wait_for_pid(pid);

	if (status < 0)
		ret = -1;

	return ret;
}

int userns_exec_minimal(const struct lxc_conf *conf,
			int (*fn_parent)(void *), void *fn_parent_data,
			int (*fn_child)(void *), void *fn_child_data)
{
	LIST_HEAD(minimal_idmap);
	call_cleaner(__lxc_free_idmap) struct list_head *idmap = &minimal_idmap;
	uid_t resuid = LXC_INVALID_UID;
	gid_t resgid = LXC_INVALID_GID;
	char c = '1';
	ssize_t ret;
	pid_t pid;
	int sock_fds[2];

	if (!conf || !fn_child)
		return ret_errno(EINVAL);

	ret = get_minimal_idmap(conf, &resuid, &resgid, idmap);
	if (ret)
		return ret_errno(ENOENT);

	ret = socketpair(PF_LOCAL, SOCK_STREAM | SOCK_CLOEXEC, 0, sock_fds);
	if (ret < 0)
		return -errno;

	pid = fork();
	if (pid < 0) {
		SYSERROR("Failed to create new process");
		goto on_error;
	}

	if (pid == 0) {
		close_prot_errno_disarm(sock_fds[1]);

		ret = unshare(CLONE_NEWUSER);
		if (ret < 0) {
			SYSERROR("Failed to unshare new user namespace");
			_exit(EXIT_FAILURE);
		}

		ret = lxc_write_nointr(sock_fds[0], &c, 1);
		if (ret != 1)
			_exit(EXIT_FAILURE);

		ret = lxc_read_nointr(sock_fds[0], &c, 1);
		if (ret != 1)
			_exit(EXIT_FAILURE);

		close_prot_errno_disarm(sock_fds[0]);

		if (!lxc_drop_groups() && errno != EPERM)
			_exit(EXIT_FAILURE);

		ret = setresgid(resgid, resgid, resgid);
		if (ret < 0) {
			SYSERROR("Failed to setresgid(%d, %d, %d)",
				 resgid, resgid, resgid);
			_exit(EXIT_FAILURE);
		}

		ret = setresuid(resuid, resuid, resuid);
		if (ret < 0) {
			SYSERROR("Failed to setresuid(%d, %d, %d)",
				 resuid, resuid, resuid);
			_exit(EXIT_FAILURE);
		}

		ret = fn_child(fn_child_data);
		if (ret) {
			SYSERROR("Running function in new user namespace failed");
			_exit(EXIT_FAILURE);
		}

		_exit(EXIT_SUCCESS);
	}

	close_prot_errno_disarm(sock_fds[0]);

	if (lxc_log_trace()) {
		struct id_map *map;

		list_for_each_entry(map, idmap, head)
			TRACE("Establishing %cid mapping for \"%d\" in new user namespace: nsuid %lu - hostid %lu - range %lu",
			      (map->idtype == ID_TYPE_UID) ? 'u' : 'g', pid, map->nsid, map->hostid, map->range);
	}

	ret = lxc_read_nointr(sock_fds[1], &c, 1);
	if (ret != 1) {
		SYSERROR("Failed waiting for child process %d\" to tell us to proceed", pid);
		goto on_error;
	}

	/* Set up {g,u}id mapping for user namespace of child process. */
	ret = lxc_map_ids(idmap, pid);
	if (ret < 0) {
		ERROR("Error setting up {g,u}id mappings for child process \"%d\"", pid);
		goto on_error;
	}

	/* Tell child to proceed. */
	ret = lxc_write_nointr(sock_fds[1], &c, 1);
	if (ret != 1) {
		SYSERROR("Failed telling child process \"%d\" to proceed", pid);
		goto on_error;
	}

	if (fn_parent && fn_parent(fn_parent_data)) {
		SYSERROR("Running parent function failed");
		_exit(EXIT_FAILURE);
	}

on_error:
	close_prot_errno_disarm(sock_fds[0]);
	close_prot_errno_disarm(sock_fds[1]);

	/* Wait for child to finish. */
	if (pid < 0)
		return -1;

	return wait_for_pid(pid);
}

int userns_exec_full(struct lxc_conf *conf, int (*fn)(void *), void *data,
		     const char *fn_name)
{
	LIST_HEAD(full_idmap);
	int ret = -1;
	char c = '1';
	struct id_map *container_root_uid = NULL, *container_root_gid = NULL,
		      *host_uid_map = NULL, *host_gid_map = NULL;
	pid_t pid;
	uid_t euid, egid;
	int p[2];
	struct id_map *map;
	struct userns_fn_data d;

	if (!conf)
		return -EINVAL;

	ret = pipe2(p, O_CLOEXEC);
	if (ret < 0)
		return -errno;

	d.fn = fn;
	d.fn_name = fn_name;
	d.arg = data;
	d.p[0] = p[0];
	d.p[1] = p[1];

	/* Clone child in new user namespace. */
	pid = lxc_clone(run_userns_fn, &d, CLONE_NEWUSER, NULL);
	if (pid < 0) {
		ERROR("Failed to clone process in new user namespace");
		goto on_error;
	}

	close(p[0]);
	p[0] = -1;

	euid = geteuid();
	egid = getegid();

	/* Find container root. */
	list_for_each_entry(map, &conf->id_map, head) {
		__do_free struct id_map *dup_map = NULL;

		dup_map = memdup(map, sizeof(struct id_map));
		if (!dup_map)
			goto on_error;

		list_add_tail(&dup_map->head, &full_idmap);
		move_ptr(dup_map);

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
		/* idmap will now keep track of that memory. */
		list_add_tail(&host_uid_map->head, &full_idmap);
		move_ptr(host_uid_map);
	}

	if (host_gid_map && (host_gid_map != container_root_gid)) {
		/* idmap will now keep track of that memory. */
		list_add_tail(&host_gid_map->head, &full_idmap);
		move_ptr(host_gid_map);
	}

	if (lxc_log_trace()) {
		list_for_each_entry(map, &full_idmap, head) {
			TRACE("establishing %cid mapping for \"%d\" in new user namespace: nsuid %lu - hostid %lu - range %lu",
			      (map->idtype == ID_TYPE_UID) ? 'u' : 'g', pid,
			      map->nsid, map->hostid, map->range);
		}
	}

	/* Set up {g,u}id mapping for user namespace of child process. */
	ret = lxc_map_ids(&full_idmap, pid);
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

	__lxc_free_idmap(&full_idmap);

	if (host_uid_map && (host_uid_map != container_root_uid))
		free(host_uid_map);
	if (host_gid_map && (host_gid_map != container_root_gid))
		free(host_gid_map);

	return ret;
}

static int add_idmap_entry(struct list_head *idmap_list, enum idtype idtype,
			   unsigned long nsid, unsigned long hostid,
			   unsigned long range)
{
	__do_free struct id_map *new_idmap = NULL;

	new_idmap = zalloc(sizeof(*new_idmap));
	if (!new_idmap)
		return ret_errno(ENOMEM);

	new_idmap->idtype = idtype;
	new_idmap->hostid = hostid;
	new_idmap->nsid = nsid;
	new_idmap->range = range;

	list_add_tail(&new_idmap->head, idmap_list);
	move_ptr(new_idmap);

	INFO("Adding id map: type %c nsid %lu hostid %lu range %lu",
	     idtype == ID_TYPE_UID ? 'u' : 'g', nsid, hostid, range);
	return 0;
}

int userns_exec_mapped_root(const char *path, int path_fd,
			    const struct lxc_conf *conf)
{
	LIST_HEAD(idmap_list);
	call_cleaner(__lxc_free_idmap) struct list_head *idmap = &idmap_list;
	__do_close int fd = -EBADF;
	int target_fd = -EBADF;
	char c = '1';
	ssize_t ret;
	pid_t pid;
	int sock_fds[2];
	uid_t container_host_uid, hostuid;
	gid_t container_host_gid, hostgid;
	struct stat st;

	if (!conf || (!path && path_fd < 0))
		return ret_errno(EINVAL);

	if (!path)
		path = "(null)";

	container_host_uid = get_mapped_rootid(conf, ID_TYPE_UID);
	if (!uid_valid(container_host_uid))
		return log_error(-1, "No uid mapping for container root");

	container_host_gid = get_mapped_rootid(conf, ID_TYPE_GID);
	if (!gid_valid(container_host_gid))
		return log_error(-1, "No gid mapping for container root");

	if (path_fd < 0) {
		fd = open(path, O_CLOEXEC | O_NOCTTY);
		if (fd < 0)
			return log_error_errno(-errno, errno, "Failed to open \"%s\"", path);
		target_fd = fd;
	} else {
		target_fd = path_fd;
	}

	hostuid = geteuid();
	/* We are root so chown directly. */
	if (hostuid == 0) {
		ret = fchown(target_fd, container_host_uid, container_host_gid);
		if (ret)
			return log_error_errno(-errno, errno,
					       "Failed to fchown(%d(%s), %d, %d)",
					       target_fd, path, container_host_uid,
					       container_host_gid);
		return log_trace(0, "Chowned %d(%s) to uid %d and %d", target_fd, path,
				 container_host_uid, container_host_gid);
	}

	/* The container's root host id matches  */
	if (container_host_uid == hostuid)
		return log_info(0, "Container root id is mapped to our uid");

	/* Get the current ids of our target. */
	ret = fstat(target_fd, &st);
	if (ret)
		return log_error_errno(-errno, errno, "Failed to stat \"%s\"", path);

	hostgid = getegid();
	if (st.st_uid == hostuid && mapped_hostid(st.st_gid, conf, ID_TYPE_GID) < 0) {
		ret = fchown(target_fd, -1, hostgid);
		if (ret)
			return log_error_errno(-errno, errno,
					       "Failed to fchown(%d(%s), -1, %d)",
					       target_fd, path, hostgid);
		TRACE("Chowned %d(%s) to -1:%d", target_fd, path, hostgid);
	}

	/* "u:0:rootuid:1" */
	ret = add_idmap_entry(idmap, ID_TYPE_UID, 0, container_host_uid, 1);
	if (ret < 0)
		return log_error_errno(ret, -ret, "Failed to add idmap entry");

	/* "u:hostuid:hostuid:1" */
	ret = add_idmap_entry(idmap, ID_TYPE_UID, hostuid, hostuid, 1);
	if (ret < 0)
		return log_error_errno(ret, -ret, "Failed to add idmap entry");

	/* "g:0:rootgid:1" */
	ret = add_idmap_entry(idmap, ID_TYPE_GID, 0, container_host_gid, 1);
	if (ret < 0)
		return log_error_errno(ret, -ret, "Failed to add idmap entry");

	/* "g:hostgid:hostgid:1" */
	ret = add_idmap_entry(idmap, ID_TYPE_GID, hostgid, hostgid, 1);
	if (ret < 0)
		return log_error_errno(ret, -ret, "Failed to add idmap entry");

	if (hostgid != st.st_gid) {
		/* "g:pathgid:rootgid+pathgid:1" */
		ret = add_idmap_entry(idmap, ID_TYPE_GID, st.st_gid,
				      container_host_gid + (gid_t)st.st_gid, 1);
		if (ret < 0)
			return log_error_errno(ret, -ret, "Failed to add idmap entry");
	}

	ret = socketpair(PF_LOCAL, SOCK_STREAM | SOCK_CLOEXEC, 0, sock_fds);
	if (ret < 0)
		return -errno;

	pid = fork();
	if (pid < 0) {
		SYSERROR("Failed to create new process");
		goto on_error;
	}

	if (pid == 0) {
		close_prot_errno_disarm(sock_fds[1]);

		ret = unshare(CLONE_NEWUSER);
		if (ret < 0) {
			SYSERROR("Failed to unshare new user namespace");
			_exit(EXIT_FAILURE);
		}

		ret = lxc_write_nointr(sock_fds[0], &c, 1);
		if (ret != 1)
			_exit(EXIT_FAILURE);

		ret = lxc_read_nointr(sock_fds[0], &c, 1);
		if (ret != 1)
			_exit(EXIT_FAILURE);

		close_prot_errno_disarm(sock_fds[0]);

		if (!lxc_drop_groups() && errno != EPERM)
			_exit(EXIT_FAILURE);

		ret = setresgid(0, 0, 0);
		if (ret < 0) {
			SYSERROR("Failed to setresgid(0, 0, 0)");
			_exit(EXIT_FAILURE);
		}

		ret = setresuid(0, 0, 0);
		if (ret < 0) {
			SYSERROR("Failed to setresuid(0, 0, 0)");
			_exit(EXIT_FAILURE);
		}

		ret = fchown(target_fd, 0, st.st_gid);
		if (ret) {
			SYSERROR("Failed to chown %d(%s) to 0:%d", target_fd, path, st.st_gid);
			_exit(EXIT_FAILURE);
		}

		TRACE("Chowned %d(%s) to 0:%d", target_fd, path, st.st_gid);
		_exit(EXIT_SUCCESS);
	}

	close_prot_errno_disarm(sock_fds[0]);

	if (lxc_log_trace()) {
		struct id_map *map;

		list_for_each_entry(map, idmap, head)
			TRACE("Establishing %cid mapping for \"%d\" in new user namespace: nsuid %lu - hostid %lu - range %lu",
			      (map->idtype == ID_TYPE_UID) ? 'u' : 'g', pid, map->nsid, map->hostid, map->range);
	}

	ret = lxc_read_nointr(sock_fds[1], &c, 1);
	if (ret != 1) {
		SYSERROR("Failed waiting for child process %d\" to tell us to proceed", pid);
		goto on_error;
	}

	/* Set up {g,u}id mapping for user namespace of child process. */
	ret = lxc_map_ids(idmap, pid);
	if (ret < 0) {
		ERROR("Error setting up {g,u}id mappings for child process \"%d\"", pid);
		goto on_error;
	}

	/* Tell child to proceed. */
	ret = lxc_write_nointr(sock_fds[1], &c, 1);
	if (ret != 1) {
		SYSERROR("Failed telling child process \"%d\" to proceed", pid);
		goto on_error;
	}

on_error:
	close_prot_errno_disarm(sock_fds[0]);
	close_prot_errno_disarm(sock_fds[1]);

	/* Wait for child to finish. */
	if (pid < 0)
		return log_error(-1, "Failed to create child process");

	if (!wait_exited(pid))
		return -1;

	return 0;
}

/* not thread-safe, do not use from api without first forking */
static char *getuname(void)
{
	__do_free char *buf = NULL;
	struct passwd pwent;
	struct passwd *pwentp = NULL;
	ssize_t bufsize;
	int ret;

	bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (bufsize < 0)
		bufsize = 1024;

	buf = zalloc(bufsize);
	if (!buf)
		return NULL;

	ret = getpwuid_r(geteuid(), &pwent, buf, bufsize, &pwentp);
	if (!pwentp) {
		if (ret == 0)
			WARN("Could not find matched password record.");

		return log_error(NULL, "Failed to get password record - %u", geteuid());
	}

	return strdup(pwent.pw_name);
}

/* not thread-safe, do not use from api without first forking */
static char *getgname(void)
{
	__do_free char *buf = NULL;
	struct group grent;
	struct group *grentp = NULL;
	ssize_t bufsize;
	int ret;

	bufsize = sysconf(_SC_GETGR_R_SIZE_MAX);
	if (bufsize < 0)
		bufsize = 1024;

	buf = zalloc(bufsize);
	if (!buf)
		return NULL;

	ret = getgrgid_r(getegid(), &grent, buf, bufsize, &grentp);
	if (!grentp) {
		if (ret == 0)
			WARN("Could not find matched group record");

		return log_error(NULL, "Failed to get group record - %u", getegid());
	}

	return strdup(grent.gr_name);
}

/* not thread-safe, do not use from api without first forking */
void suggest_default_idmap(void)
{
	__do_free char *gname = NULL, *line = NULL, *uname = NULL;
	__do_fclose FILE *subuid_f = NULL, *subgid_f = NULL;
	unsigned int uid = 0, urange = 0, gid = 0, grange = 0;
	size_t len = 0;

	uname = getuname();
	if (!uname)
		return;

	gname = getgname();
	if (!gname)
		return;

	subuid_f = fopen(subuidfile, "re");
	if (!subuid_f) {
		ERROR("Your system is not configured with subuids");
		return;
	}

	while (getline(&line, &len, subuid_f) != -1) {
		char *p, *p2;
		size_t no_newline = 0;

		p = strchr(line, ':');
		if (*line == '#')
			continue;
		if (!p)
			continue;
		*p = '\0';
		p++;

		if (!strequal(line, uname))
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

	subgid_f = fopen(subgidfile, "re");
	if (!subgid_f) {
		ERROR("Your system is not configured with subgids");
		return;
	}

	while (getline(&line, &len, subgid_f) != -1) {
		char *p, *p2;
		size_t no_newline = 0;

		p = strchr(line, ':');
		if (*line == '#')
			continue;
		if (!p)
			continue;
		*p = '\0';
		p++;

		if (!strequal(line, uname))
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
}

int lxc_set_environment(const struct lxc_conf *conf)
{
	struct environment_entry *env;

	list_for_each_entry(env, &conf->environment, head) {
		int ret;

		ret = setenv(env->key, env->val, 1);
		if (ret < 0)
			return syserror("Failed to set environment variable: %s=%s",
					env->key, env->val);
		TRACE("Set environment variable: %s=%s", env->key, env->val);
	}

	return 0;
}

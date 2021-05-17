/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <inttypes.h>
#include <linux/limits.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "cgroup.h"
#include "commands.h"
#include "conf.h"
#include "config.h"
#include "criu.h"
#include "log.h"
#include "lxc.h"
#include "lxclock.h"
#include "memory_utils.h"
#include "network.h"
#include "storage.h"
#include "syscall_wrappers.h"
#include "utils.h"

#if IS_BIONIC
#include <../include/lxcmntent.h>
#else
#include <mntent.h>
#endif

#ifndef HAVE_STRLCPY
#include "include/strlcpy.h"
#endif

#define CRIU_VERSION		"2.0"

#define CRIU_GITID_VERSION	"2.0"
#define CRIU_GITID_PATCHLEVEL	0

#define CRIU_IN_FLIGHT_SUPPORT	"2.4"
#define CRIU_EXTERNAL_NOT_VETH	"2.8"

lxc_log_define(criu, lxc);

struct criu_opts {
	/* the thing to hook to stdout and stderr for logging */
	int pipefd;

	/* The type of criu invocation, one of "dump" or "restore" */
	char *action;

	/* the user-provided migrate options relevant to this action */
	struct migrate_opts *user;

	/* The container to dump */
	struct lxc_container *c;

	/* dump: stop the container or not after dumping? */
	char tty_id[32]; /* the criu tty id for /dev/console, i.e. "tty[${rdev}:${dev}]" */

	/* restore: the file to write the init process' pid into */
	struct lxc_handler *handler;
	int console_fd;
	/* The path that is bind mounted from /dev/console, if any. We don't
	 * want to use `--ext-mount-map auto`'s result here because the pty
	 * device may have a different path (e.g. if the pty number is
	 * different) on the target host. NULL if lxc.console.path = "none".
	 */
	char *console_name;

	/* The detected version of criu */
	char *criu_version;
};

static int load_tty_major_minor(char *directory, char *output, int len)
{
	char path[PATH_MAX];
	ssize_t ret;

	ret = strnprintf(path, sizeof(path), "%s/tty.info", directory);
	if (ret < 0)
		return ret_errno(EIO);

	ret = lxc_read_from_file(path, output, len);
	if (ret < 0) {
		/*
		 * This means we're coming from a liblxc which didn't export
		 * the tty info. In this case they had to have lxc.console.path
		 * = * none, so there's no problem restoring.
		 */
		if (errno == ENOENT)
			return 0;

		return log_error_errno(-errno, errno, "Failed to open \"%s\"", path);
	}

	return 0;
}

static int cmp_version(const char *v1, const char *v2)
{
	int ret;
	int oct_v1[3], oct_v2[3];

	memset(oct_v1, -1, sizeof(oct_v1));
	memset(oct_v2, -1, sizeof(oct_v2));

	ret = sscanf(v1, "%d.%d.%d", &oct_v1[0], &oct_v1[1], &oct_v1[2]);
	if (ret < 1)
		return -1;

	ret = sscanf(v2, "%d.%d.%d", &oct_v2[0], &oct_v2[1], &oct_v2[2]);
	if (ret < 1)
		return -1;

	/* Major version is greater. */
	if (oct_v1[0] > oct_v2[0])
		return 1;

	if (oct_v1[0] < oct_v2[0])
		return -1;

	/* Minor number is greater.*/
	if (oct_v1[1] > oct_v2[1])
		return 1;

	if (oct_v1[1] < oct_v2[1])
		return -1;

	/* Patch number is greater. */
	if (oct_v1[2] > oct_v2[2])
		return 1;

	/* Patch numbers are equal. */
	if (oct_v1[2] == oct_v2[2])
		return 0;

	return -1;
}

struct criu_exec_args {
	int argc;
	char *argv[];
};

static void put_criu_exec_args(struct criu_exec_args *args)
{
	if (args) {
		for (int i = 0; i < args->argc; i++)
			free_disarm(args->argv[i]);
		free_disarm(args);
	}
}

define_cleanup_function(struct criu_exec_args *, put_criu_exec_args);

static int exec_criu(struct cgroup_ops *cgroup_ops, struct lxc_conf *conf,
		     struct criu_opts *opts)
{
	call_cleaner(put_criu_exec_args) struct criu_exec_args *args = NULL;
	__do_fclose FILE *f_mnt = NULL;
	char log[PATH_MAX];
	int static_args = 23, ret;
	int netnr = 0;
	struct lxc_list *it;
	struct mntent mntent;

	char buf[4096], ttys[32];

	/* If we are currently in a cgroup /foo/bar, and the container is in a
	 * cgroup /lxc/foo, lxcfs will give us an ENOENT if some task in the
	 * container has an open fd that points to one of the cgroup files
	 * (systemd always opens its "root" cgroup). So, let's escape to the
	 * /actual/ root cgroup so that lxcfs thinks criu has enough rights to
	 * see all cgroups.
	 */
	if (!cgroup_ops->criu_escape(cgroup_ops, conf))
		return log_error_errno(-ENOENT, ENOENT, "Failed to escape to root cgroup");

	/* The command line always looks like:
	 * criu $(action) --tcp-established --file-locks --link-remap \
	 * --manage-cgroups=full --action-script foo.sh -D $(directory) \
	 * -o $(directory)/$(action).log --ext-mount-map auto
	 * --enable-external-sharing --enable-external-masters
	 * --enable-fs hugetlbfs --enable-fs tracefs --ext-mount-map console:/dev/pts/n
	 * +1 for final NULL */

	if (strequal(opts->action, "dump") || strequal(opts->action, "pre-dump")) {
		/* -t pid --freeze-cgroup /lxc/ct */
		static_args += 4;

		/* --prev-images-dir <path-to-directory-A-relative-to-B> */
		if (opts->user->predump_dir)
			static_args += 2;

		/* --page-server --address <address> --port <port> */
		if (opts->user->pageserver_address && opts->user->pageserver_port)
			static_args += 5;

		/* --leave-running (only for final dump) */
		if (strequal(opts->action, "dump") && !opts->user->stop)
			static_args++;

		/* --external tty[88,4] */
		if (opts->tty_id[0])
			static_args += 2;

		/* --force-irmap */
		if (!opts->user->preserves_inodes)
			static_args++;

		/* --ghost-limit 1024 */
		if (opts->user->ghost_limit)
			static_args += 2;
	} else if (strequal(opts->action, "restore")) {
		/* --root $(lxc_mount_point) --restore-detached
		 * --restore-sibling
		 * --lsm-profile apparmor:whatever
		 */
		static_args += 6;

		ttys[0] = 0;
		if (load_tty_major_minor(opts->user->directory, ttys, sizeof(ttys)))
			return log_error_errno(-EINVAL, EINVAL, "Failed to load tty information");

		/* --inherit-fd fd[%d]:tty[%s] */
		if (ttys[0])
			static_args += 2;

		static_args += lxc_list_len(&opts->c->lxc_conf->network) * 2;
	} else {
		return log_error_errno(-EINVAL, EINVAL, "Invalid criu operation specified");
	}

	if (cgroup_ops->criu_num_hierarchies(cgroup_ops) > 0)
		static_args += 2 * cgroup_ops->criu_num_hierarchies(cgroup_ops);

	if (opts->user->verbose)
		static_args++;

	if (opts->user->action_script)
		static_args += 2;

	static_args += 2 * lxc_list_len(&opts->c->lxc_conf->mount_list);

	ret = strnprintf(log, sizeof(log), "%s/%s.log", opts->user->directory, opts->action);
	if (ret < 0)
		return ret_errno(EIO);

	args = zalloc(sizeof(struct criu_exec_args) + (static_args * sizeof(char **)));
	if (!args)
		return log_error_errno(-ENOMEM, ENOMEM, "Failed to allocate static arguments");

#define DECLARE_ARG(arg)                                                                 \
	do {                                                                             \
		if (arg == NULL)                                                         \
			return log_error_errno(-EINVAL, EINVAL,                          \
					       "Got NULL argument for criu");            \
		args->argv[(args->argc)++] = strdup(arg);                                \
		if (!args->argv[args->argc - 1])                                         \
			return log_error_errno(-ENOMEM, ENOMEM,				 \
					"Failed to duplicate argumen %s", arg);          \
	} while (0)

	args->argv[(args->argc)++] = on_path("criu", NULL);
	if (!args->argv[args->argc - 1])
		return log_error_errno(-ENOENT, ENOENT, "Failed to find criu binary");

	DECLARE_ARG(opts->action);
	DECLARE_ARG("--tcp-established");
	DECLARE_ARG("--file-locks");
	DECLARE_ARG("--link-remap");
	DECLARE_ARG("--manage-cgroups=full");
	DECLARE_ARG("--ext-mount-map");
	DECLARE_ARG("auto");
	DECLARE_ARG("--enable-external-sharing");
	DECLARE_ARG("--enable-external-masters");
	DECLARE_ARG("--enable-fs");
	DECLARE_ARG("hugetlbfs");
	DECLARE_ARG("--enable-fs");
	DECLARE_ARG("tracefs");
	DECLARE_ARG("-D");
	DECLARE_ARG(opts->user->directory);
	DECLARE_ARG("-o");
	DECLARE_ARG(log);

	for (int i = 0; i < cgroup_ops->criu_num_hierarchies(cgroup_ops); i++) {
		__do_free char *cgroup_base_path = NULL, *controllers;
		char **controllers_list = NULL;
		char *tmp;

		if (!cgroup_ops->criu_get_hierarchies(cgroup_ops, i, &controllers_list))
			return log_error_errno(-ENOENT, ENOENT, "Failed to retrieve cgroup hierarchies %d", i);

		/*
		 * If we are in a dump, we have to ask the monitor process what
		 * the right cgroup is. if this is a restore, we can just use
		 * the handler the restore task created.
		 */
		if (strequal(opts->action, "dump") || strequal(opts->action, "pre-dump")) {
			cgroup_base_path = lxc_cmd_get_limit_cgroup_path(opts->c->name, opts->c->config_path, controllers_list[0]);
			if (!cgroup_base_path)
				return log_error_errno(-ENOENT, ENOENT, "Failed to retrieve limit cgroup path for %s", controllers_list[0] ?: "(null)");
		} else {
			const char *p;

			p = cgroup_ops->get_limit_cgroup(cgroup_ops, controllers_list[0]);
			if (!p)
				return log_error_errno(-ENOENT, ENOENT, "Failed to retrieve limit cgroup path for %s", controllers_list[0] ?: "(null)");

			cgroup_base_path = strdup(p);
			if (!cgroup_base_path)
				return log_error_errno(-ENOMEM, ENOMEM, "Failed to duplicate limit cgroup path");
		}

		tmp = path_simplify(cgroup_base_path);
		if (!tmp)
			return log_error_errno(-ENOMEM, ENOMEM, "Failed to remove extraneous slashes from \"%s\"", tmp);
		free_move_ptr(cgroup_base_path, tmp);

		if (controllers_list[0]) {
			controllers = lxc_string_join(",", (const char **)controllers_list, false);
			if (!controllers)
				return log_error_errno(-ENOMEM, ENOMEM, "Failed to join controllers");

			ret = sprintf(buf, "%s:%s", controllers, cgroup_base_path);
		} else {
			WARN("No cgroup controllers configured in container's cgroup %s", cgroup_base_path);
			ret = sprintf(buf, "%s", cgroup_base_path);
		}
		if (ret < 0 || ret >= sizeof(buf))
			return log_error_errno(-EIO, EIO, "sprintf of cgroup root arg failed");

		DECLARE_ARG("--cgroup-root");
		DECLARE_ARG(buf);
	}

	if (opts->user->verbose)
		DECLARE_ARG("-v4");

	if (opts->user->action_script) {
		DECLARE_ARG("--action-script");
		DECLARE_ARG(opts->user->action_script);
	}

	f_mnt = make_anonymous_mount_file(&opts->c->lxc_conf->mount_list,
	                                 opts->c->lxc_conf->lsm_aa_allow_nesting);
	if (!f_mnt)
		return log_error_errno(-ENOENT, ENOENT, "Failed to create anonymous mount file");

	while (getmntent_r(f_mnt, &mntent, buf, sizeof(buf))) {
		__do_free char *mnt_options = NULL;
		unsigned long flags = 0;
		char arg[2 * PATH_MAX + 2];

		if (parse_mntopts_legacy(mntent.mnt_opts, &flags, &mnt_options) < 0)
			return log_error_errno(-EINVAL, EINVAL, "Failed to parse mount options");

		/* only add --ext-mount-map for actual bind mounts */
		if (!(flags & MS_BIND))
			continue;

		if (strequal(opts->action, "dump"))
			ret = strnprintf(arg, sizeof(arg), "/%s:%s", mntent.mnt_dir, mntent.mnt_dir);
		else
			ret = strnprintf(arg, sizeof(arg), "%s:%s", mntent.mnt_dir, mntent.mnt_fsname);
		if (ret < 0)
			return log_error_errno(-EIO, EIO, "Failed to create mount entry");

		DECLARE_ARG("--ext-mount-map");
		DECLARE_ARG(arg);
	}

	if (strequal(opts->action, "dump") || strequal(opts->action, "pre-dump")) {
		pid_t init_pid;
		char init_pid_str[INTTYPE_TO_STRLEN(int)];
		char *freezer_relative;

		init_pid = opts->c->init_pid(opts->c);
		if (init_pid < 0)
			return log_error_errno(-ESRCH, ESRCH, "Failed to retrieve init pid of container");

		ret = strnprintf(init_pid_str, sizeof(init_pid_str), "%d", init_pid);
		if (ret < 0)
			return log_error_errno(-EIO, EIO, "Failed to create entry for init pid of container");

		DECLARE_ARG("-t");
		DECLARE_ARG(init_pid_str);

		freezer_relative = lxc_cmd_get_limit_cgroup_path(opts->c->name,
								 opts->c->config_path,
								 "freezer");
		if (!freezer_relative)
			return log_error_errno(-ENOENT, ENOENT, "Failed getting freezer path");

		if (pure_unified_layout(cgroup_ops))
			ret = strnprintf(log, sizeof(log), "/sys/fs/cgroup/%s", freezer_relative);
		else
			ret = strnprintf(log, sizeof(log), "/sys/fs/cgroup/freezer/%s", freezer_relative);
		if (ret < 0)
			return log_error_errno(-EIO, EIO, "Failed to freezer cgroup entry");

		if (!opts->user->disable_skip_in_flight &&
		    strcmp(opts->criu_version, CRIU_IN_FLIGHT_SUPPORT) >= 0)
			DECLARE_ARG("--skip-in-flight");

		DECLARE_ARG("--freeze-cgroup");
		DECLARE_ARG(log);

		if (opts->tty_id[0]) {
			DECLARE_ARG("--ext-mount-map");
			DECLARE_ARG("/dev/console:console");

			DECLARE_ARG("--external");
			DECLARE_ARG(opts->tty_id);
		}

		if (opts->user->predump_dir) {
			DECLARE_ARG("--prev-images-dir");
			DECLARE_ARG(opts->user->predump_dir);
			DECLARE_ARG("--track-mem");
		}

		if (opts->user->pageserver_address && opts->user->pageserver_port) {
			DECLARE_ARG("--page-server");
			DECLARE_ARG("--address");
			DECLARE_ARG(opts->user->pageserver_address);
			DECLARE_ARG("--port");
			DECLARE_ARG(opts->user->pageserver_port);
		}

		if (!opts->user->preserves_inodes)
			DECLARE_ARG("--force-irmap");

		if (opts->user->ghost_limit) {
			char ghost_limit[32];

			ret = sprintf(ghost_limit, "%"PRIu64, opts->user->ghost_limit);
			if (ret < 0 || ret >= sizeof(ghost_limit))
				return log_error_errno(-EIO, EIO, "Failed to print ghost limit %"PRIu64, opts->user->ghost_limit);

			DECLARE_ARG("--ghost-limit");
			DECLARE_ARG(ghost_limit);
		}

		/* only for final dump */
		if (strequal(opts->action, "dump") && !opts->user->stop)
			DECLARE_ARG("--leave-running");
	} else if (strequal(opts->action, "restore")) {
		struct lxc_conf *lxc_conf = opts->c->lxc_conf;

		DECLARE_ARG("--root");
		DECLARE_ARG(opts->c->lxc_conf->rootfs.mount);
		DECLARE_ARG("--restore-detached");
		DECLARE_ARG("--restore-sibling");

		if (ttys[0]) {
			if (opts->console_fd < 0)
				return log_error_errno(-EINVAL, EINVAL, "lxc.console.path configured on source host but not target");

			ret = strnprintf(buf, sizeof(buf), "fd[%d]:%s", opts->console_fd, ttys);
			if (ret < 0)
				return log_error_errno(-EIO, EIO, "Failed to create console entry");

			DECLARE_ARG("--inherit-fd");
			DECLARE_ARG(buf);
		}
		if (opts->console_name) {
			if (strnprintf(buf, sizeof(buf), "console:%s", opts->console_name) < 0)
				return log_error_errno(-EIO, EIO, "Failed to create console entry");

			DECLARE_ARG("--ext-mount-map");
			DECLARE_ARG(buf);
		}

		if (lxc_conf->lsm_aa_profile || lxc_conf->lsm_se_context) {

			if (lxc_conf->lsm_aa_profile)
				ret = strnprintf(buf, sizeof(buf), "apparmor:%s", lxc_conf->lsm_aa_profile);
			else
				ret = strnprintf(buf, sizeof(buf), "selinux:%s", lxc_conf->lsm_se_context);
			if (ret < 0)
				return log_error_errno(-EIO, EIO, "Failed to create lsm entry");

			DECLARE_ARG("--lsm-profile");
			DECLARE_ARG(buf);
		}

		lxc_list_for_each(it, &opts->c->lxc_conf->network) {
			size_t retlen;
			char eth[128], *veth;
			struct lxc_netdev *n = it->elem;
			bool external_not_veth;

			if (cmp_version(opts->criu_version, CRIU_EXTERNAL_NOT_VETH) >= 0) {
				/* Since criu version 2.8 the usage of --veth-pair
				 * has been deprecated:
				 * git tag --contains f2037e6d3445fc400
				 * v2.8 */
				external_not_veth = true;
			} else {
				external_not_veth = false;
			}

			if (n->name[0] != '\0') {
				retlen = strlcpy(eth, n->name, sizeof(eth));
				if (retlen >= sizeof(eth))
					return log_error_errno(-E2BIG, E2BIG, "Failed to append veth device name");
			} else {
				ret = strnprintf(eth, sizeof(eth), "eth%d", netnr);
				if (ret < 0)
					return log_error_errno(-E2BIG, E2BIG, "Failed to append veth device name");
			}

			switch (n->type) {
			case LXC_NET_VETH:
				veth = n->priv.veth_attr.pair;
				if (veth[0] == '\0')
					veth = n->priv.veth_attr.veth1;

				if (n->link[0] != '\0') {
					if (external_not_veth)
						ret = strnprintf(buf, sizeof(buf), "veth[%s]:%s@%s", eth, veth, n->link);
					else
						ret = strnprintf(buf, sizeof(buf), "%s=%s@%s", eth, veth, n->link);
				} else {
					if (external_not_veth)
						ret = strnprintf(buf, sizeof(buf), "veth[%s]:%s", eth, veth);
					else
						ret = strnprintf(buf, sizeof(buf), "%s=%s", eth, veth);
				}
				if (ret < 0)
					return log_error_errno(-EIO, EIO, "Failed to append veth device name");

				TRACE("Added veth device entry %s", buf);
				break;
			case LXC_NET_MACVLAN:
				if (n->link[0] == '\0')
					return log_error_errno(-EINVAL, EINVAL, "Failed to find host interface for macvlan %s", n->name);

				ret = strnprintf(buf, sizeof(buf), "macvlan[%s]:%s", eth, n->link);
				if (ret < 0)
					return log_error_errno(-EIO, EIO, "Failed to add macvlan entry");

				TRACE("Added macvlan device entry %s", buf);

				break;
			case LXC_NET_NONE:
			case LXC_NET_EMPTY:
				break;
			default:
				/* we have screened for this earlier... */
				return log_error_errno(-EINVAL, EINVAL, "Unsupported network type %d", n->type);
			}

			if (external_not_veth)
				DECLARE_ARG("--external");
			else
				DECLARE_ARG("--veth-pair");
			DECLARE_ARG(buf);
			netnr++;
		}

	}

	args->argv[args->argc] = NULL;

	if (lxc_log_trace()) {
		buf[0] = 0;
		for (int i = 0, pos = 0; i < args->argc && args->argv[i]; i++) {
			ret = strnprintf(buf + pos, sizeof(buf) - pos, "%s ", args->argv[i]);
			if (ret < 0)
				return log_error_errno(-EIO, EIO, "Failed to reorder entries");
			else
				pos += ret;
		}

		TRACE("Using command line %s", buf);
	}

	/* before criu inits its log, it sometimes prints things to stdout/err;
	 * let's be sure we capture that.
	 */
	if (dup2(opts->pipefd, STDOUT_FILENO) < 0)
		return log_error_errno(-errno, errno, "Failed to duplicate stdout");

	if (dup2(opts->pipefd, STDERR_FILENO) < 0)
		return log_error_errno(-errno, errno, "Failed to duplicate stderr");

	close(opts->pipefd);

#undef DECLARE_ARG
	execv(args->argv[0], args->argv);
	return -ENOEXEC;
}

/*
 * Function to check if the checks activated in 'features_to_check' are
 * available with the current architecture/kernel/criu combination.
 *
 * Parameter features_to_check is a bit mask of all features that should be
 * checked (see feature check defines in lxc/lxccontainer.h).
 *
 * If the return value is true, all requested features are supported. If
 * the return value is false the features_to_check parameter is updated
 * to reflect which features are available. '0' means no feature but
 * also that something went totally wrong.
 *
 * Some of the code flow of criu_version_ok() is duplicated and maybe it
 * is a good candidate for refactoring.
 */
bool __criu_check_feature(uint64_t *features_to_check)
{
	pid_t pid;
	uint64_t current_bit = 0;
	int ret;
	uint64_t features = *features_to_check;
	/* Feature checking is currently always like
	 * criu check --feature <feature-name>
	 */
	char *args[] = { "criu", "check", "--feature", NULL, NULL };

	if ((features & ~FEATURE_MEM_TRACK & ~FEATURE_LAZY_PAGES) != 0) {
		/* There are feature bits activated we do not understand.
		 * Refusing to answer at all */
		*features_to_check = 0;
		return false;
	}

	while (current_bit < (sizeof(uint64_t) * 8 - 1)) {
		/* only test requested features */
		if (!(features & (1ULL << current_bit))) {
			/* skip this */
			current_bit++;
			continue;
		}

		pid = fork();
		if (pid < 0) {
			SYSERROR("fork() failed");
			*features_to_check = 0;
			return false;
		}

		if (pid == 0) {
			if ((1ULL << current_bit) == FEATURE_MEM_TRACK)
				/* This is needed for pre-dump support, which
				 * enables pre-copy migration. */
				args[3] = "mem_dirty_track";
			else if ((1ULL << current_bit) == FEATURE_LAZY_PAGES)
				/* CRIU has two checks for userfaultfd support.
				 *
				 * The simpler check is only for 'uffd'. If the
				 * kernel supports userfaultfd without noncoop
				 * then only process can be lazily restored
				 * which do not fork. With 'uffd-noncoop'
				 * it is also possible to lazily restore processes
				 * which do fork. For a container runtime like
				 * LXC checking only for 'uffd' makes not much sense. */
				args[3] = "uffd-noncoop";
			else
				_exit(EXIT_FAILURE);

			null_stdfds();

			execvp("criu", args);
			SYSERROR("Failed to exec \"criu\"");
			_exit(EXIT_FAILURE);
		}

		ret = wait_for_pid(pid);

		if (ret == -1) {
			/* It is not known why CRIU failed. Either
			 * CRIU is not available, the feature check
			 * does not exist or the feature is not
			 * supported. */
			INFO("feature not supported");
			/* Clear not supported feature bit */
			features &= ~(1ULL << current_bit);
		}

		current_bit++;
		/* no more checks requested; exit check loop */
		if (!(features & ~((1ULL << current_bit)-1)))
			break;
	}
	if (features != *features_to_check) {
		*features_to_check = features;
		return false;
	}
	return true;
}

/*
 * Check to see if the criu version is recent enough for all the features we
 * use. This version allows either CRIU_VERSION or (CRIU_GITID_VERSION and
 * CRIU_GITID_PATCHLEVEL) to work, enabling users building from git to c/r
 * things potentially before a version is released with a particular feature.
 *
 * The intent is that when criu development slows down, we can drop this, but
 * for now we shouldn't attempt to c/r with versions that we know won't work.
 *
 * Note: If version != NULL criu_version() stores the detected criu version in
 * version. Allocates memory for version which must be freed by caller.
 */
static bool criu_version_ok(char **version)
{
	int pipes[2];
	pid_t pid;

	if (pipe(pipes) < 0) {
		SYSERROR("pipe() failed");
		return false;
	}

	pid = fork();
	if (pid < 0) {
		SYSERROR("fork() failed");
		return false;
	}

	if (pid == 0) {
		char *args[] = { "criu", "--version", NULL };
		char *path;
		close(pipes[0]);

		close(STDERR_FILENO);
		if (dup2(pipes[1], STDOUT_FILENO) < 0)
			_exit(EXIT_FAILURE);

		path = on_path("criu", NULL);
		if (!path)
			_exit(EXIT_FAILURE);

		execv(path, args);
		_exit(EXIT_FAILURE);
	} else {
		FILE *f;
		char *tmp;
		int patch;

		close(pipes[1]);
		if (wait_for_pid(pid) < 0) {
			close(pipes[0]);
			SYSERROR("execing criu failed, is it installed?");
			return false;
		}

		f = fdopen(pipes[0], "re");
		if (!f) {
			close(pipes[0]);
			return false;
		}

		tmp = malloc(1024);
		if (!tmp) {
			fclose(f);
			return false;
		}

		if (fscanf(f, "Version: %1023[^\n]s", tmp) != 1)
			goto version_error;

		if (fgetc(f) != '\n')
			goto version_error;

		if (strcmp(tmp, CRIU_VERSION) >= 0)
			goto version_match;

		if (fscanf(f, "GitID: v%1023[^-]s", tmp) != 1)
			goto version_error;

		if (fgetc(f) != '-')
			goto version_error;

		if (fscanf(f, "%d", &patch) != 1)
			goto version_error;

		if (strcmp(tmp, CRIU_GITID_VERSION) < 0)
			goto version_error;

		if (patch < CRIU_GITID_PATCHLEVEL)
			goto version_error;

version_match:
		fclose(f);
		if (!version)
			free(tmp);
		else
			*version = tmp;
		return true;

version_error:
		fclose(f);
		free(tmp);
		ERROR("must have criu " CRIU_VERSION " or greater to checkpoint/restore");
		return false;
	}
}

/* Check and make sure the container has a configuration that we know CRIU can
 * dump. */
static bool criu_ok(struct lxc_container *c, char **criu_version)
{
	struct lxc_list *it;

	if (geteuid()) {
		ERROR("Must be root to checkpoint");
		return false;
	}

	if (!criu_version_ok(criu_version))
		return false;

	/* We only know how to restore containers with veth networks. */
	lxc_list_for_each(it, &c->lxc_conf->network) {
		struct lxc_netdev *n = it->elem;
		switch(n->type) {
		case LXC_NET_VETH:
		case LXC_NET_NONE:
		case LXC_NET_EMPTY:
		case LXC_NET_MACVLAN:
			break;
		default:
			ERROR("Found un-dumpable network: %s (%s)", lxc_net_type_to_str(n->type), n->name);
			if (criu_version) {
				free(*criu_version);
				*criu_version = NULL;
			}
			return false;
		}
	}

	return true;
}

static bool restore_net_info(struct lxc_container *c)
{
	int ret;
	struct lxc_list *it;
	bool has_error = true;

	if (container_mem_lock(c))
		return false;

	lxc_list_for_each(it, &c->lxc_conf->network) {
		struct lxc_netdev *netdev = it->elem;
		char template[IFNAMSIZ];

		if (netdev->type != LXC_NET_VETH)
			continue;

		ret = strnprintf(template, sizeof(template), "vethXXXXXX");
		if (ret < 0)
			goto out_unlock;

		if (netdev->priv.veth_attr.pair[0] == '\0' &&
		    netdev->priv.veth_attr.veth1[0] == '\0') {
			if (!lxc_ifname_alnum_case_sensitive(template))
				goto out_unlock;

			(void)strlcpy(netdev->priv.veth_attr.veth1, template, IFNAMSIZ);
		}
	}

	has_error = false;

out_unlock:
	container_mem_unlock(c);
	return !has_error;
}

/* do_restore never returns, the calling process is used as the monitor process.
 * do_restore calls _exit() if it fails.
 */
static void do_restore(struct lxc_container *c, int status_pipe, struct migrate_opts *opts, char *criu_version)
{
	int fd, ret;
	pid_t pid;
	struct lxc_handler *handler;
	int status = 0;
	int pipes[2] = {-1, -1};
	struct cgroup_ops *cgroup_ops;

	/* Try to detach from the current controlling tty if it exists.
	 * Otherwise, lxc_init (via lxc_console) will attach the container's
	 * console output to the current tty, which is probably not what any
	 * library user wants, and if they do, they can just manually configure
	 * it :)
	 */
	fd = open("/dev/tty", O_RDWR);
	if (fd >= 0) {
		if (ioctl(fd, TIOCNOTTY, NULL) < 0)
			SYSERROR("couldn't detach from tty");
		close(fd);
	}

	handler = lxc_init_handler(NULL, c->name, c->lxc_conf, c->config_path, false);
	if (!handler)
		goto out;

	if (lxc_init(c->name, handler) < 0)
		goto out;
	cgroup_ops = handler->cgroup_ops;

	if (!cgroup_ops->monitor_create(cgroup_ops, handler)) {
		ERROR("Failed to create monitor cgroup");
		goto out_fini_handler;
	}

	if (!cgroup_ops->monitor_enter(cgroup_ops, handler)) {
		ERROR("Failed to enter monitor cgroup");
		goto out_fini_handler;
	}

	if (!cgroup_ops->monitor_delegate_controllers(cgroup_ops)) {
		ERROR("Failed to delegate controllers to monitor cgroup");
		goto out_fini_handler;
	}

	if (!cgroup_ops->payload_create(cgroup_ops, handler)) {
		ERROR("Failed creating cgroups");
		goto out_fini_handler;
	}

	if (!restore_net_info(c)) {
		ERROR("failed restoring network info");
		goto out_fini_handler;
	}

	ret = resolve_clone_flags(handler);
	if (ret < 0) {
		SYSERROR("Unsupported clone flag specified");
		goto out_fini_handler;
	}

	if (pipe2(pipes, O_CLOEXEC) < 0) {
		SYSERROR("pipe() failed");
		goto out_fini_handler;
	}

	pid = fork();
	if (pid < 0)
		goto out_fini_handler;

	if (pid == 0) {
		struct criu_opts os;
		struct lxc_rootfs *rootfs;
		int flags;

		close(status_pipe);
		status_pipe = -1;

		close(pipes[0]);
		pipes[0] = -1;

		if (unshare(CLONE_NEWNS))
			goto out_fini_handler;

		ret = lxc_storage_prepare(c->lxc_conf);
		if (ret)
			goto out_fini_handler;

		/* CRIU needs the lxc root bind mounted so that it is the root of some
		 * mount. */
		rootfs = &c->lxc_conf->rootfs;

		if (rootfs_is_blockdev(c->lxc_conf)) {
			if (lxc_setup_rootfs_prepare_root(c->lxc_conf, c->name,
							  c->config_path) < 0)
				goto out_fini_handler;
		} else {
			if (mkdir(rootfs->mount, 0755) < 0 && errno != EEXIST)
				goto out_fini_handler;

			if (mount(NULL, "/", NULL, MS_SLAVE | MS_REC, NULL) < 0) {
				SYSERROR("remount / to private failed");
				goto out_fini_handler;
			}

			if (mount(rootfs->path, rootfs->mount, NULL, MS_BIND, NULL) < 0) {
				(void)rmdir(rootfs->mount);
				goto out_fini_handler;
			}
		}

		os.pipefd = pipes[1];
		os.action = "restore";
		os.user = opts;
		os.c = c;
		os.console_fd = c->lxc_conf->console.pty;
		os.criu_version = criu_version;
		os.handler = handler;

		if (os.console_fd >= 0) {
			/* Twiddle the FD_CLOEXEC bit. We want to pass this FD to criu
			 * via --inherit-fd, so we don't want it to close.
			 */
			flags = fcntl(os.console_fd, F_GETFD);
			if (flags < 0) {
				SYSERROR("F_GETFD failed: %d", os.console_fd);
				goto out_fini_handler;
			}

			flags &= ~FD_CLOEXEC;

			if (fcntl(os.console_fd, F_SETFD, flags) < 0) {
				SYSERROR("F_SETFD failed");
				goto out_fini_handler;
			}
		}
		os.console_name = c->lxc_conf->console.name;

		/* exec_criu() returning is an error */
		ret = exec_criu(handler->cgroup_ops, c->lxc_conf, &os);
		if (ret)
			SYSERROR("Failed to execute criu");
		umount(rootfs->mount);
		(void)rmdir(rootfs->mount);
		goto out_fini_handler;
	} else {
		char title[2048];

		close(pipes[1]);
		pipes[1] = -1;

		pid_t w = waitpid(pid, &status, 0);
		if (w == -1) {
			SYSERROR("waitpid");
			goto out_fini_handler;
		}

		if (WIFEXITED(status)) {
			char buf[4096];

			if (WEXITSTATUS(status)) {
				int n;

				n = lxc_read_nointr(pipes[0], buf, sizeof(buf));
				if (n < 0) {
					SYSERROR("failed reading from criu stderr");
					goto out_fini_handler;
				}

				if (n == sizeof(buf))
					n--;
				buf[n] = 0;

				ERROR("criu process exited %d, output:\n%s", WEXITSTATUS(status), buf);
				goto out_fini_handler;
			} else {
				ret = strnprintf(buf, sizeof(buf), "/proc/self/task/%lu/children", (unsigned long)syscall(__NR_gettid));
				if (ret < 0) {
					ERROR("strnprintf'd too many characters: %d", ret);
					goto out_fini_handler;
				}

				FILE *f = fopen(buf, "re");
				if (!f) {
					SYSERROR("couldn't read restore's children file %s", buf);
					goto out_fini_handler;
				}

				ret = fscanf(f, "%d", (int*) &handler->pid);
				fclose(f);
				if (ret != 1) {
					ERROR("reading restore pid failed");
					goto out_fini_handler;
				}

				if (lxc_set_state(c->name, handler, RUNNING)) {
					ERROR("error setting running state after restore");
					goto out_fini_handler;
				}
			}
		} else {
			ERROR("CRIU was killed with signal %d", WTERMSIG(status));
			goto out_fini_handler;
		}

		close(pipes[0]);

		ret = lxc_write_nointr(status_pipe, &status, sizeof(status));
		close(status_pipe);
		status_pipe = -1;

		if (sizeof(status) != ret) {
			SYSERROR("failed to write all of status");
			goto out_fini_handler;
		}

		/*
		 * See comment in lxcapi_start; we don't care if these
		 * fail because it's just a beauty thing. We just
		 * assign the return here to silence potential.
		 */
		ret = strnprintf(title, sizeof(title), "[lxc monitor] %s %s", c->config_path, c->name);
		if (ret < 0)
			INFO("Setting truncated process name");

		ret = setproctitle(title);
		if (ret < 0)
			INFO("Failed to set process name");

		ret = lxc_poll(c->name, handler);
		if (ret)
			lxc_abort(handler);
		lxc_end(handler);
		_exit(ret);
	}

out_fini_handler:
	if (pipes[0] >= 0)
		close(pipes[0]);
	if (pipes[1] >= 0)
		close(pipes[1]);

	lxc_end(handler);

out:
	if (status_pipe >= 0) {
		/* ensure getting here was a failure, e.g. if we failed to
		 * parse the child pid or something, even after a successful
		 * restore
		 */
		if (!status)
			status = 1;

		if (lxc_write_nointr(status_pipe, &status, sizeof(status)) != sizeof(status))
			SYSERROR("writing status failed");
		close(status_pipe);
	}

	_exit(EXIT_FAILURE);
}

static int save_tty_major_minor(char *directory, struct lxc_container *c, char *tty_id, int len)
{
	FILE *f;
	char path[PATH_MAX];
	int ret;
	struct stat sb;

	if (c->lxc_conf->console.path && strequal(c->lxc_conf->console.path, "none")) {
		tty_id[0] = 0;
		return 0;
	}

	ret = strnprintf(path, sizeof(path), "/proc/%d/root/dev/console", c->init_pid(c));
	if (ret < 0) {
		ERROR("strnprintf'd too many characters: %d", ret);
		return -1;
	}

	ret = stat(path, &sb);
	if (ret < 0) {
		SYSERROR("stat of %s failed", path);
		return -1;
	}

	ret = strnprintf(path, sizeof(path), "%s/tty.info", directory);
	if (ret < 0) {
		ERROR("strnprintf'd too many characters: %d", ret);
		return -1;
	}

	ret = strnprintf(tty_id, len, "tty[%llx:%llx]",
					(long long unsigned) sb.st_rdev,
					(long long unsigned) sb.st_dev);
	if (ret < 0) {
		ERROR("strnprintf'd too many characters: %d", ret);
		return -1;
	}

	f = fopen(path, "we");
	if (!f) {
		SYSERROR("failed to open %s", path);
		return -1;
	}

	ret = fprintf(f, "%s", tty_id);
	fclose(f);
	if (ret < 0)
		SYSERROR("failed to write to %s", path);
	return ret;
}

/* do one of either predump or a regular dump */
static bool do_dump(struct lxc_container *c, char *mode, struct migrate_opts *opts)
{
	int ret;
	pid_t pid;
	int criuout[2];
	char *criu_version = NULL;

	if (!criu_ok(c, &criu_version))
		return false;

	ret = pipe(criuout);
	if (ret < 0) {
		SYSERROR("pipe() failed");
		free(criu_version);
		return false;
	}

	if (mkdir_p(opts->directory, 0700) < 0)
		goto fail;

	pid = fork();
	if (pid < 0) {
		SYSERROR("fork failed");
		goto fail;
	}

	if (pid == 0) {
		struct criu_opts os;
		struct cgroup_ops *cgroup_ops;

		close(criuout[0]);

		cgroup_ops = cgroup_init(c->lxc_conf);
		if (!cgroup_ops) {
			ERROR("failed to cgroup_init()");
			_exit(EXIT_FAILURE);
		}

		os.pipefd = criuout[1];
		os.action = mode;
		os.user = opts;
		os.c = c;
		os.console_name = c->lxc_conf->console.path;
		os.criu_version = criu_version;
		os.handler = NULL;

		ret = save_tty_major_minor(opts->directory, c, os.tty_id, sizeof(os.tty_id));
		if (ret < 0) {
			free(criu_version);
			_exit(EXIT_FAILURE);
		}

		/* exec_criu() returning is an error */
		ret = exec_criu(cgroup_ops, c->lxc_conf, &os);
		if (ret)
			SYSERROR("Failed to execute criu");
		free(criu_version);
		_exit(EXIT_FAILURE);
	} else {
		int status;
		ssize_t n;
		char buf[4096];

		close(criuout[1]);

		pid_t w = waitpid(pid, &status, 0);
		if (w == -1) {
			SYSERROR("waitpid");
			close(criuout[0]);
			free(criu_version);
			return false;
		}

		n = lxc_read_nointr(criuout[0], buf, sizeof(buf));
		close(criuout[0]);
		if (n < 0) {
			SYSERROR("read");
			n = 0;
		}

		if (n == sizeof(buf))
			buf[n-1] = 0;
		else
			buf[n] = 0;

		if (WIFEXITED(status)) {
			if (WEXITSTATUS(status)) {
				ERROR("dump failed with %d", WEXITSTATUS(status));
				ret = false;
			} else {
				ret = true;
			}
		} else if (WIFSIGNALED(status)) {
			ERROR("dump signaled with %d", WTERMSIG(status));
			ret = false;
		} else {
			ERROR("unknown dump exit %d", status);
			ret = false;
		}

		if (!ret)
			ERROR("criu output: %s", buf);

		free(criu_version);
		return ret;
	}
fail:
	close(criuout[0]);
	close(criuout[1]);
	(void)rmdir(opts->directory);
	free(criu_version);
	return false;
}

bool __criu_pre_dump(struct lxc_container *c, struct migrate_opts *opts)
{
	return do_dump(c, "pre-dump", opts);
}

bool __criu_dump(struct lxc_container *c, struct migrate_opts *opts)
{
	char path[PATH_MAX];
	int ret;

	ret = strnprintf(path, sizeof(path), "%s/inventory.img", opts->directory);
	if (ret < 0)
		return false;

	if (access(path, F_OK) == 0) {
		ERROR("please use a fresh directory for the dump directory");
		return false;
	}

	return do_dump(c, "dump", opts);
}

bool __criu_restore(struct lxc_container *c, struct migrate_opts *opts)
{
	pid_t pid;
	int status, nread;
	int pipefd[2];
	char *criu_version = NULL;

	if (geteuid()) {
		ERROR("Must be root to restore");
		return false;
	}

	if (pipe(pipefd)) {
		ERROR("failed to create pipe");
		return false;
	}

	if (!criu_ok(c, &criu_version)) {
		close(pipefd[0]);
		close(pipefd[1]);
		return false;
	}

	pid = fork();
	if (pid < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		free(criu_version);
		return false;
	}

	if (pid == 0) {
		close(pipefd[0]);
		/* this never returns */
		do_restore(c, pipefd[1], opts, criu_version);
	}

	close(pipefd[1]);
	free(criu_version);

	nread = lxc_read_nointr(pipefd[0], &status, sizeof(status));
	close(pipefd[0]);
	if (sizeof(status) != nread) {
		ERROR("reading status from pipe failed");
		goto err_wait;
	}

	/* If the criu process was killed or exited nonzero, wait() for the
	 * handler, since the restore process died. Otherwise, we don't need to
	 * wait, since the child becomes the monitor process.
	 */
	if (!WIFEXITED(status) || WEXITSTATUS(status))
		goto err_wait;
	return true;

err_wait:
	if (wait_for_pid(pid))
		ERROR("restore process died");
	return false;
}

/*
 * lxc: linux Container library
 *
 * Copyright © 2014-2015 Canonical Ltd.
 *
 * Authors:
 * Tycho Andersen <tycho.andersen@canonical.com>
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
	 * want to use `--ext-mount-map auto`'s result here because the pts
	 * device may have a different path (e.g. if the pty number is
	 * different) on the target host. NULL if lxc.console.path = "none".
	 */
	char *console_name;

	/* The detected version of criu */
	char *criu_version;
};

static int load_tty_major_minor(char *directory, char *output, int len)
{
	FILE *f;
	char path[PATH_MAX];
	int ret;

	ret = snprintf(path, sizeof(path), "%s/tty.info", directory);
	if (ret < 0 || ret >= sizeof(path)) {
		ERROR("snprintf'd too many characters: %d", ret);
		return -1;
	}

	f = fopen(path, "r");
	if (!f) {
		/* This means we're coming from a liblxc which didn't export
		 * the tty info. In this case they had to have lxc.console.path
		 * = * none, so there's no problem restoring.
		 */
		if (errno == ENOENT)
			return 0;

		SYSERROR("couldn't open %s", path);
		return -1;
	}

	if (!fgets(output, len, f)) {
		fclose(f);
		SYSERROR("couldn't read %s", path);
		return -1;
	}

	fclose(f);
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

static void exec_criu(struct cgroup_ops *cgroup_ops, struct lxc_conf *conf,
		      struct criu_opts *opts)
{
	char **argv, log[PATH_MAX];
	int static_args = 23, argc = 0, i, ret;
	int netnr = 0;
	struct lxc_list *it;
	FILE *mnts;
	struct mntent mntent;

	char buf[4096], ttys[32];
	size_t pos;

	/* If we are currently in a cgroup /foo/bar, and the container is in a
	 * cgroup /lxc/foo, lxcfs will give us an ENOENT if some task in the
	 * container has an open fd that points to one of the cgroup files
	 * (systemd always opens its "root" cgroup). So, let's escape to the
	 * /actual/ root cgroup so that lxcfs thinks criu has enough rights to
	 * see all cgroups.
	 */
	if (!cgroup_ops->escape(cgroup_ops)) {
		ERROR("failed to escape cgroups");
		return;
	}

	/* The command line always looks like:
	 * criu $(action) --tcp-established --file-locks --link-remap \
	 * --manage-cgroups=full --action-script foo.sh -D $(directory) \
	 * -o $(directory)/$(action).log --ext-mount-map auto
	 * --enable-external-sharing --enable-external-masters
	 * --enable-fs hugetlbfs --enable-fs tracefs --ext-mount-map console:/dev/pts/n
	 * +1 for final NULL */

	if (strcmp(opts->action, "dump") == 0 || strcmp(opts->action, "pre-dump") == 0) {
		/* -t pid --freeze-cgroup /lxc/ct */
		static_args += 4;

		/* --prev-images-dir <path-to-directory-A-relative-to-B> */
		if (opts->user->predump_dir)
			static_args += 2;

		/* --page-server --address <address> --port <port> */
		if (opts->user->pageserver_address && opts->user->pageserver_port)
			static_args += 5;

		/* --leave-running (only for final dump) */
		if (strcmp(opts->action, "dump") == 0 && !opts->user->stop)
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
	} else if (strcmp(opts->action, "restore") == 0) {
		/* --root $(lxc_mount_point) --restore-detached
		 * --restore-sibling
		 * --lsm-profile apparmor:whatever
		 */
		static_args += 6;

		ttys[0] = 0;
		if (load_tty_major_minor(opts->user->directory, ttys, sizeof(ttys)))
			return;

		/* --inherit-fd fd[%d]:tty[%s] */
		if (ttys[0])
			static_args += 2;
	} else {
		return;
	}

	if (cgroup_ops->num_hierarchies(cgroup_ops) > 0)
		static_args += 2 * cgroup_ops->num_hierarchies(cgroup_ops);

	if (opts->user->verbose)
		static_args++;

	if (opts->user->action_script)
		static_args += 2;

	static_args += 2 * lxc_list_len(&opts->c->lxc_conf->mount_list);

	ret = snprintf(log, PATH_MAX, "%s/%s.log", opts->user->directory, opts->action);
	if (ret < 0 || ret >= PATH_MAX) {
		ERROR("logfile name too long");
		return;
	}

	argv = malloc(static_args * sizeof(*argv));
	if (!argv)
		return;

	memset(argv, 0, static_args * sizeof(*argv));

#define DECLARE_ARG(arg) 					\
	do {							\
		if (arg == NULL) {				\
			ERROR("Got NULL argument for criu");	\
			goto err;				\
		}						\
		argv[argc++] = strdup(arg);			\
		if (!argv[argc-1])				\
			goto err;				\
	} while (0)

	argv[argc++] = on_path("criu", NULL);
	if (!argv[argc-1]) {
		ERROR("Couldn't find criu binary");
		goto err;
	}

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

	for (i = 0; i < cgroup_ops->num_hierarchies(cgroup_ops); i++) {
		char **controllers = NULL, *fullname;
		char *path, *tmp;

		if (!cgroup_ops->get_hierarchies(cgroup_ops, i, &controllers)) {
			ERROR("failed to get hierarchy %d", i);
			goto err;
		}

		/* if we are in a dump, we have to ask the monitor process what
		 * the right cgroup is. if this is a restore, we can just use
		 * the handler the restore task created.
		 */
		if (!strcmp(opts->action, "dump") || !strcmp(opts->action, "pre-dump")) {
			path = lxc_cmd_get_cgroup_path(opts->c->name, opts->c->config_path, controllers[0]);
			if (!path) {
				ERROR("failed to get cgroup path for %s", controllers[0]);
				goto err;
			}
		} else {
			const char *p;

			p = cgroup_ops->get_cgroup(cgroup_ops, controllers[0]);
			if (!p) {
				ERROR("failed to get cgroup path for %s", controllers[0]);
				goto err;
			}

			path = strdup(p);
			if (!path) {
				ERROR("strdup failed");
				goto err;
			}
		}

		tmp = lxc_deslashify(path);
		if (!tmp) {
			ERROR("Failed to remove extraneous slashes from \"%s\"",
			      path);
			free(path);
			goto err;
		}
		free(path);
		path = tmp;

		fullname = lxc_string_join(",", (const char **) controllers, false);
		if (!fullname) {
			ERROR("failed to join controllers");
			free(path);
			goto err;
		}

		ret = sprintf(buf, "%s:%s", fullname, path);
		free(path);
		free(fullname);
		if (ret < 0 || ret >= sizeof(buf)) {
			ERROR("sprintf of cgroup root arg failed");
			goto err;
		}

		DECLARE_ARG("--cgroup-root");
		DECLARE_ARG(buf);
	}

	if (opts->user->verbose)
		DECLARE_ARG("-vvvvvv");

	if (opts->user->action_script) {
		DECLARE_ARG("--action-script");
		DECLARE_ARG(opts->user->action_script);
	}

	mnts = make_anonymous_mount_file(&opts->c->lxc_conf->mount_list);
	if (!mnts)
		goto err;

	while (getmntent_r(mnts, &mntent, buf, sizeof(buf))) {
		char *fmt, *key, *val, *mntdata;
		char arg[2 * PATH_MAX + 2];
		unsigned long flags;

		if (parse_mntopts(mntent.mnt_opts, &flags, &mntdata) < 0)
			goto err;

		free(mntdata);

		/* only add --ext-mount-map for actual bind mounts */
		if (!(flags & MS_BIND))
			continue;

		if (strcmp(opts->action, "dump") == 0) {
			fmt = "/%s:%s";
			key = mntent.mnt_dir;
			val = mntent.mnt_dir;
		} else {
			fmt = "%s:%s";
			key = mntent.mnt_dir;
			val = mntent.mnt_fsname;
		}

		ret = snprintf(arg, sizeof(arg), fmt, key, val);
		if (ret < 0 || ret >= sizeof(arg)) {
			fclose(mnts);
			ERROR("snprintf failed");
			goto err;
		}

		DECLARE_ARG("--ext-mount-map");
		DECLARE_ARG(arg);
	}
	fclose(mnts);

	if (strcmp(opts->action, "dump") == 0 || strcmp(opts->action, "pre-dump") == 0) {
		char pid[32], *freezer_relative;

		if (sprintf(pid, "%d", opts->c->init_pid(opts->c)) < 0)
			goto err;

		DECLARE_ARG("-t");
		DECLARE_ARG(pid);

		freezer_relative = lxc_cmd_get_cgroup_path(opts->c->name,
							   opts->c->config_path,
							   "freezer");
		if (!freezer_relative) {
			ERROR("failed getting freezer path");
			goto err;
		}

		ret = snprintf(log, sizeof(log), "/sys/fs/cgroup/freezer/%s", freezer_relative);
		if (ret < 0 || ret >= sizeof(log))
			goto err;

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
			if (ret < 0 || ret >= sizeof(ghost_limit)) {
				ERROR("failed to print ghost limit %"PRIu64, opts->user->ghost_limit);
				goto err;
			}

			DECLARE_ARG("--ghost-limit");
			DECLARE_ARG(ghost_limit);
		}

		/* only for final dump */
		if (strcmp(opts->action, "dump") == 0 && !opts->user->stop)
			DECLARE_ARG("--leave-running");
	} else if (strcmp(opts->action, "restore") == 0) {
		void *m;
		int additional;
		struct lxc_conf *lxc_conf = opts->c->lxc_conf;

		DECLARE_ARG("--root");
		DECLARE_ARG(opts->c->lxc_conf->rootfs.mount);
		DECLARE_ARG("--restore-detached");
		DECLARE_ARG("--restore-sibling");

		if (ttys[0]) {
			if (opts->console_fd < 0) {
				ERROR("lxc.console.path configured on source host but not target");
				goto err;
			}

			ret = snprintf(buf, sizeof(buf), "fd[%d]:%s", opts->console_fd, ttys);
			if (ret < 0 || ret >= sizeof(buf))
				goto err;

			DECLARE_ARG("--inherit-fd");
			DECLARE_ARG(buf);
		}
		if (opts->console_name) {
			if (snprintf(buf, sizeof(buf), "console:%s", opts->console_name) < 0) {
				SYSERROR("sprintf'd too many bytes");
			}
			DECLARE_ARG("--ext-mount-map");
			DECLARE_ARG(buf);
		}

		if (lxc_conf->lsm_aa_profile || lxc_conf->lsm_se_context) {

			if (lxc_conf->lsm_aa_profile)
				ret = snprintf(buf, sizeof(buf), "apparmor:%s", lxc_conf->lsm_aa_profile);
			else
				ret = snprintf(buf, sizeof(buf), "selinux:%s", lxc_conf->lsm_se_context);

			if (ret < 0 || ret >= sizeof(buf))
				goto err;

			DECLARE_ARG("--lsm-profile");
			DECLARE_ARG(buf);
		}

		additional = lxc_list_len(&opts->c->lxc_conf->network) * 2;

		m = realloc(argv, (argc + additional + 1) * sizeof(*argv));
		if (!m)
			goto err;
		argv = m;

		lxc_list_for_each(it, &opts->c->lxc_conf->network) {
			size_t retlen;
			char eth[128], *veth;
			char *fmt;
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
					goto err;
			} else {
				ret = snprintf(eth, sizeof(eth), "eth%d", netnr);
				if (ret < 0 || ret >= sizeof(eth))
					goto err;
			}

			switch (n->type) {
			case LXC_NET_VETH:
				veth = n->priv.veth_attr.pair;
				if (veth[0] == '\0')
					veth = n->priv.veth_attr.veth1;

				if (n->link[0] != '\0') {
					if (external_not_veth)
						fmt = "veth[%s]:%s@%s";
					else
						fmt = "%s=%s@%s";

					ret = snprintf(buf, sizeof(buf), fmt, eth, veth, n->link);
				} else {
					if (external_not_veth)
						fmt = "veth[%s]:%s";
					else
						fmt = "%s=%s";

					ret = snprintf(buf, sizeof(buf), fmt, eth, veth);
				}
				if (ret < 0 || ret >= sizeof(buf))
					goto err;
				break;
			case LXC_NET_MACVLAN:
				if (n->link[0] == '\0') {
					ERROR("no host interface for macvlan %s", n->name);
					goto err;
				}

				ret = snprintf(buf, sizeof(buf), "macvlan[%s]:%s", eth, n->link);
				if (ret < 0 || ret >= sizeof(buf))
					goto err;
				break;
			case LXC_NET_NONE:
			case LXC_NET_EMPTY:
				break;
			default:
				/* we have screened for this earlier... */
				ERROR("unexpected network type %d", n->type);
				goto err;
			}

			if (external_not_veth)
				DECLARE_ARG("--external");
			else
				DECLARE_ARG("--veth-pair");
			DECLARE_ARG(buf);
			netnr++;
		}

	}

	argv[argc] = NULL;

	buf[0] = 0;
	pos = 0;

	for (i = 0; argv[i]; i++) {
		ret = snprintf(buf + pos, sizeof(buf) - pos, "%s ", argv[i]);
		if (ret < 0 || ret >= sizeof(buf) - pos)
			goto err;
		else
			pos += ret;
	}

	INFO("execing: %s", buf);

	/* before criu inits its log, it sometimes prints things to stdout/err;
	 * let's be sure we capture that.
	 */
	if (dup2(opts->pipefd, STDOUT_FILENO) < 0) {
		SYSERROR("dup2 stdout failed");
		goto err;
	}

	if (dup2(opts->pipefd, STDERR_FILENO) < 0) {
		SYSERROR("dup2 stderr failed");
		goto err;
	}

	close(opts->pipefd);

#undef DECLARE_ARG
	execv(argv[0], argv);
err:
	for (i = 0; argv[i]; i++)
		free(argv[i]);
	free(argv);
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

		f = fdopen(pipes[0], "r");
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

		ret = snprintf(template, sizeof(template), "vethXXXXXX");
		if (ret < 0 || ret >= sizeof(template))
			goto out_unlock;

		if (netdev->priv.veth_attr.pair[0] == '\0' &&
		    netdev->priv.veth_attr.veth1[0] == '\0') {
			if (!lxc_mkifname(template))
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

	handler = lxc_init_handler(c->name, c->lxc_conf, c->config_path, false);
	if (!handler)
		goto out;

	if (lxc_init(c->name, handler) < 0)
		goto out;

	cgroup_ops = cgroup_init(NULL);
	if (!cgroup_ops)
		goto out_fini_handler;
	handler->cgroup_ops = cgroup_ops;

	if (!cgroup_ops->payload_create(cgroup_ops, handler)) {
		ERROR("failed creating groups");
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
				rmdir(rootfs->mount);
				goto out_fini_handler;
			}
		}

		os.pipefd = pipes[1];
		os.action = "restore";
		os.user = opts;
		os.c = c;
		os.console_fd = c->lxc_conf->console.slave;
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
		exec_criu(cgroup_ops, c->lxc_conf, &os);
		umount(rootfs->mount);
		rmdir(rootfs->mount);
		goto out_fini_handler;
	} else {
		int ret;
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
				ret = snprintf(buf, sizeof(buf), "/proc/self/task/%lu/children", (unsigned long)syscall(__NR_gettid));
				if (ret < 0 || ret >= sizeof(buf)) {
					ERROR("snprintf'd too many characters: %d", ret);
					goto out_fini_handler;
				}

				FILE *f = fopen(buf, "r");
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
		ret = snprintf(title, sizeof(title), "[lxc monitor] %s %s", c->config_path, c->name);
		if (ret < 0 || (size_t)ret >= sizeof(title))
			INFO("Setting truncated process name");

		ret = setproctitle(title);
		if (ret < 0)
			INFO("Failed to set process name");

		ret = lxc_poll(c->name, handler);
		if (ret)
			lxc_abort(c->name, handler);
		lxc_fini(c->name, handler);
		_exit(ret);
	}

out_fini_handler:
	if (pipes[0] >= 0)
		close(pipes[0]);
	if (pipes[1] >= 0)
		close(pipes[1]);

	lxc_fini(c->name, handler);

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

	if (c->lxc_conf->console.path && !strcmp(c->lxc_conf->console.path, "none")) {
		tty_id[0] = 0;
		return 0;
	}

	ret = snprintf(path, sizeof(path), "/proc/%d/root/dev/console", c->init_pid(c));
	if (ret < 0 || ret >= sizeof(path)) {
		ERROR("snprintf'd too many characters: %d", ret);
		return -1;
	}

	ret = stat(path, &sb);
	if (ret < 0) {
		SYSERROR("stat of %s failed", path);
		return -1;
	}

	ret = snprintf(path, sizeof(path), "%s/tty.info", directory);
	if (ret < 0 || ret >= sizeof(path)) {
		ERROR("snprintf'd too many characters: %d", ret);
		return -1;
	}

	ret = snprintf(tty_id, len, "tty[%llx:%llx]",
					(long long unsigned) sb.st_rdev,
					(long long unsigned) sb.st_dev);
	if (ret < 0 || ret >= sizeof(path)) {
		ERROR("snprintf'd too many characters: %d", ret);
		return -1;
	}

	f = fopen(path, "w");
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

		cgroup_ops = cgroup_init(NULL);
		if (!cgroup_ops) {
			ERROR("failed to cgroup_init()");
			_exit(EXIT_FAILURE);
			return -1;
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
		exec_criu(cgroup_ops, c->lxc_conf, &os);
		free(criu_version);
		_exit(EXIT_FAILURE);
	} else {
		int status;
		ssize_t n;
		char buf[4096];
		bool ret;

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
	rmdir(opts->directory);
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

	ret = snprintf(path, sizeof(path), "%s/inventory.img", opts->directory);
	if (ret < 0 || ret >= sizeof(path))
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

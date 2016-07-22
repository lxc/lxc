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
#define _GNU_SOURCE
#include <assert.h>
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

#include "config.h"

#include "bdev/bdev.h"
#include "cgroup.h"
#include "conf.h"
#include "commands.h"
#include "criu.h"
#include "log.h"
#include "lxc.h"
#include "lxclock.h"
#include "network.h"
#include "utils.h"

#define CRIU_VERSION		"2.0"

#define CRIU_GITID_VERSION	"2.0"
#define CRIU_GITID_PATCHLEVEL	0

#define CRIU_IN_FLIGHT_SUPPORT	"2.4"

lxc_log_define(lxc_criu, lxc);

struct criu_opts {
	/* The type of criu invocation, one of "dump" or "restore" */
	char *action;

	/* the user-provided migrate options relevant to this action */
	struct migrate_opts *user;

	/* The container to dump */
	struct lxc_container *c;

	/* dump: stop the container or not after dumping? */
	char tty_id[32]; /* the criu tty id for /dev/console, i.e. "tty[${rdev}:${dev}]" */

	/* restore: the file to write the init process' pid into */
	char *pidfile;
	const char *cgroup_path;
	int console_fd;
	/* The path that is bind mounted from /dev/console, if any. We don't
	 * want to use `--ext-mount-map auto`'s result here because the pts
	 * device may have a different path (e.g. if the pty number is
	 * different) on the target host. NULL if lxc.console = "none".
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
		ERROR("snprintf'd too many chacters: %d", ret);
		return -1;
	}

	f = fopen(path, "r");
	if (!f) {
		/* This means we're coming from a liblxc which didn't export
		 * the tty info. In this case they had to have lxc.console =
		 * none, so there's no problem restoring.
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

static void exec_criu(struct criu_opts *opts)
{
	char **argv, log[PATH_MAX];
	int static_args = 23, argc = 0, i, ret;
	int netnr = 0;
	struct lxc_list *it;

	char buf[4096], tty_info[32];
	size_t pos;
	/* If we are currently in a cgroup /foo/bar, and the container is in a
	 * cgroup /lxc/foo, lxcfs will give us an ENOENT if some task in the
	 * container has an open fd that points to one of the cgroup files
	 * (systemd always opens its "root" cgroup). So, let's escape to the
	 * /actual/ root cgroup so that lxcfs thinks criu has enough rights to
	 * see all cgroups.
	 */
	if (!cgroup_escape()) {
		ERROR("failed to escape cgroups");
		return;
	}

	/* The command line always looks like:
	 * criu $(action) --tcp-established --file-locks --link-remap \
	 * --manage-cgroups=full action-script foo.sh -D $(directory) \
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
		 * --restore-sibling --pidfile $foo --cgroup-root $foo
		 * --lsm-profile apparmor:whatever
		 */
		static_args += 10;

		tty_info[0] = 0;
		if (load_tty_major_minor(opts->user->directory, tty_info, sizeof(tty_info)))
			return;

		/* --inherit-fd fd[%d]:tty[%s] */
		if (tty_info[0])
			static_args += 2;
	} else {
		return;
	}

	if (opts->user->verbose)
		static_args++;

	if (opts->user->action_script)
		static_args += 2;

	ret = snprintf(log, PATH_MAX, "%s/%s.log", opts->user->directory, opts->action);
	if (ret < 0 || ret >= PATH_MAX) {
		ERROR("logfile name too long\n");
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
		ERROR("Couldn't find criu binary\n");
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

	if (opts->user->verbose)
		DECLARE_ARG("-vvvvvv");

	if (opts->user->action_script) {
		DECLARE_ARG("--action-script");
		DECLARE_ARG(opts->user->action_script);
	}

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
		DECLARE_ARG("--pidfile");
		DECLARE_ARG(opts->pidfile);
		DECLARE_ARG("--cgroup-root");
		DECLARE_ARG(opts->cgroup_path);

		if (tty_info[0]) {
			if (opts->console_fd < 0) {
				ERROR("lxc.console configured on source host but not target");
				goto err;
			}

			ret = snprintf(buf, sizeof(buf), "fd[%d]:%s", opts->console_fd, tty_info);
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
			char eth[128], *veth;
			struct lxc_netdev *n = it->elem;

			if (n->type != LXC_NET_VETH)
				continue;

			if (n->name) {
				if (strlen(n->name) >= sizeof(eth))
					goto err;
				strncpy(eth, n->name, sizeof(eth));
			} else
				sprintf(eth, "eth%d", netnr);

			veth = n->priv.veth_attr.pair;

			if (n->link)
				ret = snprintf(buf, sizeof(buf), "%s=%s@%s", eth, veth, n->link);
			else
				ret = snprintf(buf, sizeof(buf), "%s=%s", eth, veth);
			if (ret < 0 || ret >= sizeof(buf))
				goto err;

			DECLARE_ARG("--veth-pair");
			DECLARE_ARG(buf);
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

#undef DECLARE_ARG
	execv(argv[0], argv);
err:
	for (i = 0; argv[i]; i++)
		free(argv[i]);
	free(argv);
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
			exit(1);

		path = on_path("criu", NULL);
		if (!path)
			exit(1);

		execv(path, args);
		exit(1);
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
		ERROR("must have criu " CRIU_VERSION " or greater to checkpoint/restore\n");
		return false;
	}
}

/* Check and make sure the container has a configuration that we know CRIU can
 * dump. */
static bool criu_ok(struct lxc_container *c, char **criu_version)
{
	struct lxc_list *it;

	if (!criu_version_ok(criu_version))
		return false;

	if (geteuid()) {
		ERROR("Must be root to checkpoint\n");
		return false;
	}

	/* We only know how to restore containers with veth networks. */
	lxc_list_for_each(it, &c->lxc_conf->network) {
		struct lxc_netdev *n = it->elem;
		switch(n->type) {
		case LXC_NET_VETH:
		case LXC_NET_NONE:
		case LXC_NET_EMPTY:
			break;
		default:
			ERROR("Found network that is not VETH or NONE\n");
			return false;
		}
	}

	return true;
}

static bool restore_net_info(struct lxc_container *c)
{
	struct lxc_list *it;
	bool has_error = true;

	if (container_mem_lock(c))
		return false;

	lxc_list_for_each(it, &c->lxc_conf->network) {
		struct lxc_netdev *netdev = it->elem;
		char template[IFNAMSIZ];

		if (netdev->type != LXC_NET_VETH)
			continue;

		snprintf(template, sizeof(template), "vethXXXXXX");

		if (!netdev->priv.veth_attr.pair)
			netdev->priv.veth_attr.pair = lxc_mkifname(template);

		if (!netdev->priv.veth_attr.pair)
			goto out_unlock;
	}

	has_error = false;

out_unlock:
	container_mem_unlock(c);
	return !has_error;
}

// do_restore never returns, the calling process is used as the
// monitor process. do_restore calls exit() if it fails.
static void do_restore(struct lxc_container *c, int status_pipe, struct migrate_opts *opts, char *criu_version)
{
	pid_t pid;
	char pidfile[L_tmpnam];
	struct lxc_handler *handler;
	int status, pipes[2] = {-1, -1};

	if (!tmpnam(pidfile))
		goto out;

	handler = lxc_init(c->name, c->lxc_conf, c->config_path);
	if (!handler)
		goto out;

	if (!cgroup_init(handler)) {
		ERROR("failed initing cgroups");
		goto out_fini_handler;
	}

	if (!cgroup_create(handler)) {
		ERROR("failed creating groups");
		goto out_fini_handler;
	}

	if (!restore_net_info(c)) {
		ERROR("failed restoring network info");
		goto out_fini_handler;
	}

	resolve_clone_flags(handler);

	if (pipe(pipes) < 0) {
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
		if (dup2(pipes[1], STDERR_FILENO) < 0) {
			SYSERROR("dup2 failed");
			goto out_fini_handler;
		}

		if (dup2(pipes[1], STDOUT_FILENO) < 0) {
			SYSERROR("dup2 failed");
			goto out_fini_handler;
		}

		if (unshare(CLONE_NEWNS))
			goto out_fini_handler;

		/* CRIU needs the lxc root bind mounted so that it is the root of some
		 * mount. */
		rootfs = &c->lxc_conf->rootfs;

		if (rootfs_is_blockdev(c->lxc_conf)) {
			if (do_rootfs_setup(c->lxc_conf, c->name, c->config_path) < 0)
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

		os.action = "restore";
		os.user = opts;
		os.c = c;
		os.pidfile = pidfile;
		os.cgroup_path = cgroup_canonical_path(handler);
		os.console_fd = c->lxc_conf->console.slave;
		os.criu_version = criu_version;

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
		exec_criu(&os);
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

		ret = write(status_pipe, &status, sizeof(status));
		close(status_pipe);
		status_pipe = -1;

		if (sizeof(status) != ret) {
			SYSERROR("failed to write all of status");
			goto out_fini_handler;
		}

		if (WIFEXITED(status)) {
			if (WEXITSTATUS(status)) {
				char buf[4096];
				int n;

				n = read(pipes[0], buf, sizeof(buf));
				if (n < 0) {
					SYSERROR("failed reading from criu stderr");
					goto out_fini_handler;
				}

				buf[n] = 0;

				ERROR("criu process exited %d, output:\n%s\n", WEXITSTATUS(status), buf);
				goto out_fini_handler;
			} else {
				int ret;
				FILE *f = fopen(pidfile, "r");
				if (!f) {
					SYSERROR("couldn't read restore's init pidfile %s\n", pidfile);
					goto out_fini_handler;
				}

				ret = fscanf(f, "%d", (int*) &handler->pid);
				fclose(f);
				if (unlink(pidfile) < 0 && errno != ENOENT)
					SYSERROR("unlinking pidfile failed");

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
			ERROR("CRIU was killed with signal %d\n", WTERMSIG(status));
			goto out_fini_handler;
		}

		close(pipes[0]);

		/*
		 * See comment in lxcapi_start; we don't care if these
		 * fail because it's just a beauty thing. We just
		 * assign the return here to silence potential.
		 */
		ret = snprintf(title, sizeof(title), "[lxc monitor] %s %s", c->config_path, c->name);
		ret = setproctitle(title);

		ret = lxc_poll(c->name, handler);
		if (ret)
			lxc_abort(c->name, handler);
		lxc_fini(c->name, handler);
		exit(ret);
	}

out_fini_handler:
	if (pipes[0] >= 0)
		close(pipes[0]);
	if (pipes[1] >= 0)
		close(pipes[1]);

	lxc_fini(c->name, handler);
	if (unlink(pidfile) < 0 && errno != ENOENT)
		SYSERROR("unlinking pidfile failed");

out:
	if (status_pipe >= 0) {
		status = 1;
		if (write(status_pipe, &status, sizeof(status)) != sizeof(status)) {
			SYSERROR("writing status failed");
		}
		close(status_pipe);
	}

	exit(1);
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
		ERROR("snprintf'd too many chacters: %d", ret);
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
	pid_t pid;
	char *criu_version = NULL;

	if (!criu_ok(c, &criu_version))
		return false;

	if (mkdir_p(opts->directory, 0700) < 0)
		return false;

	pid = fork();
	if (pid < 0) {
		SYSERROR("fork failed");
		return false;
	}

	if (pid == 0) {
		struct criu_opts os;

		os.action = mode;
		os.user = opts;
		os.c = c;
		os.console_name = c->lxc_conf->console.path;
		os.criu_version = criu_version;

		if (save_tty_major_minor(opts->directory, c, os.tty_id, sizeof(os.tty_id)) < 0)
			exit(1);

		/* exec_criu() returning is an error */
		exec_criu(&os);
		exit(1);
	} else {
		int status;
		pid_t w = waitpid(pid, &status, 0);
		if (w == -1) {
			SYSERROR("waitpid");
			return false;
		}

		if (WIFEXITED(status)) {
			if (WEXITSTATUS(status)) {
				ERROR("dump failed with %d\n", WEXITSTATUS(status));
				return false;
			}

			return true;
		} else if (WIFSIGNALED(status)) {
			ERROR("dump signaled with %d\n", WTERMSIG(status));
			return false;
		} else {
			ERROR("unknown dump exit %d\n", status);
			return false;
		}
	}
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
		ERROR("please use a fresh directory for the dump directory\n");
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

	if (!criu_ok(c, &criu_version))
		return false;

	if (geteuid()) {
		ERROR("Must be root to restore\n");
		return false;
	}

	if (pipe(pipefd)) {
		ERROR("failed to create pipe");
		return false;
	}

	pid = fork();
	if (pid < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		return false;
	}

	if (pid == 0) {
		close(pipefd[0]);
		// this never returns
		do_restore(c, pipefd[1], opts, criu_version);
	}

	close(pipefd[1]);

	nread = read(pipefd[0], &status, sizeof(status));
	close(pipefd[0]);
	if (sizeof(status) != nread) {
		ERROR("reading status from pipe failed");
		goto err_wait;
	}

	// If the criu process was killed or exited nonzero, wait() for the
	// handler, since the restore process died. Otherwise, we don't need to
	// wait, since the child becomes the monitor process.
	if (!WIFEXITED(status) || WEXITSTATUS(status))
		goto err_wait;
	return true;

err_wait:
	if (wait_for_pid(pid))
		ERROR("restore process died");
	return false;
}

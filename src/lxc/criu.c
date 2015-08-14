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

#include "bdev.h"
#include "cgroup.h"
#include "conf.h"
#include "criu.h"
#include "log.h"
#include "lxc.h"
#include "lxclock.h"
#include "network.h"
#include "utils.h"

lxc_log_define(lxc_criu, lxc);

void exec_criu(struct criu_opts *opts)
{
	char **argv, log[PATH_MAX];
	int static_args = 22, argc = 0, i, ret;
	int netnr = 0;
	struct lxc_list *it;

	char buf[4096];

	/* The command line always looks like:
	 * criu $(action) --tcp-established --file-locks --link-remap --force-irmap \
	 * --manage-cgroups action-script foo.sh -D $(directory) \
	 * -o $(directory)/$(action).log --ext-mount-map auto
	 * --enable-external-sharing --enable-external-masters
	 * --enable-fs hugetlbfs --enable-fs tracefs
	 * +1 for final NULL */

	if (strcmp(opts->action, "dump") == 0) {
		/* -t pid */
		static_args += 2;

		/* --leave-running */
		if (!opts->stop)
			static_args++;
	} else if (strcmp(opts->action, "restore") == 0) {
		/* --root $(lxc_mount_point) --restore-detached
		 * --restore-sibling --pidfile $foo --cgroup-root $foo */
		static_args += 8;
	} else {
		return;
	}

	if (opts->verbose)
		static_args++;

	ret = snprintf(log, PATH_MAX, "%s/%s.log", opts->directory, opts->action);
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
	DECLARE_ARG("--force-irmap");
	DECLARE_ARG("--manage-cgroups");
	DECLARE_ARG("--ext-mount-map");
	DECLARE_ARG("auto");
	DECLARE_ARG("--enable-external-sharing");
	DECLARE_ARG("--enable-external-masters");
	DECLARE_ARG("--enable-fs");
	DECLARE_ARG("hugetlbfs");
	DECLARE_ARG("--enable-fs");
	DECLARE_ARG("tracefs");
	DECLARE_ARG("-D");
	DECLARE_ARG(opts->directory);
	DECLARE_ARG("-o");
	DECLARE_ARG(log);

	if (opts->verbose)
		DECLARE_ARG("-vvvvvv");

	if (strcmp(opts->action, "dump") == 0) {
		char pid[32];

		if (sprintf(pid, "%d", opts->c->init_pid(opts->c)) < 0)
			goto err;

		DECLARE_ARG("-t");
		DECLARE_ARG(pid);
		if (!opts->stop)
			DECLARE_ARG("--leave-running");
	} else if (strcmp(opts->action, "restore") == 0) {
		void *m;
		int additional;

		DECLARE_ARG("--root");
		DECLARE_ARG(opts->c->lxc_conf->rootfs.mount);
		DECLARE_ARG("--restore-detached");
		DECLARE_ARG("--restore-sibling");
		DECLARE_ARG("--pidfile");
		DECLARE_ARG(opts->pidfile);
		DECLARE_ARG("--cgroup-root");
		DECLARE_ARG(opts->cgroup_path);

		additional = lxc_list_len(&opts->c->lxc_conf->network) * 2;

		m = realloc(argv, (argc + additional + 1) * sizeof(*argv));	\
		if (!m)								\
			goto err;						\
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

			ret = snprintf(buf, sizeof(buf), "%s=%s@%s", eth, veth, n->link);
			if (ret < 0 || ret >= sizeof(buf))
				goto err;

			DECLARE_ARG("--veth-pair");
			DECLARE_ARG(buf);
		}

	}

	argv[argc] = NULL;

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
 */
static bool criu_version_ok()
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
		char version[1024];
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

		if (fscanf(f, "Version: %1024[^\n]s", version) != 1)
			goto version_error;

		if (fgetc(f) != '\n')
			goto version_error;

		if (strcmp(version, CRIU_VERSION) >= 0)
			goto version_match;

		if (fscanf(f, "GitID: v%1024[^-]s", version) != 1)
			goto version_error;

		if (fgetc(f) != '-')
			goto version_error;

		if (fscanf(f, "%d", &patch) != 1)
			goto version_error;

		if (strcmp(version, CRIU_GITID_VERSION) < 0)
			goto version_error;

		if (patch < CRIU_GITID_PATCHLEVEL)
			goto version_error;

version_match:
		fclose(f);
		return true;

version_error:
		fclose(f);
		ERROR("must have criu " CRIU_VERSION " or greater to checkpoint/restore\n");
		return false;
	}
}

/* Check and make sure the container has a configuration that we know CRIU can
 * dump. */
bool criu_ok(struct lxc_container *c)
{
	struct lxc_list *it;
	bool found_deny_rule = false;

	if (!criu_version_ok())
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

	// These requirements come from http://criu.org/LXC
	if (c->lxc_conf->console.path &&
			strcmp(c->lxc_conf->console.path, "none") != 0) {
		ERROR("lxc.console must be none\n");
		return false;
	}

	if (c->lxc_conf->tty != 0) {
		ERROR("lxc.tty must be 0\n");
		return false;
	}

	lxc_list_for_each(it, &c->lxc_conf->cgroup) {
		struct lxc_cgroup *cg = it->elem;
		if (strcmp(cg->subsystem, "devices.deny") == 0 &&
				strcmp(cg->value, "c 5:1 rwm") == 0) {

			found_deny_rule = true;
			break;
		}
	}

	if (!found_deny_rule) {
		ERROR("couldn't find devices.deny = c 5:1 rwm");
		return false;
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

void do_restore(struct lxc_container *c, int pipe, char *directory, bool verbose)
{
	pid_t pid;
	char pidfile[L_tmpnam];
	struct lxc_handler *handler;
	int status;

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

	pid = fork();
	if (pid < 0)
		goto out_fini_handler;

	if (pid == 0) {
		struct criu_opts os;
		struct lxc_rootfs *rootfs;

		close(pipe);
		pipe = -1;

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
		os.directory = directory;
		os.c = c;
		os.pidfile = pidfile;
		os.verbose = verbose;
		os.cgroup_path = cgroup_canonical_path(handler);

		/* exec_criu() returning is an error */
		exec_criu(&os);
		umount(rootfs->mount);
		rmdir(rootfs->mount);
		goto out_fini_handler;
	} else {
		int ret;
		char title[2048];

		pid_t w = waitpid(pid, &status, 0);
		if (w == -1) {
			SYSERROR("waitpid");
			goto out_fini_handler;
		}

		ret = write(pipe, &status, sizeof(status));
		close(pipe);
		pipe = -1;

		if (sizeof(status) != ret) {
			SYSERROR("failed to write all of status");
			goto out_fini_handler;
		}

		if (WIFEXITED(status)) {
			if (WEXITSTATUS(status)) {
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

				if (lxc_set_state(c->name, handler, RUNNING))
					goto out_fini_handler;
			}
		} else {
			ERROR("CRIU was killed with signal %d\n", WTERMSIG(status));
			goto out_fini_handler;
		}

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
	lxc_fini(c->name, handler);
	if (unlink(pidfile) < 0 && errno != ENOENT)
		SYSERROR("unlinking pidfile failed");

out:
	if (pipe >= 0) {
		status = 1;
		if (write(pipe, &status, sizeof(status)) != sizeof(status)) {
			SYSERROR("writing status failed");
		}
		close(pipe);
	}

	exit(1);
}

/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2010
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
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <stdlib.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include "attach.h"
#include "commands.h"
#include "arguments.h"
#include "caps.h"
#include "cgroup.h"
#include "config.h"
#include "confile.h"
#include "start.h"
#include "sync.h"
#include "log.h"
#include "namespace.h"
#include "apparmor.h"

#if HAVE_SYS_PERSONALITY_H
#include <sys/personality.h>
#endif

lxc_log_define(lxc_attach_ui, lxc);

static const struct option my_longopts[] = {
	{"elevated-privileges", no_argument, 0, 'e'},
	{"arch", required_argument, 0, 'a'},
	{"namespaces", required_argument, 0, 's'},
	{"remount-sys-proc", no_argument, 0, 'R'},
	/* TODO: decide upon short option names */
	{"clear-env", no_argument, 0, 500},
	{"keep-env", no_argument, 0, 501},
	LXC_COMMON_OPTIONS
};

static int elevated_privileges = 0;
static signed long new_personality = -1;
static int namespace_flags = -1;
static int remount_sys_proc = 0;
static lxc_attach_env_policy_t env_policy = LXC_ATTACH_KEEP_ENV;

static int my_parser(struct lxc_arguments* args, int c, char* arg)
{
	int ret;

	switch (c) {
	case 'e': elevated_privileges = 1; break;
	case 'R': remount_sys_proc = 1; break;
	case 'a':
		new_personality = lxc_config_parse_arch(arg);
		if (new_personality < 0) {
			lxc_error(args, "invalid architecture specified: %s", arg);
			return -1;
		}
		break;
	case 's':
		namespace_flags = 0;
		ret = lxc_fill_namespace_flags(arg, &namespace_flags);
		if (ret)
			return -1;
		/* -s implies -e */
		elevated_privileges = 1;
		break;
        case 500: /* clear-env */
                env_policy = LXC_ATTACH_CLEAR_ENV;
                break;
        case 501: /* keep-env */
                env_policy = LXC_ATTACH_KEEP_ENV;
                break;
	}

	return 0;
}

static struct lxc_arguments my_args = {
	.progname = "lxc-attach",
	.help     = "\
--name=NAME\n\
\n\
Execute the specified command - enter the container NAME\n\
\n\
Options :\n\
  -n, --name=NAME   NAME for name of the container\n\
  -e, --elevated-privileges\n\
                    Use elevated privileges (capabilities, cgroup\n\
                    restrictions) instead of those of the container.\n\
                    WARNING: This may leak privleges into the container.\n\
                    Use with care.\n\
  -a, --arch=ARCH   Use ARCH for program instead of container's own\n\
                    architecture.\n\
  -s, --namespaces=FLAGS\n\
                    Don't attach to all the namespaces of the container\n\
                    but just to the following OR'd list of flags:\n\
                    MOUNT, PID, UTSNAME, IPC, USER or NETWORK\n\
                    WARNING: Using -s implies -e, it may therefore\n\
                    leak privileges into the container. Use with care.\n\
  -R, --remount-sys-proc\n\
                    Remount /sys and /proc if not attaching to the\n\
                    mount namespace when using -s in order to properly\n\
                    reflect the correct namespace context. See the\n\
                    lxc-attach(1) manual page for details.\n\
      --clear-env\n\
                    Clear all environment variables before attaching.\n\
                    The attached shell/program will start with only\n\
                    container=lxc set.\n\
      --keep-env\n\
                    Keep all current enivornment variables. This\n\
                    is the current default behaviour, but is likely to\n\
                    change in the future.\n",
	.options  = my_longopts,
	.parser   = my_parser,
	.checker  = NULL,
};

int main(int argc, char *argv[])
{
	int ret;
	pid_t pid, init_pid;
	struct passwd *passwd;
	struct lxc_proc_context_info *init_ctx;
	struct lxc_handler *handler;
	uid_t uid;
	char *curdir;
	int cgroup_ipc_sockets[2];
	char *user_shell;

	ret = lxc_caps_init();
	if (ret)
		return ret;

	ret = lxc_arguments_parse(&my_args, argc, argv);
	if (ret)
		return ret;

	ret = lxc_log_init(my_args.name, my_args.log_file, my_args.log_priority,
			   my_args.progname, my_args.quiet);
	if (ret)
		return ret;

	init_pid = get_init_pid(my_args.name, my_args.lxcpath);
	if (init_pid < 0) {
		ERROR("failed to get the init pid");
		return -1;
	}

	init_ctx = lxc_proc_get_context_info(init_pid);
	if (!init_ctx) {
		ERROR("failed to get context of the init process, pid = %d", init_pid);
		return -1;
	}

	curdir = getcwd(NULL, 0);

	/* determine which namespaces the container was created with
	 * by asking lxc-start
	 */
	if (namespace_flags == -1) {
		namespace_flags = lxc_get_clone_flags(my_args.name, my_args.lxcpath);
		/* call failed */
		if (namespace_flags == -1) {
			ERROR("failed to automatically determine the "
			      "namespaces which the container unshared");
			return -1;
		}
	}

	/* For the cgroup attaching logic to work in conjunction with pid and user namespaces,
	 * we need to have the following hierarchy:
	 *
	 *     lxc-attach [process executed externally]
	 *         | socketpair(cgroup_ipc_sockets)
	 *         | fork()           -> child
	 *         |                       | setns()
	 *         |                       | fork()    -> grandchild
	 *         |                       |                   | initialize
	 *         |                       |                   | signal parent
	 *         |                       |<------------------|----+
	 *         |                       | signal parent     |
	 *         |<----------------------|-----+             |
	 *         | add to cgroups        |                   |
	 *         | signal child -------->|                   |
	 *         |                       | signal child ---->|
	 *         | waitpid()             | waitpid()         | exec()
	 *         |                       |<------------------| exit()
	 *         |<----------------------| exit()
	 *         | exit()
	 *
	 * The rationale is the following: The first parent is needed because after
	 * setns() (mount + user namespace) we can't access the cgroup filesystem
	 * to add the pid to the corresponding cgroup. Therefore, we need to do that
	 * in a process executed on the host, so that's why we need to fork and wait
	 * for it to have done some initialization (cgroups may restrict certain
	 * operations so we have to do that in the end) and use IPC for signaling.
	 *
	 * Then in the child process we do the setns(). However, a process is never
	 * really attached to a pid namespace (never changes its pid, doesn't appear
	 * in the pid namespace /proc), only child processes of that process are
	 * truely inside the new pid namespace. That's why we need to fork() again
	 * after setns() before performing final initializations, then signal our
	 * parent, which signals the primary process, which does cgroup adding,
	 * which then signals to the grandchild that it can exec().
	 */
	ret = socketpair(PF_LOCAL, SOCK_STREAM, 0, cgroup_ipc_sockets);
	if (ret < 0) {
		SYSERROR("could not set up required IPC mechanism for attaching");
		return -1;
	}

	pid = fork();
	if (pid < 0) {
		SYSERROR("failed to create first subprocess");
		return -1;
	}

	if (pid) {
		int status;
		pid_t grandchild;

		close(cgroup_ipc_sockets[1]);

	gparent_reread:
		ret = read(cgroup_ipc_sockets[0], &grandchild, sizeof(grandchild));
		if (ret <= 0) {
			if (ret < 0 && (errno == EAGAIN || errno == EINTR))
				goto gparent_reread;
			ERROR("failed to get pid of attached process to add to cgroup");
			return -1;
		}

		if (!elevated_privileges) {
			ret = lxc_cgroup_attach(grandchild, my_args.name, my_args.lxcpath);
			if (ret < 0) {
				ERROR("failed to attach process to cgroup");
				return -1;
			}
		}

		status = 0;
		ret = write(cgroup_ipc_sockets[0], &status, sizeof(status));
		if (ret <= 0) {
			ERROR("failed to signal child that cgroup logic has finished");
			return -1;
		}

		close(cgroup_ipc_sockets[0]);

	gparent_again:
		ret = waitpid(pid, &status, 0);
		if (ret < 0) {
			if (errno == EINTR)
				goto gparent_again;
			SYSERROR("failed to wait for process '%d'", pid);
			return -1;
		}

		if (WIFEXITED(status))
			return WEXITSTATUS(status);

		return -1;
	}

	/* at this point we are in the 'parent' process so we need to close the
	 * socket reserved for the 'grandparent' process
	 */
	close(cgroup_ipc_sockets[0]);

	/* we need to attach before we fork since certain namespaces
	 * (such as pid namespaces) only really affect children of the
	 * current process and not the process itself
	 */
	ret = lxc_attach_to_ns(init_pid, namespace_flags);
	if (ret < 0) {
		ERROR("failed to enter the namespace");
		return -1;
	}

	if (curdir && chdir(curdir))
		WARN("could not change directory to '%s'", curdir);

	free(curdir);

	/* hack: we need sync.h infrastructure - and that needs a handler
	 * FIXME: perhaps we should also just use a very simple socketpair()
	 * here? - like with the grandparent <-> parent communication?
	 */
	handler = calloc(1, sizeof(*handler));

	if (lxc_sync_init(handler)) {
		ERROR("failed to initialize synchronization socket");
		return -1;
	}

	pid = fork();

	if (pid < 0) {
		SYSERROR("failed to fork");
		return -1;
	}

	if (pid) {
		int status;

		lxc_sync_fini_child(handler);

		/* wait until the child has done configuring itself before
		 * we put it in a cgroup that potentially limits these
		 * possibilities */
		if (lxc_sync_wait_child(handler, LXC_SYNC_CONFIGURE))
			return -1;

		/* ask grandparent to add child to cgroups, the grandparent will
		 * itself check whether that's actually necessary
		 */
		ret = write(cgroup_ipc_sockets[1], &pid, sizeof(pid));
		if (ret != sizeof(pid)) {
			ERROR("error using IPC to notify main process of pid to add to the cgroups of the container");
			return -1;
		}

	parent_reread:
		/* we need some mechanism to check whether the grandparent could
		 * add us to the cgroups or not - so we await a dummy integer
		 * on the same socket (that's why we don't use a pipe - we need
		 * two-way communication). So if the parent fails and exits, that
		 * will close the socket, which will cause a read of 0 bytes for
		 * us, so we just terminate. If we read at least a byte, we don't
		 * care about the contents...
		 */
		ret = read(cgroup_ipc_sockets[1], &status, sizeof(status));
		if (ret <= 0) {
			if (ret < 0 && (errno == EAGAIN || errno == EINTR))
				goto parent_reread;
			/* only print someting if we can't assume the parent already
			 * gave an error message, that will reduce confusion for the
			 * user
			 */
			if (ret != 0)
				ERROR("failed to get notification that the child process was added to the container's cgroups");
			return -1;
		}

		/* we don't need that IPC interface anymore */
		close(cgroup_ipc_sockets[1]);

		/* tell the child we are done initializing */
		if (lxc_sync_wake_child(handler, LXC_SYNC_POST_CONFIGURE))
			return -1;

		lxc_sync_fini(handler);

	again:
		if (waitpid(pid, &status, 0) < 0) {
			if (errno == EINTR)
				goto again;
			SYSERROR("failed to wait '%d'", pid);
			return -1;
		}

		if (WIFEXITED(status))
			return WEXITSTATUS(status);

		return -1;
	}

	if (!pid) {
		lxc_sync_fini_parent(handler);
		close(cgroup_ipc_sockets[1]);

		if ((namespace_flags & CLONE_NEWNS)) {
			if (attach_apparmor(init_ctx->aa_profile) < 0) {
				ERROR("failed switching apparmor profiles");
				return -1;
			}
		}

		/* A description of the purpose of this functionality is
		 * provided in the lxc-attach(1) manual page. We have to
		 * remount here and not in the parent process, otherwise
		 * /proc may not properly reflect the new pid namespace.
		 */
		if (!(namespace_flags & CLONE_NEWNS) && remount_sys_proc) {
			ret = lxc_attach_remount_sys_proc();
			if (ret < 0) {
				return -1;
			}
		}

		#if HAVE_SYS_PERSONALITY_H
		if (new_personality < 0)
			new_personality = init_ctx->personality;

		if (personality(new_personality) == -1) {
			ERROR("could not ensure correct architecture: %s",
			      strerror(errno));
			return -1;
		}
		#endif

		if (!elevated_privileges && lxc_attach_drop_privs(init_ctx)) {
			ERROR("could not drop privileges");
			return -1;
		}

		if (lxc_attach_set_environment(env_policy, NULL, NULL)) {
			ERROR("could not set environment");
			return -1;
		}

		/* tell parent we are done setting up the container and wait
		 * until we have been put in the container's cgroup, if
		 * applicable */
		if (lxc_sync_barrier_parent(handler, LXC_SYNC_CONFIGURE))
			return -1;

		lxc_sync_fini(handler);

		if (namespace_flags & CLONE_NEWUSER) {
			uid_t init_uid = 0;
			gid_t init_gid = 0;

			/* ignore errors, we will fall back to root in that case
			 * (/proc was not mounted etc.)
			 */
			lxc_attach_get_init_uidgid(&init_uid, &init_gid);

			/* try to set the uid/gid combination */
			if (setgid(init_gid)) {
				SYSERROR("switching to container gid");
				return -1;
			}
			if (setuid(init_uid)) {
				SYSERROR("switching to container uid");
				return -1;
			}
		}

		if (my_args.argc) {
			execvp(my_args.argv[0], my_args.argv);
			SYSERROR("failed to exec '%s'", my_args.argv[0]);
			return -1;
		}

		uid = getuid();

		passwd = getpwuid(uid);

		/* this probably happens because of incompatible nss
		 * implementations in host and container (remember, this
		 * code is still using the host's glibc but our mount
		 * namespace is in the container)
		 * we may try to get the information by spawning a
		 * [getent passwd uid] process and parsing the result
		 */
		if (!passwd)
		        user_shell = lxc_attach_getpwshell(uid);
                else
                        user_shell = passwd->pw_shell;

                if (user_shell) {
			char *const args[] = {
				user_shell,
				NULL,
			};

			(void) execvp(args[0], args);
		}

		/* executed if either no passwd entry or execvp fails,
		 * we will fall back on /bin/sh as a default shell
		 */
		{
			char *const args[] = {
				"/bin/sh",
				NULL,
			};

			execvp(args[0], args);
			SYSERROR("failed to exec '%s'", args[0]);
			return -1;
		}

	}

	return 0;
}

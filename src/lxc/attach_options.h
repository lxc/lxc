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

#ifndef _LXC_ATTACH_OPTIONS_H
#define _LXC_ATTACH_OPTIONS_H

#include <sys/types.h>

typedef enum lxc_attach_env_policy_t {
	LXC_ATTACH_KEEP_ENV,
	LXC_ATTACH_CLEAR_ENV
} lxc_attach_env_policy_t;

enum {
	/* the following are on by default: */
	LXC_ATTACH_MOVE_TO_CGROUP        = 0x00000001,
	LXC_ATTACH_DROP_CAPABILITIES     = 0x00000002,
	LXC_ATTACH_SET_PERSONALITY       = 0x00000004,
	LXC_ATTACH_APPARMOR              = 0x00000008,

	/* the following are off by default */
	LXC_ATTACH_REMOUNT_PROC_SYS      = 0x00010000,

	/* we have 16 bits for things that are on by default
	 * and 16 bits that are off by default, that should
	 * be sufficient to keep binary compatibility for
	 * a while
	 */
	LXC_ATTACH_DEFAULT               = 0x0000FFFF
};

typedef struct lxc_attach_options_t lxc_attach_options_t;
typedef int (*lxc_attach_exec_t)(void* payload);

struct lxc_attach_options_t {
	/* any combination of the above enum */
	int attach_flags;
	/* the namespaces to attach to (CLONE_NEW... flags) */
	int namespaces;
	/* initial personality, -1 to autodetect
	 * (may be ignored if lxc is compiled w/o personality support) */
	long personality;

	/* inital current directory, use NULL to use cwd
	 * (might not exist in container, then / will be
	 * used because of kernel defaults)
	 */
	char* initial_cwd;

	/* the uid and gid to attach to,
	 * -1 for default (init uid/gid for userns containers,
	 * otherwise or if detection fails 0/0)
	 */
	uid_t uid;
	gid_t gid;

	/* environment handling */
	lxc_attach_env_policy_t env_policy;
	char** extra_env_vars;
	char** extra_keep_env;

	/* file descriptors for stdin, stdout and stderr,
	 * dup2() will be used before calling exec_function,
	 * (assuming not 0, 1 and 2 are specified) and the
	 * original fds are closed before passing control
	 * over. Any O_CLOEXEC flag will be removed after
	 * that
	 */
	int stdin_fd;
	int stdout_fd;
	int stderr_fd;
};

#define LXC_ATTACH_OPTIONS_DEFAULT \
	{ \
		/* .attach_flags = */   LXC_ATTACH_DEFAULT, \
		/* .namespaces = */     -1, \
		/* .personality = */    -1, \
		/* .initial_cwd = */    NULL, \
		/* .uid = */            (uid_t)-1, \
		/* .gid = */            (gid_t)-1, \
		/* .env_policy = */     LXC_ATTACH_KEEP_ENV, \
		/* .extra_env_vars = */ NULL, \
		/* .extra_keep_env = */ NULL, \
		/* .stdin_fd = */       0, 1, 2 \
	}

typedef struct lxc_attach_command_t {
	char* program; /* the program to run (passed to execvp) */
	char** argv;   /* the argv pointer of that program, including the program itself in argv[0] */
} lxc_attach_command_t;

/* default execution functions:
 *   run_command: pointer to lxc_attach_command_t
 *   run_shell:   no payload, will be ignored
 */
extern int lxc_attach_run_command(void* payload);
extern int lxc_attach_run_shell(void* payload);

#endif

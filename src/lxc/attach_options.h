/*! \file
 *
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

#ifndef __LXC_ATTACH_OPTIONS_H
#define __LXC_ATTACH_OPTIONS_H

#include <sys/types.h>

#ifdef  __cplusplus
extern "C" {
#endif

/*!
 * LXC environment policy.
 */
typedef enum lxc_attach_env_policy_t {
	LXC_ATTACH_KEEP_ENV,   //!< Retain the environment
	LXC_ATTACH_CLEAR_ENV   //!< Clear the environment
} lxc_attach_env_policy_t;

enum {
	/* the following are on by default: */
	LXC_ATTACH_MOVE_TO_CGROUP        = 0x00000001, //!< Move to cgroup
	LXC_ATTACH_DROP_CAPABILITIES     = 0x00000002, //!< Drop capabilities
	LXC_ATTACH_SET_PERSONALITY       = 0x00000004, //!< Set personality
	LXC_ATTACH_LSM_EXEC              = 0x00000008, //!< Execute under a Linux Security Module

	/* the following are off by default */
	LXC_ATTACH_REMOUNT_PROC_SYS      = 0x00010000, //!< Remount /proc filesystem
	LXC_ATTACH_LSM_NOW               = 0x00020000, //!< FIXME: unknown

	/* we have 16 bits for things that are on by default
	 * and 16 bits that are off by default, that should
	 * be sufficient to keep binary compatibility for
	 * a while
	 */
	LXC_ATTACH_DEFAULT               = 0x0000FFFF  //!< Mask of flags to apply by default
};

/*! All Linux Security Module flags */
#define LXC_ATTACH_LSM (LXC_ATTACH_LSM_EXEC | LXC_ATTACH_LSM_NOW)

/*! LXC attach function type.
 *
 * Function to run in container.
 *
 * \param payload \ref lxc_attach_command_t to run.
 *
 * \return Function should return \c 0 on success, and any other value to denote failure.
 */
typedef int (*lxc_attach_exec_t)(void* payload);

/*!
 * LXC attach options for \ref lxc_container \c attach().
 */
typedef struct lxc_attach_options_t {
	/*! Any combination of LXC_ATTACH_* flags */
	int attach_flags;

	/*! The namespaces to attach to (CLONE_NEW... flags) */
	int namespaces;

	/*! Initial personality (\c -1 to autodetect).
	 * \warning This may be ignored if lxc is compiled without personality support)
	 */
	long personality;

	/*! Initial current directory, use \c NULL to use cwd.
	 * If the current directory does not exist in the container, the
	 * root directory will be used instead because of kernel defaults.
	 */
	char* initial_cwd;

	/*! The user-id to run as.
	 *
	 * \note Set to \c -1 for default behaviour (init uid for userns
	 * containers or \c 0 (super-user) if detection fails).
	 */
	uid_t uid;

	/*! The group-id to run as.
	 *
	 * \note Set to \c -1 for default behaviour (init gid for userns
	 * containers or \c 0 (super-user) if detection fails).
	 */
	gid_t gid;

	/*! Environment policy */
	lxc_attach_env_policy_t env_policy;

	/*! Extra environment variables to set in the container environment */
	char** extra_env_vars;

	/*! Names of environment variables in existing environment to retain
	 * in container environment.
	 */
	char** extra_keep_env;

	/**@{*/
	/*! File descriptors for stdin, stdout and stderr,
	 * \c dup2() will be used before calling exec_function,
	 * (assuming not \c 0, \c 1 and \c 2 are specified) and the
	 * original fds are closed before passing control
	 * over. Any \c O_CLOEXEC flag will be removed after
	 * that.
	 */
	int stdin_fd; /*!< stdin file descriptor */
	int stdout_fd; /*!< stdout file descriptor */
	int stderr_fd; /*!< stderr file descriptor */
	/**@}*/
} lxc_attach_options_t;

/*! Default attach options to use */
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

/*!
 * Representation of a command to run in a container.
 */
typedef struct lxc_attach_command_t {
	char* program; /*!< The program to run (passed to execvp) */
	char** argv;   /*!< The argv pointer of that program, including the program itself in argv[0] */
} lxc_attach_command_t;

/*!
 * \brief Run a command in the container.
 *
 * \param payload \ref lxc_attach_command_t to run.
 *
 * \return \c -1 on error, exit code of lxc_attach_command_t program on success.
 */
extern int lxc_attach_run_command(void* payload);

/*!
 * \brief Run a shell command in the container.
 *
 * \param payload Not used.
 *
 * \return Exit code of shell.
 */
extern int lxc_attach_run_shell(void* payload);

#ifdef  __cplusplus
}
#endif

#endif

/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2008
 *
 * Authors:
 * Daniel Lezcano <dlezcano at fr.ibm.com>
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
#ifndef __lxc_h
#define __lxc_h

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <lxc/state.h>

struct lxc_msg;
struct lxc_conf;

/**
 Following code is for liblxc.

 lxc/lxc.h will contain exports of liblxc
 **/

/*
 * Start the specified command inside a container
 * @name     : the name of the container
 * @argv     : an array of char * corresponding to the commande line
 * @conf     : configuration
 * Returns 0 on sucess, < 0 otherwise
 */
extern int lxc_start(const char *name, char *const argv[], struct lxc_conf *conf);

/*
 * Stop the container previously started with lxc_start, all
 * the processes running inside this container will be killed.
 * @name : the name of the container
 * Returns 0 on success, < 0 otherwise
 */
extern int lxc_stop(const char *name);

/*
 * Open the monitoring mechanism for a specific container
 * The function will return an fd corresponding to the events
 * Returns a file descriptor on success, < 0 otherwise
 */
extern int lxc_monitor_open(void);

/*
 * Read the state of the container if this one has changed
 * The function will block until there is an event available
 * @fd : the file descriptor provided by lxc_monitor_open
 * @state : the variable which will be filled with the state
 * Returns 0 if the monitored container has exited, > 0 if
 * data was readen, < 0 otherwise
 */
extern int lxc_monitor_read(int fd, struct lxc_msg *msg);

/*
 * Close the fd associated with the monitoring
 * @fd : the file descriptor provided by lxc_monitor_open
 * Returns 0 on success, < 0 otherwise
 */
extern int lxc_monitor_close(int fd);

/*
 * Show the console of the container.
 * @name : the name of container
 * @tty  : the tty number
 * @fd   : a pointer to a tty file descriptor
 * Returns 0 on sucess, < 0 otherwise
 */
extern int lxc_console(const char *name, int ttynum, int *fd);

/*
 * Freeze all the tasks running inside the container <name>
 * @name : the container name
 * Returns 0 on success, < 0 otherwise
 */
extern int lxc_freeze(const char *name);

/*
 * Unfreeze all previously frozen tasks.
 * @name : the name of the container
 * Return 0 on sucess, < 0 otherwise
 */
extern int lxc_unfreeze(const char *name);

/*
 * Retrieve the container state
 * @name : the name of the container
 * Returns the state of the container on success, < 0 otherwise
 */
extern lxc_state_t lxc_state(const char *name);

/*
 * Set a specified value for a specified subsystem. The specified
 * subsystem must be fully specified, eg. "cpu.shares"
 * @name      : the name of the container
 * @filename : the cgroup attribute filename
 * @value     : the value to be set
 * Returns 0 on success, < 0 otherwise
 */
extern int lxc_cgroup_set(const char *name, const char *filename, const char *value);

/*
 * Get a specified value for a specified subsystem. The specified
 * subsystem must be fully specified, eg. "cpu.shares"
 * @name      : the name of the container
 * @filename : the cgroup attribute filename
 * @value     : the value to be set
 * @len       : the len of the value variable
 * Returns the number of bytes read, < 0 on error
 */
extern int lxc_cgroup_get(const char *name, const char *filename,
			  char *value, size_t len);

/*
 * Retrieve the error string associated with the error returned by
 * the function.
 * @error : the value of the error
 * Returns a string on success or NULL otherwise.
 */
extern const char *lxc_strerror(int error);

/*
 * Checkpoint a container
 * @name : the name of the container being checkpointed
 * @sfd: fd on which the container is checkpointed
 * @flags : checkpoint flags (an ORed value)
 * Returns 0 on success, < 0 otherwise
 */
extern int lxc_checkpoint(const char *name, int sfd, int flags);
#define LXC_FLAG_PAUSE 1
#define LXC_FLAG_HALT  2

/*
 * Restart a container
 * @name : the name of the container being restarted
 * @sfd: fd from which the container is restarted
 * @conf: lxc_conf structure.
 * @flags : restart flags (an ORed value)
 * Returns 0 on success, < 0 otherwise
 */
extern int lxc_restart(const char *, int, struct lxc_conf *, int);

/*
 * Returns the version number of the library
 */
extern const char const *lxc_version(void);

#ifdef __cplusplus
}
#endif

#endif

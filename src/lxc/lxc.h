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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
#ifndef __lxc_h
#define __lxc_h

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <sys/select.h>
#include <sys/types.h>
#include <lxc/state.h>

struct lxc_msg;
struct lxc_conf;
struct lxc_arguments;

/**
 Following code is for liblxc.

 lxc/lxc.h will contain exports of liblxc
 **/

/*
 * Start the specified command inside a system container
 * @name     : the name of the container
 * @argv     : an array of char * corresponding to the commande line
 * @conf     : configuration
 * Returns 0 on sucess, < 0 otherwise
 */
extern int lxc_start(const char *name, char *const argv[], struct lxc_conf *conf,
		     const char *lxcpath);

/*
 * Start the specified command inside an application container
 * @name     : the name of the container
 * @argv     : an array of char * corresponding to the commande line
 * @quiet    : if != 0 then lxc-init won't produce any output
 * @conf     : configuration
 * Returns 0 on sucess, < 0 otherwise
 */
extern int lxc_execute(const char *name, char *const argv[], int quiet,
		       struct lxc_conf *conf, const char *lxcpath);

/*
 * Open the monitoring mechanism for a specific container
 * The function will return an fd corresponding to the events
 * Returns a file descriptor on success, < 0 otherwise
 */
extern int lxc_monitor_open(const char *lxcpath);

/*
 * Blocking read for the next container state change
 * @fd  : the file descriptor provided by lxc_monitor_open
 * @msg : the variable which will be filled with the state
 * Returns 0 if the monitored container has exited, > 0 if
 * data was read, < 0 otherwise
 */
extern int lxc_monitor_read(int fd, struct lxc_msg *msg);

/*
 * Blocking read for the next container state change with timeout
 * @fd      : the file descriptor provided by lxc_monitor_open
 * @msg     : the variable which will be filled with the state
 * @timeout : the timeout in seconds to wait for a state change
 * Returns 0 if the monitored container has exited, > 0 if
 * data was read, < 0 otherwise
 */
extern int lxc_monitor_read_timeout(int fd, struct lxc_msg *msg, int timeout);

/*
 * Blocking read from multiple monitors for the next container state
 * change with timeout
 * @rfds    : an fd_set of file descriptors provided by lxc_monitor_open
 * @nfds    : the maximum fd number in rfds + 1
 * @msg     : the variable which will be filled with the state
 * @timeout : the timeout in seconds to wait for a state change
 * Returns 0 if the monitored container has exited, > 0 if
 * data was read, < 0 otherwise
 */
extern int lxc_monitor_read_fdset(fd_set *rfds, int nfds, struct lxc_msg *msg, int timeout);

/*
 * Close the fd associated with the monitoring
 * @fd : the file descriptor provided by lxc_monitor_open
 * Returns 0 on success, < 0 otherwise
 */
extern int lxc_monitor_close(int fd);

/*
 * Freeze all the tasks running inside the container <name>
 * @name : the container name
 * Returns 0 on success, < 0 otherwise
 */
extern int lxc_freeze(const char *name, const char *lxcpath);

/*
 * Unfreeze all previously frozen tasks.
 * @name : the name of the container
 * Return 0 on sucess, < 0 otherwise
 */
extern int lxc_unfreeze(const char *name, const char *lxcpath);

/*
 * Unfreeze all previously frozen tasks.
 * This is the function to use from inside the monitor
 * @name : the name of the container
 * Return 0 on sucess, < 0 otherwise
 */
extern int lxc_unfreeze_bypath(const char *cgpath);

/*
 * Retrieve the container state
 * @name : the name of the container
 * Returns the state of the container on success, < 0 otherwise
 */
extern lxc_state_t lxc_state(const char *name, const char *lxcpath);

struct lxc_handler;
/*
 * Set a specified value for a specified subsystem. The specified
 * subsystem must be fully specified, eg. "cpu.shares"
 * @filename  : the cgroup attribute filename
 * @value     : the value to be set
 * @handler   : the lxc_handler structure of the container
 * Returns 0 on success, < 0 otherwise
 */
extern int lxc_cgroup_set_handler(const char *filename, const char *value, struct lxc_handler *handler);

/*
 * Set a specified value for a specified subsystem. The specified
 * subsystem must be fully specified, eg. "cpu.shares"
 * @filename  : the cgroup attribute filename
 * @value     : the value to be set
 * @name      : the name of the container
 * @lxcpath   : lxc config path for container
 * Returns 0 on success, < 0 otherwise
 */
extern int lxc_cgroup_set(const char *filename, const char *value, const char *name, const char *lxcpath);

/*
 * Get a specified value for a specified subsystem. The specified
 * subsystem must be fully specified, eg. "cpu.shares"
 * @filename  : the cgroup attribute filename
 * @value     : the value to be set
 * @len       : the len of the value variable
 * @name      : the name of the container
 * @lxcpath   : lxc config path for container
 * Returns the number of bytes read, < 0 on error
 */
extern int lxc_cgroup_get(const char *filename, char *value, size_t len, const char *name, const char *lxcpath);

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
 * @lxcpath: container path
 * Returns 0 on success, < 0 otherwise
 */
extern int lxc_restart(const char *, int, struct lxc_conf *, int, const char *);

/*
 * Create and return a new lxccontainer struct.
 */
extern struct lxc_container *lxc_container_new(const char *name, const char *configpath);

/*
 * Returns 1 on success, 0 on failure.
 */
extern int lxc_container_get(struct lxc_container *c);

/*
 * Put a lxccontainer struct reference.
 * Return -1 on error.
 * Return 0 if this was not the last reference.
 * If it is the last reference, free the lxccontainer and return 1.
 */
extern int lxc_container_put(struct lxc_container *c);

/*
 * Get a list of valid wait states.
 * If states is NULL, simply return the number of states
 */
extern int lxc_get_wait_states(const char **states);

/*
 * Add a dependency to a container
 */
extern int add_rdepend(struct lxc_conf *lxc_conf, char *rdepend);

#ifdef __cplusplus
}
#endif

#endif

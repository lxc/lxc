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
#ifndef __LXC_LXC_H
#define __LXC_LXC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <sys/select.h>
#include <sys/types.h>
#include "state.h"

struct lxc_msg;
struct lxc_conf;
struct lxc_arguments;
struct lxc_handler;

/**
 Following code is for liblxc.

 lxc/lxc.h will contain exports of liblxc
 **/

/*
 * Start the specified command inside a system container
 * @name         : the name of the container
 * @argv         : an array of char * corresponding to the commande line
 * @conf         : configuration
 * @backgrounded : whether or not the container is daemonized
 * Returns 0 on success, < 0 otherwise
 */
extern int lxc_start(const char *name, char *const argv[],
		     struct lxc_handler *handler, const char *lxcpath,
		     bool backgrounded, int *error_num);

/*
 * Start the specified command inside an application container
 * @name         : the name of the container
 * @argv         : an array of char * corresponding to the commande line
 * @quiet        : if != 0 then lxc-init won't produce any output
 * @conf         : configuration
 * @backgrounded : whether or not the container is daemonized
 * Returns 0 on success, < 0 otherwise
 */
extern int lxc_execute(const char *name, char *const argv[], int quiet,
		       struct lxc_handler *handler, const char *lxcpath,
		       bool backgrounded, int *error_num);

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
 * Return 0 on success, < 0 otherwise
 */
extern int lxc_unfreeze(const char *name, const char *lxcpath);

/*
 * Retrieve the container state
 * @name : the name of the container
 * Returns the state of the container on success, < 0 otherwise
 */
extern lxc_state_t lxc_state(const char *name, const char *lxcpath);

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

/*
 * Set a key/value configuration option. Requires that to take a lock on the
 * in-memory config of the container.
 */
extern int lxc_set_config_item_locked(struct lxc_conf *conf, const char *key,
				      const char *v);

#ifdef __cplusplus
}
#endif

#endif

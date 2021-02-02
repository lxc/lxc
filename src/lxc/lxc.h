/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_LXC_H
#define __LXC_LXC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <sys/select.h>
#include <sys/types.h>

#include "compiler.h"
#include "memory_utils.h"
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
 * @argv         : an array of char * corresponding to the command line
 * @conf         : configuration
 * @daemonize    : whether or not the container is daemonized
 * Returns 0 on success, < 0 otherwise
 */
__hidden extern int lxc_start(char *const argv[], struct lxc_handler *handler, const char *lxcpath,
			      bool daemonize, int *error_num);

/*
 * Start the specified command inside an application container
 * @name         : the name of the container
 * @argv         : an array of char * corresponding to the command line
 * @quiet        : if != 0 then lxc-init won't produce any output
 * @conf         : configuration
 * @daemonize    : whether or not the container is daemonized
 * Returns 0 on success, < 0 otherwise
 */
__hidden extern int lxc_execute(const char *name, char *const argv[], int quiet,
				struct lxc_handler *handler, const char *lxcpath, bool daemonize,
				int *error_num);

/*
 * Close the fd associated with the monitoring
 * @fd : the file descriptor provided by lxc_monitor_open
 * Returns 0 on success, < 0 otherwise
 */
__hidden extern int lxc_monitor_close(int fd);

/*
 * Freeze all the tasks running inside the container <name>
 * @name : the container name
 * Returns 0 on success, < 0 otherwise
 */
__hidden extern int lxc_freeze(struct lxc_conf *conf, const char *name, const char *lxcpath);

/*
 * Unfreeze all previously frozen tasks.
 * @name : the name of the container
 * Return 0 on success, < 0 otherwise
 */
__hidden extern int lxc_unfreeze(struct lxc_conf *conf, const char *name, const char *lxcpath);

/*
 * Retrieve the container state
 * @name : the name of the container
 * Returns the state of the container on success, < 0 otherwise
 */
__hidden extern lxc_state_t lxc_state(const char *name, const char *lxcpath);

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
static inline void put_lxc_container(struct lxc_container *c)
{
	if (c)
		lxc_container_put(c);
}
define_cleanup_function(struct lxc_container *, put_lxc_container);
#define __put_lxc_container call_cleaner(put_lxc_container)

/*
 * Get a list of valid wait states.
 * If states is NULL, simply return the number of states
 */
extern int lxc_get_wait_states(const char **states);

/*
 * Add a dependency to a container
 */
__hidden extern int add_rdepend(struct lxc_conf *lxc_conf, char *rdepend);

/*
 * Set a key/value configuration option. Requires that to take a lock on the
 * in-memory config of the container.
 */
__hidden extern int lxc_set_config_item_locked(struct lxc_conf *conf, const char *key, const char *v);

#ifdef __cplusplus
}
#endif

#endif /* __LXC_LXC_H */

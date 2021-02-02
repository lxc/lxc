/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_COMMANDS_UTILS_H
#define __LXC_COMMANDS_UTILS_H

#include <stdio.h>

#include "state.h"
#include "commands.h"

__hidden extern int lxc_make_abstract_socket_name(char *path, size_t pathlen, const char *lxcname,
						  const char *lxcpath, const char *hashed_sock_name,
						  const char *suffix);

/* lxc_cmd_sock_get_state      Register a new state client fd in the container's
 *                             in-memory handler and retrieve the requested
 *                             states.
 *
 * @param[in] name             Name of container to connect to.
 * @param[in] lxcpath          The lxcpath in which the container is running.
 * @param[in] states           The states to wait for.
 * @return                     Return  < 0 on error
 *                                     < MAX_STATE current container state
 */
__hidden extern int lxc_cmd_sock_get_state(const char *name, const char *lxcpath,
					   lxc_state_t states[MAX_STATE], int timeout);

/* lxc_cmd_sock_rcv_state      Retrieve the requested state from a state client
 *                             fd registerd in the container's in-memory
 *                             handler.
 *
 * @param[int] state_client_fd The state client fd from which the state can be
 *                             received.
 * @return                     Return  < 0 on error
 *                                     < MAX_STATE current container state
 */
__hidden extern int lxc_cmd_sock_rcv_state(int state_client_fd, int timeout);

/* lxc_add_state_client        Add a new state client to the container's
 *                             in-memory handler.
 *
 * @param[int] state_client_fd The state client fd to add.
 * @param[int] handler         The container's in-memory handler.
 * @param[in] states           The states to wait for.
 *
 * @return                     Return  < 0 on error
 *                                       0 on success
 */
__hidden extern int lxc_add_state_client(int state_client_fd, struct lxc_handler *handler,
					 lxc_state_t states[MAX_STATE]);

/* lxc_cmd_connect             Connect to the container's command socket.
 *
 * @param[in] name             Name of container to connect to.
 * @param[in] lxcpath          The lxcpath in which the container is running.
 * @param[in] hashed_sock_name The hashed name of the socket (optional). Can be
 *                             NULL.
 *
 * @return                     Return   < 0 on error
 *                                     >= 0 client fd
 */
__hidden extern int lxc_cmd_connect(const char *name, const char *lxcpath,
				    const char *hashed_sock_name, const char *suffix);

__hidden extern void lxc_cmd_notify_state_listeners(const char *name,
                                                    const char *lxcpath,
                                                    lxc_state_t state);
#endif /* __LXC_COMMANDS_UTILS_H */

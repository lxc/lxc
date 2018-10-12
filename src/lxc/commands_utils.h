/* liblxcapi
 *
 * Copyright © 2017 Christian Brauner <christian.brauner@ubuntu.com>.
 * Copyright © 2017 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __LXC_COMMANDS_UTILS_H
#define __LXC_COMMANDS_UTILS_H

#include <stdio.h>

#include "state.h"
#include "commands.h"

int lxc_make_abstract_socket_name(char *path, size_t pathlen,
				  const char *lxcname,
				  const char *lxcpath,
				  const char *hashed_sock_name,
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
extern int lxc_cmd_sock_get_state(const char *name, const char *lxcpath,
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
extern int lxc_cmd_sock_rcv_state(int state_client_fd, int timeout);

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
extern int lxc_add_state_client(int state_client_fd,
				struct lxc_handler *handler,
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
extern int lxc_cmd_connect(const char *name, const char *lxcpath,
			   const char *hashed_sock_name, const char *suffix);

#endif /* __LXC_COMMANDS_UTILS_H */

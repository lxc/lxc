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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#define __STDC_FORMAT_MACROS /* Required for PRIu64 to work. */
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "af_unix.h"
#include "commands.h"
#include "commands_utils.h"
#include "config.h"
#include "file_utils.h"
#include "initutils.h"
#include "log.h"
#include "lxclock.h"
#include "monitor.h"
#include "state.h"
#include "utils.h"

lxc_log_define(commands_utils, lxc);

int lxc_cmd_sock_rcv_state(int state_client_fd, int timeout)
{
	int ret;
	struct lxc_msg msg;
	struct timeval out;

	if (timeout >= 0) {
		memset(&out, 0, sizeof(out));
		out.tv_sec = timeout;
		ret = setsockopt(state_client_fd, SOL_SOCKET, SO_RCVTIMEO,
				(const void *)&out, sizeof(out));
		if (ret < 0) {
			SYSERROR("Failed to set %ds timeout on container "
				 "state socket",
				 timeout);
			return -1;
		}
	}

	memset(&msg, 0, sizeof(msg));

	ret = lxc_recv_nointr(state_client_fd, &msg, sizeof(msg), 0);
	if (ret < 0) {
		SYSERROR("Failed to receive message");
		return -1;
	}

	TRACE("Received state %s from state client %d",
	      lxc_state2str(msg.value), state_client_fd);

	return msg.value;
}

/* Register a new state client and retrieve state from command socket. */
int lxc_cmd_sock_get_state(const char *name, const char *lxcpath,
			   lxc_state_t states[MAX_STATE], int timeout)
{
	int ret;
	int state_client_fd;

	ret = lxc_cmd_add_state_client(name, lxcpath, states, &state_client_fd);
	if (ret < 0)
		return -1;

	if (ret < MAX_STATE)
		return ret;

	ret = lxc_cmd_sock_rcv_state(state_client_fd, timeout);
	close(state_client_fd);
	return ret;
}

int lxc_make_abstract_socket_name(char *path, size_t pathlen,
				  const char *lxcname,
				  const char *lxcpath,
				  const char *hashed_sock_name,
				  const char *suffix)
{
	const char *name;
	char *offset;
	char *tmppath;
	size_t len;
	size_t tmplen;
	uint64_t hash;
	int ret;

	if (!path)
		return -1;

	offset = &path[1];

	/* -2 here because this is an abstract unix socket so it needs a
	 * leading \0, and we null terminate, so it needs a trailing \0.
	 * Although null termination isn't required by the API, we do it anyway
	 * because we print the sockname out sometimes.
	 */
	len = pathlen - 2;

	name = lxcname;
	if (!name)
		name = "";

	if (hashed_sock_name != NULL) {
		ret = snprintf(offset, len, "lxc/%s/%s", hashed_sock_name, suffix);
		if (ret < 0 || ret >= len) {
			ERROR("Failed to create abstract socket name");
			return -1;
		}
		return 0;
	}

	if (!lxcpath) {
		lxcpath = lxc_global_config_value("lxc.lxcpath");
		if (!lxcpath) {
			ERROR("Failed to allocate memory");
			return -1;
		}
	}

	ret = snprintf(offset, len, "%s/%s/%s", lxcpath, name, suffix);
	if (ret < 0) {
		ERROR("Failed to create abstract socket name");
		return -1;
	}
	if (ret < len)
		return 0;

	/* ret >= len; lxcpath or name is too long.  hash both */
	tmplen = strlen(name) + strlen(lxcpath) + 2;
	tmppath = alloca(tmplen);
	ret = snprintf(tmppath, tmplen, "%s/%s", lxcpath, name);
	if (ret < 0 || (size_t)ret >= tmplen) {
		ERROR("Failed to create abstract socket name");
		return -1;
	}

	hash = fnv_64a_buf(tmppath, ret, FNV1A_64_INIT);
	ret = snprintf(offset, len, "lxc/%016" PRIx64 "/%s", hash, suffix);
	if (ret < 0 || ret >= len) {
		ERROR("Failed to create abstract socket name");
		return -1;
	}

	return 0;
}

int lxc_cmd_connect(const char *name, const char *lxcpath,
		    const char *hashed_sock_name, const char *suffix)
{
	int ret, client_fd;
	char path[LXC_AUDS_ADDR_LEN] = {0};

	ret = lxc_make_abstract_socket_name(path, sizeof(path), name, lxcpath,
					    hashed_sock_name, suffix);
	if (ret < 0)
		return -1;

	/* Get new client fd. */
	client_fd = lxc_abstract_unix_connect(path);
	if (client_fd < 0)
		return -1;

	return client_fd;
}

int lxc_add_state_client(int state_client_fd, struct lxc_handler *handler,
			 lxc_state_t states[MAX_STATE])
{
	int state;
	struct lxc_state_client *newclient;
	struct lxc_list *tmplist;

	newclient = malloc(sizeof(*newclient));
	if (!newclient)
		return -ENOMEM;

	/* copy requested states */
	memcpy(newclient->states, states, sizeof(newclient->states));
	newclient->clientfd = state_client_fd;

	tmplist = malloc(sizeof(*tmplist));
	if (!tmplist) {
		free(newclient);
		return -ENOMEM;
	}

	state = handler->state;
	if (states[state] != 1) {
		lxc_list_add_elem(tmplist, newclient);
		lxc_list_add_tail(&handler->conf->state_clients, tmplist);
	} else {
		free(newclient);
		free(tmplist);
		return state;
	}

	TRACE("Added state client %d to state client list", state_client_fd);
	return MAX_STATE;
}

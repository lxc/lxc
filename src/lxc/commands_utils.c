/* SPDX-License-Identifier: LGPL-2.1+ */

#include "config.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "attach_options.h"
#include "af_unix.h"
#include "commands.h"
#include "commands_utils.h"
#include "file_utils.h"
#include "initutils.h"
#include "log.h"
#include "lxclock.h"
#include "memory_utils.h"
#include "monitor.h"
#include "state.h"
#include "string_utils.h"
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
		if (ret < 0)
			return log_error_errno(-1, errno, "Failed to set %ds timeout on container state socket", timeout);
	}

	memset(&msg, 0, sizeof(msg));

	ret = lxc_recv_nointr(state_client_fd, &msg, sizeof(msg), 0);
	if (ret < 0)
		return log_error_errno(-1, errno, "Failed to receive message");

	return log_trace(msg.value, "Received state %s from state client %d",
			 lxc_state2str(msg.value), state_client_fd);
}

/* Register a new state client and retrieve state from command socket. */
int lxc_cmd_sock_get_state(const char *name, const char *lxcpath,
			   lxc_state_t states[MAX_STATE], int timeout)
{
	__do_close int state_client_fd = -EBADF;
	int ret;

	ret = lxc_cmd_add_state_client(name, lxcpath, states, &state_client_fd);
	if (ret < 0)
		return -errno;

	if (ret < MAX_STATE)
		return ret;

	if (state_client_fd < 0)
		return ret_errno(EBADF);

	return lxc_cmd_sock_rcv_state(state_client_fd, timeout);
}

int lxc_make_abstract_socket_name(char *path, size_t pathlen,
				  const char *lxcname,
				  const char *lxcpath,
				  const char *hashed_sock_name,
				  const char *suffix)
{
	__do_free char *tmppath = NULL;
	const char *name;
	char *offset;
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
		ret = strnprintf(offset, len, "lxc/%s/%s", hashed_sock_name, suffix);
		if (ret < 0)
			return log_error_errno(-1, errno, "Failed to create abstract socket name");
		return 0;
	}

	if (!lxcpath) {
		lxcpath = lxc_global_config_value("lxc.lxcpath");
		if (!lxcpath)
			return log_error(-1, "Failed to allocate memory");
	}

	/*
	 * Here we allow exceeding the buffer because we're falling back to
	 * hashing. So we're not using strnprintf() here.
	 */
	ret = snprintf(offset, len, "%s/%s/%s", lxcpath, name, suffix);
	if (ret < 0)
		return log_error_errno(-1, errno, "Failed to create abstract socket name");

	/*
	 * ret >= len. This means lxcpath and name are too long. We need to
	 * hash both.
	 */
	if ((size_t)ret >= len) {
		tmplen = strlen(name) + strlen(lxcpath) + 2;
		tmppath = must_realloc(NULL, tmplen);
		ret = strnprintf(tmppath, tmplen, "%s/%s", lxcpath, name);
		if (ret < 0)
			return log_error_errno(-1, errno, "Failed to create abstract socket name");

		hash = fnv_64a_buf(tmppath, ret, FNV1A_64_INIT);
		ret = strnprintf(offset, len, "lxc/%016" PRIx64 "/%s", hash, suffix);
		if (ret < 0)
			return log_error_errno(-1, errno, "Failed to create abstract socket name");
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
	__do_free struct lxc_state_client *newclient = NULL;
	int state;

	newclient = zalloc(sizeof(*newclient));
	if (!newclient)
		return -ENOMEM;

	/* copy requested states */
	memcpy(newclient->states, states, sizeof(newclient->states));
	newclient->clientfd = state_client_fd;

	state = handler->state;
	if (states[state] != 1) {
		list_add_tail(&newclient->head, &handler->conf->state_clients);
		move_ptr(newclient);
	} else {
		TRACE("Container already in requested state");
		return state;
	}

	TRACE("Added state client fd %d to state client list", state_client_fd);
	return MAX_STATE;
}

void lxc_cmd_notify_state_listeners(const char *name, const char *lxcpath,
				    lxc_state_t state)
{
	(void)lxc_cmd_serve_state_clients(name, lxcpath, state);
	(void)lxc_monitor_send_state(name, state, lxcpath);
}

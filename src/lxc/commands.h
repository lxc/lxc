/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2009
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

#ifndef __LXC_COMMANDS_H
#define __LXC_COMMANDS_H

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

#include "state.h"
#include "lxccontainer.h"

#define LXC_CMD_DATA_MAX (MAXPATHLEN * 2)

/* https://developer.gnome.org/glib/2.28/glib-Type-Conversion-Macros.html */
#define INT_TO_PTR(n) ((void *)(long)(n))
#define PTR_TO_INT(p) ((int)(long)(p))

typedef enum {
	LXC_CMD_CONSOLE,
	LXC_CMD_CONSOLE_WINCH,
	LXC_CMD_STOP,
	LXC_CMD_GET_STATE,
	LXC_CMD_GET_INIT_PID,
	LXC_CMD_GET_CLONE_FLAGS,
	LXC_CMD_GET_CGROUP,
	LXC_CMD_GET_CONFIG_ITEM,
	LXC_CMD_GET_NAME,
	LXC_CMD_GET_LXCPATH,
	LXC_CMD_ADD_STATE_CLIENT,
	LXC_CMD_SET_CONFIG_ITEM,
	LXC_CMD_CONSOLE_LOG,
	LXC_CMD_MAX,
} lxc_cmd_t;

struct lxc_cmd_req {
	lxc_cmd_t cmd;
	int datalen;
	const void *data;
};

struct lxc_cmd_rsp {
	int ret; /* 0 on success, -errno on failure */
	int datalen;
	void *data;
};

struct lxc_cmd_rr {
	struct lxc_cmd_req req;
	struct lxc_cmd_rsp rsp;
};

struct lxc_cmd_console_rsp_data {
	int masterfd;
	int ttynum;
};

struct lxc_cmd_set_config_item_req_data {
	const char *item;
	void *value;
};

struct lxc_cmd_console_log {
	bool clear;
	bool read;
	uint64_t read_max;
	bool write_logfile;

};

extern int lxc_cmd_console_winch(const char *name, const char *lxcpath);
extern int lxc_cmd_console(const char *name, int *ttynum, int *fd,
			   const char *lxcpath);
/*
 * Get the 'real' cgroup path (as seen in /proc/self/cgroup) for a container
 * for a particular subsystem
 */
extern char *lxc_cmd_get_cgroup_path(const char *name, const char *lxcpath,
			const char *subsystem);
extern int lxc_cmd_get_clone_flags(const char *name, const char *lxcpath);
extern char *lxc_cmd_get_config_item(const char *name, const char *item, const char *lxcpath);
extern char *lxc_cmd_get_name(const char *hashed_sock);
extern char *lxc_cmd_get_lxcpath(const char *hashed_sock);
extern pid_t lxc_cmd_get_init_pid(const char *name, const char *lxcpath);
extern int lxc_cmd_get_state(const char *name, const char *lxcpath);
extern int lxc_cmd_stop(const char *name, const char *lxcpath);

/* lxc_cmd_add_state_client    Register a new state client fd in the container's
 *                             in-memory handler.
 *
 * @param[in] name             Name of container to connect to.
 * @param[in] lxcpath          The lxcpath in which the container is running.
 * @param[in] states           The states to wait for.
 * @param[out] state_client_fd The state client fd from which the state can be
 *                             received.
 * @return                     Return  < 0 on error
 *                                    == MAX_STATE when state needs to retrieved
 *                                                 via socket fd
 *                                     < MAX_STATE current container state
 */
extern int lxc_cmd_add_state_client(const char *name, const char *lxcpath,
				    lxc_state_t states[MAX_STATE],
				    int *state_client_fd);

struct lxc_epoll_descr;
struct lxc_handler;

extern int lxc_cmd_init(const char *name, const char *lxcpath, const char *suffix);
extern int lxc_cmd_mainloop_add(const char *name, struct lxc_epoll_descr *descr,
				    struct lxc_handler *handler);
extern int lxc_try_cmd(const char *name, const char *lxcpath);

extern int lxc_cmd_set_config_item(const char *name, const char *item,
				   const char *value, const char *lxcpath);
extern int lxc_cmd_console_log(const char *name, const char *lxcpath,
			       struct lxc_console_log *log);

#endif /* __commands_h */

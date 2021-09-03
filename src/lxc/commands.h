/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_COMMANDS_H
#define __LXC_COMMANDS_H

#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include "lxc.h"

#include "compiler.h"
#include "cgroups/cgroup.h"
#include "macro.h"
#include "state.h"

/*
 * Value command callbacks should return when they want the client fd to be
 * cleaned up by the main loop. This is most certainly what you want unless you
 * have specific reasons to keep the file descriptor alive.
 */
#define LXC_CMD_REAP_CLIENT_FD 1
#define LXC_CMD_KEEP_CLIENT_FD 2

typedef enum {
	LXC_CMD_GET_TTY_FD			= 0,
	LXC_CMD_TERMINAL_WINCH			= 1,
	LXC_CMD_STOP				= 2,
	LXC_CMD_GET_STATE			= 3,
	LXC_CMD_GET_INIT_PID			= 4,
	LXC_CMD_GET_CLONE_FLAGS			= 5,
	LXC_CMD_GET_CGROUP			= 6,
	LXC_CMD_GET_CONFIG_ITEM			= 7,
	LXC_CMD_GET_NAME			= 8,
	LXC_CMD_GET_LXCPATH			= 9,
	LXC_CMD_ADD_STATE_CLIENT		= 10,
	LXC_CMD_CONSOLE_LOG			= 11,
	LXC_CMD_SERVE_STATE_CLIENTS		= 12,
	LXC_CMD_SECCOMP_NOTIFY_ADD_LISTENER	= 13,
	LXC_CMD_ADD_BPF_DEVICE_CGROUP		= 14,
	LXC_CMD_FREEZE				= 15,
	LXC_CMD_UNFREEZE			= 16,
	LXC_CMD_GET_CGROUP2_FD			= 17,
	LXC_CMD_GET_INIT_PIDFD 			= 18,
	LXC_CMD_GET_LIMIT_CGROUP		= 19,
	LXC_CMD_GET_LIMIT_CGROUP2_FD		= 20,
	LXC_CMD_GET_DEVPTS_FD			= 21,
	LXC_CMD_GET_SECCOMP_NOTIFY_FD		= 22,
	LXC_CMD_GET_CGROUP_CTX			= 23,
	LXC_CMD_GET_CGROUP_FD			= 24,
	LXC_CMD_GET_LIMIT_CGROUP_FD		= 25,
	LXC_CMD_MAX,
} lxc_cmd_t;

struct lxc_cmd_req {
	lxc_cmd_t cmd;
	int datalen;
	const void *data;
};

#define ENCODE_INTO_PTR_LEN 0

struct lxc_cmd_rsp {
	int ret; /* 0 on success, -errno on failure */
	int datalen;
	void *data;
};

struct lxc_cmd_rr {
	struct lxc_cmd_req req;
	struct lxc_cmd_rsp rsp;
};

static inline void lxc_cmd_init(struct lxc_cmd_rr *cmd, lxc_cmd_t command)
{
	*cmd = (struct lxc_cmd_rr){
		.req = {.cmd = command },
		.rsp = {.ret = -ENOSYS },
	};
}

static inline void lxc_cmd_data(struct lxc_cmd_rr *cmd, int len_data, const void *data)
{
	cmd->req.data = data;
	cmd->req.datalen = len_data;
}

struct lxc_cmd_tty_rsp_data {
	int ptxfd;
	int ttynum;
};

struct lxc_cmd_console_log {
	bool clear;
	bool read;
	uint64_t read_max;
	bool write_logfile;

};

__hidden extern int lxc_cmd_terminal_winch(const char *name, const char *lxcpath);
__hidden extern int lxc_cmd_get_tty_fd(const char *name, int *ttynum, int *fd,
				       const char *lxcpath);
/*
 * Get the 'real' cgroup path (as seen in /proc/self/cgroup) for a container
 * for a particular controller
 */
__hidden extern char *lxc_cmd_get_cgroup_path(const char *name, const char *lxcpath,
					      const char *controller);
__hidden extern int lxc_cmd_get_clone_flags(const char *name, const char *lxcpath);
__hidden extern char *lxc_cmd_get_config_item(const char *name, const char *item,
					      const char *lxcpath);
__hidden extern char *lxc_cmd_get_name(const char *hashed_sock);
__hidden extern char *lxc_cmd_get_lxcpath(const char *hashed_sock);
__hidden extern pid_t lxc_cmd_get_init_pid(const char *name, const char *lxcpath);
__hidden extern int lxc_cmd_get_init_pidfd(const char *name, const char *lxcpath);
__hidden extern int lxc_cmd_get_state(const char *name, const char *lxcpath);
__hidden extern int lxc_cmd_stop(const char *name, const char *lxcpath);

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
__hidden __access_r_nosize(3) extern int lxc_cmd_add_state_client(const char *name,
								  const char *lxcpath,
								  lxc_state_t states[static MAX_STATE],
								  int *state_client_fd);
__hidden extern int lxc_cmd_serve_state_clients(const char *name, const char *lxcpath,
						lxc_state_t state);

struct lxc_async_descr;
struct lxc_handler;

__hidden extern int lxc_server_init(const char *name, const char *lxcpath, const char *suffix);
__hidden extern int lxc_cmd_mainloop_add(const char *name, struct lxc_async_descr *descr,
					 struct lxc_handler *handler);
__hidden extern int lxc_try_cmd(const char *name, const char *lxcpath);
__hidden extern int lxc_cmd_console_log(const char *name, const char *lxcpath,
					struct lxc_console_log *log);
__hidden extern int lxc_cmd_get_seccomp_notify_fd(const char *name, const char *lxcpath);
__hidden extern int lxc_cmd_get_cgroup_ctx(const char *name, const char *lxcpath,
					   size_t size_ret_ctx,
					   struct cgroup_ctx *ret_ctx);
__hidden extern int lxc_cmd_seccomp_notify_add_listener(const char *name, const char *lxcpath, int fd,
							/* unused */ unsigned int command,
							/* unused */ unsigned int flags);

struct device_item;
__hidden extern int lxc_cmd_add_bpf_device_cgroup(const char *name, const char *lxcpath,
						  struct device_item *device);
__hidden extern int lxc_cmd_freeze(const char *name, const char *lxcpath, int timeout);
__hidden extern int lxc_cmd_unfreeze(const char *name, const char *lxcpath, int timeout);
__hidden extern int lxc_cmd_get_cgroup2_fd(const char *name, const char *lxcpath);
__hidden extern int lxc_cmd_get_cgroup_fd(const char *name, const char *lxcpath,
					  size_t size_ret_fd,
					  struct cgroup_fd *ret_fd);
__hidden extern char *lxc_cmd_get_limit_cgroup_path(const char *name,
						    const char *lxcpath,
						    const char *controller);
__hidden extern int lxc_cmd_get_limit_cgroup2_fd(const char *name,
						 const char *lxcpath);
__hidden extern int lxc_cmd_get_limit_cgroup_fd(const char *name,
						const char *lxcpath,
						size_t size_ret_fd,
						struct cgroup_fd *ret_fd);
__hidden extern int lxc_cmd_get_devpts_fd(const char *name, const char *lxcpath);

#endif /* __commands_h */

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
#ifndef __LXC_MONITOR_H
#define __LXC_MONITOR_H

#include <limits.h>
#include <sys/param.h>
#include <sys/un.h>
#include <poll.h>

#include "conf.h"

typedef enum {
	lxc_msg_state,
	lxc_msg_priority,
	lxc_msg_exit_code,
} lxc_msg_type_t;

struct lxc_msg {
	lxc_msg_type_t type;
	char name[NAME_MAX+1];
	int value;
};

extern int lxc_monitor_sock_name(const char *lxcpath, struct sockaddr_un *addr);
extern int lxc_monitor_fifo_name(const char *lxcpath, char *fifo_path,
				 size_t fifo_path_sz, int do_mkdirp);
extern void lxc_monitor_send_state(const char *name, lxc_state_t state,
			    const char *lxcpath);
extern void lxc_monitor_send_exit_code(const char *name, int exit_code,
			    const char *lxcpath);
extern int lxc_monitord_spawn(const char *lxcpath);

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
 * @fds     : struct pollfd descripting the fds to use
 * @nfds    : the number of entries in fds
 * @msg     : the variable which will be filled with the state
 * @timeout : the timeout in seconds to wait for a state change
 * Returns 0 if the monitored container has exited, > 0 if
 * data was read, < 0 otherwise
 */
extern int lxc_monitor_read_fdset(struct pollfd *fds, nfds_t nfds, struct lxc_msg *msg,
			   int timeout);


#endif

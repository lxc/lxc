/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2009
 *
 * Authors:
 * Daniel Lezcano <dlezcano at fr.ibm.com>
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */
#ifndef __commands_h
#define __commands_h

enum {
	LXC_COMMAND_TTY,
	LXC_COMMAND_STOP,
	LXC_COMMAND_STATE,
	LXC_COMMAND_PID,
	LXC_COMMAND_MAX,
};

struct lxc_request {
	int type;
	int data;
};

struct lxc_answer {
	int fd;
	int ret; /* 0 on success, -errno on failure */
	pid_t pid;
};

struct lxc_command {
	struct lxc_request request;
	struct lxc_answer answer;
};

extern pid_t get_init_pid(const char *name);

extern int lxc_command(const char *name, struct lxc_command *command,
			int *stopped);

extern int lxc_command_connected(const char *name, struct lxc_command *command,
				 int *stopped);

struct lxc_epoll_descr;
struct lxc_handler;

extern int lxc_command_mainloop_add(const char *name, struct lxc_epoll_descr *descr,
				    struct lxc_handler *handler);

#endif

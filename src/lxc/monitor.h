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

#include "conf.h"

typedef enum {
	lxc_msg_state,
	lxc_msg_priority,
} lxc_msg_type_t;

struct lxc_msg {
	lxc_msg_type_t type;
	char name[NAME_MAX+1];
	int value;
};

extern int lxc_monitor_open(const char *lxcpath);
extern int lxc_monitor_sock_name(const char *lxcpath, struct sockaddr_un *addr);
extern int lxc_monitor_fifo_name(const char *lxcpath, char *fifo_path,
				 size_t fifo_path_sz, int do_mkdirp);
extern void lxc_monitor_send_state(const char *name, lxc_state_t state,
			    const char *lxcpath);
extern int lxc_monitord_spawn(const char *lxcpath);

#endif

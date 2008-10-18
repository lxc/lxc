/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2008
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
#ifndef __monitor_h
#define __monitor_h

#include <sys/param.h>

typedef enum {
	lxc_msg_state,
	lxc_msg_priority,
} lxc_msg_type_t;

struct lxc_msg {
	lxc_msg_type_t type;
	char name[MAXPATHLEN];
	int value;
};

void lxc_monitor_send_state(const char *name, lxc_state_t state);
void lxc_monitor_send_priority(const char *name, int priority);
void lxc_monitor_cleanup(const char *name);

#endif

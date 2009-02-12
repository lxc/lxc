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

#include <stdio.h>
#include <stdlib.h>
#include "error.h"

static const char *const catalogue[] = {

	[LXC_ERROR_LOCK] = "Failed to lock the container",

	[LXC_ERROR_ESRCH] = "The container is empty",
	[LXC_ERROR_EEXIST] = "The container already exists",
	[LXC_ERROR_EBUSY] = "The container is busy",
	[LXC_ERROR_ENOENT] = "The container was not found",
	[LXC_ERROR_EACCES] = "Not enough privilege to use the container",
	[LXC_ERROR_WRONG_COMMAND] = "Wrong command",

	[LXC_ERROR_CONF_CGROUP] = "Failed to configure the control group",
	[LXC_ERROR_CONF_MOUNT] = "Failed to configure the mount points",
	[LXC_ERROR_CONF_UTSNAME] = "Failed to configure the utsname",
	[LXC_ERROR_CONF_NETWORK] = "Failed to configure the network",
	[LXC_ERROR_CONF_TTY] = "Failed to configure the tty",
	[LXC_ERROR_CONF_ROOTFS] = "Failed to configure the root fs",
	[LXC_ERROR_CONF_PTS] = "Failed to configure the pts",

	[LXC_ERROR_SETUP_CGROUP] = "Failed to setup the control group",
	[LXC_ERROR_SETUP_MOUNT] = "Failed to setup the mount points",
	[LXC_ERROR_SETUP_UTSNAME] = "Failed to setup the utsname",
	[LXC_ERROR_SETUP_NETWORK] = "Failed to setup the network",
	[LXC_ERROR_SETUP_CONSOLE] = "Failed to setup the console",
	[LXC_ERROR_SETUP_TTY] = "Failed to setup the tty",
	[LXC_ERROR_SETUP_ROOTFS] = "Failed to setup the root fs",
	[LXC_ERROR_SETUP_PTS] = "Failed to setup the new pts instance",

	[LXC_ERROR_TTY_DENIED] = "tty service denied",
	[LXC_ERROR_TTY_EAGAIN] = "tty service is not available",
	[LXC_ERROR_INTERNAL] = "Internal system error",
};

const char *const lxc_strerror(int error)
{
	error = abs(error);

	if (error >= LXC_LAST_ERROR)
		return NULL;

	return catalogue[error];
}

/* liblxcapi
 *
 * Copyright © 2018 Christian Brauner <christian.brauner@ubuntu.com>.
 * Copyright © 2018 Canonical Ltd.
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

#ifndef __LXC_API_EXTENSIONS_H
#define __LXC_API_EXTENSIONS_H

#include <stdio.h>
#include <stdlib.h>

/*
 * api_extensions is the list of all API extensions in the order they were
 * added.

 The following kind of changes come with a new extensions:

 - New public functions
 - New configuration key
 - New valid values for a configuration key
*/
static char *api_extensions[] = {
	"lxc_log",
	"lxc_config_item_is_supported",
	"console_log",
	"reboot2",
	"mount_injection",
	"cgroup_relative",
};

static size_t nr_api_extensions = sizeof(api_extensions) / sizeof(*api_extensions);

#endif /* __LXC_API_EXTENSIONS_H */

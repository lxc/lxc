/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_API_EXTENSIONS_H
#define __LXC_API_EXTENSIONS_H

#include <stdio.h>
#include <stdlib.h>

#include "config.h"

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
	"mount_injection_file",
	"seccomp_allow_nesting",
	"seccomp_notify",
	"network_veth_routes",
	"network_ipvlan",
	"network_l2proxy",
	"network_gateway_device_route",
	"network_phys_macvlan_mtu",
	"network_veth_router",
	"cgroup2_devices",
	"cgroup2",
	"pidfd",
	"cgroup_advanced_isolation",
	"network_bridge_vlan",
	"time_namespace",
	"seccomp_allow_deny_syntax",
	"devpts_fd",
	"seccomp_notify_fd_active",
	"seccomp_proxy_send_notify_fd",
	"idmapped_mounts",
	"idmapped_mounts_v2",
};

static size_t nr_api_extensions = sizeof(api_extensions) / sizeof(*api_extensions);

#endif /* __LXC_API_EXTENSIONS_H */

# SPDX-License-Identifier: LGPL-2.1-or-later

tools_common_sources = liblxc_sources + files('arguments.c', 'arguments.h') + include_sources + netns_ifaddrs_sources

tools_commands = ['attach', 'autostart', 'cgroup', 'checkpoint', 'config',
    'console', 'copy', 'create', 'destroy', 'device', 'execute', 'freeze',
    'info', 'ls', 'monitor', 'snapshot', 'start', 'stop', 'top', 'unfreeze',
    'unshare', 'wait']

if want_tools
    foreach cmd : tools_commands 
        public_programs += executable(
            'lxc-' + cmd,
            files('lxc_' + cmd + '.c') + tools_common_sources,
            include_directories: liblxc_includes,
            dependencies: liblxc_dep,
            install: true)
    endforeach
endif

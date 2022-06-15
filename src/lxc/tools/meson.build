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

if want_tools_multicall
    tools_all_sources = files('lxc_multicall.c') + tools_common_sources
    foreach cmd : tools_commands
        tools_all_sources += files('lxc_' + cmd + '.c')
    endforeach

    public_programs += executable(
        'lxc',
        tools_all_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    if want_tools == false
        foreach cmd : tools_commands
            public_programs += install_symlink(
                'lxc-' + cmd,
                pointing_to: 'lxc',
                install_dir: get_option('bindir'))
        endforeach
    endif
endif

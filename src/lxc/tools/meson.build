# SPDX-License-Identifier: LGPL-2.1+

tools_common_sources = files('arguments.c', 'arguments.h') + include_sources
tools_common_sources_for_dynamic_link = tools_common_sources + netns_ifaddrs_sources

tools_commands_dynamic_link = ['attach', 'autostart', 'cgroup', 'checkpoint', 'config',
    'console', 'copy', 'create', 'destroy', 'device', 'execute', 'freeze',
    'info', 'ls', 'snapshot', 'start', 'stop', 'top', 'unfreeze',
    'unshare', 'wait']

tools_commands_static_link = ['monitor']

tools_commands = tools_commands_dynamic_link + tools_commands_static_link

if want_tools
    foreach cmd : tools_commands_dynamic_link
        public_programs += executable(
            'lxc-' + cmd,
            files('lxc_' + cmd + '.c') + tools_common_sources_for_dynamic_link + liblxc_ext_sources,
            dependencies: liblxc_dependencies,
            include_directories: liblxc_includes,
            c_args: ['-DNO_LXC_CONF'],
            link_with: [liblxc],
            install: true)
    endforeach

    foreach cmd : tools_commands_static_link
        public_programs += executable(
            'lxc-' + cmd,
            files('lxc_' + cmd + '.c') + files('arguments.c', 'arguments.h'),
            dependencies: liblxc_dependencies,
            include_directories: liblxc_includes,
            link_whole: [liblxc_static],
            install: true)
    endforeach
endif

if want_tools_multicall
    tools_all_sources = files('lxc_multicall.c') + files('arguments.c', 'arguments.h')
    foreach cmd : tools_commands
        tools_all_sources += files('lxc_' + cmd + '.c')
    endforeach

    public_programs += executable(
        'lxc',
        tools_all_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dependencies,
        link_whole: [liblxc_static],
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

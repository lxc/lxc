# SPDX-License-Identifier: LGPL-2.1+

if 'dinit' in init_script
    dinit_service_dir = get_option('dinit-servicedir')
    if dinit_service_dir == ''
        dinit_service_dir = join_paths(sysconfdir, 'dinit.d')
    endif

    configure_file(
        configuration: conf,
        input: 'lxc.in',
        output: 'lxc',
        install: true,
        install_dir: dinit_service_dir)

    configure_file(
        configuration: conf,
        input: 'lxc-containers.in',
        output: 'lxc-containers',
        install: true,
        install_dir: dinit_service_dir)

    configure_file(
        configuration: conf,
        input: 'lxc-net.in',
        output: 'lxc-net',
        install: true,
        install_dir: dinit_service_dir)

    configure_file(
        configuration: conf,
        input: 'lxc-monitord.in',
        output: 'lxc-monitord',
        install: true,
        install_dir: dinit_service_dir)

    configure_file(
        configuration: conf,
        input: 'lxc@.in',
        output: 'lxc@',
        install: true,
        install_dir: dinit_service_dir)
endif

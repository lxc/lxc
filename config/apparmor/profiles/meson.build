# SPDX-License-Identifier: LGPL-2.1-or-later

if libapparmor.found()
    configure_file(
        configuration: dummy_config_data,
        input: 'lxc-default',
        output: 'lxc-default',
        install: true,
        install_dir: join_paths(sysconfdir, 'apparmor.d', 'lxc'))

    configure_file(
        configuration: dummy_config_data,
        input: 'lxc-default-cgns',
        output: 'lxc-default-cgns',
        install: true,
        install_dir: join_paths(sysconfdir, 'apparmor.d', 'lxc'))

    configure_file(
        configuration: dummy_config_data,
        input: 'lxc-default-with-mounting',
        output: 'lxc-default-with-mounting',
        install: true,
        install_dir: join_paths(sysconfdir, 'apparmor.d', 'lxc'))

    configure_file(
        configuration: dummy_config_data,
        input: 'lxc-default-with-nesting',
        output: 'lxc-default-with-nesting',
        install: true,
        install_dir: join_paths(sysconfdir, 'apparmor.d', 'lxc'))
endif

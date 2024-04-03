# SPDX-License-Identifier: LGPL-2.1+

if libapparmor.found()
    configure_file(
        configuration: dummy_config_data,
        input: 'lxc-containers',
        output: 'lxc-containers',
        install: true,
        install_dir: join_paths(sysconfdir, 'apparmor.d'))

    configure_file(
        configuration: dummy_config_data,
        input: 'usr.bin.lxc-start',
        output: 'usr.bin.lxc-start',
        install: true,
        install_dir: join_paths(sysconfdir, 'apparmor.d'))

    configure_file(
        configuration: dummy_config_data,
        input: 'usr.bin.lxc-copy',
        output: 'usr.bin.lxc-copy',
        install: true,
        install_dir: join_paths(sysconfdir, 'apparmor.d'))
endif

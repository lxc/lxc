# SPDX-License-Identifier: LGPL-2.1-or-later

if 'upstart' in init_script
    configure_file(
        configuration: conf,
        input: 'lxc.conf.in',
        output: 'lxc.conf',
        install: true,
        install_dir: join_paths(sysconfdir, 'init'))

    configure_file(
        configuration: conf,
        input: 'lxc-instance.conf',
        output: 'lxc-instance.conf',
        install: true,
        install_dir: join_paths(sysconfdir, 'init'))

    configure_file(
        configuration: conf,
        input: 'lxc-net.conf.in',
        output: 'lxc-net.conf',
        install: true,
        install_dir: join_paths(sysconfdir, 'init'))
endif

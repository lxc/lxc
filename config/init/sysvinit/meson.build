# SPDX-License-Identifier: LGPL-2.1-or-later

if 'sysvinit' in init_script
    configure_file(
        configuration: conf,
        input: 'lxc-containers.in',
        output: 'lxc-containers',
        install: true,
        install_dir: join_paths(sysconfdir, 'init.d'))

    configure_file(
        configuration: conf,
        input: 'lxc-net.in',
        output: 'lxc-net',
        install: true,
        install_dir: join_paths(sysconfdir, 'init.d'))
endif

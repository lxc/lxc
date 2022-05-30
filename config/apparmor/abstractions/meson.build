# SPDX-License-Identifier: LGPL-2.1-or-later

if libapparmor.found()
    configure_file(
        configuration: conf,
        input: 'container-base',
        output: 'container-base',
        install: true,
        install_dir: join_paths(sysconfdir, 'apparmor.d', 'abstractions', 'lxc'))

    configure_file(
        configuration: conf,
        input: 'start-container.in',
        output: 'start-container',
        install: true,
        install_dir: join_paths(sysconfdir, 'apparmor.d', 'abstractions', 'lxc'))
endif

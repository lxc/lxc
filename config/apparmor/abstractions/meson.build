# SPDX-License-Identifier: LGPL-2.1+

if libapparmor.found()
    configure_file(
        command: ['cat', '@INPUT@'],
        capture: true,
        input: ['container-base.in', '../container-rules'],
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

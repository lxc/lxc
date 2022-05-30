# SPDX-License-Identifier: LGPL-2.1-or-later

fs = import('fs')
if fs.is_dir('/etc/sysconfig')
    configure_file(
        configuration: conf,
        input: 'lxc.in',
        output: 'lxc',
        install: true,
        install_dir: join_paths(sysconfdir, 'sysconfig'))
elif fs.is_dir('/etc/default')
    configure_file(
        configuration: conf,
        input: 'lxc.in',
        output: 'lxc',
        install: true,
        install_dir: join_paths(sysconfdir, 'default'))
endif

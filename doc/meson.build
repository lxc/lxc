# SPDX-License-Identifier: LGPL-2.1-or-later

if want_mans
    PAGES = [
        ['lxc', '7'],
        ['lxc.conf', '5'],
        ['lxc.container.conf', '5'],
        ['lxc.system.conf', '5'],
        ['lxc-update-config', '1'],
        ['lxc-usernet', '5'],
        ['lxc-user-nic', '1'],
        ['lxc-usernsexec', '1'],
    ]

    if want_tools
        PAGES += [
            ['lxc-attach', '1'],
            ['lxc-autostart', '1'],
            ['lxc-cgroup', '1'],
            ['lxc-checkconfig', '1'],
            ['lxc-checkpoint', '1'],
            ['lxc-config', '1'],
            ['lxc-console', '1'],
            ['lxc-copy', '1'],
            ['lxc-create', '1'],
            ['lxc-destroy', '1'],
            ['lxc-device', '1'],
            ['lxc-execute', '1'],
            ['lxc-freeze', '1'],
            ['lxc-info', '1'],
            ['lxc-ls', '1'],
            ['lxc-monitor', '1'],
            ['lxc-snapshot', '1'],
            ['lxc-start', '1'],
            ['lxc-stop', '1'],
            ['lxc-top', '1'],
            ['lxc-unfreeze', '1'],
            ['lxc-unshare', '1'],
            ['lxc-wait', '1'],
        ]
    endif

    if want_pam_cgroup
        PAGES += [
            ['pam_cgfs', '8'],
        ]
    endif

    # Common files.
    configure_file(
        configuration: docconf,
        input: 'common_options.sgml.in',
        output: 'common_options.sgml')

    configure_file(
        configuration: docconf,
        input: 'see_also.sgml.in',
        output: 'see_also.sgml')

    # Initial templating.
    foreach page : PAGES
        sgml = configure_file(
            configuration: docconf,
            input: page[0] + '.sgml.in',
            output: page[0] + '.sgml')

        configure_file(
            input: sgml,
            output: page[0] + '.' + page[1],
            command: [sgml2man, '--encoding=UTF-8', page[0] + '.sgml'],
            install: true,
            install_dir: join_paths(mandir, 'man' + page[1]))
    endforeach
endif

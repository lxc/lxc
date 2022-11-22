# SPDX-License-Identifier: LGPL-2.1-or-later

lxc_apparmor_load = configure_file(
    configuration: dummy_config_data,
    input: 'lxc-apparmor-load',
    output: 'lxc-apparmor-load',
    install: true,
    install_dir: lxclibexec)

if 'systemd' in init_script
    systemd_system_unit_dir = get_option('systemd-unitdir')
    if systemd_system_unit_dir == ''
        systemd = dependency('systemd')
        systemd_system_unit_dir = systemd.get_variable('systemdsystemunitdir')
    endif

    configure_file(
        configuration: conf,
        input: 'lxc-monitord.service.in',
        output: 'lxc-monitord.service',
        install: true,
        install_dir: systemd_system_unit_dir)

    configure_file(
        configuration: conf,
        input: 'lxc-net.service.in',
        output: 'lxc-net.service',
        install: true,
        install_dir: systemd_system_unit_dir)

    configure_file(
        configuration: conf,
        input: 'lxc.service.in',
        output: 'lxc.service',
        install: true,
        install_dir: systemd_system_unit_dir)

    configure_file(
        configuration: conf,
        input: 'lxc@.service.in',
        output: 'lxc@.service',
        install: true,
        install_dir: systemd_system_unit_dir)
endif

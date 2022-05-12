# SPDX-License-Identifier: LGPL-2.1-or-later

lxc_selinux_if = configure_file(
    configuration: dummy_config_data,
    input: 'lxc.if',
    output: 'lxc.if',
    install: libselinux.found(),
    install_dir: lxcselinuxdir)

lxc_selinux_te = configure_file(
    configuration: dummy_config_data,
    input: 'lxc.te',
    output: 'lxc.te',
    install: libselinux.found(),
    install_dir: lxcselinuxdir)

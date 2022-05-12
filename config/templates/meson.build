# SPDX-License-Identifier: LGPL-2.1-or-later

lxc_conf_common_seccomp = configure_file(
    configuration: conf,
    input: 'common.seccomp',
    output: 'common.seccomp',
    install: true,
    install_dir: lxctemplateconfdir)

lxc_conf_common_main = configure_file(
    configuration: conf,
    input: 'common.conf.in',
    output: 'common.conf',
    install: true,
    install_dir: lxctemplateconfdir)

lxc_conf_common_nesting = configure_file(
    configuration: conf,
    input: 'nesting.conf.in',
    output: 'nesting.conf',
    install: true,
    install_dir: lxctemplateconfdir)

lxc_conf_common_oci = configure_file(
    configuration: conf,
    input: 'oci.common.conf.in',
    output: 'oci.common.conf',
    install: true,
    install_dir: lxctemplateconfdir)

lxc_conf_common_userns = configure_file(
    configuration: conf,
    input: 'userns.conf.in',
    output: 'userns.conf',
    install: true,
    install_dir: lxctemplateconfdir)

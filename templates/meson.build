# SPDX-License-Identifier: LGPL-2.1-or-later

template_scripts = configure_file(
    configuration: dummy_config_data,
    input: 'lxc-busybox.in',
    output: 'lxc-busybox',
    install: true,
    install_dir: lxctemplatedir)

template_config_data = configuration_data()
template_config_data.set_quoted('LXCHOOKDIR', lxchookdir)
template_config_data.set_quoted('LXCTEMPLATECONFIG', lxctemplateconfig)
template_config_data.set_quoted('LOCALSTATEDIR', localstatedir)
template_config_data.set_quoted('PACKAGE_VERSION', meson.project_version())

template_scripts = configure_file(
    configuration: template_config_data,
    input: 'lxc-download.in',
    output: 'lxc-download',
    install: true,
    install_dir: lxctemplatedir)

template_scripts = configure_file(
    configuration: template_config_data,
    input: 'lxc-local.in',
    output: 'lxc-local',
    install: true,
    install_dir: lxctemplatedir)

template_scripts = configure_file(
    configuration: template_config_data,
    input: 'lxc-oci.in',
    output: 'lxc-oci',
    install: true,
    install_dir: lxctemplatedir)

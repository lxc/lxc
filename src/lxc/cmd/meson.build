# SPDX-License-Identifier: LGPL-2.1-or-later

cmd_common_sources = liblxc_sources + include_sources

cmd_lxc_init_sources = files(
    'lxc_init.c',
    '../af_unix.c',
    '../af_unix.h',
    '../caps.c',
    '../caps.h',
    '../error.c',
    '../error.h',
    '../file_utils.c',
    '../file_utils.h',
    '../initutils.c',
    '../initutils.h',
    '../log.h',
    '../log.c',
    '../macro.h',
    '../memory_utils.h',
    '../namespace.c',
    '../namespace.h',
    '../open_utils.h',
    '../string_utils.c',
    '../string_utils.h') + include_sources

cmd_lxc_init_static_sources = files(
    'lxc_init.c',
    '../af_unix.c',
    '../af_unix.h',
    '../caps.c',
    '../caps.h',
    '../error.c',
    '../error.h',
    '../file_utils.c',
    '../file_utils.h',
    '../initutils.c',
    '../initutils.h',
    '../log.h',
    '../log.c',
    '../macro.h',
    '../memory_utils.h',
    '../namespace.c',
    '../namespace.h',
    '../open_utils.h',
    '../string_utils.c',
    '../string_utils.h') + include_sources

cmd_lxc_monitord_sources = files('lxc_monitord.c') + cmd_common_sources + netns_ifaddrs_sources
cmd_lxc_user_nic_sources = files('lxc_user_nic.c') + cmd_common_sources + netns_ifaddrs_sources
cmd_lxc_usernsexec_sources = files('lxc_usernsexec.c') + cmd_common_sources + netns_ifaddrs_sources

cmd_lxc_checkconfig = configure_file(
    configuration: dummy_config_data,
    input: 'lxc-checkconfig.in',
    output: 'lxc-checkconfig')
install_data(join_paths(project_build_root, 'src/lxc/cmd/lxc-checkconfig'), install_dir: bindir)

cmd_lxc_update_config = configure_file(
    configuration: dummy_config_data,
    input: 'lxc-update-config.in',
    output: 'lxc-update-config')
install_data(join_paths(project_build_root, 'src/lxc/cmd/lxc-update-config'), install_dir: bindir)

if sanitize == 'none' and libcap_static_linkable
    cmd_programs += executable(
        'init.lxc.static',
        cmd_lxc_init_sources,
        include_directories: liblxc_includes,
        link_with: [liblxc_static],
        link_args: ['-static'],
        c_args: ['-DNO_LXC_CONF'],
        dependencies: [libcap_static] + liblxc_dependency_headers,
        install_dir: sbindir,
        install: true)
endif

cmd_programs += executable(
    'init.lxc',
    cmd_lxc_init_sources,
    include_directories: liblxc_includes,
    c_args: ['-DNO_LXC_CONF'],
    dependencies: liblxc_dep,
    install_dir: sbindir,
    install: true)

cmd_programs += executable(
    'lxc-monitord',
    cmd_lxc_monitord_sources,
    include_directories: liblxc_includes,
    dependencies: liblxc_dep,
    install: true,
    install_dir: lxclibexec)

cmd_programs += executable(
    'lxc-user-nic',
    cmd_lxc_user_nic_sources,
    include_directories: liblxc_includes,
    dependencies: liblxc_dep,
    install: true,
    install_mode: 'rwsr-xr-x', # 4755
    install_dir: lxclibexec)

cmd_programs += executable(
    'lxc-usernsexec',
    cmd_lxc_usernsexec_sources,
    include_directories: liblxc_includes,
    dependencies: liblxc_dep,
    install: true)

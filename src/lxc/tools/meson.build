# SPDX-License-Identifier: LGPL-2.1-or-later

tools_common_sources = liblxc_sources + files('arguments.c', 'arguments.h') + include_sources + netns_ifaddrs_sources

tools_lxc_attach_sources = files(
    'lxc_attach.c') + tools_common_sources

tools_lxc_autostart_sources = files(
    'lxc_autostart.c') + tools_common_sources

tools_lxc_cgroup_sources = files(
    'lxc_cgroup.c') + tools_common_sources

tools_lxc_checkpoint_sources = files(
    'lxc_checkpoint.c') + tools_common_sources

tools_lxc_config_sources = files(
    'lxc_config.c') + tools_common_sources

tools_lxc_console_sources = files(
    'lxc_console.c') + tools_common_sources

tools_lxc_copy_sources = files(
    'lxc_copy.c') + tools_common_sources

tools_lxc_create_sources = files(
    'lxc_create.c') + tools_common_sources

tools_lxc_destroy_sources = files(
    'lxc_destroy.c') + tools_common_sources

tools_lxc_device_sources = files(
    'lxc_device.c') + tools_common_sources

tools_lxc_execute_sources = files(
    'lxc_execute.c') + tools_common_sources

tools_lxc_freeze_sources = files(
    'lxc_freeze.c') + tools_common_sources

tools_lxc_info_sources = files(
    'lxc_info.c') + tools_common_sources

tools_lxc_ls_sources = files(
    'lxc_ls.c') + tools_common_sources

tools_lxc_monitor_sources = files(
    'lxc_monitor.c') + tools_common_sources

tools_lxc_snapshot_sources = files(
    'lxc_snapshot.c') + tools_common_sources

tools_lxc_start_sources = files(
    'lxc_start.c') + tools_common_sources

tools_lxc_stop_sources = files(
    'lxc_stop.c') + tools_common_sources

tools_lxc_top_sources = files(
    'lxc_top.c') + tools_common_sources

tools_lxc_unfreeze_sources = files(
    'lxc_unfreeze.c') + tools_common_sources

tools_lxc_unshare_sources = files(
    'lxc_unshare.c') + tools_common_sources

tools_lxc_wait_sources = files(
    'lxc_wait.c') + tools_common_sources

if want_tools
    public_programs += executable(
        'lxc-attach',
        tools_lxc_attach_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    public_programs += executable(
        'lxc-autostart',
        tools_lxc_autostart_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    public_programs += executable(
       'lxc-cgroup',
        tools_lxc_cgroup_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    public_programs += executable(
       'lxc-checkpoint',
        tools_lxc_checkpoint_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    public_programs += executable(
        'lxc-config',
        tools_lxc_config_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    public_programs += executable(
        'lxc-console',
        tools_lxc_console_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    public_programs += executable(
        'lxc-copy',
        tools_lxc_copy_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    public_programs += executable(
        'lxc-create',
        tools_lxc_create_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    public_programs += executable(
        'lxc-destroy',
        tools_lxc_destroy_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    public_programs += executable(
        'lxc-device',
        tools_lxc_device_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    public_programs += executable(
        'lxc-execute',
        tools_lxc_execute_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    public_programs += executable(
        'lxc-freeze',
        tools_lxc_freeze_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    public_programs += executable(
        'lxc-info',
        tools_lxc_info_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    public_programs += executable(
        'lxc-ls',
        tools_lxc_ls_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    public_programs += executable(
        'lxc-monitor',
        tools_lxc_monitor_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    public_programs += executable(
        'lxc-snapshot',
        tools_lxc_snapshot_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    public_programs += executable(
        'lxc-start',
        tools_lxc_start_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    public_programs += executable(
        'lxc-stop',
        tools_lxc_stop_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    public_programs += executable(
        'lxc-top',
        tools_lxc_top_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    public_programs += executable(
        'lxc-unfreeze',
        tools_lxc_unfreeze_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    public_programs += executable(
        'lxc-unshare',
        tools_lxc_unshare_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    public_programs += executable(
        'lxc-wait',
        tools_lxc_wait_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)
endif

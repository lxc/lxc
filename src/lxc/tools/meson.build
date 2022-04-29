# SPDX-License-Identifier: LGPL-2.1-or-later

tools_liblxc_includes = include_directories(
    '.',
    '../',
    '../cgroups',
    '../lsm',
    '../storage',
    '../../include',
    '../../../')

tools_common_sources = files(
    'arguments.c',
    'arguments.h',
    '../af_unix.c',
    '../af_unix.h',
    '../attach_options.h',
    '../caps.c',
    '../caps.h',
    '../commands.c',
    '../commands.h',
    '../commands_utils.c',
    '../commands_utils.h',
    '../compiler.h',
    '../conf.c',
    '../conf.h',
    '../confile.c',
    '../confile.h',
    '../confile_utils.c',
    '../confile_utils.h',
    '../cgroups/cgfsng.c',
    '../cgroups/cgroup.c',
    '../cgroups/cgroup.h',
    '../cgroups/cgroup2_devices.c',
    '../cgroups/cgroup2_devices.h',
    '../cgroups/cgroup_utils.c',
    '../cgroups/cgroup_utils.h',
    '../error.c',
    '../error.h',
    '../initutils.c',
    '../initutils.h',
    '../file_utils.c',
    '../file_utils.h',
    '../lsm/apparmor.c',
    '../lsm/lsm.c',
    '../lsm/lsm.h',
    '../lsm/nop.c',
    '../lsm/selinux.c',
    '../lxcseccomp.h',
    '../lxclock.c',
    '../lxclock.h',
    '../macro.h',
    '../mainloop.c',
    '../mainloop.h',
    '../memory_utils.h',
    '../monitor.c',
    '../monitor.h',
    '../mount_utils.c',
    '../mount_utils.h',
    '../namespace.c',
    '../namespace.h',
    '../network.c',
    '../network.h',
    '../nl.c',
    '../nl.h',
    '../parse.c',
    '../parse.h',
    '../process_utils.c',
    '../process_utils.h',
    '../ringbuf.c',
    '../ringbuf.h',
    '../seccomp.c',
    '../start.c',
    '../start.h',
    '../state.c',
    '../state.h',
    '../storage/btrfs.c',
    '../storage/btrfs.h',
    '../storage/dir.c',
    '../storage/dir.h',
    '../storage/loop.c',
    '../storage/loop.h',
    '../storage/lvm.c',
    '../storage/lvm.h',
    '../storage/nbd.c',
    '../storage/nbd.h',
    '../storage/overlay.c',
    '../storage/overlay.h',
    '../storage/rbd.c',
    '../storage/rbd.h',
    '../storage/rsync.c',
    '../storage/rsync.h',
    '../storage/storage.c',
    '../storage/storage.h',
    '../storage/storage_utils.c',
    '../storage/storage_utils.h',
    '../storage/zfs.c',
    '../storage/zfs.h',
    '../string_utils.c',
    '../string_utils.h',
    '../sync.c',
    '../sync.h',
    '../terminal.c',
    '../terminal.h',
    '../utils.c',
    '../utils.h',
    '../uuid.c',
    '../uuid.h',
    '../log.h',
    '../log.c') + include_sources + netns_ifaddrs_sources

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

public_programs += executable(
    'lxc-autostart',
    tools_lxc_autostart_sources,
    include_directories: tools_liblxc_includes,
    dependencies: liblxc_dep,
    install: true)

public_programs += executable(
   'lxc-cgroup',
    tools_lxc_cgroup_sources,
    include_directories: tools_liblxc_includes,
    dependencies: liblxc_dep,
    install: true)

public_programs += executable(
   'lxc-checkpoint',
    tools_lxc_checkpoint_sources,
    include_directories: tools_liblxc_includes,
    dependencies: liblxc_dep,
    install: true)

public_programs += executable(
    'lxc-config',
    tools_lxc_config_sources,
    include_directories: tools_liblxc_includes,
    dependencies: liblxc_dep,
    install: true)

public_programs += executable(
    'lxc-console',
    tools_lxc_console_sources,
    include_directories: tools_liblxc_includes,
    dependencies: liblxc_dep,
    install: true)

public_programs += executable(
    'lxc-copy',
    tools_lxc_copy_sources,
    include_directories: tools_liblxc_includes,
    dependencies: liblxc_dep,
    install: true)

public_programs += executable(
    'lxc-create',
    tools_lxc_create_sources,
    include_directories: tools_liblxc_includes,
    dependencies: liblxc_dep,
    install: true)

public_programs += executable(
    'lxc-destroy',
    tools_lxc_destroy_sources,
    include_directories: tools_liblxc_includes,
    dependencies: liblxc_dep,
    install: true)

public_programs += executable(
    'lxc-device',
    tools_lxc_device_sources,
    include_directories: tools_liblxc_includes,
    dependencies: liblxc_dep,
    install: true)

public_programs += executable(
    'lxc-execute',
    tools_lxc_execute_sources,
    include_directories: tools_liblxc_includes,
    dependencies: liblxc_dep,
    install: true)

public_programs += executable(
    'lxc-freeze',
    tools_lxc_freeze_sources,
    include_directories: tools_liblxc_includes,
    dependencies: liblxc_dep,
    install: true)

public_programs += executable(
    'lxc-info',
    tools_lxc_info_sources,
    include_directories: tools_liblxc_includes,
    dependencies: liblxc_dep,
    install: true)

public_programs += executable(
    'lxc-ls',
    tools_lxc_ls_sources,
    include_directories: tools_liblxc_includes,
    dependencies: liblxc_dep,
    install: true)

public_programs += executable(
    'lxc-monitor',
    tools_lxc_monitor_sources,
    include_directories: tools_liblxc_includes,
    dependencies: liblxc_dep,
    install: true)

public_programs += executable(
    'lxc-snapshot',
    tools_lxc_snapshot_sources,
    include_directories: tools_liblxc_includes,
    dependencies: liblxc_dep,
    install: true)

public_programs += executable(
    'lxc-start',
    tools_lxc_start_sources,
    include_directories: tools_liblxc_includes,
    dependencies: liblxc_dep,
    install: true)

public_programs += executable(
    'lxc-stop',
    tools_lxc_stop_sources,
    include_directories: tools_liblxc_includes,
    dependencies: liblxc_dep,
    install: true)

public_programs += executable(
    'lxc-top',
    tools_lxc_top_sources,
    include_directories: tools_liblxc_includes,
    dependencies: liblxc_dep,
    install: true)

public_programs += executable(
    'lxc-unfreeze',
    tools_lxc_unfreeze_sources,
    include_directories: tools_liblxc_includes,
    dependencies: liblxc_dep,
    install: true)

public_programs += executable(
    'lxc-unshare',
    tools_lxc_unshare_sources,
    include_directories: tools_liblxc_includes,
    dependencies: liblxc_dep,
    install: true)

public_programs += executable(
    'lxc-wait',
    tools_lxc_wait_sources,
    include_directories: tools_liblxc_includes,
    dependencies: liblxc_dep,
    install: true)

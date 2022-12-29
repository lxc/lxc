# SPDX-License-Identifier: LGPL-2.1-or-later

liblxcfs_attach_file = configure_file(
    configuration: dummy_config_data,
    input: 'attach_options.h',
    output: 'attach_options.h',
    install: true,
    install_dir: lxcinclude
)

liblxcfs_header_file = configure_file(
    configuration: dummy_config_data,
    input: 'lxccontainer.h',
    output: 'lxccontainer.h',
    install: true,
    install_dir: lxcinclude
)

liblxcfs_version_file = configure_file(
    configuration: version_data,
    input: 'version.h.in',
    output: 'version.h',
    install: true,
    install_dir: lxcinclude
)

liblxc_sources = files(
    'cgroups/cgfsng.c',
    'cgroups/cgroup.c',
    'cgroups/cgroup.h',
    'cgroups/cgroup2_devices.c',
    'cgroups/cgroup2_devices.h',
    'cgroups/cgroup_utils.c',
    'cgroups/cgroup_utils.h',
    'lsm/lsm.c',
    'lsm/lsm.h',
    'lsm/nop.c',
    'storage/btrfs.c',
    'storage/btrfs.h',
    'storage/dir.c',
    'storage/dir.h',
    'storage/loop.c',
    'storage/loop.h',
    'storage/lvm.c',
    'storage/lvm.h',
    'storage/nbd.c',
    'storage/nbd.h',
    'storage/overlay.c',
    'storage/overlay.h',
    'storage/rbd.c',
    'storage/rbd.h',
    'storage/rsync.c',
    'storage/rsync.h',
    'storage/storage.c',
    'storage/storage.h',
    'storage/storage_utils.c',
    'storage/storage_utils.h',
    'storage/zfs.c',
    'storage/zfs.h',
    'af_unix.c',
    'af_unix.h',
    'api_extensions.h',
    'attach.c',
    'attach.h',
    'attach_options.h',
    'caps.c',
    'caps.h',
    'commands.c',
    'commands.h',
    'commands_utils.c',
    'commands_utils.h',
    'compiler.h',
    'conf.c',
    'conf.h',
    'confile.c',
    'confile.h',
    'confile_utils.c',
    'confile_utils.h',
    'criu.c',
    'criu.h',
    'error.c',
    'error.h',
    'error_utils.h',
    'execute.c',
    'file_utils.c',
    'file_utils.h',
    'freezer.c',
    'hlist.h',
    'initutils.c',
    'initutils.h',
    'list.h',
    'log.c',
    'log.h',
    'lxc.h',
    'lxccontainer.c',
    'lxccontainer.h',
    'lxclock.c',
    'lxclock.h',
    'lxcseccomp.h',
    'macro.h',
    'mainloop.c',
    'mainloop.h',
    'memory_utils.h',
    'monitor.c',
    'monitor.h',
    'mount_utils.c',
    'mount_utils.h',
    'namespace.c',
    'namespace.h',
    'network.c',
    'network.h',
    'nl.c',
    'nl.h',
    'parse.c',
    'parse.h',
    'open_utils.h',
    'process_utils.c',
    'process_utils.h',
    'rexec.c',
    'rexec.h',
    'ringbuf.c',
    'ringbuf.h',
    'rtnl.c',
    'rtnl.h',
    'start.c',
    'start.h',
    'state.c',
    'state.h',
    'string_utils.c',
    'string_utils.h',
    'sync.c',
    'sync.h',
    'syscall_numbers.h',
    'syscall_wrappers.h',
    'terminal.c',
    'terminal.h',
    'utils.c',
    'utils.h',
    'uuid.c',
    'uuid.h')

if want_apparmor and libapparmor.found()
    liblxc_sources += files('lsm/apparmor.c')
endif

if want_seccomp and libseccomp.found()
    liblxc_sources += files('seccomp.c')
endif

if want_selinux and libselinux.found()
    liblxc_sources += files('lsm/selinux.c')
endif

liblxc_static = static_library(
    'lxc',
    liblxc_sources + include_sources + netns_ifaddrs_sources,
    install: true,
    include_directories: liblxc_includes,
    dependencies: [threads] + liblxc_dependency_headers,
    c_args: '-fvisibility=default')

lxc_functions = configure_file(
    configuration: conf,
    input: 'lxc.functions.in',
    output: 'lxc.functions',
    install: true,
    install_dir: lxcdatadir)

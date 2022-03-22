# SPDX-License-Identifier: LGPL-2.1-or-later

tests_liblxc_includes = include_directories(
	'.',
	'../lxc/',
	'../lxc/cgroups',
	'../lxc/lsm',
	'../lxc/storage',
	'../include',
	'../../')

tests_common_sources = files(
	'../lxc/af_unix.c',
	'../lxc/af_unix.h',
	'../lxc/attach_options.h',
	'../lxc/caps.c',
	'../lxc/caps.h',
	'../lxc/commands.c',
	'../lxc/commands.h',
	'../lxc/commands_utils.c',
	'../lxc/commands_utils.h',
	'../lxc/compiler.h',
	'../lxc/conf.c',
	'../lxc/conf.h',
	'../lxc/confile.c',
	'../lxc/confile.h',
	'../lxc/confile_utils.c',
	'../lxc/confile_utils.h',
	'../lxc/cgroups/cgfsng.c',
	'../lxc/cgroups/cgroup.c',
	'../lxc/cgroups/cgroup.h',
	'../lxc/cgroups/cgroup2_devices.c',
	'../lxc/cgroups/cgroup2_devices.h',
	'../lxc/cgroups/cgroup_utils.c',
	'../lxc/cgroups/cgroup_utils.h',
	'../lxc/error.c',
	'../lxc/error.h',
	'../lxc/initutils.c',
	'../lxc/initutils.h',
	'../lxc/file_utils.c',
	'../lxc/file_utils.h',
	'../lxc/lsm/apparmor.c',
	'../lxc/lsm/lsm.c',
	'../lxc/lsm/lsm.h',
	'../lxc/lsm/nop.c',
	'../lxc/lsm/selinux.c',
	'../lxc/lxcseccomp.h',
	'../lxc/lxclock.c',
	'../lxc/lxclock.h',
	'../lxc/macro.h',
	'../lxc/mainloop.c',
	'../lxc/mainloop.h',
	'../lxc/memory_utils.h',
	'../lxc/monitor.c',
	'../lxc/monitor.h',
	'../lxc/mount_utils.c',
	'../lxc/mount_utils.h',
	'../lxc/namespace.c',
	'../lxc/namespace.h',
	'../lxc/network.c',
	'../lxc/network.h',
	'../lxc/nl.c',
	'../lxc/nl.h',
	'../lxc/parse.c',
	'../lxc/parse.h',
	'../lxc/process_utils.c',
	'../lxc/process_utils.h',
	'../lxc/ringbuf.c',
	'../lxc/ringbuf.h',
	'../lxc/seccomp.c',
	'../lxc/start.c',
	'../lxc/start.h',
	'../lxc/state.c',
	'../lxc/state.h',
	'../lxc/storage/btrfs.c',
	'../lxc/storage/btrfs.h',
	'../lxc/storage/dir.c',
	'../lxc/storage/dir.h',
	'../lxc/storage/loop.c',
	'../lxc/storage/loop.h',
	'../lxc/storage/lvm.c',
	'../lxc/storage/lvm.h',
	'../lxc/storage/nbd.c',
	'../lxc/storage/nbd.h',
	'../lxc/storage/overlay.c',
	'../lxc/storage/overlay.h',
	'../lxc/storage/rbd.c',
	'../lxc/storage/rbd.h',
	'../lxc/storage/rsync.c',
	'../lxc/storage/rsync.h',
	'../lxc/storage/storage.c',
	'../lxc/storage/storage.h',
	'../lxc/storage/storage_utils.c',
	'../lxc/storage/storage_utils.h',
	'../lxc/storage/zfs.c',
	'../lxc/storage/zfs.h',
	'../lxc/string_utils.c',
	'../lxc/string_utils.h',
	'../lxc/sync.c',
	'../lxc/sync.h',
	'../lxc/terminal.c',
	'../lxc/terminal.h',
	'../lxc/utils.c',
	'../lxc/utils.h',
	'../lxc/uuid.c',
	'../lxc/uuid.h',
	'../lxc/log.h',
	'../lxc/log.c') + include_sources + netns_ifaddrs_sources

test_programs += executable(
                'lxc-test-arch-parse',
		files('arch_parse.c') + tests_common_sources,
                include_directories : tests_liblxc_includes,
		dependencies : liblxc_dep,
		install: false,
		build_by_default: want_tests != false)

test_programs += executable(
                'lxc-test-apparmor',
		files('aa.c') + tests_common_sources,
                include_directories : tests_liblxc_includes,
		dependencies : liblxc_dep,
		install: false,
		build_by_default: want_tests != false)

test_programs += executable(
                'lxc-test-api-reboot',
		files('api_reboot.c') + tests_common_sources,
                include_directories : tests_liblxc_includes,
		dependencies : liblxc_dep,
		install: false,
		build_by_default: want_tests != false)

test_programs += executable(
                'lxc-test-attach',
		files('attach.c') + tests_common_sources,
                include_directories : tests_liblxc_includes,
		dependencies : liblxc_dep,
		install: false,
		build_by_default: want_tests != false)

test_programs += executable(
                'lxc-test-basic',
		files('basic.c') + tests_common_sources,
                include_directories : tests_liblxc_includes,
		dependencies : liblxc_dep,
		install: false,
		build_by_default: want_tests != false)

test_programs += executable(
                'lxc-test-capabilities',
		files('capabilities.c') + tests_common_sources,
                include_directories : tests_liblxc_includes,
		dependencies : liblxc_dep,
		install: false,
		build_by_default: want_tests != false)

test_programs += executable(
                'lxc-test-cgpath',
		files('cgpath.c') + tests_common_sources,
                include_directories : tests_liblxc_includes,
		dependencies : liblxc_dep,
		install: false,
		build_by_default: want_tests != false)

test_programs += executable(
                'lxc-test-clonetest',
		files('clonetest.c') + tests_common_sources,
                include_directories : tests_liblxc_includes,
		dependencies : liblxc_dep,
		install: false,
		build_by_default: want_tests != false)

test_programs += executable(
                'lxc-test-concurrent',
		files('concurrent.c') + tests_common_sources,
                include_directories : tests_liblxc_includes,
		dependencies : liblxc_dep,
		install: false,
		build_by_default: want_tests != false)

test_programs += executable(
                'lxc-test-config-jump-table',
		files('config_jump_table.c') + tests_common_sources,
                include_directories : tests_liblxc_includes,
		dependencies : liblxc_dep,
		install: false,
		build_by_default: want_tests != false)

test_programs += executable(
                'lxc-test-console',
		files('console.c') + tests_common_sources,
                include_directories : tests_liblxc_includes,
		dependencies : liblxc_dep,
		install: false,
		build_by_default: want_tests != false)

test_programs += executable(
                'lxc-test-console-log',
		files('console_log.c') + tests_common_sources,
                include_directories : tests_liblxc_includes,
		dependencies : liblxc_dep,
		install: false,
		build_by_default: want_tests != false)

test_programs += executable(
                'lxc-test-containertests',
		files('containertests.c') + tests_common_sources,
                include_directories : tests_liblxc_includes,
		dependencies : liblxc_dep,
		install: false,
		build_by_default: want_tests != false)

test_programs += executable(
                'lxc-test-createtest',
		files('createtest.c') + tests_common_sources,
                include_directories : tests_liblxc_includes,
		dependencies : liblxc_dep,
		install: false,
		build_by_default: want_tests != false)

test_programs += executable(
                'lxc-test-criu-check-feature',
		files('criu_check_feature.c') + tests_common_sources,
                include_directories : tests_liblxc_includes,
		dependencies : liblxc_dep,
		install: false,
		build_by_default: want_tests != false)

test_programs += executable(
                'lxc-test-cve-2019-5736',
		files('cve-2019-5736.c') + tests_common_sources,
                include_directories : tests_liblxc_includes,
		dependencies : liblxc_dep,
		install: false,
		build_by_default: want_tests != false)

test_programs += executable(
                'lxc-test-destroytest',
		files('destroytest.c') + tests_common_sources,
                include_directories : tests_liblxc_includes,
		dependencies : liblxc_dep,
		install: false,
		build_by_default: want_tests != false)

test_programs += executable(
                'lxc-test-device-add-remove',
		files('device_add_remove.c') + tests_common_sources,
                include_directories : tests_liblxc_includes,
		dependencies : liblxc_dep,
		install: false,
		build_by_default: want_tests != false)

test_programs += executable(
                'lxc-test-fuzz-lxc-cgroup-init',
		files('fuzz-lxc-cgroup-init.c',
		      'dummy.cxx') + tests_common_sources,
		link_args : ['-static'],
                include_directories : tests_liblxc_includes,
		install: false,
		build_by_default: want_tests != false)

test_programs += executable(
                'lxc-test-fuzz-lxc-config-read',
		files('fuzz-lxc-config-read.c',
		      'dummy.cxx') + tests_common_sources,
		link_args : ['-static'],
                include_directories : tests_liblxc_includes,
		install: false,
		build_by_default: want_tests != false)

test_programs += executable(
                'lxc-test-fuzz-lxc-define-load',
		files('fuzz-lxc-define-load.c',
		      'dummy.cxx') + tests_common_sources,
		link_args : ['-static'],
                include_directories : tests_liblxc_includes,
		install: false,
		build_by_default: want_tests != false)

test_programs += executable(
                'lxc-test-get-item',
		files('get_item.c') + tests_common_sources,
                include_directories : tests_liblxc_includes,
		dependencies : liblxc_dep,
		install: false,
		build_by_default: want_tests != false)

test_programs += executable(
                'lxc-test-getkeys',
		files('getkeys.c') + tests_common_sources,
                include_directories : tests_liblxc_includes,
		dependencies : liblxc_dep,
		install: false,
		build_by_default: want_tests != false)

test_programs += executable(
                'lxc-test-list',
		files('list.c') + tests_common_sources,
                include_directories : tests_liblxc_includes,
		dependencies : liblxc_dep,
		install: false,
		build_by_default: want_tests != false)

test_programs += executable(
                'lxc-test-locktests',
		files('locktests.c') + tests_common_sources,
                include_directories : tests_liblxc_includes,
		dependencies : liblxc_dep,
		install: false,
		build_by_default: want_tests != false)

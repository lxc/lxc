# SPDX-License-Identifier: LGPL-2.1-or-later

tests_common_sources = liblxc_sources + include_sources + netns_ifaddrs_sources

if want_tests
    test_programs += executable(
        'lxc-test-arch-parse',
        files('arch_parse.c') + tests_common_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    test_programs += executable(
        'lxc-test-apparmor',
        files('aa.c') + tests_common_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    test_programs += executable(
        'lxc-test-api-reboot',
        files('api_reboot.c') + tests_common_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    test_programs += executable(
        'lxc-test-attach',
        files('attach.c') + tests_common_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    test_programs += executable(
        'lxc-test-basic',
        files('basic.c') + tests_common_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    test_programs += executable(
        'lxc-test-capabilities',
        files('capabilities.c') + tests_common_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    test_programs += executable(
        'lxc-test-cgpath',
        files('cgpath.c') + tests_common_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    test_programs += executable(
        'lxc-test-clonetest',
        files('clonetest.c') + tests_common_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    test_programs += executable(
        'lxc-test-concurrent',
        files('concurrent.c') + tests_common_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    test_programs += executable(
        'lxc-test-config-jump-table',
        files('config_jump_table.c') + tests_common_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    test_programs += executable(
        'lxc-test-console',
        files('console.c') + tests_common_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    test_programs += executable(
        'lxc-test-console-log',
        files('console_log.c') + tests_common_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    test_programs += executable(
        'lxc-test-containertests',
        files('containertests.c') + tests_common_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    test_programs += executable(
        'lxc-test-createtest',
        files('createtest.c') + tests_common_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    test_programs += executable(
        'lxc-test-criu-check-feature',
        files('criu_check_feature.c') + tests_common_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    test_programs += executable(
        'lxc-test-cve-2019-5736',
        files('cve-2019-5736.c') + tests_common_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    test_programs += executable(
        'lxc-test-destroytest',
        files('destroytest.c') + tests_common_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    test_programs += executable(
        'lxc-test-device-add-remove',
        files('device_add_remove.c') + tests_common_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    test_programs += executable(
        'lxc-test-get_item',
        files('get_item.c') + tests_common_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    test_programs += executable(
        'lxc-test-getkeys',
        files('getkeys.c') + tests_common_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    test_programs += executable(
        'lxc-test-list',
        files('list.c') + tests_common_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    test_programs += executable(
        'lxc-test-locktests',
        files('locktests.c') + tests_common_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    test_programs += executable(
        'lxc-test-utils',
        files('lxc-test-utils.c') + tests_common_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    test_programs += executable(
        'lxc-test-raw-clone',
        files('lxc_raw_clone.c') + tests_common_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    test_programs += executable(
        'lxc-test-lxcpath',
        files('lxcpath.c') + tests_common_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    test_programs += executable(
        'lxc-test-may-control',
        files('may_control.c') + tests_common_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    test_programs += executable(
        'lxc-test-mount-injection',
        files('mount_injection.c') + tests_common_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    test_programs += executable(
        'lxc-test-parse-config-file',
        files('parse_config_file.c') + tests_common_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    test_programs += executable(
        'lxc-test-proc-pid',
        files('proc_pid.c') + tests_common_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    test_programs += executable(
        'lxc-test-reboot',
        files('reboot.c') + tests_common_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    test_programs += executable(
        'lxc-test-rootfs-options',
        files('rootfs_options.c') + tests_common_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    test_programs += executable(
        'lxc-test-saveconfig',
        files('saveconfig.c') + tests_common_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    test_programs += executable(
        'lxc-test-share-ns',
        files('share_ns.c') + tests_common_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    test_programs += executable(
        'lxc-test-shortlived',
        files('shortlived.c') + tests_common_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    test_programs += executable(
        'lxc-test-shutdowntest',
        files('shutdowntest.c') + tests_common_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    test_programs += executable(
        'lxc-test-snapshot',
        files('snapshot.c') + tests_common_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    test_programs += executable(
        'lxc-test-startone',
        files('startone.c') + tests_common_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    test_programs += executable(
        'lxc-test-state-server',
        files('state_server.c') + tests_common_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    test_programs += executable(
        'lxc-test-sys-mixed',
        files('sys_mixed.c') + tests_common_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    test_programs += executable(
        'lxc-test-sysctls',
        files('sysctls.c') + tests_common_sources,
        include_directories: liblxc_includes,
        dependencies: liblxc_dep,
        install: true)

    test_programs += configure_file(
        configuration: dummy_config_data,
        install: true,
        install_dir: bindir,
        input: 'lxc-test-apparmor-generated',
        output: 'lxc-test-apparmor-generated')

    test_programs += configure_file(
        configuration: dummy_config_data,
        install: true,
        install_dir: bindir,
        input: 'lxc-test-apparmor-mount',
        output: 'lxc-test-apparmor-mount')

    test_programs += configure_file(
        configuration: dummy_config_data,
        install: true,
        install_dir: bindir,
        input: 'lxc-test-automount',
        output: 'lxc-test-automount')

    test_programs += configure_file(
        configuration: dummy_config_data,
        install: true,
        install_dir: bindir,
        input: 'lxc-test-autostart',
        output: 'lxc-test-autostart')

    test_programs += configure_file(
        configuration: dummy_config_data,
        install: true,
        install_dir: bindir,
        input: 'lxc-test-checkpoint-restore',
        output: 'lxc-test-checkpoint-restore')

    test_programs += configure_file(
        configuration: dummy_config_data,
        install: true,
        install_dir: bindir,
        input: 'lxc-test-cloneconfig',
        output: 'lxc-test-cloneconfig')

    test_programs += configure_file(
        configuration: dummy_config_data,
        install: true,
        install_dir: bindir,
        input: 'lxc-test-createconfig',
        output: 'lxc-test-createconfig')

    test_programs += configure_file(
        configuration: dummy_config_data,
        install: true,
        install_dir: bindir,
        input: 'lxc-test-exit-code',
        output: 'lxc-test-exit-code')

    test_programs += configure_file(
        configuration: dummy_config_data,
        install: true,
        install_dir: bindir,
        input: 'lxc-test-lxc-attach',
        output: 'lxc-test-lxc-attach')

    test_programs += configure_file(
        configuration: dummy_config_data,
        install: true,
        install_dir: bindir,
        input: 'lxc-test-no-new-privs',
        output: 'lxc-test-no-new-privs')

    test_programs += configure_file(
        configuration: dummy_config_data,
        install: true,
        install_dir: bindir,
        input: 'lxc-test-procsys',
        output: 'lxc-test-procsys')

    test_programs += configure_file(
        configuration: dummy_config_data,
        install: true,
        install_dir: bindir,
        input: 'lxc-test-rootfs',
        output: 'lxc-test-rootfs')

    test_programs += configure_file(
        configuration: dummy_config_data,
        install: true,
        install_dir: bindir,
        input: 'lxc-test-snapdeps',
        output: 'lxc-test-snapdeps')

    test_programs += configure_file(
        configuration: dummy_config_data,
        install: true,
        install_dir: bindir,
        input: 'lxc-test-symlink',
        output: 'lxc-test-symlink')

    test_programs += configure_file(
        configuration: dummy_config_data,
        install: true,
        install_dir: bindir,
        input: 'lxc-test-unpriv',
        output: 'lxc-test-unpriv')

    test_programs += configure_file(
        configuration: conf,
        install: true,
        install_dir: bindir,
        input: 'lxc-test-usernic.in',
        output: 'lxc-test-usernic')

    test_programs += configure_file(
        configuration: dummy_config_data,
        install: true,
        install_dir: bindir,
        input: 'lxc-test-usernsexec',
        output: 'lxc-test-usernsexec')
endif

if want_oss_fuzz
    test_programs += executable(
        'fuzz-lxc-cgroup-init',
        files('fuzz-lxc-cgroup-init.c') + tests_common_sources,
        include_directories: liblxc_includes,
        dependencies: [fuzzing_engine, oss_fuzz_dependencies],
        link_with: [liblxc_static],
        install: false,
        install_dir: bindir)

    test_programs += executable(
        'fuzz-lxc-config-read',
        files('fuzz-lxc-config-read.c') + tests_common_sources,
        include_directories: liblxc_includes,
        dependencies: [fuzzing_engine, oss_fuzz_dependencies],
        link_with: [liblxc_static],
        install: false,
        install_dir: bindir)

    test_programs += executable(
        'fuzz-lxc-define-load',
        files('fuzz-lxc-define-load.c') + tests_common_sources,
        include_directories: liblxc_includes,
        dependencies: [fuzzing_engine, oss_fuzz_dependencies],
        link_with: [liblxc_static],
        install: false,
        install_dir: bindir)
endif

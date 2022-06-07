# SPDX-License-Identifier: LGPL-2.1-or-later

pam_cgfs_sources = files(
    'pam_cgfs.c',
    '../file_utils.c',
    '../file_utils.h',
    '../macro.h',
    '../memory_utils.h',
    '../string_utils.c',
    '../string_utils.h') + include_sources

if want_pam_cgroup
    pam_cgfs = shared_module(
        'pam_cgfs',
        include_directories: liblxc_includes,
        sources: pam_cgfs_sources,
        dependencies: [pkgconfig_libs],
        name_prefix: '',
        install_mode: 'rw-r--r--', # 644
        install: true,
        install_dir: pam_security)
endif

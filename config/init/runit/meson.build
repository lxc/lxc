# SPDX-License-Identifier: LGPL-2.1+

if 'runit' in init_script
    runit_service_dir = get_option('runit-servicedir')
    if runit_service_dir == ''
        runit_service_dir = join_paths(sysconfdir, 'sv')
    endif

    subdir('lxc-containers')
    subdir('lxc-net')
    subdir('lxc-monitord')
endif

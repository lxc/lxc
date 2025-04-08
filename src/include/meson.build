# SPDX-License-Identifier: LGPL-2.1+

include_sources = files(
    'bpf.h',
    'bpf_common.h')

netns_ifaddrs_sources = files(
    'netns_ifaddrs.c',
    'netns_ifaddrs.h')

if srcconf.get('HAVE_FEXECVE') == 0
    include_sources += files(
        'fexecve.c',
        'fexecve.h')
endif


if srcconf.get('HAVE_GETGRGID_R') == 0
    include_sources += files(
        'getgrgid_r.c',
        'getgrgid_r.h')
endif

if srcconf.get('HAVE_STRLCPY') == 0
    include_sources += files(
        'strlcpy.c',
        'strlcpy.h')
endif

if srcconf.get('HAVE_STRLCAT') == 0
    include_sources += files(
        'strlcat.c',
        'strlcat.h')
endif

if srcconf.get('HAVE_STRCHRNUL') == 0
    include_sources += files(
        'strchrnul.c',
        'strchrnul.h')
endif

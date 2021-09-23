# SPDX-License-Identifier: LGPL-2.1-or-later

include_sources = files(
	'bpf.h',
	'bpf_common.h')

netns_ifaddrs_sources = files(
	'netns_ifaddrs.c',
	'netns_ifaddrs.h')

if conf.get('HAVE_GETLINE') == 0
	include_sources += files(
		'getline.c',
		'getline.h')
endif

if conf.get('HAVE_FEXECVE') == 0
	include_sources += files(
		'fexecve.c',
		'fexecve.h')
endif


if conf.get('HAVE_GETGRGID_R') == 0
	include_sources += files(
		'getgrgid_r.c',
		'getgrgid_r.h')
endif

if conf.get('HAVE_HASMNTOPT') == 0 or conf.get('HAVE_SETMNTENT') == 0 or conf.get('HAVE_ENDMNTENT') == 0
	include_sources += files(
		'lxcmntent.c',
		'lxcmntent.h')
endif

if conf.get('HAVE_STRLCPY') == 0
	include_sources += files(
		'strlcpy.c',
		'strlcpy.h')
endif

if conf.get('HAVE_STRLCAT') == 0
	include_sources += files(
		'strlcat.c',
		'strlcat.h')
endif

if conf.get('HAVE_STRCHRNUL') == 0
	include_sources += files(
		'strchrnul.c',
		'strchrnul.h')
endif

if conf.get('HAVE_OPENPTY') == 0
	include_sources += files(
		'openpty.c',
		'openpty.h')
endif

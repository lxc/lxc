# SPDX-License-Identifier: LGPL-2.1-or-later

include_sources = files(
	'bpf.h',
	'bpf_common.h')

netns_ifaddrs_sources = files(
	'netns_ifaddrs.c',
	'netns_ifaddrs.h')

if cc.has_function('getline', prefix : '#include <stdio.h>', args : '-D_GNU_SOURCE')
	conf.set10('HAVE_GETLINE', true)
else
	include_sources += files(
		'getline.c',
		'getline.h')
endif

if cc.has_function('fexecve', prefix : '#include <unistd.h>', args : '-D_GNU_SOURCE')
	conf.set10('HAVE_FEXECVE', true)
else
	include_sources += files(
		'fexecve.c',
		'fexecve.h')
endif


getgr_headers = '''
#include <sys/types.h>
#include <grp.h>
'''

if cc.has_function('getgrgid_r', prefix : getgr_headers, args : '-D_GNU_SOURCE')
	conf.set10('HAVE_GETGRGID_R', true)
else
	include_sources += files(
		'getgrgid_r.c',
		'getgrgid_r.h')
endif

mntent_headers = '''
#include <stdio.h>
#include <mntent.h>
'''

have_hasmntopt = cc.has_function('hasmntopt', prefix : mntent_headers, args : '-D_GNU_SOURCE')
if have_hasmntopt
	conf.set10('HAVE_HASMNTOPT', true)
endif

have_setmntent = cc.has_function('setmntent', prefix : mntent_headers, args : '-D_GNU_SOURCE')
if have_setmntent
	conf.set10('HAVE_SETMNTENT', true)
endif

have_endmntent = cc.has_function('endmntent', prefix : mntent_headers, args : '-D_GNU_SOURCE')
if have_endmntent
	conf.set10('HAVE_ENDMNTENT', true)
endif

if have_hasmntopt == false or have_setmntent == false or have_endmntent == false
	include_sources += files(
		'lxcmntent.c',
		'lxcmntent.h')
endif

if cc.has_function('strlcpy', prefix : '#include <string.h>', args : '-D_GNU_SOURCE')
	conf.set10('HAVE_STRLCPY', true)
else
	include_sources += files(
		'strlcpy.c',
		'strlcpy.h')
endif

if cc.has_function('strlcat', prefix : '#include <string.h>', args : '-D_GNU_SOURCE')
	conf.set10('HAVE_STRLCAT', true)
else
	include_sources += files(
		'strlcat.c',
		'strlcat.h')
endif

if cc.has_function('strchrnul', prefix : '#include <string.h>', args : '-D_GNU_SOURCE')
	conf.set10('HAVE_STRCHRNUL', true)
else
	include_sources += files(
		'strchrnul.c',
		'strchrnul.h')
endif

if cc.has_function('openpty', prefix : '#include <pty.h>', args : '-D_GNU_SOURCE')
	conf.set10('HAVE_OPENPTY', true)
else
	include_sources += files(
		'openpty.c',
		'openpty.h')
endif

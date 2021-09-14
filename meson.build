# SPDX-License-Identifier: LGPL-2.1-or-later

project('lxc', 'c',
        version : '4.0.0',
        license : 'LGPLv2+',
        default_options: [
		'b_colorout=always',
		'b_asneeded=true',
		'b_pie=true',
                'c_std=gnu11',
                'warning_level=2',
        ],
        meson_version : '>= 0.46',
       )

liblxc_version = '4.0.0'

conf = configuration_data()
conf.set_quoted('PROJECT_URL', 'https://linuxcontainers.org/lxc/introduction/')
conf.set('PROJECT_VERSION',    meson.project_version(),
         description : 'Numerical project version (used where a simple number is expected)')
conf.set('_GNU_SOURCE', true)
conf.set('__STDC_FORMAT_MACROS', true)

version_data = configuration_data()
version_data.set('LXC_VERSION_MAJOR', '4')
version_data.set('LXC_VERSION_MINOR', '0')
version_data.set('LXC_VERSION_MICRO', '7')
version_data.set('LXC_ABI', '4.0.7')
version_data.set('LXC_DEVEL', '1')
version_data.set('LXC_VERSION', '4.0.7-devel')

project_source_root = meson.current_source_dir()
project_build_root = meson.current_build_dir()

# join_paths ignores the preceding arguments if an absolute component is
# encountered, so this should canonicalize various paths when they are
# absolute or relative.
prefixdir = get_option('prefix')
bindir = join_paths(prefixdir, get_option('bindir'))
datadir = join_paths(prefixdir, get_option('datadir'))
docdir = join_paths(prefixdir, get_option('docdir'))
includedir = join_paths(prefixdir, get_option('includedir'))
libdir = join_paths(prefixdir, get_option('libdir'))
libexecdir = join_paths(prefixdir, get_option('libexecdir'))
localstatedir = join_paths('/', get_option('localstatedir'))
sbindir = join_paths(prefixdir, get_option('sbindir'))
sysconfdir = join_paths(prefixdir, get_option('sysconfdir'))

apparmorcachedir = get_option('apparmor-cache-dir')
cgrouppattern = get_option('cgroup-pattern')
globalconfig = get_option('global-config')

logpath = get_option('log-path')
lxcpathprefix = get_option('config-path')
rootfsmount = get_option('rootfs-mount-dir')
runtimepath = join_paths(prefixdir, get_option('runtime-path'))

conf.set_quoted('BINDIR',			bindir)
conf.set_quoted('DATADIR',			datadir)
conf.set_quoted('DOCDIR',			docdir)
conf.set_quoted('INCLUDEDIR',			includedir)
conf.set_quoted('LOCALSTATEDIR',		localstatedir)
conf.set_quoted('LIBDIR',			libdir)
conf.set_quoted('LIBEXECDIR',			libexecdir)
conf.set_quoted('SBINDIR',			sbindir)
conf.set_quoted('SYSCONFDIR',			sysconfdir)

conf.set_quoted('LXCINITDIR',			libexecdir)
conf.set_quoted('DEFAULT_CGROUP_PATTERN',	cgrouppattern)
conf.set_quoted('RUNTIME_PATH',			runtimepath)

lxcdefaultconfig = join_paths(sysconfdir, 'lxc/default.conf')
conf.set_quoted('LXC_DEFAULT_CONFIG',		lxcdefaultconfig)

lxcapparmorcachedir = join_paths(localstatedir, apparmorcachedir)
conf.set_quoted('APPARMOR_CACHE_DIR',		lxcapparmorcachedir)

lxcrootfsmount = join_paths(prefixdir, rootfsmount)
conf.set_quoted('LXCROOTFSMOUNT',		lxcrootfsmount)

lxcglobalconfig = join_paths(sysconfdir, globalconfig)
conf.set_quoted('LXC_GLOBAL_CONF',		lxcglobalconfig)

lxclogpath = join_paths(localstatedir, logpath)
conf.set_quoted('LOGPATH',			lxclogpath)

lxcpath = join_paths(localstatedir, lxcpathprefix)
conf.set_quoted('LXCPATH',			lxcpath)

lxctemplateconfig = join_paths(datadir, 'lxc/config')
conf.set_quoted('LXCTEMPLATECONFIG',		lxctemplateconfig)

lxctemplatedir = join_paths(datadir, 'lxc/templates')
conf.set_quoted('LXCTEMPLATEDIR',		lxctemplatedir)

lxchookdir = join_paths(datadir, 'lxc/hooks')
conf.set_quoted('LXCHOOKDIR',			lxchookdir)

lxchookbindir = join_paths(libexecdir, 'lxc/hooks')
conf.set_quoted('LXCBINHOOKDIR',		lxchookbindir)

# AS_AC_EXPAND(LXC_GENERATE_DATE, "$(date --utc --date=@${SOURCE_DATE_EPOCH:-$(date +%s)} '+%Y-%m-%d')")
# AS_AC_EXPAND(LXC_USERNIC_CONF, "$with_usernic_conf")
# AS_AC_EXPAND(LXC_USERNIC_DB, "$with_usernic_db")
# AS_AC_EXPAND(LXC_DISTRO_SYSCONF, "$distrosysconf")

cc = meson.get_compiler('c')
pkgconfig = import('pkgconfig')

possible_cc_flags = [
	'-Wvla',
	'-Wimplicit-fallthrough=5',
	'-Wcast-align',
	'-Wstrict-prototypes',
	'-fno-strict-aliasing',
	'-fstack-clash-protection',
	'-fstack-protector-strong',
	'--param=ssp-buffer-size=4',
	'--mcet -fcf-protection',
	'-Werror=implicit-function-declaration',
	'-Wlogical-op',
	'-Wmissing-include-dirs',
	'-Wold-style-definition',
	'-Winit-self',
	'-Wunused-but-set-variable',
	'-Wno-unused-parameter',
	'-Wfloat-equal',
	'-Wsuggest-attribute=noreturn',
	'-Werror=return-type',
	'-Werror=incompatible-pointer-types',
	'-Wformat=2',
	'-Wshadow',
	'-Wendif-labels',
	'-Werror=overflow',
	'-fdiagnostics-show-option',
	'-Werror=shift-count-overflow',
	'-Werror=shift-overflow=2',
	'-Wdate-time',
	'-Wnested-externs',
	'-fasynchronous-unwind-tables',
	'-fexceptions',
	'-Warray-bounds',
	'-Wrestrict',
	'-Wreturn-local-addr',
	'-fsanitize=cfi',
	'-Wstringop-overflow',
]

possible_link_flags = [
	'-Wl,--gc-sections',
	'-Wl,-z,relro',
	'-Wl,-z,now',
	'-Wl,-fuse-ld=gold',
]

if meson.version().version_compare('>=0.46')
	add_project_link_arguments(cc.get_supported_link_arguments(possible_link_flags), language : 'c')
else
	add_project_link_arguments(possible_link_flags, language : 'c')
endif

add_project_arguments(cc.get_supported_arguments(possible_cc_flags), language : 'c')

foreach header : ['sys/resource.h',
                  'sys/memfd.h',
                  'sys/personality.h',
                  'sys/signalfd.h',
                  'sys/timerfd.h',
                  'pty.h',
                  'utmpx.h',
                 ]

        conf.set10('HAVE_' + header.underscorify().to_upper(),
                   cc.has_header(header))
endforeach

decl_headers = '''
#include <uchar.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/openat2.h>
#include <linux/sched.h>
'''

foreach decl : [
                '__aligned_u64',
                'struct mount_attr',
                'struct open_how',
                'struct clone_args',
               ]

        # We get -1 if the size cannot be determined
        if cc.sizeof(decl, prefix : decl_headers, args : '-D_GNU_SOURCE') > 0
		conf.set10('HAVE_' + decl.underscorify().to_upper(), true)
	endif
endforeach

foreach ident : [
        ['memfd_create',      '''#include <sys/mman.h>'''],
        ['gettid',            '''#include <sys/types.h>
                                 #include <unistd.h>'''],
        ['pivot_root',        '''#include <stdlib.h>
                                 #include <unistd.h>'''],     # no known header declares pivot_root
        ['setns',             '''#include <sched.h>'''],
        ['renameat2',         '''#include <stdio.h>
                                 #include <fcntl.h>'''],
        ['kcmp',              '''#include <linux/kcmp.h>'''],
        ['keyctl',            '''#include <sys/types.h>
                                 #include <keyutils.h>'''],
        ['bpf',               '''#include <sys/syscall.h>
                                 #include <unistd.h>'''],
        ['statx',             '''#include <sys/types.h>
                                 #include <sys/stat.h>
                                 #include <unistd.h>'''],
        ['pidfd_send_signal', '''#include <stdlib.h>
                                 #include <unistd.h>
                                 #include <signal.h>
                                 #include <sys/wait.h>'''],
        ['pidfd_open',        '''#include <stdlib.h>
                                 #include <unistd.h>
                                 #include <signal.h>
                                 #include <sys/wait.h>'''],
        ['execveat',          '''#include <unistd.h>'''],
        ['close_range',       '''#include <unistd.h>'''],
        ['mount_setattr',     '''#include <sys/mount.h>'''],
        ['move_mount',        '''#include <sys/mount.h>'''],
        ['open_tree',         '''#include <sys/mount.h>'''],
        ['strlcpy',	      '''#include <string.h>'''],
        ['strlcat',	      '''#include <string.h>'''],
        ['sethostname',	      '''#include <unistd.h>'''],
        ['faccessat',         '''#include <fcntl.h>
                                 #include <unistd.h>'''],
        ['unshare',	      '''#include <sched.h>'''],
        ['prlimit',	      '''#include <sys/time.h>
                               #include <sys/resource.h>'''],
        ['prlimit64',	      '''#include <sys/time.h>
                               #include <sys/resource.h>'''],
]

        if cc.has_function(ident[0], prefix : ident[1], args : '-D_GNU_SOURCE')
		conf.set10('HAVE_' + ident[0].to_upper(), true)
	endif
endforeach

threads = dependency('threads')
libseccomp = dependency('libseccomp')
if libseccomp.found()
	conf.set10('HAVE_SECCOMP', libseccomp.found())

	if libseccomp.version().version_compare('>=2.5.0')
		# https://github.com/seccomp/libseccomp/commit/dead12bc788b259b148cc4d93b970ef0bd602b1a
		conf.set10('HAVE_DECL_SECCOMP_NOTIFY_FD', true)
	endif

	if libseccomp.version().version_compare('>=2.0.0')
		# https://github.com/seccomp/libseccomp/commit/6220c8c0fc479d97b6d3e3166a4e46fbfe25a3c0
		conf.set10('HAVE_DECL_SECCOMP_SYSCALL_RESOLVE_NAME_ARCH', true)
	endif

	seccomp_headers = '''
	#include <seccomp.h>
	'''
	foreach decl : [
	                'scmp_filter_ctx',
	                'struct seccomp_notif_sizes',
	                'struct clone_args',
	               ]

	        # We get -1 if the size cannot be determined
	        if cc.sizeof(decl, prefix : seccomp_headers, args : '-D_GNU_SOURCE') > 0
			conf.set10('HAVE_' + decl.underscorify().to_upper(), true)
		endif
	endforeach
endif

libselinux = dependency('libselinux', required : false)
if libselinux.found()
	conf.set10('HAVE_SELINUX', libselinux.found())
endif

libapparmor = dependency('libapparmor', required : false)
if libapparmor.found()
	conf.set10('HAVE_APPARMOR', libapparmor.found())
endif

libopenssl = dependency('openssl', required : false)
if libopenssl.found()
	conf.set10('HAVE_OPENSSL', libopenssl.found())
endif

libcap = dependency('libcap', required : false)
if not libcap.found()
        # Compat with Ubuntu 14.04 which ships libcap w/o .pc file
        libcap = cc.find_library('cap', required : false)
endif

if libcap.found()
	conf.set10('HAVE_LIBCAP', libcap.found())
endif

basic_includes = include_directories(
	'src',
	'src/include',
	'.')

liblxc_includes = [basic_includes, include_directories(
        'src/lxc/cgroups',
        'src/lxc/lsm',
        'src/lxc/storage')]

add_project_arguments('-include', 'config.h', language : 'c')

subdir('src/include')
subdir('src/lxc')
subdir('src/lxc/tools')

config_h = configure_file(
        output : 'config.h',
        configuration : conf)

liblxc = shared_library(
        'lxc',
        version : liblxc_version,
        include_directories : tools_liblxc_includes,
        link_args : ['-DPIC'],
        c_args : ['-DPIC'],
        link_whole : [liblxc_static],
        dependencies : [threads,
			libseccomp,
			libcap,
			libopenssl,
			libselinux,
			libapparmor],
        install : true)

liblxc_dep = declare_dependency(
		link_with: liblxc,
		dependencies : [threads,
				libseccomp,
				libcap,
				libopenssl,
				libselinux,
				libapparmor])

public_programs = []

public_programs += executable(
                'lxc-autostart',
		tools_lxc_autostart_sources,
                include_directories : tools_liblxc_includes,
		dependencies : liblxc_dep,
                install : true)

public_programs += executable(
                'lxc-cgroup',
		tools_lxc_cgroup_sources,
                include_directories : tools_liblxc_includes,
		dependencies : liblxc_dep,
                install : true)

public_programs += executable(
                'lxc-checkpoint',
		tools_lxc_checkpoint_sources,
                include_directories : tools_liblxc_includes,
		dependencies : liblxc_dep,
                install : true)

public_programs += executable(
                'lxc-config',
		tools_lxc_config_sources,
                include_directories : tools_liblxc_includes,
		dependencies : liblxc_dep,
                install : true)

public_programs += executable(
                'lxc-console',
		tools_lxc_console_sources,
                include_directories : tools_liblxc_includes,
		dependencies : liblxc_dep,
                install : true)

public_programs += executable(
                'lxc-copy',
		tools_lxc_copy_sources,
                include_directories : tools_liblxc_includes,
		dependencies : liblxc_dep,
                install : true)

public_programs += executable(
                'lxc-create',
		tools_lxc_create_sources,
                include_directories : tools_liblxc_includes,
		dependencies : liblxc_dep,
                install : true)

public_programs += executable(
                'lxc-destroy',
		tools_lxc_destroy_sources,
                include_directories : tools_liblxc_includes,
		dependencies : liblxc_dep,
                install : true)

public_programs += executable(
                'lxc-device',
		tools_lxc_device_sources,
                include_directories : tools_liblxc_includes,
		dependencies : liblxc_dep,
                install : true)

public_programs += executable(
                'lxc-execute',
		tools_lxc_execute_sources,
                include_directories : tools_liblxc_includes,
		dependencies : liblxc_dep,
                install : true)

public_programs += executable(
                'lxc-freeze',
		tools_lxc_freeze_sources,
                include_directories : tools_liblxc_includes,
		dependencies : liblxc_dep,
                install : true)

public_programs += executable(
                'lxc-info',
		tools_lxc_info_sources,
                include_directories : tools_liblxc_includes,
		dependencies : liblxc_dep,
                install : true)

public_programs += executable(
                'lxc-ls',
		tools_lxc_ls_sources,
                include_directories : tools_liblxc_includes,
		dependencies : liblxc_dep,
                install : true)

public_programs += executable(
                'lxc-monitor',
		tools_lxc_monitor_sources,
                include_directories : tools_liblxc_includes,
		dependencies : liblxc_dep,
                install : true)

public_programs += executable(
                'lxc-snapshot',
		tools_lxc_snapshot_sources,
                include_directories : tools_liblxc_includes,
		dependencies : liblxc_dep,
                install : true)

public_programs += executable(
                'lxc-start',
		tools_lxc_start_sources,
                include_directories : tools_liblxc_includes,
		dependencies : liblxc_dep,
                install : true)

public_programs += executable(
                'lxc-stop',
		tools_lxc_stop_sources,
                include_directories : tools_liblxc_includes,
		dependencies : liblxc_dep,
                install : true)

public_programs += executable(
                'lxc-top',
		tools_lxc_top_sources,
                include_directories : tools_liblxc_includes,
		dependencies : liblxc_dep,
                install : true)

public_programs += executable(
                'lxc-unfreeze',
		tools_lxc_unfreeze_sources,
                include_directories : tools_liblxc_includes,
		dependencies : liblxc_dep,
                install : true)

public_programs += executable(
                'lxc-unshare',
		tools_lxc_unshare_sources,
                include_directories : tools_liblxc_includes,
		dependencies : liblxc_dep,
                install : true)

public_programs += executable(
                'lxc-wait',
		tools_lxc_wait_sources,
                include_directories : tools_liblxc_includes,
		dependencies : liblxc_dep,
                install : true)

status = [
        '@0@ @1@'.format(meson.project_name(), meson.project_version()),

        'Meson version:			@0@'.format(meson.version()),

        'prefix directory:		@0@'.format(prefixdir),
        'bin directory:			@0@'.format(bindir),
        'data directory:		@0@'.format(datadir),
        'doc directory:			@0@'.format(docdir),
        'include directory:		@0@'.format(includedir),
        'lib directory:			@0@'.format(libdir),
        'libexec directory:		@0@'.format(libexecdir),
        'local state directory:		@0@'.format(localstatedir),
        'sbin directory:		@0@'.format(sbindir),
        'sysconf directory:		@0@'.format(sysconfdir),

        'lxc cgroup pattern:		@0@'.format(cgrouppattern),
        'lxc init directory:		@0@'.format(libexecdir),
        'runtime path:			@0@'.format(runtimepath),

        'lxc default config:		@0@'.format(lxcdefaultconfig),
        'lxc global config:		@0@'.format(lxcglobalconfig),
        'lxc hook directory:		@0@'.format(lxchookdir),
        'lxc hook bin directory:	@0@'.format(lxchookbindir),
        'lxc rootfs mount directory:	@0@'.format(lxcrootfsmount),
        'log path:			@0@'.format(lxclogpath),
        'lxc path:			@0@'.format(lxcpath),
        'lxc template config:		@0@'.format(lxctemplateconfig),
        'lxc template directory:	@0@'.format(lxctemplatedir)]

message('\n         '.join(status))

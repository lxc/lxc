# SPDX-License-Identifier: LGPL-2.1-or-later

# Project.
project(
    'lxc',
    'c',
    version: '5.0.0',
    license: 'LGPLv2+',
    default_options: [
        'b_lto=true',
        'b_lto_mode=thin',
        'b_colorout=always',
        'b_asneeded=false',
        'b_pie=true',
        'b_staticpic=true',
        'c_std=gnu11',
        'warning_level=2',
    ],
    meson_version: '>= 0.61')

cc = meson.get_compiler('c')
pkgconfig = import('pkgconfig')
pkgconfig_libs = []

liblxc_dependencies = []
oss_fuzz_dependencies = []

# Version.
liblxc_version = '1.7.0'
version_data = configuration_data()
version_data.set('LXC_VERSION_MAJOR', '5')
version_data.set('LXC_VERSION_MINOR', '0')
version_data.set('LXC_VERSION_MICRO', '0')
version_data.set('LXC_VERSION_BETA', '')
version_data.set('LXC_ABI', liblxc_version)
version_data.set('LXC_DEVEL', '1')
version_data.set('LXC_VERSION', meson.project_version())

# Path handling.
project_source_root = meson.current_source_dir()
project_build_root = meson.current_build_dir()
prefixdir = get_option('prefix')

apparmorcachedir = get_option('apparmor-cache-path')
globalconfig = get_option('global-config-path')
localstatedir = join_paths('/', get_option('localstatedir'))
logpath = get_option('log-path')
lxcpathprefix = get_option('data-path')
rootfsmount = get_option('rootfs-mount-path')
user_network_db_opt = get_option('usernet-db-path')
user_network_conf_opt = get_option('usernet-config-path')

bashcompletiondir = join_paths('/', 'usr', 'share', 'bash-completion', 'completions')
bindir = join_paths(prefixdir, get_option('bindir'))
datadir = join_paths(prefixdir, get_option('datadir'))
mandir = join_paths(prefixdir, get_option('mandir'))
docdir = join_paths(datadir, get_option('doc-path'))
includedir = join_paths(prefixdir, get_option('includedir'))
libdir = join_paths(prefixdir, get_option('libdir'))
libexecdir = join_paths(prefixdir, get_option('libexecdir'))
runtimepath = join_paths(prefixdir, get_option('runtime-path'))
sbindir = join_paths(prefixdir, get_option('sbindir'))
sysconfdir = join_paths(prefixdir, get_option('sysconfdir'))

lxcapparmorcachedir = join_paths(localstatedir, apparmorcachedir)
lxcconfdir = join_paths(sysconfdir, globalconfig)
lxcdefaultconfig = join_paths(lxcconfdir, 'default.conf')
lxcglobalconfig = join_paths(lxcconfdir, 'lxc.conf')
lxcexamplesdir = join_paths(docdir, 'examples')
lxchookbindir = join_paths(libexecdir, 'lxc/hooks')
lxcinclude = join_paths(includedir, 'lxc')
lxclibexec = join_paths(libexecdir, 'lxc')
lxclogpath = join_paths(localstatedir, logpath)
lxcpath = join_paths(localstatedir, lxcpathprefix)
lxcrootfsmount = join_paths(libdir, rootfsmount)
lxcdatadir = join_paths(datadir, 'lxc')
lxchookdir = join_paths(lxcdatadir, 'hooks')
lxcselinuxdir = join_paths(lxcdatadir, 'selinux')
lxctemplateconfdir = join_paths(lxcdatadir, 'config')
lxctemplateconfcommondir = join_paths(lxctemplateconfdir, 'common.conf.d')
lxctemplatedir = join_paths(lxcdatadir, 'templates')
lxc_user_network_conf = join_paths(sysconfdir, user_network_conf_opt)
lxc_user_network_db = join_paths(runtimepath, user_network_db_opt)
pam_security = join_paths(libdir, 'security')

# Configuration options.
srcconf = configuration_data()
srcconf.set('_GNU_SOURCE', true)
srcconf.set('_FILE_OFFSET_BITS', 64)
srcconf.set('__STDC_FORMAT_MACROS', true)

## This is a hack to prevent any inclusion ofr linux/mount.h which causes
## conflicts with sys/mount.h all over the place
srcconf.set('_LINUX_MOUNT_H', true)

srcconf.set_quoted('APPARMOR_CACHE_DIR', lxcapparmorcachedir)
srcconf.set_quoted('LIBEXECDIR', libexecdir)
srcconf.set_quoted('LOGPATH', lxclogpath)
srcconf.set_quoted('LXC_DEFAULT_CONFIG', lxcdefaultconfig)
srcconf.set_quoted('LXC_GLOBAL_CONF', lxcglobalconfig)
srcconf.set_quoted('LXCINITDIR', libexecdir)
srcconf.set_quoted('LXCPATH', lxcpath)
srcconf.set_quoted('LXCROOTFSMOUNT', lxcrootfsmount)
srcconf.set_quoted('LXCTEMPLATECONFIG', lxctemplateconfdir)
srcconf.set_quoted('LXCTEMPLATECONFIG', lxctemplateconfdir)
srcconf.set_quoted('LXCTEMPLATEDIR', lxctemplatedir)
srcconf.set_quoted('LXC_USERNIC_CONF', lxc_user_network_conf)
srcconf.set_quoted('LXC_USERNIC_DB', lxc_user_network_db)
srcconf.set_quoted('RUNTIME_PATH', runtimepath)
srcconf.set_quoted('SBINDIR', sbindir)

conf = configuration_data()
conf.set('BINDIR', bindir)
conf.set('LIBEXECDIR', libexecdir)
conf.set('LOCALSTATEDIR', localstatedir)
conf.set('LXC_GLOBAL_CONF', lxcglobalconfig)
conf.set('LXCHOOKDIR', lxchookdir)
conf.set('LXCINITDIR', libexecdir)
conf.set('LXCROOTFSMOUNT', lxcrootfsmount)
conf.set('LXCTEMPLATECONFIG', lxctemplateconfdir)
conf.set('LXCTEMPLATEDIR', lxctemplatedir)
conf.set('PACKAGE_VERSION', meson.project_version())
conf.set('RUNTIME_PATH', runtimepath)
conf.set('SYSCONFDIR', sysconfdir)

# Set sysconfdir
fs = import('fs')
distrosysconfdir = get_option('distrosysconfdir')
if distrosysconfdir != ''
    distrosysconfdir = join_paths(sysconfdir, distrosysconfdir)
    conf.set('LXC_DISTRO_SYSCONF', distrosysconfdir)
elif fs.is_dir('/etc/sysconfig')
    distrosysconfdir = join_paths(sysconfdir, 'sysconfig')
    conf.set('LXC_DISTRO_SYSCONF', distrosysconfdir)
elif fs.is_dir('/etc/default')
    distrosysconfdir = join_paths(sysconfdir, 'default')
    conf.set('LXC_DISTRO_SYSCONF', distrosysconfdir)
else
    error('"distrosysconfdir" is not set')
endif

# Cross-compile on Android.
srcconf.set10('IS_BIONIC', host_machine.system() == 'android')

# Custom configuration.
cgrouppattern = get_option('cgroup-pattern')
coverity = get_option('coverity-build')
init_script = get_option('init-script')
sanitize = get_option('b_sanitize')
want_examples = get_option('examples')
want_io_uring = get_option('io-uring-event-loop')
want_pam_cgroup = get_option('pam-cgroup')
want_mans = get_option('man')
want_tests = get_option('tests')
want_tools = get_option('tools')
want_tools_multicall = get_option('tools-multicall')
want_commands = get_option('commands')
want_capabilities = get_option('capabilities')
want_apparmor = get_option('apparmor')
want_openssl = get_option('openssl')
want_selinux = get_option('selinux')
want_oss_fuzz = get_option('oss-fuzz')
want_seccomp = get_option('seccomp')
want_thread_safety = get_option('thread-safety')
want_memfd_rexec = get_option('memfd-rexec')
want_dbus = get_option('dbus')

srcconf.set_quoted('DEFAULT_CGROUP_PATTERN', cgrouppattern)
if coverity
    srcconf.set('ENABLE_COVERITY_BUILD', 1)
endif

dummy_config_data = configuration_data()
dummy_config_data.set_quoted('DUMMY_VARIABLE', '1')

# Those generate many false positives, and we do not want to change the code to
# avoid them.
basic_disabled_warnings = [
        '-Wno-format-signedness',
        '-Wno-missing-field-initializers',
        '-Wno-unused-parameter',
]

# Build flags.
possible_cc_flags = [
    '-Wvla',
    '-Wimplicit-fallthrough=5',
    '-Wcast-align',
    '-Wstrict-prototypes',
    '-fno-strict-aliasing',
    '-fstack-clash-protection',
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
    '-Wl,--no-as-needed',
    '-Wl,--gc-sections',
    '-Wl,-z,relro',
    '-Wl,-z,now',
    '-fstack-protector',
    '-fstack-protector-strong',
]

# The gold linker fails with a bus error on sparc64
if build_machine.cpu_family() != 'sparc64'
    possible_link_flags += '-Wl,-fuse-ld=gold'
endif

if sanitize == 'none'
    possible_link_flags += '-Wl,--warn-common'
endif

if cc.get_id() == 'clang'
    possible_cc_flags += [
            '-Wno-typedef-redefinition',
            '-Wno-gnu-variable-sized-type-not-at-end',
    ]
endif

if meson.version().version_compare('>=0.46')
    add_project_link_arguments(cc.get_supported_link_arguments(possible_link_flags), language: 'c')
else
    add_project_link_arguments(possible_link_flags, language: 'c')
endif

add_project_arguments(cc.get_supported_arguments(basic_disabled_warnings), language : 'c')
add_project_arguments(cc.get_supported_arguments(possible_cc_flags), language: 'c')

if add_languages('cpp', required : want_oss_fuzz)
    #  Used only for tests
    cxx = meson.get_compiler('cpp')
    cxx_cmd = ' '.join(cxx.cmd_array())
    add_project_arguments(cxx.get_supported_arguments(basic_disabled_warnings), language : 'cpp')
endif

# Feature detection
## I/O uring.
if want_io_uring
    liburing = dependency('liburing')
    if cc.has_function('io_uring_prep_poll_add', prefix: '#include <liburing.h>', dependencies: liburing) == false
        error('liburing version does not support IORING_POLL_ADD_MULTI')
    endif
    pkgconfig_libs += liburing
    liblxc_dependencies += liburing

    srcconf.set10('HAVE_LIBURING', true)
else
    srcconf.set10('HAVE_LIBURING', false)
endif

if want_dbus
    libdbus = dependency('dbus-1', required: true)
    pkgconfig_libs += libdbus
    liblxc_dependencies += libdbus
    srcconf.set10('HAVE_DBUS', libdbus.found())
else
    srcconf.set10('HAVE_DBUS', false)
endif

## Time EPOCH.
sh = find_program('sh')
date = find_program('date')
git = find_program('git', required: false)
time_epoch = run_command(sh, '-c', 'echo "$SOURCE_DATE_EPOCH"', check: true).stdout().strip()
if time_epoch == '' and git.found() and run_command('test', '-e', '.git', check: false).returncode() == 0
    # If we're in a git repository, use the creation time of the latest git tag.
    latest_tag = run_command(git, 'describe', '--abbrev=0', '--tags', check: false).stdout().strip()
    if latest_tag != ''
      time_epoch = run_command(git, 'log', '--no-show-signature', '-1', '--format=%at', latest_tag, check: true).stdout().strip()
    endif
endif

# Fallback to current epoch.
if time_epoch == ''
    time_epoch = run_command(date, '+%s', check: true).stdout().strip()
endif
generate_date = run_command(date, '--utc', '--date=@' + time_epoch, '+%Y-%m-%d', check: true).stdout().strip()

## Manpages.
docconf = configuration_data()
docconf.set('builddir', '.')
docconf.set('BINDIR', bindir)
docconf.set('DATADIR', datadir)
docconf.set('DOCDIR', docdir)
docconf.set('LOGPATH', lxclogpath)
docconf.set('LXC_DEFAULT_CONFIG', lxcdefaultconfig)
docconf.set('LXC_GENERATE_DATE', generate_date)
docconf.set('LXC_GLOBAL_CONF', lxcglobalconfig)
docconf.set('LXCPATH', lxcpath)
docconf.set('LXCTEMPLATEDIR', lxctemplatedir)
docconf.set('LXC_USERNIC_CONF', lxc_user_network_conf)
docconf.set('LXC_USERNIC_DB', lxc_user_network_db)
docconf.set('PACKAGE_VERSION', version_data.get('LXC_VERSION'))
docconf.set('docdtd', '"-//OASIS//DTD DocBook XML" "http://www.oasis-open.org/docbook/xml/4.5/docbookx.dtd"')
sgml2man = find_program('docbook2X2man', 'docbook2x-man', 'db2x_docbook2man', 'docbook2man', 'docbook-to-man', required: false, version: '>=0.8')
if not sgml2man.found()
    sgml2man = find_program('docbook2man', required: false, version: '<0.8')
    if sgml2man.found()
        docconf.set('docdtd', '"-//Davenport//DTD DocBook V3.0//EN"')
    elif want_mans
        error('missing required docbook2x or docbook-utils dependency')
    endif
endif

## Threads.
threads = dependency('threads')
liblxc_dependencies += threads

## Seccomp.
if want_seccomp
    libseccomp = dependency('libseccomp', required: false)
    srcconf.set10('HAVE_SECCOMP', libseccomp.found())
    pkgconfig_libs += libseccomp
    liblxc_dependencies += libseccomp
    if libseccomp.found()
        if libseccomp.version().version_compare('>=2.5.0')
            # https://github.com/seccomp/libseccomp/commit/dead12bc788b259b148cc4d93b970ef0bd602b1a
            srcconf.set10('HAVE_DECL_SECCOMP_NOTIFY_FD', true)
        else
            srcconf.set10('HAVE_DECL_SECCOMP_NOTIFY_FD', false)
        endif

        if libseccomp.version().version_compare('>=2.0.0')
            # https://github.com/seccomp/libseccomp/commit/6220c8c0fc479d97b6d3e3166a4e46fbfe25a3c0
            srcconf.set10('HAVE_DECL_SECCOMP_SYSCALL_RESOLVE_NAME_ARCH', true)
        else
            srcconf.set10('HAVE_DECL_SECCOMP_SYSCALL_RESOLVE_NAME_ARCH', false)
        endif

        seccomp_headers = '''
        #include <seccomp.h>
        '''

        foreach decl: [
            'scmp_filter_ctx',
            'struct seccomp_notif_sizes',
            'struct clone_args',
        ]

            # We get -1 if the size cannot be determined
            if cc.sizeof(decl, prefix: seccomp_headers, args: '-D_GNU_SOURCE', dependencies: libseccomp) > 0
                srcconf.set10('HAVE_' + decl.underscorify().to_upper(), true)
            else
                srcconf.set10('HAVE_' + decl.underscorify().to_upper(), false)
            endif
        endforeach
    endif
else
    srcconf.set10('HAVE_SECCOMP', false)
endif

## SELinux.
if want_selinux
    libselinux = dependency('libselinux', required: false)
    srcconf.set10('HAVE_SELINUX', libselinux.found())
    pkgconfig_libs += libselinux
    liblxc_dependencies += libselinux
else
    srcconf.set10('HAVE_SELINUX', false)
endif

## AppArmor.
if want_apparmor
    libapparmor = dependency('libapparmor', required: false)
    srcconf.set10('HAVE_APPARMOR', libapparmor.found())
    # We do not use the AppArmor library at runtime, so it's not in our pkg-config.
    liblxc_dependencies += libapparmor
else
    srcconf.set10('HAVE_APPARMOR', false)
endif

## OpenSSL.
if want_openssl
    libopenssl = dependency('openssl', required: false)
    srcconf.set10('HAVE_OPENSSL', libopenssl.found())
    pkgconfig_libs += libopenssl
    liblxc_dependencies += libopenssl
else
    srcconf.set10('HAVE_OPENSSL', false)
endif

## Libcap..
if want_capabilities
    libcap = dependency('libcap', required: false)
    if not libcap.found()
        # Compat with Ubuntu 14.04 which ships libcap w/o .pc file
        libcap = cc.find_library('cap', required: false)
    else
        have = cc.has_function('cap_get_file', dependencies: libcap, prefix: '#include <sys/capability.h>')
        srcconf.set10('LIBCAP_SUPPORTS_FILE_CAPABILITIES', have)
    endif
    srcconf.set10('HAVE_LIBCAP', libcap.found())
    pkgconfig_libs += libcap
    liblxc_dependencies += libcap

    libcap_static = dependency('libcap', required: false, static: true)
    if not libcap_static.found()
        # Compat with Ubuntu 14.04 which ships libcap w/o .pc file
        libcap_static = cc.find_library('cap', required: false, static: true)
    endif

    code = '''
int main(int argc, char *argv[]) { return 0; };
'''
    if libcap_static.found()
        libcap_static_linkable = cc.links(code, args: '-static', dependencies: libcap_static)
    else
        libcap_static_linkable = false
    endif
    srcconf.set10('HAVE_STATIC_LIBCAP', libcap_static_linkable)
else
    libcap_static = []
    libcap_static_linkable = false
    srcconf.set10('HAVE_LIBCAP', false)
    srcconf.set10('HAVE_STATIC_LIBCAP', false)
endif

libutil = cc.find_library('util', required: false)

if want_oss_fuzz
    srcconf.set10('FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION', true)
    srcconf.set10('RUN_ON_OSS_FUZZ', true)
    fuzzing_engine = meson.get_compiler('cpp').find_library('FuzzingEngine')
endif

srcconf.set10('ENFORCE_THREAD_SAFETY', want_thread_safety)
srcconf.set10('ENFORCE_MEMFD_REXEC', want_memfd_rexec)

## PAM.
pam = cc.find_library('pam', has_headers: 'security/pam_modules.h', required: want_pam_cgroup)
srcconf.set10('HAVE_PAM', pam.found())
pkgconfig_libs += pam

## Others.
have = cc.has_function('fmemopen', prefix: '#include <stdio.h>', args: '-D_GNU_SOURCE')
srcconf.set10('HAVE_FMEMOPEN', have)

have = cc.has_function('openpty', dependencies: libutil, prefix: '#include <pty.h>')
srcconf.set10('HAVE_OPENPTY', have)
if have
    liblxc_dependencies += libutil
    if want_oss_fuzz
        oss_fuzz_dependencies += libutil
    endif
endif

have = cc.has_function('pthread_setcancelstate', prefix: '#include <pthread.h>')
srcconf.set10('HAVE_PTHREAD_SETCANCELSTATE', have)

have = cc.has_function('rand_r')
srcconf.set10('HAVE_RAND_R', have)

have = cc.has_function('strchrnul', prefix: '#include <string.h>', args: '-D_GNU_SOURCE')
srcconf.set10('HAVE_STRCHRNUL', have)

have_func_strerror_r = cc.has_function('strerror_r', prefix: '#include <string.h>', args: '-D_GNU_SOURCE')
srcconf.set10('HAVE_STRERROR_R', have_func_strerror_r)

have_func_strerror_r_char_p = false

if have_func_strerror_r
    code = '''
#define _GNU_SOURCE
#include <string.h>
int func (void) {
    char error_string[256];
    char *ptr = strerror_r (-2, error_string, 256);
    char c = *strerror_r (-2, error_string, 256);
    return c != 0 && ptr != (void*) 0L;
}
'''

have_func_strerror_r_char_p = cc.compiles(code, name : 'strerror_r() returns char *')
endif

srcconf.set10('STRERROR_R_CHAR_P', have_func_strerror_r_char_p)

## Compiler attributes.
foreach ccattr: [
    'fallthrough',
    'nonnull',
    'returns_nonnull',
]

    srcconf.set10('HAVE_COMPILER_ATTR_' + ccattr.underscorify().to_upper(), cc.has_function_attribute(ccattr))
endforeach

## Syscalls.
found_syscalls = []
missing_syscalls = []
foreach tuple: [
    ['bpf'],
    ['close_range'],
    ['endmntent'],
    ['execveat'],
    ['faccessat'],
    ['strchrnul'],
    ['strerror_r'],
    ['fgetln'],
    ['fsconfig'],
    ['fsmount'],
    ['fsopen'],
    ['fspick'],
    ['getgrgid_r'],
    ['getline'],
    ['getsubopt'],
    ['gettid'],
    ['hasmntopt'],
    ['kcmp'],
    ['keyctl'],
    ['memfd_create'],
    ['mount_setattr'],
    ['move_mount'],
    ['openat2'],
    ['open_tree'],
    ['personality'],
    ['pidfd_open'],
    ['pidfd_send_signal'],
    ['pivot_root'],
    ['prlimit'],
    ['prlimit64'],
    ['renameat2'],
    ['sethostname'],
    ['setmntent'],
    ['setns'],
    ['sigdescr_np'],
    ['signalfd'],
    ['statx'],
    ['statvfs'],
    ['strlcat'],
    ['strlcpy'],
    ['unshare'],
]

    if tuple.length() >= 2
        cond = tuple[1]
    else
        ident1 = 'HAVE_' + tuple[0].underscorify().to_upper()
        ident2 = 'ENABLE_' + tuple[0].underscorify().to_upper()
        cond = srcconf.get(ident1, 0) == 1 or srcconf.get(ident2, 0) == 1
    endif

    if cond
        found_syscalls += tuple[0]
    else
        missing_syscalls += tuple[0]
    endif
endforeach

## Types.
decl_headers = '''
#include <uchar.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <linux/if_link.h>
#include <linux/types.h>
'''

foreach decl: [
    '__aligned_u64',
    'struct clone_args',
    'struct open_how',
    'struct rtnl_link_stats64',
]

    # We get -1 if the size cannot be determined
    if cc.sizeof(decl, prefix: decl_headers, args: '-D_GNU_SOURCE') > 0
        srcconf.set10('HAVE_' + decl.underscorify().to_upper(), true)
    else
        srcconf.set10('HAVE_' + decl.underscorify().to_upper(), false)
    endif
endforeach

found_types = []
missing_types = []
foreach tuple: [
    ['scmp_filter_ctx'],
    ['struct seccomp_notif_sizes'],
    ['struct clone_args'],
    ['__aligned_u64'],
    ['struct open_how'],
    ['struct rtnl_link_stats64'],
]

    if tuple.length() >= 2
        cond = tuple[1]
    else
        ident1 = 'HAVE_' + tuple[0].underscorify().to_upper()
        ident2 = 'ENABLE_' + tuple[0].underscorify().to_upper()
        cond = srcconf.get(ident1, 0) == 1 or srcconf.get(ident2, 0) == 1
    endif

    if cond
        found_types += tuple[0]
    else
        missing_types += tuple[0]
    endif
endforeach

decl_headers = '''
#include <sys/mount.h>
'''

# We get -1 if the size cannot be determined
if cc.sizeof('struct mount_attr', prefix: decl_headers, args: '-D_GNU_SOURCE') > 0
    srcconf.set10('HAVE_' + 'struct mount_attr'.underscorify().to_upper(), true)
    found_types += 'struct mount_attr (sys/mount.h)'
else
    srcconf.set10('HAVE_' + 'struct mount_attr'.underscorify().to_upper(), false)
    missing_types += 'struct mount_attr (sys/mount.h)' endif

## Check if sys/mount.h defines the fsconfig commands
if cc.get_define('FSCONFIG_SET_FLAG', prefix: decl_headers) != ''
    srcconf.set10('HAVE_' + 'FSCONFIG_SET_FLAG'.underscorify().to_upper(), true)
    found_types += 'FSCONFIG_SET_FLAG (sys/mount.h)'
else
    srcconf.set10('HAVE_' + 'FSCONFIG_SET_FLAG'.underscorify().to_upper(), false)
    missing_types += 'FSCONFIG_SET_FLAG (sys/mount.h)'
endif

if cc.get_define('FS_CONFIG_SET_STRING', prefix: decl_headers) != ''
    srcconf.set10('HAVE_' + 'FS_CONFIG_SET_STRING'.underscorify().to_upper(), true)
    found_types += 'FS_CONFIG_SET_STRING (sys/mount.h)'
else
    srcconf.set10('HAVE_' + 'FS_CONFIG_SET_STRING'.underscorify().to_upper(), false)
    missing_types += 'FS_CONFIG_SET_STRING (sys/mount.h)'
endif

if cc.get_define('FS_CONFIG_SET_BINARY', prefix: decl_headers) != ''
    srcconf.set10('HAVE_' + 'FS_CONFIG_SET_BINARY'.underscorify().to_upper(), true)
    found_types += 'FS_CONFIG_SET_BINARY (sys/mount.h)'
else
    srcconf.set10('HAVE_' + 'FS_CONFIG_SET_BINARY'.underscorify().to_upper(), false)
    missing_types += 'FS_CONFIG_SET_BINARY (sys/mount.h)'
endif

if cc.get_define('FS_CONFIG_SET_PATH_EMPTY', prefix: decl_headers) != ''
    srcconf.set10('HAVE_' + 'FS_CONFIG_SET_PATH_EMPTY'.underscorify().to_upper(), true)
    found_types += 'FS_CONFIG_SET_PATH_EMPTY (sys/mount.h)'
else
    srcconf.set10('HAVE_' + 'FS_CONFIG_SET_PATH_EMPTY'.underscorify().to_upper(), false)
    missing_types += 'FS_CONFIG_SET_PATH_EMPTY (sys/mount.h)'
endif

if cc.get_define('FS_CONFIG_SET_PATH_FD', prefix: decl_headers) != ''
    srcconf.set10('HAVE_' + 'FS_CONFIG_SET_PATH_FD'.underscorify().to_upper(), true)
    found_types += 'FS_CONFIG_SET_PATH_FD (sys/mount.h)'
else
    srcconf.set10('HAVE_' + 'FS_CONFIG_SET_PATH_FD'.underscorify().to_upper(), false)
    missing_types += 'FS_CONFIG_SET_PATH_FD (sys/mount.h)'
endif

if cc.get_define('FS_CONFIG_SET_CMD_CREATE', prefix: decl_headers) != ''
    srcconf.set10('HAVE_' + 'FS_CONFIG_SET_CMD_CREATE'.underscorify().to_upper(), true)
    found_types += 'FS_CONFIG_SET_CMD_CREAT (sys/mount.h)'
else
    srcconf.set10('HAVE_' + 'FS_CONFIG_SET_CMD_CREATE'.underscorify().to_upper(), false)
    missing_types += 'FS_CONFIG_SET_CMD_CREATE (sys/mount.h)'
endif

if cc.get_define('FS_CONFIG_SET_CMD_RECONFIGURE', prefix: decl_headers) != ''
    srcconf.set10('HAVE_' + 'FS_CONFIG_SET_CMD_RECONFIGURE'.underscorify().to_upper(), true)
    found_types += 'FS_CONFIG_SET_CMD_RECONFIGURE (sys/mount.h)'
else
    srcconf.set10('HAVE_' + 'FS_CONFIG_SET_CMD_RECONFIGURE'.underscorify().to_upper(), false)
    missing_types += 'FS_CONFIG_SET_CMD_RECONFIGURE (sys/mount.h)'
endif

## Headers.
foreach ident: [
    ['bpf',               '''#include <sys/syscall.h>
                             #include <unistd.h>'''],
    ['close_range',       '''#include <unistd.h>'''],
    ['execveat',          '''#include <unistd.h>'''],
    ['endmntent',         '''#include <stdio.h>
                             #include <mntent.h>'''],
    ['faccessat',         '''#include <fcntl.h>
                             #include <unistd.h>'''],
    ['fexecve',           '''#include <unistd.h>'''],
    ['fgetln',            '''#include <stdio.h>'''],
    ['fsconfig',          '''#include <sys/mount.h>'''],
    ['fsmount',           '''#include <sys/mount.h>'''],
    ['fsopen',            '''#include <sys/mount.h>'''],
    ['fspick',            '''#include <sys/mount.h>'''],
    ['getgrgid_r',        '''#include <sys/types.h>
                             #include <grp.h>'''],
    ['getline',           '''#include <stdio.h>'''],
    ['getsubopt',         '''#include <stdlib.h>'''],
    ['gettid',            '''#include <sys/types.h>
                             #include <unistd.h>'''],
    ['hasmntopt',         '''#include <stdio.h>
                             #include <mntent.h>'''],
    ['kcmp',              '''#include <linux/kcmp.h>'''],
    ['keyctl',            '''#include <sys/types.h>
                             #include <keyutils.h>'''],
    ['memfd_create',      '''#include <sys/mman.h>'''],
    ['mount_setattr',     '''#include <sys/mount.h>'''],
    ['move_mount',        '''#include <sys/mount.h>'''],
    ['openat2',           '''#include <sys/types.h>
                             #include <sys/stat.h>
                             #include <fctnl.h>'''],
    ['open_tree',         '''#include <sys/mount.h>'''],
    ['personality',       '''#include <sys/personality.h>'''],
    ['pidfd_open',        '''#include <stdlib.h>
                             #include <unistd.h>
                             #include <signal.h>
                             #include <sys/wait.h>'''],
    ['pidfd_send_signal', '''#include <stdlib.h>
                             #include <unistd.h>
                             #include <signal.h>
                             #include <sys/wait.h>'''],
    ['pivot_root',        '''#include <stdlib.h>
                             #include <unistd.h>'''],     # no known header declares pivot_root
    ['prlimit',           '''#include <sys/time.h>
                             #include <sys/resource.h>'''],
    ['prlimit64',         '''#include <sys/time.h>
                             #include <sys/resource.h>'''],
    ['renameat2',         '''#include <stdio.h>
                             #include <fcntl.h>'''],
    ['sethostname',       '''#include <unistd.h>'''],
    ['setmntent',         '''#include <stdio.h>
                             #include <mntent.h>'''],
    ['setns',             '''#include <sched.h>'''],
    ['sigdescr_np',       '''#include <string.h>'''],
    ['signalfd',          '''#include <sys/signalfd.h>'''],
    ['statvfs',           '''#include <sys/statvfs.h>'''],
    ['statx',             '''#include <sys/types.h>
                             #include <sys/stat.h>
                             #include <unistd.h>'''],
    ['strchrnul',         '''#include <string.h>'''],
    ['strlcat',           '''#include <string.h>'''],
    ['strlcpy',           '''#include <string.h>'''],
    ['unshare',           '''#include <sched.h>'''],
]

    have = cc.has_function(ident[0], prefix: ident[1], args: '-D_GNU_SOURCE')
    srcconf.set10('HAVE_' + ident[0].to_upper(), have)
endforeach

found_headers = []
missing_headers = []
foreach tuple: [
    ['sys/resource.h'],
    ['sys/memfd.h'],
    ['sys/personality.h'],
    ['sys/pidfd.h'],
    ['sys/signalfd.h'],
    ['sys/timerfd.h'],
    ['pty.h'],
    ['utmpx.h'],
]
    srcconf.set10('HAVE_' + tuple[0].underscorify().to_upper(), cc.has_header(tuple[0]))

    if tuple.length() >= 2
        cond = tuple[1]
    else
        ident1 = 'HAVE_' + tuple[0].underscorify().to_upper()
        ident2 = 'ENABLE_' + tuple[0].underscorify().to_upper()
        cond = srcconf.get(ident1, 0) == 1 or srcconf.get(ident2, 0) == 1
    endif

    if cond
        found_headers += tuple[0]
    else
        missing_headers += tuple[0]
    endif
endforeach

## Deps.
found_deps = []
missing_deps = []
foreach tuple: [
    ['AppArmor'],
    ['SECCOMP'],
    ['SELinux'],
    ['libcap'],
    ['static libcap'],
    ['pam'],
    ['openssl'],
    ['liburing'],
]

    if tuple.length() >= 2
        cond = tuple[1]
    else
        ident1 = 'HAVE_' + tuple[0].underscorify().to_upper()
        ident2 = 'ENABLE_' + tuple[0].underscorify().to_upper()
        cond = srcconf.get(ident1, 0) == 1 or srcconf.get(ident2, 0) == 1
    endif

    if cond
        found_deps += tuple[0]
    else
        missing_deps += tuple[0]
    endif
endforeach

# Generate config.h
config_h = configure_file(
        output: 'config.h',
        configuration: srcconf)

add_project_arguments('-include', 'config.h', language: 'c')

# Binaries.
cmd_programs = []
hook_programs = []
public_programs = []
template_scripts = []
test_programs = []

# Includes.
liblxc_includes = include_directories(
    '.',
    'src',
    'src/include',
    'src/lxc',
    'src/lxc/cgroups',
    'src/lxc/storage')

# Our static sub-project binaries don't (and in fact can't) link to our
# dependencies directly, but need access to the headers when compiling (most
# notably seccomp headers).
liblxc_dependency_headers = []
foreach dep: liblxc_dependencies
    liblxc_dependency_headers += dep.partial_dependency(compile_args: true)
endforeach

# Early sub-directories.
subdir('src/include')
subdir('src/lxc')
subdir('src/lxc/pam')

liblxc_link_whole = [liblxc_static]

liblxc = shared_library(
    'lxc',
    version: liblxc_version,
    include_directories: liblxc_includes,
    link_args: ['-DPIC'],
    c_args: ['-DPIC'],
    link_whole: liblxc_link_whole,
    dependencies: liblxc_dependencies,
    install: true)

liblxc_dep = declare_dependency(
    link_with: liblxc,
    dependencies: liblxc_dependencies)

# Rest of sub-directories.
if want_apparmor
    subdir('config/apparmor')
    subdir('config/apparmor/abstractions')
    subdir('config/apparmor/profiles')
endif
subdir('config/bash')
subdir('config/etc')
subdir('config/init/common')
subdir('config/init/systemd')
subdir('config/init/sysvinit')
subdir('config/init/upstart')
if want_selinux
    subdir('config/selinux')
endif
subdir('config/sysconfig')
subdir('config/templates')
subdir('config/templates/common.conf.d')
subdir('config/yum')
subdir('doc')
subdir('doc/ja')
subdir('doc/ko')
subdir('doc/examples')
subdir('doc/rootfs')
subdir('hooks')
if want_commands
    subdir('src/lxc/cmd')
endif
if want_tools or want_tools_multicall
    subdir('src/lxc/tools')
endif
subdir('src/lxc/tools/include')
subdir('src/tests')
subdir('templates')

# Pkg-config.
pkg_config_file = pkgconfig.generate(liblxc,
    description: 'linux container tools',
    version: version_data.get('LXC_VERSION'),
    url: 'http://linuxcontainers.org',
    libraries: '-lutil -lpthread -ldl',
    libraries_private: pkgconfig_libs,
)

# Empty dirs.
install_emptydir(join_paths(localstatedir, 'cache', 'lxc'))
install_emptydir(join_paths(localstatedir, 'lib', 'lxc'))

# RPM spec file.
specconf = configuration_data()
specconf.set('LXC_VERSION_BASE', meson.project_version())
specconf.set('LXC_VERSION_BETA', version_data.get('LXC_VERSION_BETA'))
specconf.set('PACKAGE', meson.project_name())
specconf.set('LXC_DISTRO_SYSCONF', conf.get('LXC_DISTRO_SYSCONF'))

configure_file(
    configuration: specconf,
    input: 'lxc.spec.in',
    output: 'lxc.spec',
    install: false)

# Build overview.
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
    'lxc template config:		@0@'.format(lxctemplateconfdir),
    'lxc template directory:	@0@'.format(lxctemplatedir),
    'lxc user network config:	@0@'.format(lxc_user_network_conf),
    'lxc user network database:	@0@'.format(lxc_user_network_db)]

alt_time_epoch = run_command('date', '-Is', '-u', '-d',
                             '@@0@'.format(time_epoch), check: true).stdout().strip()
status += [
    'time epoch:			@0@ (@1@)'.format(time_epoch, alt_time_epoch)]

status += [
    '',
    'supported dependencies:	@0@'.format(', '.join(found_deps)),
    '',
    'unsupported dependencies:	@0@'.format(', '.join(missing_deps)),
    '']

status += [
    '',
    'supported headers:	@0@'.format(', '.join(found_headers)),
    '',
    'unsupported headers:	@0@'.format(', '.join(missing_headers)),
    '']

status += [
    '',
    'supported calls:	@0@'.format(', '.join(found_syscalls)),
    '',
    'unsupported calls:	@0@'.format(', '.join(missing_syscalls)),
    '']

status += [
    '',
    'supported types:	@0@'.format(', '.join(found_types)),
    '',
    'unsupported types:	@0@'.format(', '.join(missing_types)),
    '']

message('\n     '.join(status))

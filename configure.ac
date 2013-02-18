#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_INIT([lxc], [0.9.0.alpha3])

AC_CONFIG_SRCDIR([configure.ac])
AC_CONFIG_AUX_DIR([config])
AM_CONFIG_HEADER([src/config.h])
AM_INIT_AUTOMAKE([-Wall -Werror -Wno-portability])
AC_CANONICAL_HOST
AM_PROG_CC_C_O
AC_GNU_SOURCE

# Detect the distribution. This is used for the default configuration and
# for some distro-specific build options.
AC_MSG_CHECKING([host distribution])
AC_ARG_WITH(distro, AS_HELP_STRING([--with-distro=DISTRO], [Specify the Linux distribution to target: One of redhat, oracle, fedora, suse, gentoo, debian, arch, slackware, paldo, mandriva or pardus.]))
if test "z$with_distro" = "z"; then
	with_distro=`lsb_release -is`
fi
if test "z$with_distro" = "z"; then
	AC_CHECK_FILE(/etc/redhat-release,with_distro="redhat")
	AC_CHECK_FILE(/etc/oracle-release,with_distro="oracle")
	AC_CHECK_FILE(/etc/fedora-release,with_distro="fedora")
	AC_CHECK_FILE(/etc/SuSE-release,with_distro="suse")
	AC_CHECK_FILE(/etc/gentoo-release,with_distro="gentoo")
	AC_CHECK_FILE(/etc/debian_version,with_distro="debian")
	AC_CHECK_FILE(/etc/arch-release,with_distro="arch")
	AC_CHECK_FILE(/etc/slackware-version,with_distro="slackware")
	AC_CHECK_FILE(/etc/frugalware-release,with_distro="frugalware")
	AC_CHECK_FILE(/etc/mandrakelinux-release, with_distro="mandriva")
	AC_CHECK_FILE(/etc/mandriva-release,with_distro="mandriva")
	AC_CHECK_FILE(/etc/pardus-release,with_distro="pardus")
fi
with_distro=`echo ${with_distro} | tr '[[:upper:]]' '[[:lower:]]'`

if test "z$with_distro" = "z"; then
	with_distro="unknown"
fi
case $with_distro in
	ubuntu)
		defaultconf=default.conf.ubuntu
		;;
	redhat|fedora|oracle|oracleserver)
		defaultconf=default.conf.libvirt
		;;
	*)
		echo -n "Linux distribution network config unknown, defaulting to lxc.network.type = empty"
		defaultconf=default.conf.unknown
		;;
esac
AC_MSG_RESULT([$with_distro])
AM_CONDITIONAL([HAVE_DEBIAN], [test x"$with_distro" = "xdebian" -o x"$with_distro" = "xubuntu"])

# Allow disabling rpath
AC_ARG_ENABLE([rpath],
	[AC_HELP_STRING([--disable-rpath], [do not set rpath in executables])],
	[], [enable_rpath=yes])
AM_CONDITIONAL([ENABLE_RPATH], [test "x$enable_rpath" = "xyes"])

# Documentation (manpages)
AC_ARG_ENABLE([doc],
	[AC_HELP_STRING([--enable-doc], [make mans (require docbook2x-man installed) [default=auto]])],
	[], [enable_doc=auto])

if test "x$enable_doc" = "xyes" -o "x$enable_doc" = "xauto"; then
	db2xman=""

	AC_MSG_CHECKING(for docbook2x-man)
	for name in docbook2x-man db2x_docbook2man; do
		if "$name" --help >/dev/null 2>&1; then
			db2xman="$name"
			break;
		fi
	done

	if test -n "${db2xman}"; then
		AC_MSG_RESULT([${db2xman}])
	else
		AC_MSG_RESULT([no])
		if test "x$enable_doc" = "xyes"; then
			AC_MSG_ERROR([docbook2x-man required by man request, but not found])
		fi
	fi

	AC_SUBST(db2xman)
fi
AM_CONDITIONAL([ENABLE_DOCBOOK], [test "x$db2xman" != "x"])

# Apparmor
AC_ARG_ENABLE([apparmor],
	[AC_HELP_STRING([--enable-apparmor], [enable apparmor])],
	[], [enable_apparmor=check])

if test "$enable_apparmor" = "check" ; then
	AC_CHECK_LIB([apparmor],[aa_change_profile],[enable_apparmor=yes], [enable_apparmor=no])
fi
AM_CONDITIONAL([ENABLE_APPARMOR], [test "x$enable_apparmor" = "xyes"])

AM_COND_IF([ENABLE_APPARMOR],
	[AC_CHECK_HEADER([sys/apparmor.h],[],[AC_MSG_ERROR([You must install the AppArmor development package in order to compile lxc])])
	AC_CHECK_LIB([apparmor], [aa_change_profile],[],[AC_MSG_ERROR([You must install the AppArmor development package in order to compile lxc])])
	AC_SUBST([APPARMOR_LIBS], [-lapparmor])])

# Seccomp syscall filter
AC_ARG_ENABLE([seccomp],
	[AC_HELP_STRING([--enable-seccomp], [enable seccomp])],
	[], [enable_seccomp=check])

if test "$enable_seccomp" = "check" ; then
	AC_CHECK_LIB([seccomp],[seccomp_init],[enable_seccomp=yes],[enable_seccomp=no])
fi
AM_CONDITIONAL([ENABLE_SECCOMP], [test "x$enable_seccomp" = "xyes"])

AM_COND_IF([ENABLE_SECCOMP],
	[AC_CHECK_HEADER([seccomp.h],[],[AC_MSG_ERROR([You must install the seccomp development package in order to compile lxc])])
	AC_CHECK_LIB([seccomp], [seccomp_init],[],[AC_MSG_ERROR([You must install the seccomp development package in order to compile lxc])])
	AC_SUBST([SECCOMP_LIBS], [-lseccomp])])

# HAVE_SCMP_FILTER_CTX=1 will tell us we have libseccomp api >= 1.0.0
AC_CHECK_TYPES([scmp_filter_ctx], [], [], [#include <seccomp.h>])

# Configuration examples
AC_ARG_ENABLE([examples],
	[AC_HELP_STRING([--disable-examples], [do not install configuration examples])],
	[], [enable_examples=yes])
AM_CONDITIONAL([ENABLE_EXAMPLES], [test "x$enable_examples" = "xyes"])

# Python3 module and scripts
AC_ARG_ENABLE([python],
	[AC_HELP_STRING([--enable-python], [enable python binding])],
	[enable_python=yes], [enable_python=no])
AM_CONDITIONAL([ENABLE_PYTHON], [test "x$enable_python" = "xyes"])

AM_COND_IF([ENABLE_PYTHON],
	[AM_PATH_PYTHON([3.2], [], [AC_MSG_ERROR([You must install python3])])
	PKG_CHECK_MODULES([PYTHONDEV], [python3 >= 3.2],[],[AC_MSG_ERROR([You must install python3-dev])])
	AC_DEFINE_UNQUOTED([ENABLE_PYTHON], 1, [Python3 is available])])

# Lua module and scripts
if test x"$with_distro" = "xdebian" -o x"$with_distro" = "xubuntu" ; then
    LUAPKGCONFIG=lua5.1
else
    LUAPKGCONFIG=lua
fi

AC_ARG_ENABLE([lua],
	[AC_HELP_STRING([--enable-lua], [enable lua binding])],
	[enable_lua=yes], [enable_lua=no])

AM_CONDITIONAL([ENABLE_LUA], [test "x$enable_lua" = "xyes"])

AM_COND_IF([ENABLE_LUA],
	[PKG_CHECK_MODULES([LUA], [$LUAPKGCONFIG >= 5.1],[],[AC_MSG_ERROR([You must install lua-devel for lua 5.1])])
	AC_DEFINE_UNQUOTED([ENABLE_LUA], 1, [Lua is available])])

# Optional test binaries
AC_ARG_ENABLE([tests],
	[AC_HELP_STRING([--enable-tests], [build test/example binaries])],
	[enable_tests=yes], [enable_tests=no])
AM_CONDITIONAL([ENABLE_TESTS], [test "x$enable_tests" = "xyes"])

# LXC container path, where the containers are actually stored
# This is overriden by an entry in the file called LXCCONF
# (i.e. /etc/lxc/lxc.conf)
AC_ARG_WITH([config-path],
	[AC_HELP_STRING(
		[--with-config-path=dir],
		[lxc configuration repository path]
	)], [], [with_config_path=['${localstatedir}/lib/lxc']])

# The path of the global lxc configuration file.
AC_ARG_WITH([global-conf],
	[AC_HELP_STRING(
		[--with-global-conf=dir],
		[global lxc configuration file]
	)], [], [with_global_conf=['${sysconfdir}/lxc/lxc.conf']])

# Rootfs path, where the container mount structure is assembled
AC_ARG_WITH([rootfs-path],
	[AC_HELP_STRING(
		[--with-rootfs-path=dir],
		[lxc rootfs mount point]
	)], [], [with_rootfs_path=['${libdir}/lxc/rootfs']])

# Container log path.  By default, use $lxcpath.
AC_MSG_CHECKING([Whether to place logfiles in container config path])
AC_ARG_ENABLE([configpath-log],
	[AC_HELP_STRING([--enable-configpath-log], [use logfiles in config path])],
	[use_configpath_logs=yes], [use_configpath_logs=no])
AC_MSG_RESULT([$use_configpath_logs])
AM_CONDITIONAL([USE_CONFIGPATH_LOGS], [test "$use_configpath_logs" = "yes"])

if test "$use_configpath_logs" = "yes"; then
	default_log_path="${with_config_path}"
else
	default_log_path="/var/log/lxc"
fi

AC_ARG_WITH([log-path],
	[AC_HELP_STRING(
		[--with-log-path=dir],
		[per container log path]
	)], [], [with_log_path=['${default_log_path}']])

# Expand some useful variables
AS_AC_EXPAND(PREFIX, "$prefix")
AS_AC_EXPAND(LIBDIR, "$libdir")
AS_AC_EXPAND(BINDIR, "$bindir")
AS_AC_EXPAND(LIBEXECDIR, "$libexecdir")
AS_AC_EXPAND(INCLUDEDIR, "$includedir")
AS_AC_EXPAND(SYSCONFDIR, "$sysconfdir")
AS_AC_EXPAND(DATADIR, "$datadir")
AS_AC_EXPAND(LOCALSTATEDIR, "$localstatedir")
AS_AC_EXPAND(DOCDIR, "$docdir")
AS_AC_EXPAND(LXC_DEFAULT_CONF, "$defaultconf")
AS_AC_EXPAND(LXC_GENERATE_DATE, "$(date)")
AS_AC_EXPAND(LXCPATH, "$with_config_path")
AS_AC_EXPAND(LXC_GLOBAL_CONF, "$with_global_conf")
AS_AC_EXPAND(LXCROOTFSMOUNT, "$with_rootfs_path")
AS_AC_EXPAND(LXCTEMPLATEDIR, "$datadir/lxc/templates")
AS_AC_EXPAND(LXCINITDIR, "$libexecdir")
AS_AC_EXPAND(LOGPATH, "$with_log_path")

# Check for some standard kernel headers
AC_CHECK_HEADERS([linux/unistd.h linux/netlink.h linux/genetlink.h],
				[],
				AC_MSG_ERROR([Please install the Linux kernel headers.]),
				[#include <sys/socket.h>])

# Allow disabling libcap support
AC_ARG_ENABLE([capabilities],
	[AC_HELP_STRING([--disable-capabilities], [disable kernel capabilities])],
	[], [enable_capabilities=yes])

# Check for libcap support
if test "x$enable_capabilities" = "xyes"; then
	AC_CHECK_LIB(cap,cap_set_proc,caplib=yes,caplib=no)
	AC_MSG_CHECKING([linux capabilities])
	if test "x$caplib" = "xyes" ; then
		CAP_LIBS="-lcap"
		AC_MSG_RESULT([$CAP_LIBS])
	else
		AC_MSG_RESULT([no])
		AC_MSG_ERROR([You are missing libcap support. If you really want to build without kernel capabilities, use --disable-capabilities])
	fi
else
	CAP_LIBS=""
fi
AC_SUBST([CAP_LIBS])

# Check for alternate C libraries
AC_MSG_CHECKING(for bionic libc)
AC_COMPILE_IFELSE([AC_LANG_PROGRAM(
	[[#ifndef __ANDROID__
error: Not bionic!
#endif]])],
	[is_bionic=yes],
	[is_bionic=no])
if test "x$is_bionic" = "xyes"; then
	AC_DEFINE([IS_BIONIC], 1, [bionic libc])
	AC_MSG_RESULT([yes])
else
	AC_MSG_RESULT([no])
fi
AM_CONDITIONAL([IS_BIONIC], [test "x$is_bionic" = "xyes"])

# Some systems lack PR_CAPBSET_DROP definition => HAVE_DECL_PR_CAPBSET_DROP
AC_CHECK_DECLS([PR_CAPBSET_DROP], [], [], [#include <sys/prctl.h>])

# Check for some headers
AC_CHECK_HEADERS([sys/signalfd.h pty.h sys/capability.h sys/personality.h utmpx.h sys/timerfd.h])

# Check for some syscalls functions
AC_CHECK_FUNCS([setns pivot_root sethostname unshare])

# Check for some functions
AC_CHECK_LIB(util, openpty)
AC_CHECK_FUNCS([openpty hasmntopt setmntent endmntent])
AC_CHECK_FUNCS([getline],
	AM_CONDITIONAL(HAVE_GETLINE, true)
	AC_DEFINE(HAVE_GETLINE,1,[Have getline]),
	AM_CONDITIONAL(HAVE_GETLINE, false))
AC_CHECK_FUNCS([fgetln],
	AM_CONDITIONAL(HAVE_FGETLN, true)
	AC_DEFINE(HAVE_FGETLN,1,[Have fgetln]),
	AM_CONDITIONAL(HAVE_FGETLN, false))

# Check for some standard binaries
AC_PROG_GCC_TRADITIONAL
AC_PROG_SED

if test "x$GCC" = "xyes"; then
	CFLAGS="$CFLAGS -Wall -Werror"
fi

# Files requiring some variable expansion
AC_CONFIG_FILES([
	Makefile
	lxc.pc
	lxc.spec
	config/Makefile

	doc/Makefile
	doc/legacy/lxc-ls.sgml
	doc/lxc-attach.sgml
	doc/lxc-cgroup.sgml
	doc/lxc-checkconfig.sgml
	doc/lxc-checkpoint.sgml
	doc/lxc-clone.sgml
	doc/lxc-console.sgml
	doc/lxc-create.sgml
	doc/lxc-destroy.sgml
	doc/lxc-device.sgml
	doc/lxc-execute.sgml
	doc/lxc-freeze.sgml
	doc/lxc-info.sgml
	doc/lxc-kill.sgml
	doc/lxc-ls.sgml
	doc/lxc-monitor.sgml
	doc/lxc-netstat.sgml
	doc/lxc-ps.sgml
	doc/lxc-restart.sgml
	doc/lxc-shutdown.sgml
	doc/lxc-start-ephemeral.sgml
	doc/lxc-start.sgml
	doc/lxc-stop.sgml
	doc/lxc-top.sgml
	doc/lxc-unfreeze.sgml
	doc/lxc-unshare.sgml
	doc/lxc-version.sgml
	doc/lxc-wait.sgml

	doc/lxc.conf.sgml
	doc/lxc.sgml
	doc/common_options.sgml
	doc/see_also.sgml

	doc/rootfs/Makefile

	doc/examples/Makefile
	doc/examples/lxc-macvlan.conf
	doc/examples/lxc-vlan.conf
	doc/examples/lxc-no-netns.conf
	doc/examples/lxc-empty-netns.conf
	doc/examples/lxc-phys.conf
	doc/examples/lxc-veth.conf
	doc/examples/lxc-complex.conf

	templates/Makefile
	templates/lxc-lenny
	templates/lxc-debian
	templates/lxc-ubuntu
	templates/lxc-ubuntu-cloud
	templates/lxc-opensuse
	templates/lxc-busybox
	templates/lxc-fedora
	templates/lxc-oracle
	templates/lxc-altlinux
	templates/lxc-sshd
	templates/lxc-archlinux
	templates/lxc-alpine

	src/Makefile
	src/lxc/Makefile
	src/lxc/lxc-ps
	src/lxc/lxc-netstat
	src/lxc/lxc-checkconfig
	src/lxc/lxc-version
	src/lxc/lxc-create
	src/lxc/lxc-clone
	src/lxc/lxc-shutdown
	src/lxc/lxc-start-ephemeral
	src/lxc/lxc-destroy
	src/lxc/legacy/lxc-ls
	src/lxc/lxc.functions

	src/python-lxc/Makefile
	src/python-lxc/lxc/__init__.py
	src/python-lxc/examples/api_test.py

	src/lua-lxc/Makefile

	src/tests/Makefile
])
AC_CONFIG_COMMANDS([default],[[]],[[]])
AC_OUTPUT

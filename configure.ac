#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

m4_define([lxc_version_major], 2)
m4_define([lxc_version_minor], 0)
m4_define([lxc_version_micro], 0)
m4_define([lxc_version_beta], [])
m4_define([lxc_version_abi], 1.2.0)

m4_define([lxc_version_base], [lxc_version_major.lxc_version_minor.lxc_version_micro])
m4_define([lxc_version],
	  [ifelse(lxc_version_beta, [], [lxc_version_base], [lxc_version_base.lxc_version_beta])])

AC_INIT([lxc], [lxc_version])

# We need pkg-config
PKG_PROG_PKG_CONFIG

AC_SUBST(LXC_VERSION_BASE, lxc_version_base)
AC_SUBST(LXC_VERSION_BETA, lxc_version_beta)

AC_SUBST([LXC_VERSION_MAJOR], [lxc_version_major])
AC_SUBST([LXC_VERSION_MINOR], [lxc_version_minor])
AC_SUBST([LXC_VERSION_MICRO], [lxc_version_micro])
AC_SUBST([LXC_VERSION_ABI], [lxc_version_abi])
AC_SUBST([LXC_VERSION], [lxc_version])

AC_CONFIG_SRCDIR([configure.ac])
AC_CONFIG_AUX_DIR([config])
AC_CONFIG_HEADERS([src/config.h])
AM_INIT_AUTOMAKE([-Wall -Werror -Wno-portability subdir-objects])
AC_CANONICAL_HOST
AM_PROG_CC_C_O
AC_GNU_SOURCE

# Detect the distribution. This is used for the default configuration and
# for some distro-specific build options.
AC_MSG_CHECKING([host distribution])
AC_ARG_WITH(distro, AS_HELP_STRING([--with-distro=DISTRO], [Specify the Linux distribution to target: One of redhat, oracle, centos, fedora, suse, gentoo, debian, arch, slackware, plamo, paldo, openmandriva, pardus, sparclinux, altlinux.]))
if type lsb_release >/dev/null 2>&1 && test "z$with_distro" = "z"; then
	with_distro=`lsb_release -is`
fi
if test "z$with_distro" = "z"; then
	AC_CHECK_FILE(/etc/redhat-release,with_distro="redhat")
	AC_CHECK_FILE(/etc/oracle-release,with_distro="oracle")
	AC_CHECK_FILE(/etc/sparclinux-release,with_distro="sparclinux")
	AC_CHECK_FILE(/etc/centos-release,with_distro="centos")
	AC_CHECK_FILE(/etc/fedora-release,with_distro="fedora")
	AC_CHECK_FILE(/etc/SuSE-release,with_distro="suse")
	AC_CHECK_FILE(/etc/gentoo-release,with_distro="gentoo")
	AC_CHECK_FILE(/etc/debian_version,with_distro="debian")
	AC_CHECK_FILE(/etc/arch-release,with_distro="arch")
	AC_CHECK_FILE(/etc/slackware-version,with_distro="slackware")
	AC_CHECK_FILE(/etc/plamo-version,with_distro="plamo")
	AC_CHECK_FILE(/etc/frugalware-release,with_distro="frugalware")
	AC_CHECK_FILE(/etc/mandrakelinux-release, with_distro="openmandriva")
	AC_CHECK_FILE(/etc/mandriva-release,with_distro="openmandriva")
	AC_CHECK_FILE(/etc/pardus-release,with_distro="pardus")
	AC_CHECK_FILE(/etc/altlinux-release,with_distro="altlinux")
fi
with_distro=`echo ${with_distro} | tr '[[:upper:]]' '[[:lower:]]'`

if test "z$with_distro" = "zforsparc"; then
	with_distro="sparclinux"
fi

if test "z$with_distro" = "z"; then
	with_distro="unknown"
fi
case $with_distro in
	ubuntu|raspbian)
		distroconf=default.conf.lxcbr
		distrosysconf="$sysconfdir/default"
		;;
	redhat|centos|fedora|oracle|oracleserver|sparclinux|altlinux|suse|opensuse*|plamo)
		distroconf=default.conf.lxcbr
		distrosysconf="$sysconfdir/sysconfig"
		;;
	*)
		distroconf=default.conf.unknown
		distrosysconf="$sysconfdir/default"
		;;
esac
AC_MSG_RESULT([$with_distro])
AM_CONDITIONAL([HAVE_DEBIAN], [test x"$with_distro" = "xdebian" -o x"$with_distro" = "xubuntu" -o x"$with_distro" = "xraspbian"])
AM_CONDITIONAL([DISTRO_UBUNTU], [test "x$with_distro" = "xubuntu"])

AC_CONFIG_LINKS([config/etc/default.conf:config/etc/${distroconf}])

# Check for init system type
AC_MSG_CHECKING([for init system type])
AC_ARG_WITH([init-script],
	    [AC_HELP_STRING([--with-init-script@<:@=TYPE@<:@,TYPE,...@:>@@:>@],
			    [Type(s) of init script to install: sysvinit, systemd, upstart,
			     distro @<:@default=distro@:>@])],[],[with_init_script=distro])
case "$with_init_script" in
	distro)
		case $with_distro in
			fedora|altlinux|opensuse*)
				init_script=systemd
				;;
			redhat|centos|oracle|oracleserver|sparclinux|plamo)
				init_script=sysvinit
				;;
			debian|raspbian)
				init_script=upstart,systemd
				;;
			ubuntu)
				init_script=upstart,systemd
				;;
			*)
				echo -n "Linux distribution init system unknown."
				init_script=
				;;
		esac
		;;
	*)
		init_script=$with_init_script
		;;
esac

# Check valid init systems were given, run in subshell so we don't mess up IFS
(IFS="," ; for init_sys in $init_script;
do
	case "$init_sys" in
		none|sysvinit|systemd|upstart)
			;;
		*)
			exit 1
			;;
	esac
done) || AC_MSG_ERROR([Unknown init system type in $init_script])

AM_CONDITIONAL([INIT_SCRIPT_SYSV], [echo "$init_script" |grep -q "sysvinit"])
AM_CONDITIONAL([INIT_SCRIPT_SYSTEMD], [echo "$init_script" |grep -q "systemd"])
AM_CONDITIONAL([INIT_SCRIPT_UPSTART], [echo "$init_script" |grep -q "upstart"])
AC_MSG_RESULT($init_script)

# systemd unit dir
AC_ARG_WITH([systemdsystemunitdir],
            AS_HELP_STRING([--with-systemdsystemunitdir=DIR], [Directory for systemd service files]),
            [],
            [with_systemdsystemunitdir=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)])
if test -z "$with_systemdsystemunitdir"; then
  with_systemdsystemunitdir=/lib/systemd/system
fi
if test "x$with_systemdsystemunitdir" != "xno"; then
  AC_SUBST([SYSTEMD_UNIT_DIR], [$with_systemdsystemunitdir])
fi

# Allow enabling deprecated executables
AC_ARG_ENABLE([deprecated],
	[AC_HELP_STRING([--enable-deprecated],
	[enable deprecated executables [default=no]])],
	[], [enable_deprecated=false])
AM_CONDITIONAL([ENABLE_DEPRECATED], [test "x$enable_deprecated" = "xyes"])

# Allow disabling rpath
AC_ARG_ENABLE([rpath],
	[AC_HELP_STRING([--enable-rpath], [set rpath in executables [default=no]])],
	[], [enable_rpath=no])
AM_CONDITIONAL([ENABLE_RPATH], [test "x$enable_rpath" = "xyes"])

# Documentation (manpages)
AC_ARG_ENABLE([doc],
	[AC_HELP_STRING([--enable-doc], [make man pages [default=auto]])],
	[], [enable_doc=auto])

if test "x$enable_doc" = "xyes" -o "x$enable_doc" = "xauto"; then
	db2xman=""
	dbparsers="docbook2x-man db2x_docbook2man docbook2man docbook-to-man"

	AC_MSG_CHECKING(for docbook2x-man)
	for name in ${dbparsers}; do
		if "$name" --help >/dev/null 2>&1; then
			db2xman="$name"
			break;
		fi
	done

	if test -n "${db2xman}"; then
		AC_MSG_RESULT([${db2xman}])
		enable_doc="yes"
	else
		AC_MSG_RESULT([no])
		if test "x$enable_doc" = "xyes"; then
			AC_MSG_ERROR([docbook2x-man is required, but could not be found])
		fi
		enable_doc="no"
	fi

	AC_SUBST(db2xman)
fi
AM_CONDITIONAL([ENABLE_DOCBOOK], [test "x$db2xman" != "x"])
AM_CONDITIONAL([USE_DOCBOOK2X], [test "x$db2xman" != "xdocbook2man"])

if test "x$db2xman" = "xdocbook2man"; then
	docdtd="\"-//Davenport//DTD DocBook V3.0//EN\""
else
	docdtd="\"-//OASIS//DTD DocBook XML\" \"http://www.oasis-open.org/docbook/xml/4.5/docbookx.dtd\""
fi
AC_SUBST(docdtd)

# Documentation (API)
AC_ARG_ENABLE([api-docs],
	[AC_HELP_STRING([--enable-api-docs],
	[make API documentation [default=auto]])],
	[], [enable_api_docs=auto])

if test "x$enable_api_docs" = "xyes" -o "x$enable_api_docs" = "xauto"; then
	AC_CHECK_PROGS([HAVE_DOXYGEN],[doxygen])
	AC_SUBST([HAVE_DOXYGEN])

	if test "x$HAVE_DOXYGEN" != "x"; then
		enable_api_docs="yes"
	else
		if test "x$enable_api_docs" = "xyes"; then
			AC_MSG_ERROR([doxygen is required, but could not be found])
		fi
		enable_api_docs="no"
	fi
fi

AM_CONDITIONAL([ENABLE_API_DOCS], [test "x$HAVE_DOXYGEN" != "x"])

# Apparmor
AC_ARG_ENABLE([apparmor],
	[AC_HELP_STRING([--enable-apparmor], [enable apparmor support [default=auto]])],
	[], [enable_apparmor=auto])

if test "$enable_apparmor" = "auto" ; then
	AC_CHECK_LIB([apparmor],[aa_change_profile],[enable_apparmor=yes], [enable_apparmor=no])
fi
AM_CONDITIONAL([ENABLE_APPARMOR], [test "x$enable_apparmor" = "xyes"])

AC_CHECK_LIB([gnutls], [gnutls_hash_fast], [enable_gnutls=yes], [enable_gnutls=no])

AM_COND_IF([ENABLE_APPARMOR],
	[AC_CHECK_HEADER([sys/apparmor.h],[],[AC_MSG_ERROR([You must install the AppArmor development package in order to compile lxc])])
	AC_CHECK_LIB([apparmor], [aa_change_profile],[],[AC_MSG_ERROR([You must install the AppArmor development package in order to compile lxc])])
	AC_SUBST([APPARMOR_LIBS], [-lapparmor])])

# SELinux
AC_ARG_ENABLE([selinux],
	[AC_HELP_STRING([--enable-selinux], [enable SELinux support [default=auto]])],
	[], [enable_selinux=auto])

if test "x$enable_selinux" = xauto; then
	AC_CHECK_LIB([selinux],[setexeccon_raw],[enable_selinux=yes],[enable_selinux=no])
fi
AM_CONDITIONAL([ENABLE_SELINUX], [test "x$enable_selinux" = "xyes"])
AM_COND_IF([ENABLE_SELINUX],
	[AC_CHECK_HEADER([selinux/selinux.h],[],[AC_MSG_ERROR([You must install the SELinux development package in order to compile lxc])])
	AC_CHECK_LIB([selinux], [setexeccon_raw],[true],[AC_MSG_ERROR([You must install the SELinux development package in order to compile lxc])])
	AC_SUBST([SELINUX_LIBS], [-lselinux])])

# Seccomp syscall filter
AC_ARG_ENABLE([seccomp],
	[AC_HELP_STRING([--enable-seccomp], [enable seccomp support [default=auto]])],
	[], [enable_seccomp=auto])

if test "x$enable_seccomp" = "xauto" ; then
	AC_CHECK_LIB([seccomp],[seccomp_init],[enable_seccomp=yes],[enable_seccomp=no])
fi
AM_CONDITIONAL([ENABLE_SECCOMP], [test "x$enable_seccomp" = "xyes"])

AM_COND_IF([ENABLE_SECCOMP],
	[PKG_CHECK_MODULES([SECCOMP],[libseccomp],[],[
		AC_CHECK_HEADER([seccomp.h],[],[AC_MSG_ERROR([You must install the seccomp development package in order to compile lxc])])
		AC_CHECK_LIB([seccomp], [seccomp_init],[],[AC_MSG_ERROR([You must install the seccomp development package in order to compile lxc])])
		AC_SUBST([SECCOMP_LIBS], [-lseccomp])
		])
	])

# cgmanager
AC_ARG_ENABLE([cgmanager],
	[AC_HELP_STRING([--enable-cgmanager], [enable cgmanager support [default=auto]])],
	[], [enable_cgmanager=auto])

if test "x$enable_cgmanager" = "xauto" ; then
	AC_CHECK_LIB([cgmanager],[cgmanager_create],[enable_cgmanager=yes],[enable_cgmanager=no],[-lnih -lnih-dbus -ldbus-1])
fi
AM_CONDITIONAL([ENABLE_CGMANAGER], [test "x$enable_cgmanager" = "xyes"])

AM_COND_IF([ENABLE_CGMANAGER],
	[PKG_CHECK_MODULES([CGMANAGER], [libcgmanager])
	PKG_CHECK_MODULES([NIH], [libnih >= 1.0.2])
	PKG_CHECK_MODULES([NIH_DBUS], [libnih-dbus >= 1.0.0])
	PKG_CHECK_MODULES([DBUS], [dbus-1 >= 1.2.16])
	])

AC_MSG_CHECKING(for get_pid_cgroup_abs_sync)
save_LIBS=$LIBS
AC_SEARCH_LIBS([cgmanager_get_pid_cgroup_abs_sync], [cgmanager], [have_abs_cgroups=yes], [have_abs_cgroups=no], [-lnih -lnih-dbus -ldbus-1])
LIBS=$save_LIBS
if test "x$have_abs_cgroups" = "xyes"; then
	AC_DEFINE([HAVE_CGMANAGER_GET_PID_CGROUP_ABS_SYNC], 1, [Have cgmanager_get_pid_cgroup_abs_sync])
	AC_MSG_RESULT([yes])
else
	AC_MSG_RESULT([no])
fi

AC_MSG_CHECKING(for cgmanager_list_controllers)
save_LIBS=$LIBS
AC_SEARCH_LIBS([cgmanager_list_controllers_sync], [cgmanager], [have_list_controllers=yes], [have_list_controllers=no], [-lnih -lnih-dbus -ldbus-1])
LIBS=$save_LIBS
if test "x$have_list_controllers" = "xyes"; then
	AC_DEFINE([HAVE_CGMANAGER_LIST_CONTROLLERS], 1, [Have cgmanager_list_controllers])
	AC_MSG_RESULT([yes])
else
	AC_MSG_RESULT([no])
fi

# Check for static libcap, make sure the function checked for differs from the
# the one checked below so the cache doesn't give a wrong answer
OLD_CFLAGS="$CFLAGS"
CFLAGS="$CFLAGS -static"
AC_CHECK_LIB([cap],[cap_init],[have_static_libcap=yes],[have_static_libcap=no])
AM_CONDITIONAL([HAVE_STATIC_LIBCAP], [test "x$have_static_libcap" = "xyes"])
if test "x$have_static_libcap" = "xyes"; then
	AC_DEFINE([HAVE_STATIC_LIBCAP], 1, [Have static libcap])
fi
CFLAGS="$OLD_CFLAGS"


# Linux capabilities
AC_ARG_ENABLE([capabilities],
	[AC_HELP_STRING([--enable-capabilities], [enable kernel capabilities support [default=auto]])],
	[], [enable_capabilities=auto])

if test "x$enable_capabilities" = "xauto"; then
	AC_CHECK_LIB([cap],[cap_set_proc],[enable_capabilities=yes],[enable_capabilities=no])
fi
AM_CONDITIONAL([ENABLE_CAP], [test "x$enable_capabilities" = "xyes"])

AM_COND_IF([ENABLE_CAP],
	[AC_CHECK_LIB(cap,cap_set_proc,[true],[AC_MSG_ERROR([You are missing libcap support.])])
	AC_SUBST([CAP_LIBS], [-lcap])])

# HAVE_SCMP_FILTER_CTX=1 will tell us we have libseccomp api >= 1.0.0
OLD_CFLAGS="$CFLAGS"
CFLAGS="$CFLAGS $SECCOMP_CFLAGS"
AC_CHECK_TYPES([scmp_filter_ctx], [], [], [[#include <seccomp.h>]])
AC_CHECK_DECLS([seccomp_syscall_resolve_name_arch], [], [], [[#include <seccomp.h>]])
CFLAGS="$OLD_CFLAGS"

# Configuration examples
AC_ARG_ENABLE([examples],
	[AC_HELP_STRING([--enable-examples], [install examples [default=yes]])],
	[], [enable_examples=yes])
AM_CONDITIONAL([ENABLE_EXAMPLES], [test "x$enable_examples" = "xyes"])

# Python3 module and scripts
AC_ARG_ENABLE([python],
	[AC_HELP_STRING([--enable-python], [enable python binding [default=auto]])],
	[], [enable_python=auto])

if test "x$enable_python" = "xauto"; then
	PKG_CHECK_MODULES([PYTHONDEV], [python3 >= 3.2],[enable_python=yes],[enable_python=no])
	if test "$CC" = "clang"; then
		enable_python=no
	fi
fi

if test "x$enable_python" = "xyes" && test "$CC" = "clang"; then
	AC_MSG_ERROR([Python3 is incompatible with the clang compiler])
fi

AM_CONDITIONAL([ENABLE_PYTHON], [test "x$enable_python" = "xyes"])

AM_COND_IF([ENABLE_PYTHON],
	[AM_PATH_PYTHON([3.2], [], [AC_MSG_ERROR([You must install python3])])
	PKG_CHECK_MODULES([PYTHONDEV], [python3 >= 3.2],[],[AC_MSG_ERROR([You must install python3-dev])])
	AC_DEFINE_UNQUOTED([ENABLE_PYTHON], 1, [Python3 is available])])

# Enable dumping stack traces
AC_ARG_ENABLE([mutex-debugging],
	[AC_HELP_STRING([--enable-mutex-debugging], [Makes mutexes to report error and provide stack trace [default=no]])],
	[], [enable_mutex_debugging=no])
AM_CONDITIONAL([MUTEX_DEBUGGING], [test "x$enable_mutex_debugging" = "xyes"])

AM_COND_IF([MUTEX_DEBUGGING],
	AC_DEFINE_UNQUOTED([MUTEX_DEBUGGING], 1, [Enabling mutex debugging]))

# Not in older autoconf versions
# AS_VAR_COPY(DEST, SOURCE)
# -------------------------
# Set the polymorphic shell variable DEST to the contents of the polymorphic
# shell variable SOURCE.
m4_ifdef([AS_VAR_COPY], [],
[AC_DEFUN([AS_VAR_COPY],
    [AS_LITERAL_IF([$1[]$2], [$1=$$2], [eval $1=\$$2])])
])

dnl PKG_CHECK_VAR was introduced with pkg-config 0.28
m4_ifdef([PKG_CHECK_VAR], [],
[AC_DEFUN([PKG_CHECK_VAR],
    [AC_REQUIRE([PKG_PROG_PKG_CONFIG])dnl
     AC_ARG_VAR([$1], [value of $3 for $2, overriding pkg-config])dnl
     _PKG_CONFIG([$1], [variable="][$3]["], [$2])
     AS_VAR_COPY([$1], [pkg_cv_][$1])
     AS_VAR_IF([$1], [""], [$5], [$4])dnl
    ])# PKG_CHECK_VAR
])

# Lua module and scripts
AC_ARG_ENABLE([lua],
	[AC_HELP_STRING([--enable-lua], [enable lua binding [default=auto]])],
	[], [enable_lua=auto])

AC_ARG_WITH([lua-pc],
	[AS_HELP_STRING(
		[--with-lua-pc=PKG],
		[Specify pkg-config package name for lua]
	)], [], [with_lua_pc=no])

if test "x$enable_lua" = "xyes" -a "x$with_lua_pc" != "xno"; then
	# exit with error if not found
	PKG_CHECK_MODULES([LUA], [$with_lua_pc], [LUAPKGCONFIG=$with_lua_pc])
fi

if test "x$enable_lua" = "xauto" -a "x$with_lua_pc" != "xno"; then
	PKG_CHECK_MODULES([LUA], [$with_lua_pc],
		[LUAPKGCONFIG=$with_lua_pc
		enable_lua=yes],
		[enable_lua=no])
fi

if test "x$enable_lua" != "xno"; then
	PKG_CHECK_MODULES([LUA], [lua], [LUAPKGCONFIG=lua],
		[PKG_CHECK_MODULES([LUA], [lua5.2], [LUAPKGCONFIG=lua5.2],
			[PKG_CHECK_MODULES([LUA], [lua5.1], [LUAPKGCONFIG=lua5.1],
				[AS_IF([test "x$enable_lua" = "xyes"],
					[AC_MSG_ERROR([Lua not found. Please use --with-lua-pc=PKG])],
					[enable_lua=no])]
			)]
		)])
	AS_IF([test "x$LUAPKGCONFIG" != "x"], [enable_lua=yes])
fi

AM_CONDITIONAL([ENABLE_LUA],
	[test "x$enable_lua" = "xyes"])

AM_COND_IF([ENABLE_LUA],
	[AC_MSG_CHECKING([Lua version])
	PKG_CHECK_VAR([LUA_VERSION], [$LUAPKGCONFIG], [V],,
		[PKG_CHECK_VAR([LUA_VERSION], [$LUAPKGCONFIG], [major_version])])
	AC_MSG_RESULT([$LUA_VERSION])
	AC_SUBST([LUA_LIBDIR], [$libdir/lua/$LUA_VERSION])
	AC_SUBST([LUA_SHAREDIR], [$datadir/lua/$LUA_VERSION])
	])

# Optional bash integration
AC_ARG_ENABLE([bash],
	[AC_HELP_STRING([--enable-bash], [build bash integration [default=yes]])],
	[], [enable_bash=yes])
AM_CONDITIONAL([ENABLE_BASH], [test "x$enable_bash" = "xyes"])

# Optional test binaries
AC_ARG_ENABLE([tests],
	[AC_HELP_STRING([--enable-tests], [build test/example binaries [default=no]])],
	[], [enable_tests=no])
AM_CONDITIONAL([ENABLE_TESTS], [test "x$enable_tests" = "xyes"])

# Allow overriding the default runtime dir (/run)
AC_ARG_WITH([runtime-path],
	[AC_HELP_STRING(
		[--with-runtime-path=dir],
		[runtime directory (default: /run)]
	)], [], [with_runtime_path=['/run']])

# LXC container path, where the containers are actually stored
# This is overridden by an entry in the file called LXCCONF
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

# The path of the userns network configuration file
AC_ARG_WITH([usernic-conf],
	[AC_HELP_STRING(
		[--with-usernic-conf],
		[user network interface configuration file]
	)], [], [with_usernic_conf=['${sysconfdir}/lxc/lxc-usernet']])

# The path of the runtime usernic database
AC_ARG_WITH([usernic-db],
	[AC_HELP_STRING(
		[--with-usernic-db],
		[lxc user nic database]
	)], [], [with_usernic_db=['${with_runtime_path}/lxc/nics']])

# Rootfs path, where the container mount structure is assembled
AC_ARG_WITH([rootfs-path],
	[AC_HELP_STRING(
		[--with-rootfs-path=dir],
		[lxc rootfs mount point]
	)], [], [with_rootfs_path=['${libdir}/lxc/rootfs']])

# cgroup pattern specification
AC_ARG_WITH([cgroup-pattern],
	[AC_HELP_STRING(
		[--with-cgroup-pattern=pattern],
		[pattern for container cgroups]
	)], [], [with_cgroup_pattern=['/lxc/%n']])

# Container log path.  By default, use $lxcpath.
AC_MSG_CHECKING([Whether to place logfiles in container config path])
AC_ARG_ENABLE([configpath-log],
	[AC_HELP_STRING([--enable-configpath-log], [use logfiles in config path [default=no]])],
	[], [enable_configpath_log=no])
AC_MSG_RESULT([$enable_configpath_log])
AM_CONDITIONAL([USE_CONFIGPATH_LOGS], [test "$enable_configpath_log" = "yes"])

if test "$enable_configpath_log" = "yes"; then
	default_log_path="${with_config_path}"
else
	default_log_path="${localstatedir}/log/lxc"
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
AS_AC_EXPAND(SBINDIR, "$sbindir")
AS_AC_EXPAND(LIBEXECDIR, "$libexecdir")
AS_AC_EXPAND(INCLUDEDIR, "$includedir")
AS_AC_EXPAND(SYSCONFDIR, "$sysconfdir")
AS_AC_EXPAND(LXC_DEFAULT_CONFIG, "$sysconfdir/lxc/default.conf")
AS_AC_EXPAND(DATADIR, "$datadir")
AS_AC_EXPAND(LOCALSTATEDIR, "$localstatedir")
AS_AC_EXPAND(DOCDIR, "$docdir")
AS_AC_EXPAND(LXC_GENERATE_DATE, "$(date --utc --date=@${SOURCE_DATE_EPOCH:-$(date +%s)} '+%Y-%m-%d')")
AS_AC_EXPAND(LXCPATH, "$with_config_path")
AS_AC_EXPAND(LXC_GLOBAL_CONF, "$with_global_conf")
AS_AC_EXPAND(LXC_USERNIC_CONF, "$with_usernic_conf")
AS_AC_EXPAND(LXC_USERNIC_DB, "$with_usernic_db")
AS_AC_EXPAND(LXC_DISTRO_SYSCONF, "$distrosysconf")
AS_AC_EXPAND(LXCROOTFSMOUNT, "$with_rootfs_path")
AS_AC_EXPAND(LXCTEMPLATEDIR, "$datadir/lxc/templates")
AS_AC_EXPAND(LXCTEMPLATECONFIG, "$datadir/lxc/config")
AS_AC_EXPAND(LXCHOOKDIR, "$datadir/lxc/hooks")
AS_AC_EXPAND(LXCBINHOOKDIR, "$libexecdir/lxc/hooks")
AS_AC_EXPAND(LXCINITDIR, "$libexecdir")
AS_AC_EXPAND(LOGPATH, "$with_log_path")
AS_AC_EXPAND(RUNTIME_PATH, "$with_runtime_path")
AC_SUBST(DEFAULT_CGROUP_PATTERN, ["$with_cgroup_pattern"])

# We need the install path so criu knows where to reference the hook scripts.
AC_DEFINE_UNQUOTED([DATADIR], "$DATADIR", ["Prefix for shared files."])

# Check for some standard kernel headers
AC_CHECK_HEADERS([linux/unistd.h linux/netlink.h linux/genetlink.h],
				[],
				AC_MSG_ERROR([Please install the Linux kernel headers.]),
				[#include <sys/socket.h>])

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
AC_CHECK_HEADERS([sys/signalfd.h pty.h ifaddrs.h sys/capability.h sys/personality.h utmpx.h sys/timerfd.h])

# Check for some syscalls functions
AC_CHECK_FUNCS([setns pivot_root sethostname unshare rand_r confstr faccessat])

# Check for some functions
AC_CHECK_LIB(pthread, main)
AC_CHECK_FUNCS(pthread_atfork)
AC_CHECK_FUNCS(statvfs)
AC_CHECK_LIB(util, openpty)
AC_CHECK_FUNCS([openpty hasmntopt setmntent endmntent utmpxname])
AC_CHECK_FUNCS([getline],
	AM_CONDITIONAL(HAVE_GETLINE, true)
	AC_DEFINE(HAVE_GETLINE,1,[Have getline]),
	AM_CONDITIONAL(HAVE_GETLINE, false))
AC_CHECK_FUNCS([getsubopt],
	AM_CONDITIONAL(HAVE_GETSUBOPT, true)
	AC_DEFINE(HAVE_GETSUBOPT,1,[Have getsubopt]),
	AM_CONDITIONAL(HAVE_GETSUBOPT, false))
AC_CHECK_FUNCS([fgetln],
	AM_CONDITIONAL(HAVE_FGETLN, true)
	AC_DEFINE(HAVE_FGETLN,1,[Have fgetln]),
	AM_CONDITIONAL(HAVE_FGETLN, false))

# Check for some libraries
AC_SEARCH_LIBS(sem_open, [rt pthread])
AC_SEARCH_LIBS(clock_gettime, [rt])

# Check for some standard binaries
AC_PROG_GCC_TRADITIONAL
AC_PROG_SED

# See if we support thread-local storage.
LXC_CHECK_TLS

if test "x$GCC" = "xyes"; then
	CFLAGS="$CFLAGS -Wall -Werror"
fi

# Files requiring some variable expansion
AC_CONFIG_FILES([
	Makefile
	lxc.pc
	lxc.spec

	config/Makefile
	config/apparmor/Makefile
	config/selinux/Makefile
	config/bash/Makefile
	config/bash/lxc
	config/init/Makefile
	config/init/common/Makefile
	config/init/common/lxc-containers
	config/init/common/lxc-net
	config/init/systemd/Makefile
	config/init/systemd/lxc.service
	config/init/systemd/lxc@.service
	config/init/systemd/lxc-net.service
	config/init/sysvinit/Makefile
	config/init/sysvinit/lxc-containers
	config/init/sysvinit/lxc-net
	config/init/upstart/lxc.conf
	config/init/upstart/lxc-net.conf
	config/init/upstart/Makefile
	config/etc/Makefile
	config/templates/Makefile
	config/templates/alpine.common.conf
	config/templates/alpine.userns.conf
	config/templates/archlinux.common.conf
	config/templates/archlinux.userns.conf
	config/templates/centos.common.conf
	config/templates/centos.userns.conf
	config/templates/common.conf
	config/templates/common.conf.d/Makefile
	config/templates/debian.common.conf
	config/templates/debian.userns.conf
	config/templates/fedora.common.conf
	config/templates/fedora.userns.conf
	config/templates/gentoo.common.conf
	config/templates/gentoo.moresecure.conf
	config/templates/gentoo.userns.conf
	config/templates/nesting.conf
	config/templates/opensuse.common.conf
	config/templates/opensuse.userns.conf
	config/templates/oracle.common.conf
	config/templates/oracle.userns.conf
	config/templates/plamo.common.conf
	config/templates/plamo.userns.conf
	config/templates/slackware.common.conf
	config/templates/slackware.userns.conf
	config/templates/ubuntu-cloud.common.conf
	config/templates/ubuntu-cloud.lucid.conf
	config/templates/ubuntu-cloud.userns.conf
	config/templates/ubuntu.common.conf
	config/templates/ubuntu.lucid.conf
	config/templates/ubuntu.userns.conf
	config/templates/openwrt.common.conf
	config/templates/sparclinux.common.conf
	config/templates/sparclinux.userns.conf
	config/templates/userns.conf
	config/yum/Makefile
	config/sysconfig/Makefile
	config/sysconfig/lxc

	doc/Makefile
	doc/api/Makefile
	doc/lxc-attach.sgml
	doc/lxc-autostart.sgml
	doc/lxc-cgroup.sgml
	doc/lxc-checkconfig.sgml
	doc/lxc-checkpoint.sgml
	doc/lxc-clone.sgml
	doc/lxc-config.sgml
	doc/lxc-console.sgml
	doc/lxc-copy.sgml
	doc/lxc-create.sgml
	doc/lxc-destroy.sgml
	doc/lxc-device.sgml
	doc/lxc-execute.sgml
	doc/lxc-freeze.sgml
	doc/lxc-info.sgml
	doc/lxc-ls.sgml
	doc/lxc-monitor.sgml
	doc/lxc-snapshot.sgml
	doc/lxc-start-ephemeral.sgml
	doc/lxc-start.sgml
	doc/lxc-stop.sgml
	doc/lxc-top.sgml
	doc/lxc-unfreeze.sgml
	doc/lxc-unshare.sgml
	doc/lxc-user-nic.sgml
	doc/lxc-usernsexec.sgml
	doc/lxc-wait.sgml

	doc/lxc.conf.sgml
	doc/lxc.container.conf.sgml
	doc/lxc.system.conf.sgml
	doc/lxc-usernet.sgml
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

	doc/ja/Makefile
	doc/ja/lxc-attach.sgml
	doc/ja/lxc-autostart.sgml
	doc/ja/lxc-cgroup.sgml
	doc/ja/lxc-checkconfig.sgml
	doc/ja/lxc-checkpoint.sgml
	doc/ja/lxc-clone.sgml
	doc/ja/lxc-config.sgml
	doc/ja/lxc-console.sgml
	doc/ja/lxc-copy.sgml
	doc/ja/lxc-create.sgml
	doc/ja/lxc-destroy.sgml
	doc/ja/lxc-device.sgml
	doc/ja/lxc-execute.sgml
	doc/ja/lxc-freeze.sgml
	doc/ja/lxc-info.sgml
	doc/ja/lxc-ls.sgml
	doc/ja/lxc-monitor.sgml
	doc/ja/lxc-snapshot.sgml
	doc/ja/lxc-start-ephemeral.sgml
	doc/ja/lxc-start.sgml
	doc/ja/lxc-stop.sgml
	doc/ja/lxc-top.sgml
	doc/ja/lxc-unfreeze.sgml
	doc/ja/lxc-unshare.sgml
	doc/ja/lxc-user-nic.sgml
	doc/ja/lxc-usernsexec.sgml
	doc/ja/lxc-wait.sgml

	doc/ja/lxc.conf.sgml
	doc/ja/lxc.container.conf.sgml
	doc/ja/lxc.system.conf.sgml
	doc/ja/lxc-usernet.sgml
	doc/ja/lxc.sgml
	doc/ja/common_options.sgml
	doc/ja/see_also.sgml

	doc/ko/Makefile
	doc/ko/lxc-attach.sgml
	doc/ko/lxc-autostart.sgml
	doc/ko/lxc-cgroup.sgml
	doc/ko/lxc-checkconfig.sgml
	doc/ko/lxc-checkpoint.sgml
	doc/ko/lxc-clone.sgml
	doc/ko/lxc-config.sgml
	doc/ko/lxc-console.sgml
	doc/ko/lxc-copy.sgml
	doc/ko/lxc-create.sgml
	doc/ko/lxc-destroy.sgml
	doc/ko/lxc-device.sgml
	doc/ko/lxc-execute.sgml
	doc/ko/lxc-freeze.sgml
	doc/ko/lxc-info.sgml
	doc/ko/lxc-ls.sgml
	doc/ko/lxc-monitor.sgml
	doc/ko/lxc-snapshot.sgml
	doc/ko/lxc-start-ephemeral.sgml
	doc/ko/lxc-start.sgml
	doc/ko/lxc-stop.sgml
	doc/ko/lxc-top.sgml
	doc/ko/lxc-unfreeze.sgml
	doc/ko/lxc-unshare.sgml
	doc/ko/lxc-user-nic.sgml
	doc/ko/lxc-usernsexec.sgml
	doc/ko/lxc-wait.sgml

	doc/ko/lxc.conf.sgml
	doc/ko/lxc.container.conf.sgml
	doc/ko/lxc.system.conf.sgml
	doc/ko/lxc-usernet.sgml
	doc/ko/lxc.sgml
	doc/ko/common_options.sgml
	doc/ko/see_also.sgml

	hooks/Makefile

	templates/Makefile
	templates/lxc-alpine
	templates/lxc-altlinux
	templates/lxc-archlinux
	templates/lxc-busybox
	templates/lxc-centos
	templates/lxc-cirros
	templates/lxc-debian
	templates/lxc-download
	templates/lxc-fedora
	templates/lxc-gentoo
	templates/lxc-openmandriva
	templates/lxc-opensuse
	templates/lxc-oracle
	templates/lxc-plamo
	templates/lxc-slackware
	templates/lxc-sshd
	templates/lxc-ubuntu
	templates/lxc-ubuntu-cloud
	templates/lxc-sparclinux

	src/Makefile
	src/lxc/Makefile
	src/lxc/lxc-checkconfig
	src/lxc/lxc-start-ephemeral
	src/lxc/lxc.functions
	src/lxc/version.h
	src/python-lxc/Makefile

	src/lua-lxc/Makefile

	src/tests/Makefile
	src/tests/lxc-test-usernic
])
AC_CONFIG_COMMANDS([default],[[]],[[]])
AC_OUTPUT

# Configuration overview
cat << EOF

----------------------------
Environment:
 - compiler: $CC
 - distribution: $with_distro
 - init script type(s): $init_script
 - rpath: $enable_rpath
 - GnuTLS: $enable_gnutls
 - Bash integration: $enable_bash

Security features:
 - Apparmor: $enable_apparmor
 - Linux capabilities: $enable_capabilities
 - seccomp: $enable_seccomp
 - SELinux: $enable_selinux
 - cgmanager: $enable_cgmanager

Bindings:
 - lua: $enable_lua
 - python3: $enable_python

Documentation:
 - examples: $enable_examples
 - API documentation: $enable_api_docs
 - user documentation: $enable_doc

Debugging:
 - tests: $enable_tests
 - mutex debugging: $enable_mutex_debugging

Paths:
 - Logs in configpath: $enable_configpath_log
EOF

if test "x$ac_cv_func_pthread_atfork" = "xno" ; then
cat << EOF

WARNING: Threading not supported on your platform

	You are compiling LXC for bionic target which lacks certain threading related functionality used by LXC API (like pthread_atfork).
	Please note that, because of the missing functionality, multithreaded usage of LXC API cause some problems.
EOF
fi

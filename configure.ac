#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_INIT([lxc], [0.6.3])

AC_CONFIG_SRCDIR([configure.ac])
AC_CONFIG_AUX_DIR([config])
AM_CONFIG_HEADER([src/config.h])
AM_INIT_AUTOMAKE([-Wno-portability])
AC_CANONICAL_HOST
AM_PROG_CC_C_O
AC_GNU_SOURCE
AC_PROG_LIBTOOL
AC_CHECK_PROG(SETCAP, setcap, yes, no, $PATH$PATH_SEPARATOR/sbin)
AC_CHECK_PROG(DOCBOOK, docbook2man, yes, no)
AM_CONDITIONAL(ENABLE_DOCBOOK, test x$DOCBOOK = xyes)
AS_AC_EXPAND(PREFIX, $prefix)
AS_AC_EXPAND(LIBDIR, $libdir)
AS_AC_EXPAND(BINDIR, $bindir)
AS_AC_EXPAND(INCLUDEDIR, $includedir)
AS_AC_EXPAND(LIBEXECDIR, $libexecdir)
AS_AC_EXPAND(SYSCONFDIR, $sysconfdir)
AS_AC_EXPAND(DATADIR, $datadir)
AS_AC_EXPAND(LOCALSTATEDIR, $localstatedir)
AS_AC_EXPAND(LXCPATH, "${localstatedir}/lib/lxc")
AS_AC_EXPAND(LXC_GENERATE_DATE, "$(date)")

AC_CHECK_HEADERS([linux/netlink.h linux/genetlink.h], [], AC_MSG_ERROR([netlink headers not found. Please install the linux kernel headers.]),
[#include <linux/types.h>
#include <bits/sockaddr.h>
#include <linux/socket.h>])

AC_CHECK_HEADERS([sys/capability.h], [], AC_MSG_ERROR([please install libcap-devel.]),
[#include <sys/types.h>
#include <sys/capability.h>])

# Some systems lack PR_CAPBSET_DROP definition => HAVE_DECL_PR_CAPBSET_DROP
AC_CHECK_DECLS([PR_CAPBSET_DROP], [], [], [#include <sys/prctl.h>])

AC_CHECK_HEADERS([sys/signalfd.h])

AC_PROG_GCC_TRADITIONAL

if test "x$GCC" = "xyes"; then
  CFLAGS="$CFLAGS -Wall"
fi

LXC_MAJOR_VERSION=$(echo $PACKAGE_VERSION | cut -d. -f1)
LXC_MINOR_VERSION=$(echo $PACKAGE_VERSION | cut -d. -f2)
LXC_MICRO_VERSION=$(echo $PACKAGE_VERSION | cut -d. -f3)

AC_ARG_WITH([kernel-release],
 [AC_HELP_STRING([--with-kernel-release=RELEASE],
		[specify the "uname -r"-value to build for])],
	[KERNEL_RELEASE="${withval}"],
	[KERNEL_RELEASE=`uname -r`])

AC_ARG_ENABLE(test, [  --enable-test    compile test program [default=no]],, enable_test=no)
AM_CONDITIONAL(ENABLE_TEST, test x$enable_test = xyes)

AC_SUBST(LXC_MAJOR_VERSION)
AC_SUBST(LXC_MINOR_VERSION)
AC_SUBST(LXC_MICRO_VERSION)

AC_CONFIG_FILES([
        Makefile
	lxc.pc
	lxc.spec
        config/Makefile

        doc/Makefile
	doc/lxc-create.sgml
	doc/lxc-destroy.sgml
	doc/lxc-execute.sgml
	doc/lxc-start.sgml
	doc/lxc-stop.sgml
	doc/lxc-console.sgml
	doc/lxc-freeze.sgml
	doc/lxc-unfreeze.sgml
	doc/lxc-monitor.sgml
	doc/lxc-wait.sgml
	doc/lxc-ls.sgml
	doc/lxc-ps.sgml
	doc/lxc-cgroup.sgml
	doc/lxc.conf.sgml
	doc/lxc.sgml
	doc/common_options.sgml
	doc/see_also.sgml

	scripts/Makefile
	scripts/lxc-debian
	scripts/lxc-fedora
	scripts/lxc-sshd

        src/Makefile
	src/lxc/Makefile
	src/lxc/lxc-ps
	src/lxc/lxc-ls
	src/lxc/lxc-netstat
	src/lxc/lxc-checkconfig
	src/lxc/lxc-setcap
	src/lxc/lxc-version

	etc/Makefile
	etc/lxc-macvlan.conf
	etc/lxc-no-netns.conf
	etc/lxc-empty-netns.conf
	etc/lxc-phys.conf
	etc/lxc-veth.conf
	etc/lxc-complex-config

	test/Makefile
])
AC_CONFIG_COMMANDS([default],[[]],[[]])
AC_OUTPUT

if test "x$DOCBOOK" = "xno"; then
   AC_MSG_NOTICE([

Warning:
--------
The docbook tool is not installed, the man pages won't be generated.
If you want the man pages, install docbook and rerun 'configure'.

])

fi

if test "x$SETCAP" = "xno"; then
   AC_MSG_NOTICE([

Warning:
--------

The setcap binary was not found. This means the tools to set the
privilege for the lxc commands are not available, that's ok, but you
will need to run these commands as root or install libcap-2.

])

else

   AC_MSG_NOTICE([

Advice:
-------

If you wish to have a non root user to use the lxc tools,
you can add the needed capabilities to the tools by invoking
the 'lxc-setcap' script. To remove the capabilities, use
'lxc-setcap -d'.
])

fi

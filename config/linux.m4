AC_DEFUN([AC_LINUX],
[
	AC_LINUX_DIR()
	AC_LINUX_SRCARCH()
])

AC_DEFUN([AS_TRY_LINUX_DIR],
	[AC_MSG_CHECKING(for Linux in $1)

	if test -f "$1/Makefile" ; then
		result=yes
		$2
	else
		result="not found"
		$3
	fi

	AC_MSG_RESULT($result)
])

AC_DEFUN([AC_LINUX_DIR],
[
	AC_ARG_WITH([linuxdir],
		[AC_HELP_STRING([--with-linuxdir=DIR],
			[specify path to Linux source directory])],
		[LINUX_DIR="${withval}"],
		[LINUX_DIR=default])

	dnl if specified, use the specified one
	if test "${LINUX_DIR}" != "default" ; then
		AS_TRY_LINUX_DIR([${LINUX_DIR}], , AC_MSG_ERROR([Linux dir not found]) )
	fi

	dnl if not specified, first try with previously set LINUX_KERNEL_RELEASE
	if test "${LINUX_DIR}" = "default" ; then
		dir="/lib/modules/$LINUX_KERNEL_RELEASE/build";
		AS_TRY_LINUX_DIR([${dir}], [LINUX_DIR=${dir}], )
	fi

	dnl next try using the kernel source dir
	if test "${LINUX_DIR}" = "default" ; then
		dir="/usr/src/linux-$LINUX_KERNEL_RELEASE";
		AS_TRY_LINUX_DIR([${dir}], [LINUX_DIR=${dir}], )
	fi

	dnl then try a common default of /usr/src/linux
	if test "${LINUX_DIR}" = "default" ; then
		dir="/usr/src/linux";
		AS_TRY_LINUX_DIR([${dir}], [LINUX_DIR=${dir}], )
	fi

	dnl if still nothing found, fail
	if test "${LINUX_DIR}" = "default" ; then
		AC_MSG_WARN([Linux source directory not found])
	fi

	AC_SUBST(LINUX_DIR)
])

AC_DEFUN([AC_LINUX_SRCARCH],[
	AC_MSG_CHECKING(for linux SRCARCH)

	case "${host}" in
	i[[3456]]86-*) LINUX_SRCARCH=x86;;
	x86_64-*) LINUX_SRCARCH=x86;;
	powerpc*-*) LINUX_SRCARCH=powerpc;;
	s390*-*) LINUX_SRCARCH=s390;;
	arm*-*) LINUX_SRCARCH=arm;;
	*) AC_MSG_ERROR([architecture ${host} not supported]);;
	esac

	AC_MSG_RESULT(${LINUX_SRCARCH})
	AC_SUBST(LINUX_SRCARCH)
])

# See if we have working TLS.  We only check to see if it compiles, and that
# the resulting program actually runs, not whether the resulting TLS variables
# work properly; that check is done at runtime, since we can run binaries
# compiled with __thread on systems without TLS.
AC_DEFUN([LXC_CHECK_TLS],
[
    AC_MSG_CHECKING(for TLS)
    AC_RUN_IFELSE([AC_LANG_SOURCE([[ static __thread int val; int main() { return 0; } ]])],[have_tls=yes],[have_tls=no],[have_tls=no ])
    AC_MSG_RESULT($have_tls)
    if test "$have_tls" = "yes"; then
        AC_DEFINE([HAVE_TLS],[1],[Define if the compiler supports __thread])
        AC_DEFINE([thread_local],[__thread],[Define to the compiler TLS keyword])
    fi
])

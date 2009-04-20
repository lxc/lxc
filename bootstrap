#!/bin/sh

set -x

test -d autom4te.cache && rm -rf autom4te.cache
test -d m4 || mkdir m4
ACLOCAL_AMFLAGS="-I m4 -I config $ACLOCAL_AMFLAGS"
libtoolize --force --copy
aclocal $ACLOCAL_AMFLAGS || exit 1
autoheader || exit 1
autoconf || exit 1
automake --add-missing --copy || exit 1

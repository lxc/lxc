#!/bin/sh

set -x

test -d autom4te.cache && rm -rf autom4te.cache
test -d m4 || mkdir m4
libtoolize --force --copy
aclocal -I m4 -I config || exit 1
autoheader || exit 1
autoconf || exit 1
automake --add-missing --copy || exit 1

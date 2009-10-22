#!/bin/sh

set -x

test -d autom4te.cache && rm -rf autom4te.cache
 aclocal -I config || exit 1
autoheader || exit 1
autoconf || exit 1
automake --add-missing --copy || exit 1

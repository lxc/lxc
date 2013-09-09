#!/bin/sh
# liblxcapi
#
# Copyright © 2012 Serge Hallyn <serge.hallyn@ubuntu.com>.
# Copyright © 2012 Canonical Ltd.
#
#  This library is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public
#  License as published by the Free Software Foundation; either
#  version 2.1 of the License, or (at your option) any later version.

#  This library is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  Lesser General Public License for more details.

#  You should have received a copy of the GNU Lesser General Public
#  License along with this library; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

cleanup() {
    rm -f /etc/lxc/test-busybox.conf
    rm -f liblxc.so.0
}

if [ `id -u` -ne 0 ]; then
    echo "Run as root"
    exit 1
fi

cat > /etc/lxc/test-busybox.conf << EOF
lxc.network.type=veth
lxc.network.link=lxcbr0
lxc.network.flags=up
EOF

[ -f liblxc.so.0 ] || ln -s src/lxc/liblxc.so ./liblxc.so.0
export LD_LIBRARY_PATH=.
TESTS="lxc-test-containertests lxc-test-locktests lxc-test-startone"
for curtest in $TESTS; do
    echo "running $curtest"
    ./src/tests/$curtest
    if [ $? -ne 0 ]; then
        echo "Test $curtest failed.  Stopping"
        cleanup
        exit 1
    fi
done
echo "All tests passed"
cleanup

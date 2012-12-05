#!/bin/sh

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

#!/bin/bash
set -eux
set -o pipefail

export ASAN_OPTIONS=detect_stack_use_after_return=1:check_initialization_order=1:strict_init_order=1

# https://github.com/lxc/lxc/issues/3757
ASAN_OPTIONS="$ASAN_OPTIONS:detect_odr_violation=0"

export UBSAN_OPTIONS=print_stacktrace=1:print_summary=1:halt_on_error=1

apt-get install --yes --no-install-recommends \
    apparmor automake autoconf bash-completion bridge-utils build-essential \
    busybox-static clang cloud-image-utils curl dbus debhelper debootstrap \
    devscripts dh-apparmor dh-autoreconf dh-systemd dnsmasq-base \
    docbook2x doxygen ed fakeroot file gcc gnupg graphviz git iptables \
    net-tools libapparmor-dev libcap-dev libgnutls28-dev liblua5.2-dev \
    libpam0g-dev libseccomp-dev libselinux1-dev libtool linux-libc-dev \
    llvm lsb-release make openssl pkg-config python3-all-dev \
    python3-setuptools rsync squashfs-tools uidmap unzip uuid-runtime \
    wget xz-utils

# init.lxc.static is run in arbitrary containers where the libasan library lxc has been built with
# isn't always installed. To make it work let's override GCC's default and link both libasan
# and libubsan statically. It should help to fix issues like
# ...
# ++ lxc-execute -n c1 -- sudo -u ubuntu /nnptest
# lxc-init: error while loading shared libraries: libasan.so.5: cannot open shared object file: No such file or directory
if [[ "$CC" == "gcc" ]]; then
    sed -i '/init_lxc_static_LDFLAGS/s/$/ -static-libasan -static-libubsan/' src/lxc/Makefile.am
fi

./autogen.sh
CFLAGS=-fsanitize=address,undefined ./configure --enable-tests --prefix=/usr/ --sysconfdir=/etc/ --localstatedir=/var/ --disable-no-undefined
make
make install

sed -i 's/USE_LXC_BRIDGE="false"/USE_LXC_BRIDGE="true"/' /etc/default/lxc
systemctl daemon-reload
systemctl restart apparmor
systemctl restart lxc-net

git clone --depth=1 https://github.com/lxc/lxc-ci
lxc-ci/deps/lxc-exercise

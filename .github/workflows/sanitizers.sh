#!/bin/bash
set -eux
set -o pipefail

export ASAN_OPTIONS=detect_stack_use_after_return=1:check_initialization_order=1:strict_init_order=1:strict_string_checks=1

# https://github.com/lxc/lxc/issues/3757
ASAN_OPTIONS="$ASAN_OPTIONS:detect_odr_violation=0"

export UBSAN_OPTIONS=print_stacktrace=1:print_summary=1:halt_on_error=1

apt-get update -qq
apt-get install --yes --no-install-recommends \
    apparmor automake autoconf bash-completion bridge-utils build-essential \
    busybox-static clang cloud-image-utils curl dbus debhelper debootstrap \
    devscripts dnsmasq-base docbook2x doxygen ed fakeroot file gcc gnupg graphviz \
    git iptables net-tools libapparmor-dev libcap-dev libgnutls28-dev liblua5.2-dev \
    libpam0g-dev libseccomp-dev libselinux1-dev libtool linux-libc-dev \
    llvm lsb-release make openssl pkg-config python3-all-dev \
    python3-setuptools rsync squashfs-tools uidmap unzip uuid-runtime \
    wget xz-utils

ARGS="--enable-sanitizers --enable-tests --prefix=/usr/ --sysconfdir=/etc/ --localstatedir=/var/ --disable-no-undefined"
case "$CC" in clang*)
	ARGS="$ARGS --enable-fuzzers"
esac

./autogen.sh
CFLAGS="-Wall -Werror" ./configure $ARGS
make -j$(nproc)
make install

cat <<'EOF' >/usr/bin/lxc-test-share-ns
#!/bin/bash
printf "The test is skipped due to https://github.com/lxc/lxc/issues/3798.\n"
EOF

mv /usr/bin/{lxc-test-concurrent,test-concurrent.orig}
cat <<EOF >/usr/bin/lxc-test-concurrent
#!/bin/bash
printf "Memory leaks are ignored due to https://github.com/lxc/lxc/issues/3788.\n"
ASAN_OPTIONS=$ASAN_OPTIONS:detect_leaks=0 UBSAN_OPTIONS=$UBSAN_OPTIONS /usr/bin/test-concurrent.orig
EOF
chmod +x /usr/bin/lxc-test-concurrent

sed -i 's/USE_LXC_BRIDGE="false"/USE_LXC_BRIDGE="true"/' /etc/default/lxc
systemctl daemon-reload
systemctl restart apparmor
systemctl restart lxc-net

git clone --depth=1 https://github.com/lxc/lxc-ci
timeout 30m bash -x lxc-ci/deps/lxc-exercise

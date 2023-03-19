#!/bin/bash

set -ex

export LC_CTYPE=C.UTF-8

export CC=${CC:-clang}
export CXX=${CXX:-clang++}
clang_version="$($CC --version | sed -nr 's/.*version ([^ ]+?) .*/\1/p' | sed -r 's/-$//')"

SANITIZER=${SANITIZER:-address -fsanitize-address-use-after-scope}
flags="-O1 -fno-omit-frame-pointer -g -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=$SANITIZER"

clang_lib="/usr/lib64/clang/${clang_version}/lib/linux"
[ -d "$clang_lib" ] || clang_lib="/usr/lib/clang/${clang_version}/lib/linux"

export CFLAGS=${CFLAGS:-$flags}
export CXXFLAGS=${CXXFLAGS:-$flags}
export LDFLAGS=${LDFLAGS:--L${clang_lib}}

export OUT=${OUT:-$(pwd)/out}
mkdir -p $OUT

apt-get update -qq
apt-get install --yes --no-install-recommends \
    build-essential docbook2x doxygen git \
    wget xz-utils systemd-coredump pkgconf libdbus-1-dev
apt-get remove --yes lxc-utils liblxc-common liblxc1 liblxc-dev

# make sure we have a new enough meson version
pip3 install meson ninja

# Sanitized build
meson setup san_build \
	-Dprefix=/usr \
	-Db_lundef=false \
	-Dtests=false \
	-Dpam-cgroup=false \
	-Dwerror=true \
	-Dtools=false \
	-Dcommands=false \
	-Dcapabilities=false \
	-Dapparmor=false \
	-Dopenssl=false \
	-Dselinux=false \
	-Dseccomp=false \
	-Db_lto=false \
	-Db_pie=false \
	-Dthread-safety=false \
	-Ddbus=false \
	-Doss-fuzz=true
ninja -C san_build -v

for fuzz_target_source in src/tests/fuzz-lxc*.c; do
    fuzz_target_name=$(basename "$fuzz_target_source" ".c")
    cp "san_build/src/tests/$fuzz_target_name" "$OUT"
done

perl -lne 'if (/config_jump_table\[\]\s*=/../^}/) { /"([^"]+)"/ && print "$1=" }' src/lxc/confile.c >san_build/doc/examples/keys.conf
[[ -s san_build/doc/examples/keys.conf ]]

perl -lne 'if (/config_jump_table_net\[\]\s*=/../^}/) { /"([^"]+)"/ && print "lxc.net.$1=" }' src/lxc/confile.c >san_build/doc/examples/lxc-net-keys.conf
[[ -s san_build/doc/examples/lxc-net-keys.conf ]]

zip -r $OUT/fuzz-lxc-config-read_seed_corpus.zip san_build/doc/examples

mkdir fuzz-lxc-define-load_seed_corpus
perl -lne '/([^=]+)/ && print "printf $1= >fuzz-lxc-define-load_seed_corpus/$1"' san_build/doc/examples/{keys,lxc-net-keys}.conf | bash
zip -r $OUT/fuzz-lxc-define-load_seed_corpus.zip fuzz-lxc-define-load_seed_corpus

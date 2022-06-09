#!/bin/bash

set -ex

export SANITIZER=${SANITIZER:-address}
flags="-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
coverage_flags="-fsanitize=fuzzer-no-link"

sanitizer_flags="-fsanitize=address -fsanitize-address-use-after-scope"
if [[ "$SANITIZER" == "undefined" ]]; then
    sanitizer_flags="-fsanitize=undefined"
elif [[ "$SANITIZER" == "memory" ]]; then
    sanitizer_flags="-fsanitize=memory -fsanitize-memory-track-origins"
fi

export CC=${CC:-clang}
export CFLAGS=${CFLAGS:-$flags $sanitizer_flags $coverage_flags}

export CXX=${CXX:-clang++}
export CXXFLAGS=${CXXFLAGS:-$flags $sanitizer_flags $coverage_flags}

export OUT=${OUT:-$(pwd)/out}
mkdir -p $OUT

export LIB_FUZZING_ENGINE=${LIB_FUZZING_ENGINE:--fsanitize=fuzzer}

apt-get update -qq
apt-get install --yes --no-install-recommends \
    build-essential docbook2x doxygen git \
    wget xz-utils systemd-coredump pkgconf
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

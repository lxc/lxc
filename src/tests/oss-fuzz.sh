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
	-Db_lto_mode=default \
	-Db_sanitize=address,undefined
ninja -C san_build
ninja -C san_build install

for fuzz_target_source in src/tests/fuzz-lxc*.c; do
    fuzz_target_name=$(basename "$fuzz_target_source" ".c")
    cp "src/tests/$fuzz_target_name" "$OUT"
done

perl -lne 'if (/config_jump_table\[\]\s*=/../^}/) { /"([^"]+)"/ && print "$1=" }' src/lxc/confile.c >doc/examples/keys.conf
[[ -s doc/examples/keys.conf ]]

perl -lne 'if (/config_jump_table_net\[\]\s*=/../^}/) { /"([^"]+)"/ && print "lxc.net.$1=" }' src/lxc/confile.c >doc/examples/lxc-net-keys.conf
[[ -s doc/examples/lxc-net-keys.conf ]]

zip -r $OUT/fuzz-lxc-config-read_seed_corpus.zip doc/examples

mkdir fuzz-lxc-define-load_seed_corpus
perl -lne '/([^=]+)/ && print "printf $1= >fuzz-lxc-define-load_seed_corpus/$1"' doc/examples/{keys,lxc-net-keys}.conf | bash
zip -r $OUT/fuzz-lxc-define-load_seed_corpus.zip fuzz-lxc-define-load_seed_corpus

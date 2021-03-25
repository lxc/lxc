#!/bin/bash

set -ex

export SANITIZER=${SANITIZER:-address}
flags="-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
sanitizer_flags="-fsanitize=address -fsanitize-address-use-after-scope"
coverage_flags="-fsanitize=fuzzer-no-link"

export CC=${CC:-clang}
export CFLAGS=${CFLAGS:-$flags $sanitizer_flags $coverage_flags}

export CXX=${CXX:-clang++}
export CXXFLAGS=${CXXFLAGS:-$flags $sanitizer_flags $coverage_flags}

export OUT=${OUT:-$(pwd)/out}
mkdir -p $OUT

export LIB_FUZZING_ENGINE=${LIB_FUZZING_ENGINE:--fsanitize=fuzzer}

# -fsanitize=... isn't compatible with -Wl,-no-undefined
# https://github.com/google/sanitizers/issues/380
sed -i 's/-Wl,-no-undefined *\\/\\/' src/lxc/Makefile.am

# AFL++ and hoggfuzz are both incompatible with lto=thin apparently
sed -i '/-flto=thin/d' configure.ac

# turn off the libutil dependency
sed -i 's/^AC_CHECK_LIB(util/#/' configure.ac

./autogen.sh
./configure \
    --disable-tools \
    --disable-commands \
    --disable-apparmor \
    --disable-openssl \
    --disable-selinux \
    --disable-seccomp \
    --disable-capabilities

make -j$(nproc)

$CC -c -o fuzz-lxc-config-read.o $CFLAGS -Isrc -Isrc/lxc src/tests/fuzz-lxc-config-read.c
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz-lxc-config-read.o src/lxc/.libs/liblxc.a -o $OUT/fuzz-lxc-config-read

zip -r $OUT/fuzz-lxc-config-read_seed_corpus.zip doc/examples

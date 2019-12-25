#! /bin/bash

set -e

./coccinelle/run-coccinelle.sh -i
git diff --exit-code
export CFLAGS="-Wall -Werror"
export LDFLAGS="-pthread -lpthread"
./autogen.sh
rm -Rf build
mkdir build
cd build
if [ "$CC_FOR_BUILD" == "gcc" ]; then
  ../configure --enable-tests --enable-ubsan --with-distro=unknown
else
  ../configure --enable-tests --with-distro=unknown
fi
make -j4
make DESTDIR="$TRAVIS_BUILD_DIR"/install install
cd ../config/apparmor
./lxc-generate-aa-rules.py container-rules.base > /tmp/output
diff /tmp/output container-rules

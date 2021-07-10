./autogen.sh
./configure

make clean
make

for fuzzTar in $SRC/fuzz/stringFuzz/*; do
    $CXX $CXXFLAGS -Isrc src/lxc/fuzz/stringFuzz/$fuzzTar -o $OUT/$fuzzTar $LIB_FUZZING_ENGINE src/lxc/.libs/liblxc.a

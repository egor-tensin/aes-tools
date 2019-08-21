#!/usr/bin/env bash

set -o errexit -o nounset -o pipefail -o xtrace

readonly boost_fs="boost_${boost_version//\./_}"

readonly boost_dir="$HOME/$boost_fs"
readonly boost_librarydir="$boost_dir/stage/$arch/$build_type/lib"

compiler_prefix=i686
[ "$arch" = x64 ] && compiler_prefix=x86_64

readonly cc="$compiler_prefix-w64-mingw32-gcc"
readonly cxx="$compiler_prefix-w64-mingw32-g++"

cd -- "$HOME"
mkdir -- cmake
cd -- cmake/

cmake                                       \
    -D "CMAKE_BUILD_TYPE=$build_type"       \
    -D "CMAKE_C_COMPILER=$cc"               \
    -D "CMAKE_CXX_COMPILER=$cxx"            \
    -D "BOOST_ROOT=$boost_dir"              \
    -D "BOOST_LIBRARYDIR=$boost_librarydir" \
    -D Boost_USE_STATIC_LIBS=ON             \
    -D CMAKE_SYSTEM_NAME=Windows            \
    "$TRAVIS_BUILD_DIR"

cmake --build .

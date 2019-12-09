#!/usr/bin/env bash

set -o errexit -o nounset -o pipefail -o xtrace

readonly boost_fs="boost_${boost_version//\./_}"

readonly boost_dir="$HOME/$boost_fs"
readonly boost_librarydir="$boost_dir/stage/$arch/$build_type/lib"

cd -- "$HOME"
mkdir -- cmake
cd -- cmake/

cmake                                       \
    -D "CMAKE_BUILD_TYPE=$build_type"       \
    -D "CMAKE_TOOLCHAIN_FILE=$TRAVIS_BUILD_DIR/cmake/toolchains/mingw-w64-$arch.cmake" \
    -D "BOOST_ROOT=$boost_dir"              \
    -D "BOOST_LIBRARYDIR=$boost_librarydir" \
    -D CMAKE_SYSTEM_NAME=Windows            \
    "$TRAVIS_BUILD_DIR"

cmake --build . -- -j

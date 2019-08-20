#!/usr/bin/env bash

set -o errexit -o nounset -o pipefail -o xtrace

readonly boost_fs="boost_${boost_version//\./_}"
readonly boost_url=https://dl.bintray.com/boostorg/release/$boost_version/source/$boost_fs.tar.gz

cd -- "$HOME/"

wget -- "$boost_url"
tar xzvf "$boost_fs.tar.gz" > /dev/null
cd -- "$boost_fs/"
./bootstrap.sh

compiler_prefix=i686
[ "$arch" = x64 ] && compiler_prefix=x86_64

readonly cxx="$compiler_prefix-w64-mingw32-g++"

echo "using gcc : : $cxx ;" > "user-config-$arch.jam"

address_model=32
[ "$arch" = x64 ] && address_model=64

./b2 \
    toolset=gcc \
    "address-model=$address_model" \
    target-os=windows \
    link=static \
    variant="$build_type" \
    "--stagedir=stage/$arch/$build_type" \
    "--user-config=user-config-$arch.jam" \
    --with-filesystem \
    --with-program_options \
    --with-system

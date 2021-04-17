AES tools
=========

[![CI](https://github.com/egor-tensin/aes-tools/actions/workflows/ci.yml/badge.svg)](https://github.com/egor-tensin/aes-tools/actions/workflows/ci.yml)

Simple AES implementation and utilities.

Development
-----------

Build using CMake.
Depends on Boost.{Filesystem,Program_options}.
The project is Windows-only, so building with either MSVC or MinGW-w64 is
required.

There's a Makefile with useful shortcuts to build the project in the .build/
directory along with the dependencies (defaults to building with MinGW-w64):

    make deps
    make build
    make test

Usage on older CPUs
-------------------

To run the executables that are using the AES-NI instruction set on a CPU
without the support for these instructions, you can use [Intel Software
Development Emulator].
After you install the emulator, you can run an executable like this:

    > sde -- encrypt_block -a aes128 -m ecb -- 000102030405060708090a0b0c0d0e0f 00112233445566778899aabbccddeeff
    69c4e0d86a7b0430d8cdb78070b4c55a

[Intel Software Development Emulator]: https://software.intel.com/en-us/articles/intel-software-development-emulator

See also
--------

* [Utilities]
* [Testing]

[Utilities]: aesxx/utils/README.md
[Testing]: test/README.md

License
-------

Distributed under the MIT License.
See [LICENSE.txt] for details.

[LICENSE.txt]: LICENSE.txt

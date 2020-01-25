AES tools
=========

[![AppVeyor branch](https://img.shields.io/appveyor/ci/egor-tensin/aes-tools/master?label=Build%20%28Visual%20Studio%29)](https://ci.appveyor.com/project/egor-tensin/aes-tools/branch/master)
[![Travis (.com) branch](https://img.shields.io/travis/com/egor-tensin/aes-tools/master?label=Build%20%28MinGW-w64%29)](https://travis-ci.com/egor-tensin/aes-tools)

Simple AES implementation and utilities.

Building
--------

Create the build files using CMake and build using your native build tools
(Visual Studio/make/etc.).

* **Prerequisites.**
Depends on Boost.{Filesystem,Program_options}.
* **Customization.**
The runtime libraries are linked statically by default.
Therefore, the Boost libraries must also link them statically.
You can link the runtime dynamically by passing `-D CC_STATIC_RUNTIME=OFF` to
`cmake`.
* **Example.**
Using Visual Studio 2015 (targeting x86), build & install the release version
to C:\aes-tools:

      > cmake -G "Visual Studio 14 2015" -A Win32 ^
          -D BOOST_ROOT=C:\path\to\boost          ^
          C:\path\to\aes-tools
      ...

      > cmake --build . --config Release --target install -- /m
      ...

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

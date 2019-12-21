AES tools
=========

[![Travis (.com) branch](https://img.shields.io/travis/com/egor-tensin/aes-tools/master?label=Travis)](https://travis-ci.com/egor-tensin/aes-tools)
[![AppVeyor branch](https://img.shields.io/appveyor/ci/egor-tensin/aes-tools/master?label=AppVeyor)](https://ci.appveyor.com/project/egor-tensin/aes-tools/branch/master)

Simple AES implementation and utilities.

Building
--------

Create the build files using CMake and build using your native build tools
(Visual Studio/make/etc.).

* **Prerequisites.**
The following Boost libraries are required to build the project: Filesystem,
Program_options, System.
* **Customization.**
The runtime libraries are linked statically by default (when this project is
the root CMake project).
Therefore, the Boost dependencies must also link them statically.
You can link the runtime dynamically by passing `-D USE_STATIC_RUNTIME=OFF` to
`cmake`.
* **Example.**
In the example below, the project directory is
"C:\workspace\personal\aes-tools", Boost can be found in
"C:\workspace\third-party\boost_1_58_0" and Visual Studio 2013 is used,
targeting x86.

      > cmake -G "Visual Studio 12 2013"                      ^
          -D BOOST_ROOT=C:\workspace\third-party\boost_1_58_0 ^
          -D Boost_USE_STATIC_RUNTIME=ON                      ^
          C:\workspace\personal\aes-tools
      ...

      > cmake --build . --config release -- /m
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

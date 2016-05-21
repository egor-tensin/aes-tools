# AES tools

Simple AES implementation and utilities.

## Development

### Prerequisites

* Boost.Filesystem, Boost.Program_options and Boost.System

### Building the utilities

Create the build files using CMake and build using your native build tools
(Visual Studio/make/etc.).

For example, using Visual Studio 2013 Update 4 for Windows Desktop (targetting
x86 and using static Boost libraries):

    > cd
    C:\workspace\personal\build\aes-tools

    > cmake -G "Visual Studio 12 2013" ^
        -D BOOST_ROOT=C:\workspace\third-party\boost_1_58_0 ^
        -D Boost_USE_STATIC_LIBS=ON ^
        C:\workspace\personal\aes-tools
    ...

    > msbuild aes-tools.sln
    ...

## Usage on older CPUs

To run the executables that are using the AES-NI instruction set on a CPU
without the support for these instructions, you can use [Intel Software
Development Emulator].
After you install the emulator, you can run an executable like this:

    > sde -- encrypt_block.exe -a aes128 -m ecb -- 000102030405060708090a0b0c0d0e0f 00112233445566778899aabbccddeeff
    69c4e0d86a7b0430d8cdb78070b4c55a

[Intel Software Development Emulator]: https://software.intel.com/en-us/articles/intel-software-development-emulator

## Documentation

You can generate the docs using [Doxygen].
The docs will be generated in the "doc/" directory under the project's root.

[Doxygen]: http://www.stack.nl/~dimitri/doxygen/

## Utilities

See [Utilities].

[Utilities]: utils/README.md

## Testing

See [Testing].

[Testing]: test/README.md

## License

This project, including all of the files and their contents, is licensed under
the terms of the MIT License.
See [LICENSE.txt] for details.

[LICENSE.txt]: LICENSE.txt
